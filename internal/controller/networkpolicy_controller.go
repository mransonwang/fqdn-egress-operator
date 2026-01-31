/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/mransonwang/fqdn-egress-operator/pkg/network"
	"github.com/mransonwang/fqdn-egress-operator/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
)

// DNSResolver resolves domains to IP addresses
type DNSResolver interface {
	// Resolve all the given fqdns to a DNSResolverResult
	Resolve(
		ctx context.Context,
		timeout time.Duration,
		maxConcurrent int,
		networkType v1alpha1.NetworkType,
		fqdns []v1alpha1.FQDN,
	) network.DNSResolverResultList
}

// NetworkPolicyReconciler reconciles a NetworkPolicy object
type NetworkPolicyReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	EventRecorder         record.EventRecorder
	DNSResolver           DNSResolver
	MaxConcurrentResolves int
}

// +kubebuilder:rbac:groups=k8s.cni.cncf.io,resources=multi-networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.turbosimone.com,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.turbosimone.com,resources=networkpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.turbosimone.com,resources=networkpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the NetworkPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *NetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	np := &v1alpha1.NetworkPolicy{}
	if err := r.Get(ctx, req.NamespacedName, np); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	patch := client.MergeFrom(np.DeepCopy())

	if np.Spec.TargetNetwork != "" {
		expectedAnnotationValue := fmt.Sprintf("%s/%s", np.Namespace, np.Spec.TargetNetwork)
		annotationKey := "k8s.v1.cni.cncf.io/policy-for"

		if np.Annotations == nil || np.Annotations[annotationKey] != expectedAnnotationValue {
			if np.Annotations == nil {
				np.Annotations = make(map[string]string)
			}
			np.Annotations[annotationKey] = expectedAnnotationValue

			if err := r.Patch(ctx, np, patch); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
	}

	// Resolve the FQDNs to IP addresses
	resolveTimeout := time.Duration(np.Spec.ResolveTimeoutSeconds) * time.Second
	results := r.DNSResolver.Resolve(
		ctx, resolveTimeout, r.MaxConcurrentResolves, np.Spec.EnabledNetworkType, np.FQDNs(),
	)

	np.Status.FQDNs = updateFQDNStatuses(
		r.EventRecorder, np, np.Status.FQDNs, results, int(np.Spec.RetryTimeoutSeconds),
	)

	// Generate a network policy from the FQDN based network policy using the resolved addresses
	networkPolicy := np.ToMultiNetworkPolicy(np.Status.FQDNs)

	np.Status.TotalAddressCount = int32(len(results.CIDRs()))
	np.Status.AppliedAddressCount = int32(len(utils.UniqueCidrsInNetworkPolicy(networkPolicy)))
	np.Status.LatestLookupTime = metav1.NewTime(time.Now())

	// Set the resolve status condition
	resolveStatus := results.AggregatedResolveStatus()
	np.SetResolveCondition(
		resolveStatus,
		results.AggregatedResolveMessage(),
	)

	logger := logf.FromContext(ctx).WithValues(
		"policy", np.GetName(), "namespace", np.GetNamespace(),
		"status", resolveStatus,
		"resolved", np.Status.TotalAddressCount,
		"applied", np.Status.AppliedAddressCount,
	)
	logf.IntoContext(ctx, logger)

	utils.RemoveDuplicateCidrsInNetworkPolicy(networkPolicy)

	// The network policy does not define any Egress rules, delete network policy if it exists
	if networkPolicy == nil {
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyFailed, "No Egress rules specified")
		if err := r.Client.Status().Update(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.reconcileNetworkPolicyDeletion(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("No Egress rules, will not requeue until updated")
		return ctrl.Result{}, nil
	}

	// There are Egress rules defined in our FQDN network policy, we create or update the underlying
	// network policy, so we create it.
	if err := r.reconcileNetworkPolicyCreation(ctx, np, networkPolicy); err != nil {
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyFailed, err.Error())
		if err := r.Client.Status().Update(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	// If the underlying network policy is empty we set a different status
	// This happens when the FQDN's do not resole to any valid addresses
	if utils.IsEmpty(networkPolicy) {
		np.SetReadyConditionTrue(
			v1alpha1.NetworkPolicyEmptyRules,
			"Resolved to an empty NetworkPolicy. Egress deny-all in effect.",
		)
		if err := r.Client.Status().Update(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("Network policy is empty", "requeueAfter", np.Spec.TTLSeconds)
		return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
	}

	// Creation succeeded, update the status and requeue after TTL
	np.SetReadyConditionTrue(v1alpha1.NetworkPolicyReady, "The network policy is ready.")
	if err := r.Client.Status().Update(ctx, np); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("Reconciliation succeeded", "requeueAfter", np.Spec.TTLSeconds)
	return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NetworkPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("fqdnnetworkpolicy").
		Complete(r)
}
