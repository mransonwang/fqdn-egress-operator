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
	"sort"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/mransonwang/fqdn-egress-operator/pkg/network"
	"github.com/mransonwang/fqdn-egress-operator/pkg/utils"

	"k8s.io/client-go/tools/record"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
)

type DNSResolver interface {
	Resolve(
		ctx context.Context,
		timeout time.Duration,
		maxConcurrent int,
		networkType v1alpha1.NetworkType,
		fqdns []v1alpha1.FQDN,
	) network.DNSResolverResultList
}

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

	previous := np.DeepCopy()

	resolutionTimeout := time.Duration(np.Spec.ResolutionTimeoutSeconds) * time.Second
	results := r.DNSResolver.Resolve(
		ctx, resolutionTimeout, r.MaxConcurrentResolves, np.Spec.EnabledNetworkType, np.FQDNs(),
	)

	np.Status.FQDNs = updateFQDNStatuses(
		r.EventRecorder, np, np.Status.FQDNs, results, int(np.Spec.RetryTimeoutSeconds),
	)

	mnp := np.ToMultiNetworkPolicy(np.Status.FQDNs)

	np.Status.TotalAddressCount = int32(len(results.CIDRs()))
	utils.RemoveDuplicateCidrsInNetworkPolicy(mnp)
	np.Status.AppliedAddressCount = int32((utils.CountDeDupedAddresses(mnp)))

	resolvedStatus := results.AggregatedResolvedStatus()
	np.SetResolvedCondition(
		resolvedStatus,
		results.AggregatedResolvedMessage(),
	)

	logger := logf.FromContext(ctx).WithValues(
		"status", resolvedStatus,
		"resolved", np.Status.TotalAddressCount,
		"applied", np.Status.AppliedAddressCount,
	)
	ctx = logf.IntoContext(ctx, logger)

	// egress: []
	if mnp == nil {
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyReadyFailure, "Network policy has no egress rules specified.")
		if err := r.updateStatusIfNeeded(ctx, np, previous); err != nil {
			return ctrl.Result{}, err
		}
		// 要去删除底层对应的MultiNetworkPolicy，因为有可能以前的策略中egress并不是空数组，那现在变成egress: []了，不能留着
		// 但对于第一次创建就使用egress: []的情况，这里实际上是没有底层的MultiNetworkPolicy可以删除的，被调用函数内部已自行做判断
		if err := r.reconcileNetworkPolicyDeletion(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		// 删除完底层的MultiNetworkPolicy后，自己静默直到被修改后唤醒
		logger.Info("Network policy has no egress rules specified, will not requeue until the policy is updated")
		return ctrl.Result{}, nil
	}

	// egress: [{...},{...}] 包含有正常的规则，进行正常处理就行
	if err := r.reconcileNetworkPolicyCreation(ctx, np, mnp); err != nil {
		formattedErr := fmt.Sprintf("Network policy failed to apply: %v.", err)
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyReadyFailure, formattedErr)
		if err := r.updateStatusIfNeeded(ctx, np, previous); err != nil {
			return ctrl.Result{}, err
		}
		// 创建底层MultiNetworkPolicy出错后固定每60秒重试一次
		logger.Info("Network policy failed to apply", "error", err.Error(), "requeueAfter", "60s")
		return ctrl.Result{RequeueAfter:  60 * time.Second}, nil
	}

	// 无法解析出任何IP地址，因此无法构造egress: []中的内容，所以生成的底层MultiNetworkPolicy实质上没有egress元素
	// 没有egress元素实质上等同于egress: []的效果
	if utils.IsEmpty(mnp) {
		np.SetReadyConditionTrue(
			v1alpha1.NetworkPolicyReadyEmptyRules,
			"Network policy has no FQDNs resolved to valid IP addresses, the default egress deny-all is in effect.",
		)
		if err := r.updateStatusIfNeeded(ctx, np, previous); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("Network policy has no FQDNs resolved to valid IP addresses", "requeueAfter", np.Spec.TTLSeconds)
		return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
	}

	// Creation succeeded, update the status and requeue after TTL
	np.SetReadyConditionTrue(v1alpha1.NetworkPolicyReadySuccess, "Network policy was successfully applied.")
	if err := r.updateStatusIfNeeded(ctx, np, previous); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("Reconciliation succeeded", "requeueAfter", np.Spec.TTLSeconds)
	return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
}

func (r *NetworkPolicyReconciler) updateStatusIfNeeded(ctx context.Context, np *v1alpha1.NetworkPolicy, previous *v1alpha1.NetworkPolicy) error {
	logger := logf.FromContext(ctx)

	sortStatus := func(status *v1alpha1.NetworkPolicyStatus) {
		sort.Slice(status.FQDNs, func(i, j int) bool {
			return string(status.FQDNs[i].FQDN) < string(status.FQDNs[j].FQDN)
		})
		for i := range status.FQDNs {
			sort.Strings(status.FQDNs[i].Addresses)
		}
	}

	sortStatus(&np.Status)
	sortStatus(&previous.Status)

	if equality.Semantic.DeepEqual(previous.Status, np.Status) {
		// logger.Info("Network policy status is unchanged")
		return nil
	}

	err := r.Client.Status().Update(ctx, np)
	if err != nil {
		if errors.IsConflict(err) {
			// 并发冲突通常是瞬时的，下次调和会修补，无需当作错误抛出
			return nil
		}
		return err
	}

	// 成功回写后打印日志
	logger.Info("Network policy status was updated")
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NetworkPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("fqdn-egress-operator").
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5,
		}).
		Complete(r)
}
