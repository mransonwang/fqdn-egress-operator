package controller

import (
	"context"

	mnetv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
	"github.com/mransonwang/fqdn-egress-operator/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *NetworkPolicyReconciler) reconcileNetworkPolicyCreation(
	ctx context.Context, np *v1alpha1.NetworkPolicy, mnp *mnetv1beta1.MultiNetworkPolicy,
) error {
	current := &mnetv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: np.Namespace,
		},
	}
	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, current, func() error {
		if current.Labels == nil {
			current.Labels = make(map[string]string, len(mnp.Labels))
		}
		for k := range current.Labels {
			if _, exists := mnp.Labels[k]; !exists {
				delete(current.Labels, k)
			}
		}
		for k, v := range mnp.Labels {
			current.Labels[k] = v
		}

		if current.Annotations == nil {
			current.Annotations = make(map[string]string, len(mnp.Annotations))
		}
		for k := range current.Annotations {
			if _, exists := mnp.Annotations[k]; !exists {
				delete(current.Annotations, k)
			}
		}
		for k, v := range mnp.Annotations {
			current.Annotations[k] = v
		}

		if !equality.Semantic.DeepEqual(current.Spec, mnp.Spec) {
			current.Spec = *mnp.Spec.DeepCopy()
		}
		return ctrl.SetControllerReference(np, current, r.Scheme)
	})
	if err != nil {
		r.EventRecorder.Event(
			np,
			corev1.EventTypeWarning,
			utils.OperationErrorReason(mnp),
			err.Error(),
		)
		return err
	}
	if op != controllerutil.OperationResultNone {
		r.EventRecorder.Event(
			np,
			corev1.EventTypeNormal,
			utils.OperationReason(mnp, op),
			utils.OperationMessage(mnp, op))
	}
	return nil
}
