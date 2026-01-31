package controller

import (
	"context"

	mnetv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
	"github.com/mransonwang/fqdn-egress-operator/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// reconcileNetworkPolicyCreation Removes the underlying network policy
func (r *NetworkPolicyReconciler) reconcileNetworkPolicyDeletion(ctx context.Context, np *v1alpha1.NetworkPolicy) error {
	networkPolicy := &mnetv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: np.Namespace,
		},
	}
	if err := r.Delete(ctx, networkPolicy); err != nil && !errors.IsNotFound(err) {
		return err
	}
	r.EventRecorder.Event(
		np, corev1.EventTypeNormal,
		utils.DeletionReason(networkPolicy), utils.DeletionMessage(networkPolicy),
	)
	return nil
}
