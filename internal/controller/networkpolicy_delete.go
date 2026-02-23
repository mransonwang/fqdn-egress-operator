package controller

import (
	"context"

	mnetv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
	"github.com/mransonwang/fqdn-egress-operator/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *NetworkPolicyReconciler) reconcileNetworkPolicyDeletion(ctx context.Context, np *v1alpha1.NetworkPolicy) error {
	mnp := &mnetv1beta1.MultiNetworkPolicy{}

	err := r.Get(ctx, client.ObjectKey{
		Name:      np.Name,
		Namespace: np.Namespace,
	}, mnp)

	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if err := r.Delete(ctx, mnp); err != nil {
		return client.IgnoreNotFound(err)
	}

	r.EventRecorder.Event(
		np, 
		corev1.EventTypeNormal,
		utils.DeletionReason(mnp), 
		utils.DeletionMessage(mnp),
	)
	
	return nil
}
