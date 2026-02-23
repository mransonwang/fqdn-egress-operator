package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (np *NetworkPolicy) SetResolvedCondition(reason NetworkPolicyResolutionReason, message string) {
	condition := metav1.ConditionFalse
	// 只有NetworkPolicyResolutionSuccess才会置其为Ture，否则其他两种状态PartialSuccess和Failure都是False
	// 使用resolver.go中设定的提示信息，而不要在这里硬编码
	if reason == NetworkPolicyResolutionSuccess {
		condition = metav1.ConditionTrue
		//message = "The network policy resolved successfully."
	}
	meta.SetStatusCondition(&np.Status.Conditions, metav1.Condition{
		Type:               string(NetworkPolicyResolved),
		Status:             condition,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: np.GetGeneration(),
	})
}

func (np *NetworkPolicy) SetReadyConditionTrue(reason NetworkPolicyReadyReason, message string) {
	meta.SetStatusCondition(&np.Status.Conditions, metav1.Condition{
		Type:               string(NetworkPolicyReady),
		Status:             metav1.ConditionTrue,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: np.GetGeneration(),
	})
	np.Status.ObservedGeneration = np.GetGeneration()
}

func (np *NetworkPolicy) SetReadyConditionFalse(reason NetworkPolicyReadyReason, message string) {
	meta.SetStatusCondition(&np.Status.Conditions, metav1.Condition{
		Type:               string(NetworkPolicyReady),
		Status:             metav1.ConditionFalse,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: np.GetGeneration(),
	})
}
