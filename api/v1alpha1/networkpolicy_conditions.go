package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetResolvedCondition updates the Resolved condition based on the provided reason and message.
// If the reason indicates success, the status is set to True with a standard success message.
func (np *NetworkPolicy) SetResolvedCondition(reason NetworkPolicyResolutionReason, message string) {
	condition := metav1.ConditionFalse
	// 只有NetworkPolicyResolvedSuccess才会置其为Ture，否则其他两种状态PartialSuccess和Failure都是False
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

// SetReadyConditionTrue sets the Ready condition to True with a standard success message.
// Updates the ObservedGeneration to reflect the current spec generation.
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

// SetReadyConditionFalse sets the Ready condition to False with the provided reason and message.
func (np *NetworkPolicy) SetReadyConditionFalse(reason NetworkPolicyReadyReason, message string) {
	meta.SetStatusCondition(&np.Status.Conditions, metav1.Condition{
		Type:               string(NetworkPolicyReady),
		Status:             metav1.ConditionFalse,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: np.GetGeneration(),
	})
}
