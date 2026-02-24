package controller

import (
	"fmt"
	"time"

	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
	"github.com/mransonwang/fqdn-egress-operator/pkg/network"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
)

func updateFQDNStatuses(
	recorder record.EventRecorder, object runtime.Object,
	previous []v1alpha1.FQDNStatus, results network.DNSResolverResultList,
	retryTimeoutSeconds int,
) []v1alpha1.FQDNStatus {
	newFQDNStatuses := make([]v1alpha1.FQDNStatus, 0, len(results))
	previousLookup := v1alpha1.FQDNStatusList(previous).LookupTable()

	for _, result := range results {
		var status v1alpha1.FQDNStatus
		if existing, ok := previousLookup[result.FQDN]; ok {
			status = *existing
		} else {
			status = v1alpha1.FQDNStatus{
				FQDN: result.FQDN,
			}
		}

		cleared := status.Update(result.CIDRs, result.Status, result.Message, retryTimeoutSeconds)
		newFQDNStatuses = append(newFQDNStatuses, status)

		if cleared {
			var eventMsg string
			var eventReason string
			if result.Status.Transient() {
				eventReason = "StaleIPsRemoved"
				eventMsg = fmt.Sprintf(
					"Removed stale IPs for FQDN %s after %s (Status: %s)",
					status.FQDN,
					(time.Duration(retryTimeoutSeconds) * time.Second).String(),
					status.Reason,
				)
			} else {
				eventReason = "IPsRevoked"
				eventMsg = fmt.Sprintf(
					"Immediately removed IPs for FQDN %s: domain not found or no address records exist (Status: %s)",
					status.FQDN,
					status.Reason,
				)
			}

			recorder.Event(object, corev1.EventTypeWarning, eventReason, eventMsg)
		}
	}
	return newFQDNStatuses
}
