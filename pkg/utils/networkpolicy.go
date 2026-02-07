package utils

import (
	"sort"
	"strings"

	mnetv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
)

// Remove duplicate CIDRs in MultiNetworkPolicy
func RemoveDuplicateCidrsInNetworkPolicy(networkPolicy *mnetv1beta1.MultiNetworkPolicy) {
	if networkPolicy == nil || len(networkPolicy.Spec.Egress) == 0 {
		return
	}

	totalPeers := 0
	for i := range networkPolicy.Spec.Egress {
		totalPeers += len(networkPolicy.Spec.Egress[i].To)
	}

	cidrToPortsMap := make(map[string]map[string]mnetv1beta1.MultiNetworkPolicyPort, totalPeers)

	for _, rule := range networkPolicy.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock == nil || peer.IPBlock.CIDR == "" {
				continue
			}
			cidr := peer.IPBlock.CIDR
			if _, ok := cidrToPortsMap[cidr]; !ok {
				cidrToPortsMap[cidr] = make(map[string]mnetv1beta1.MultiNetworkPolicyPort, 8)
			}

			for _, p := range rule.Ports {
				pKey := getSinglePortKey(p)
				cidrToPortsMap[cidr][pKey] = p
			}
		}
	}

	portsFingerprintToCidrs := make(map[string][]string, 16)
	fingerprintToPortSlice := make(map[string][]mnetv1beta1.MultiNetworkPolicyPort, 16)

	for cidr, portsMap := range cidrToPortsMap {
		portSlice := make([]mnetv1beta1.MultiNetworkPolicyPort, 0, len(portsMap))
		for _, p := range portsMap {
			portSlice = append(portSlice, p)
		}
		
		f := getPortsFingerprint(portSlice)
		
		if _, ok := portsFingerprintToCidrs[f]; !ok {
			portsFingerprintToCidrs[f] = make([]string, 0)
			fingerprintToPortSlice[f] = portSlice
		}
		portsFingerprintToCidrs[f] = append(portsFingerprintToCidrs[f], cidr)
	}

	newEgressRules := make([]mnetv1beta1.MultiNetworkPolicyEgressRule, 0, len(portsFingerprintToCidrs))
	
	sortedFingerprints := make([]string, 0, len(portsFingerprintToCidrs))
	for f := range portsFingerprintToCidrs {
		sortedFingerprints = append(sortedFingerprints, f)
	}
	sort.Strings(sortedFingerprints)

	for _, f := range sortedFingerprints {
		cidrs := portsFingerprintToCidrs[f]
		sort.Strings(cidrs)

		peers := make([]mnetv1beta1.MultiNetworkPolicyPeer, len(cidrs))
		for i, c := range cidrs {
			peers[i] = mnetv1beta1.MultiNetworkPolicyPeer{
				IPBlock: &mnetv1beta1.IPBlock{CIDR: c},
			}
		}

		newEgressRules = append(newEgressRules, mnetv1beta1.MultiNetworkPolicyEgressRule{
			Ports: fingerprintToPortSlice[f],
			To:    peers,
		})
	}

	networkPolicy.Spec.Egress = newEgressRules
}

func getSinglePortKey(p mnetv1beta1.MultiNetworkPolicyPort) string {
	protocol := "TCP"
	if p.Protocol != nil {
		protocol = string(*p.Protocol)
	}
	port := "any"
	if p.Port != nil {
		port = p.Port.String()
	}
	return protocol + ":" + port
}

func getPortsFingerprint(ports []mnetv1beta1.MultiNetworkPolicyPort) string {
	if len(ports) == 0 {
		return "all-ports"
	}

	tmp := make([]string, len(ports))
	for i, p := range ports {
		tmp[i] = getSinglePortKey(p)
	}
	
	sort.Strings(tmp)
	return strings.Join(tmp, ",")
}

func CountDeDupedAddresses(networkPolicy *mnetv1beta1.MultiNetworkPolicy) int {
	if networkPolicy == nil {
		return 0
	}

	var count int
	for i := range networkPolicy.Spec.Egress {
		count += len(networkPolicy.Spec.Egress[i].To)
	}

	return count
}

func IsEmpty(networkPolicy *mnetv1beta1.MultiNetworkPolicy) bool {
	if networkPolicy == nil {
		return true
	}	
	return len(networkPolicy.Spec.Ingress) == 0 && len(networkPolicy.Spec.Egress) == 0
}
