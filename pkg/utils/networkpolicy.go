package utils

import (
	"encoding/json"
	"fmt"
	"sort"

	mnetv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
)

// Remove duplicate CIDRs in MultiNetworkPolicy
func RemoveDuplicateCidrsInNetworkPolicy(networkPolicy *mnetv1beta1.MultiNetworkPolicy) {
	if networkPolicy == nil {
		return
	}

	fmt.Println("--- Before remove duplicate CIDRs, the original MultiNetworkPolicy as the following ---")
	printJSON(networkPolicy)

	var cleanedEgressRules []mnetv1beta1.MultiNetworkPolicyEgressRule

	for _, rule := range networkPolicy.Spec.Egress {

		cidrSet := make(map[string]struct{})

		for _, to := range rule.To {
			if to.IPBlock != nil {
				cidrSet[to.IPBlock.CIDR] = struct{}{}
			}
		}

		var sortedCIDRs []string
		for cidrStr := range cidrSet {
			sortedCIDRs = append(sortedCIDRs, cidrStr)
		}
		sort.Strings(sortedCIDRs)

		var newPeers []mnetv1beta1.MultiNetworkPolicyPeer

		for _, cidrStr := range sortedCIDRs {
			peer := mnetv1beta1.MultiNetworkPolicyPeer{
				IPBlock: &mnetv1beta1.IPBlock{
					CIDR: cidrStr,
				},
			}
			newPeers = append(newPeers, peer)
		}

		updatedRule := mnetv1beta1.MultiNetworkPolicyEgressRule{
			Ports: rule.Ports,
			To:    newPeers,
		}

		cleanedEgressRules = append(cleanedEgressRules, updatedRule)
	}

	networkPolicy.Spec.Egress = cleanedEgressRules

	fmt.Println("--- After removed duplicate CIDRs, the MultiNetworkPolicy as the following ---")
	printJSON(networkPolicy)
}

// UniqueCidrsInNetworkPolicy returns all the unique CIDR's applied in the network policy
func UniqueCidrsInNetworkPolicy(networkPolicy *mnetv1beta1.MultiNetworkPolicy) []*v1alpha1.CIDR {
	if networkPolicy == nil {
		return []*v1alpha1.CIDR{}
	}

	set := make(map[string]struct{})
	for _, rule := range networkPolicy.Spec.Ingress {
		for _, from := range rule.From {
			if from.IPBlock != nil {
				set[from.IPBlock.CIDR] = struct{}{}
			}
		}
	}
	for _, rule := range networkPolicy.Spec.Egress {
		for _, to := range rule.To {
			if to.IPBlock != nil {
				set[to.IPBlock.CIDR] = struct{}{}
			}
		}
	}

	var cidrs []*v1alpha1.CIDR
	for cidr := range set {
		if c, err := v1alpha1.NewCIDR(cidr); err == nil {
			cidrs = append(cidrs, c)
		}
	}

	return cidrs
}

func IsEmpty(networkPolicy *mnetv1beta1.MultiNetworkPolicy) bool {
	return len(networkPolicy.Spec.Ingress) == 0 && len(networkPolicy.Spec.Egress) == 0
}

func printJSON(obj interface{}) {
	b, _ := json.MarshalIndent(obj, "", "  ")
	fmt.Println(string(b))
}
