package v1alpha1

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	mnetv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var labelRegexp = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// CIDR represents a network range in CIDR (Classless Inter-Domain Routing) notation.
// It consists of an IP address and a Prefix (prefix length) that defines the size of the network.
type CIDR struct {
	IP     net.IP
	Prefix int
}

func NewCIDR(cidr string) (*CIDR, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	prefix, _ := ipNet.Mask.Size()
	return &CIDR{
		IP:     ip,
		Prefix: prefix,
	}, nil
}

func MustCIDR(cidr string) *CIDR {
	if c, err := NewCIDR(cidr); err != nil {
		panic(err)
	} else {
		return c
	}
}

// String returns the string representation of the CIDR
func (c *CIDR) String() string {
	return fmt.Sprintf("%s/%d", c.IP.String(), c.Prefix)
}

// IsPrivate returns true if the CIDR is a private address
func (c *CIDR) IsPrivate() bool {
	return c.IP.IsPrivate()
}

type CIDRList []*CIDR

func (l CIDRList) String() []string {
	result := make([]string, 0, len(l))
	for _, cidr := range l {
		result = append(result, cidr.String())
	}
	return result
}

// Valid returns true if the FQDN is valid
func (f *FQDN) Valid() bool {
	labels := strings.Split(string(*f), ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || !labelRegexp.MatchString(label) {
			return false
		}
	}
	return true
}

func isAllowed(cidrString string, globalBlock bool, ruleBlock *bool) bool {
	blockPrivateIP := globalBlock
	if ruleBlock != nil {
		blockPrivateIP = *ruleBlock
	}
	cidr, err := NewCIDR(cidrString)
	if err != nil {
		return false
	}
	if cidr.IsPrivate() && blockPrivateIP {
		return false
	}
	return true
}

func sortPeersByCIDR(peers []mnetv1beta1.MultiNetworkPolicyPeer) {
	sort.SliceStable(peers, func(i, j int) bool {
		// Make sure both peers have IPBlocks
		if peers[i].IPBlock == nil {
			return false
		}
		if peers[j].IPBlock == nil {
			return true
		}
		return peers[i].IPBlock.CIDR < peers[j].IPBlock.CIDR
	})
}

func getPeers(fqdns []FQDN, ips map[FQDN]*FQDNStatus, globalBlock bool, ruleBlock *bool) []mnetv1beta1.MultiNetworkPolicyPeer {
	peers := make([]mnetv1beta1.MultiNetworkPolicyPeer, 0, len(fqdns))

	for _, fqdn := range fqdns {
		if status, ok := ips[fqdn]; ok {
			for _, addr := range status.Addresses {
				if isAllowed(addr, globalBlock, ruleBlock) {
					peers = append(peers, mnetv1beta1.MultiNetworkPolicyPeer{
						IPBlock: &mnetv1beta1.IPBlock{CIDR: addr},
					})
				}
			}
		}
	}
	sortPeersByCIDR(peers)
	return peers
}

// toNetworkPolicyEgressRule converts the EgressRule to a mnetv1beta1.MultiNetworkPolicyEgressRule.
// Returns nil if no peers were found.
func (r *EgressRule) toMultiNetworkPolicyEgressRule(ips map[FQDN]*FQDNStatus, blockPrivate bool) *mnetv1beta1.MultiNetworkPolicyEgressRule {
	peers := getPeers(r.ToFQDNs, ips, blockPrivate, r.BlockPrivateIPs)
	if len(peers) == 0 {
		return nil
	}

	ports := make([]mnetv1beta1.MultiNetworkPolicyPort, len(r.Ports))
	for i := range r.Ports {
		val := intstr.FromInt(int(r.Ports[i].Port))
		proto := r.Ports[i].Protocol
		ports[i] = mnetv1beta1.MultiNetworkPolicyPort{
			Port:     &val,
			Protocol: &proto,
		}
	}

	return &mnetv1beta1.MultiNetworkPolicyEgressRule{
		Ports: ports,
		To:    peers,
	}
}

// FQDNs Returns all unique FQDNs defined in the network policy
func (np *NetworkPolicy) FQDNs() []FQDN {
	totalPossible := 0
	for i := range np.Spec.Egresses {
		totalPossible += len(np.Spec.Egresses[i].ToFQDNs)
	}

	set := make(map[FQDN]struct{}, totalPossible)
	for i := range np.Spec.Egresses {
		for _, fqdn := range np.Spec.Egresses[i].ToFQDNs {
			set[fqdn] = struct{}{}
		}
	}

	fqdns := make([]FQDN, 0, len(set))
	for fqdn := range set {
		fqdns = append(fqdns, fqdn)
	}

	sort.SliceStable(fqdns, func(i, j int) bool {
		return fqdns[i] < fqdns[j]
	})

	return fqdns
}

// ToMultiNetworkPolicy converts the NetworkPolicy to a mnetv1beta1.MultiNetworkPolicy.
// If no Egress rules are specified, nil is returned.
func (np *NetworkPolicy) ToMultiNetworkPolicy(fqdnStatuses []FQDNStatus) *mnetv1beta1.MultiNetworkPolicy {
	numRules := len(np.Spec.Egresses)
	if numRules == 0 {
		return nil
	}

	lookup := FQDNStatusList(fqdnStatuses).LookupTable()

	egress := make([]mnetv1beta1.MultiNetworkPolicyEgressRule, 0, numRules)

	for i := range np.Spec.Egresses {
		if rule := np.Spec.Egresses[i].toMultiNetworkPolicyEgressRule(lookup, np.Spec.BlockPrivateIPs); rule != nil {
			egress = append(egress, *rule)
		}
	}

	matchLabels := make(map[string]string, len(np.Spec.MatchLabels))
	for i := range np.Spec.MatchLabels {
		item := &np.Spec.MatchLabels[i]
		matchLabels[string(item.Label)] = item.Value
	}

	matchExpressions := make([]metav1.LabelSelectorRequirement, len(np.Spec.MatchExpressions))
	for i := range np.Spec.MatchExpressions {
		src := &np.Spec.MatchExpressions[i]
		dst := &matchExpressions[i]

		dst.Key = src.Key
		dst.Operator = src.Operator
		dst.Values = make([]string, len(src.Values))
		for j := range src.Values {
			dst.Values[j] = string(src.Values[j])
		}
	}

	return &mnetv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: np.Namespace,
			Labels:    np.Labels,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": fmt.Sprintf("%s/%s", np.Namespace, np.Spec.TargetNetwork),
			},
		},
		Spec: mnetv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels:      matchLabels,
				MatchExpressions: matchExpressions,
			},
			Egress:      egress,
			PolicyTypes: []mnetv1beta1.MultiPolicyType{mnetv1beta1.PolicyTypeEgress},
		},
	}
}

// Update updates the status of the FQDN.
// If addresses were cleared due to an error during the update, the method returns true.
func (f *FQDNStatus) Update(
	cidrs []*CIDR, reason NetworkPolicyResolvedConditionReason, message string, retryTimeoutSeconds int,
) bool {
	cleared := false
	if reason == NetworkPolicyResolvedSuccess {
		f.LastSuccessfulTime = metav1.Now()
		f.Addresses = CIDRList(cidrs).String()
	}
	// On transient errors we want to adhere to the retry timeout specification
	if reason != NetworkPolicyResolvedSuccess && reason.Transient() {
		retryLimitReached := time.Now().After(
			f.LastSuccessfulTime.Add(time.Duration(retryTimeoutSeconds) * time.Second),
		)

		if retryLimitReached {
			f.Addresses = []string{}
			cleared = true
		}
	}
	// On non-transient errors we clear the addresses immediately
	if reason != NetworkPolicyResolvedSuccess && !reason.Transient() {
		f.Addresses = []string{}
		cleared = true
	}
	if f.ResolvedReason != reason {
		f.LastTransitionTime = metav1.Now()
	}
	f.ResolvedReason = reason
	f.ResolvedMessage = message
	return cleared
}

func NewFQDNStatus(fqdn FQDN, cidrs []*CIDR, reason NetworkPolicyResolvedConditionReason, message string) FQDNStatus {
	timeNow := metav1.Now()
	return FQDNStatus{
		FQDN:               fqdn,
		LastSuccessfulTime: timeNow,
		LastTransitionTime: timeNow,
		ResolvedReason:     reason,
		ResolvedMessage:    message,
		Addresses:          CIDRList(cidrs).String(),
	}
}

type FQDNStatusList []FQDNStatus

func (s FQDNStatusList) LookupTable() map[FQDN]*FQDNStatus {
	lookupTable := make(map[FQDN]*FQDNStatus, len(s))
	for i := range s {
		lookupTable[s[i].FQDN] = &s[i]
	}
	return lookupTable
}
