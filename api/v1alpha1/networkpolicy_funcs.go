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

func (l CIDRList) Strings() []string {
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
	for i := range np.Spec.Egress {
		totalPossible += len(np.Spec.Egress[i].ToFQDNs)
	}

	set := make(map[FQDN]struct{}, totalPossible)
	for i := range np.Spec.Egress {
		for _, fqdn := range np.Spec.Egress[i].ToFQDNs {
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
	// 前端没有校验的情况下，egress: []和egress: [{}]都是可以传入的，而egress: {}由于类型不匹配，前端不管是否有校验的情况下都会报错
	// 目前前端已添加校验，所以极端的全阻断egress: []和全放行egress: [{}]都是无法传入的
	// 所以，这里是永远不会返回nil值，但是程序处理逻辑还是保留
	numRules := len(np.Spec.Egress)
	if numRules == 0 {
		return nil
	}

	lookup := FQDNStatusList(fqdnStatuses).LookupTable()

	egress := make([]mnetv1beta1.MultiNetworkPolicyEgressRule, 0, numRules)

	for i := range np.Spec.Egress {
		if rule := np.Spec.Egress[i].toMultiNetworkPolicyEgressRule(lookup, np.Spec.BlockPrivateIPs); rule != nil {
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
	cidrs []*CIDR, reason NetworkPolicyResolutionReason, message string, retryTimeoutSeconds int,
) bool {
	cleared := false

	if reason == NetworkPolicyResolutionSuccess {
		// 只要成功，立刻重置失败时间戳为nil
		f.FailingSince = nil
		f.Addresses = CIDRList(cidrs).Strings()
	} else if reason.Transient() {
		// 如果是瞬时错误，而且是第一次出错
		if f.FailingSince == nil {
			// 记录起点
			now := metav1.Now()
			f.FailingSince = &now
		} else {
			// 持续失败中，对比ResolvedFailingSince判断是否真正超时
			deadline := f.FailingSince.Add(time.Duration(retryTimeoutSeconds) * time.Second)
			if time.Now().After(deadline) {
				if len(f.Addresses) > 0 {
					f.Addresses = []string{}
					cleared = true
				}
			}
		}
	} else {
		// 永久性错误
		if len(f.Addresses) > 0 {
			f.Addresses = []string{}
			cleared = true
		}
		if f.FailingSince == nil {
			now := metav1.Now()
			f.FailingSince = &now
		}
	}

	// 仅在状态变化时更新转换时间
	if f.Reason != reason {
		f.LastTransitionTime = metav1.Now()
	}
	f.Reason = reason
	f.Message = message

	return cleared
}

/*
func NewFQDNStatus(fqdn FQDN, cidrs []*CIDR, reason NetworkPolicyResolutionReason, message string) FQDNStatus {
	timeNow := metav1.Now()
	return FQDNStatus{
		FQDN: fqdn,
		//LastSuccessfulTime: timeNow,
		LastTransitionTime: timeNow,
		Reason:             reason,
		Message:            message,
		Addresses:          CIDRList(cidrs).String(),
	}
}*/

type FQDNStatusList []FQDNStatus

func (s FQDNStatusList) LookupTable() map[FQDN]*FQDNStatus {
	lookupTable := make(map[FQDN]*FQDNStatus, len(s))
	for i := range s {
		lookupTable[s[i].FQDN] = &s[i]
	}
	return lookupTable
}
