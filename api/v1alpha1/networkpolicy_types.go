/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NetworkType defines the IP address protocol types allowed for DNS resolution.
//
// +kubebuilder:validation:Enum=ipv4;ipv6;all
type NetworkType string

const (
	IPv4 NetworkType = "ipv4"
	IPv6 NetworkType = "ipv6"
	All  NetworkType = "all"
)

// ResolverString returns the protocol string parameter expected by the standard net.Resolver during LookupIP.
// Returns an empty string for unknown types.
func (n NetworkType) ResolverString() string {
	switch n {
	case IPv4:
		return "ip4"
	case IPv6:
		return "ip6"
	case All:
		return "ip"
	}
	return ""
}

// Label defines the label key name used for matching resources.
//
// +kubebuilder:validation:Enum=vm.kubevirt.io/name;app.kubernetes.io/name
type Label string

const (
	LabelWithVirtualMachineName Label = "vm.kubevirt.io/name"
	LabelWithKubernetesAppName  Label = "app.kubernetes.io/name"
)

// MatchLabel is a shadow struct used to apply custom kubebuilder validations.
// It defines the label key-value pair used to select target Pods while enforcing strict input constraints.
type MatchLabel struct {
	// Label is the label key that the target resource must contain.
	//
	// +kubebuilder:default="vm.kubevirt.io/name"
	Label Label `json:"label"`
	// Value is the string value corresponding to the label key.
	//
	// +kubebuilder:validation:MinLength=1
	Value string `json:"value"`
}

// Value represents a single string value in the label selector requirement.
//
// +kubebuilder:validation:MinLength=1
type LabelValue string

// LabelSelectorRequirement is a shadow struct of the standard metav1.LabelSelectorRequirement.
// It is specifically designed to apply custom kubebuilder validations (e.g., Enum constraints, MaxItems) to the label selector filter conditions.
type LabelSelectorRequirement struct {
	// Key is the target label key that the selector applies to.
	//
	// +kubebuilder:default="vm.kubevirt.io/name"
	// +kubebuilder:validation:Enum=vm.kubevirt.io/name;app.kubernetes.io/name
	Key string `json:"key"`
	// Operator represents a key's relationship to a set of values. Valid operators are In and NotIn.
	//
	// +kubebuilder:default="In"
	// +kubebuilder:validation:Enum=In;NotIn
	Operator metav1.LabelSelectorOperator `json:"operator"`
	// Values is an array of string values. If the operator is In or NotIn, the values array must be non-empty.
	//
	// +kubebuilder:validation:MaxItems=50
	// +listType=set
	Values []LabelValue `json:"values"`
}

// MultiNetworkPolicyPort is a shadow struct used to apply custom kubebuilder validations.
// It mirrors the underlying network policy port definition while enforcing strict port range and protocol constraints on user inputs.
type MultiNetworkPolicyPort struct {
	// Protocol defines the transport layer protocol of the container network port.
	//
	// +kubebuilder:default="TCP"
	// +kubebuilder:validation:Enum=TCP;UDP;SCTP
	Protocol corev1.Protocol `json:"protocol"`
	// Port is the specific port number allowed for traffic.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// FQDN represents a Fully Qualified Domain Name used to uniquely identify a host on the internet.
//
// Format constraints:
//	▸ Rule: Labels separated by dots (e.g., api.example.com)
//	▸ Rule: Alphanumeric and hyphens only
//	▸ Rule: No leading or trailing hyphens
//	▸ Rule: Top-level domain must be 2+ characters
//
// +kubebuilder:validation:Pattern=`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
type FQDN string

// EgressRule defines the rules for outbound network traffic.
// The system will periodically resolve the IP addresses of the FQDNs in the rule to dynamically update the underlying network policy.
type EgressRule struct {
	// ToFQDNs contains the list of target FQDNs allowed for outbound traffic communication.
	// 
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +listType=set
	ToFQDNs []FQDN `json:"toFQDNs"`
	// Ports specifies the list of network ports allowed for outbound traffic access.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +listType=map
	// +listMapKey=protocol
	// +listMapKey=port
	Ports []MultiNetworkPolicyPort `json:"ports"`
	// BlockPrivateIPs overrides the default configuration of the same name at the NetworkPolicySpec level for the current rule.
	//
	// Configuration:
	//	▸ Default: Inherits from NetworkPolicySpec.BlockPrivateIPs
	BlockPrivateIPs *bool `json:"blockPrivateIPs,omitempty"`
}

// NetworkPolicySpec defines the desired state of NetworkPolicy.
type NetworkPolicySpec struct {
	// TargetNetwork specifies the target NAD resource where this NetworkPolicy takes effect. If the selection dropdown is empty, no NADs are available in the current project, preventing the policy from taking effect. Please ensure at least one valid NAD is created before proceeding.
	//
	// +kubebuilder:validation:MinLength=1
	TargetNetwork string `json:"targetNetwork"`

	// MatchLabels defines a collection of label key-value pairs used to select the Pods to which this NetworkPolicy applies.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=label
	// +listMapKey=value
	MatchLabels []MatchLabel `json:"matchLabels,omitempty"`

	// MatchExpressions defines a collection of advanced label expressions used to select the Pods to which this NetworkPolicy applies.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=30
	// +kubebuilder:validation:XValidation:rule="self.all(i, self.filter(j, i.key == j.key && i.operator == j.operator && j.values.exists(v, v in i.values)).size() == 1)",message="spec.matchExpressions in body should not contain overlapping values for the same key and operator"
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`

	// Egress defines the outbound network traffic allowance rules for the selected Pods.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=30
	// +kubebuilder:validation:XValidation:rule="self.all(i, self.filter(j, j.toFQDNs.exists(f, f in i.toFQDNs) && j.ports.exists(p, p in i.ports)).size() == 1)",message="spec.egress in body should not contain overlapping toFQDNs and ports across different rules"
	Egress []EgressRule `json:"egress"`

	// EnabledNetworkType determines the IP address families used for DNS resolution and subsequent traffic allowance.
	//
	// Configuration:
	//	▸ Default: ipv4
	//
	// +kubebuilder:default:=ipv4
	EnabledNetworkType NetworkType `json:"enabledNetworkType,omitempty"`

	// ResolutionTimeoutSeconds defines the maximum timeout duration for a single FQDN during DNS queries.
	//
	// Configuration:
	//	▸ Default: 3s
	//	▸ Range: 1s to 60s
	//	▸ Constraint: Must be strictly less than TTLSeconds
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=60
	// +kubebuilder:default:=3
	ResolutionTimeoutSeconds int32 `json:"resolutionTimeoutSeconds,omitempty"`

	// RetryTimeoutSeconds defines the tolerance duration when FQDN resolution errors occur. Within this time window, previously successfully resolved IP addresses will be retained in the underlying network policy to prevent intermittent DNS failures from disrupting business traffic.
	//
	// Configuration:
	//	▸ Default: 3600s (1 hour)
	//	▸ Range: 1s to 86400s (24 hours)
	//
	// +kubebuilder:validation:Maximum=86400
	// +kubebuilder:default:=3600
	RetryTimeoutSeconds int32 `json:"retryTimeoutSeconds,omitempty"`

	// TTLSeconds defines the polling interval to re-evaluate and resolve all FQDN addresses.
	//
	// Configuration:
	//	▸ Default: 60s
	//	▸ Range: 5s to 1800s
	//	▸ Constraint: Must be strictly greater than ResolutionTimeoutSeconds
	//
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=1800
	// +kubebuilder:default:=60
	TTLSeconds int32 `json:"ttlSeconds,omitempty"`

	// BlockPrivateIPs controls whether to automatically intercept and drop all private IP address ranges from the DNS resolution results. When enabled (true), private IPs are blocked unless explicitly overridden and allowed at a specific EgressRule level.
	//
	// Configuration:
	//	▸ Default: false
	BlockPrivateIPs bool `json:"blockPrivateIPs,omitempty"`
}

type NetworkPolicyConditionType string

const (
	NetworkPolicyReady    NetworkPolicyConditionType = "Ready"
	NetworkPolicyResolved NetworkPolicyConditionType = "Resolved"
)

type NetworkPolicyReadyReason string

const (
	// 网络策略下发成功，策略中至少包含一条规则（以IP地址块为放行目标），也即至少有一个FQDN是解析成功的
	NetworkPolicyReadySuccess NetworkPolicyReadyReason = "Success"
	// 网络策略下发成功，但策略中不含任何规则，一般认为是没有任何一个FQDN解析成功所导致
	NetworkPolicyReadyEmptyRules NetworkPolicyReadyReason = "EmptyRules"
	// 网络策略下发失败，原因有很多，比如MultiNetworkPolicy CRD不存在等
	NetworkPolicyReadyFailure NetworkPolicyReadyReason = "Failure"
)

type NetworkPolicyResolutionReason string

const (
	// 所有FQDN都解析成功（下面单个FQDN的解析成功也会使用这个状态）
	NetworkPolicyResolutionSuccess NetworkPolicyResolutionReason = "Success"
	// 部分FQDN解析成功（下面单个FQDN的解析不会使用到这个状态）
	NetworkPolicyResolutionPartialSuccess NetworkPolicyResolutionReason = "PartialSuccess"
	// 所有FQDN都解析失败（下面单个FQDN的解析失败不会直接使用到这个状态，而是会使用下面各种细化出来的状态）
	NetworkPolicyResolutionFailure NetworkPolicyResolutionReason = "Failure"

	// 针对单个FQDN解析的状态
	// 解析出错了，Error其实可以包含很多错误状态，瞬时
	NetworkPolicyResolutionError NetworkPolicyResolutionReason = "Error"
	// FQDN不存在，包含两种情况：域名不存在、域名存在但主机记录不存在，这两种情况的错误信息都是no such host
	NetworkPolicyResolutionHostNotFound NetworkPolicyResolutionReason = "HostNotFound"
	// FQDN格式错误，在进入真正解析时通过格式检查，有可能抛出这个错误。但实际上由于前端已有严格的格式检查，程序中永远不会出现这个错误
	NetworkPolicyResolutionInvalidFormat NetworkPolicyResolutionReason = "InvalidFormat"
	// FQDN解析等待延时，瞬时
	NetworkPolicyResolutionTimeout NetworkPolicyResolutionReason = "Timeout"
	// FQDN解析中遭遇临时错误，瞬时
	NetworkPolicyResolutionTemporaryError NetworkPolicyResolutionReason = "TemporaryError"
)

func (r NetworkPolicyResolutionReason) Priority() int {
	switch r {
	case NetworkPolicyResolutionFailure:
		return 100
	case NetworkPolicyResolutionPartialSuccess:
		return 90

	case NetworkPolicyResolutionError:
		return 10
	case NetworkPolicyResolutionHostNotFound:
		return 8
	case NetworkPolicyResolutionInvalidFormat:
		return 6
	case NetworkPolicyResolutionTimeout:
		return 4
	case NetworkPolicyResolutionTemporaryError:
		return 2
	default:
		return 0
	}
}

func (r NetworkPolicyResolutionReason) Transient() bool {
	switch r {
	// 解析延时、解析时临时错误、解析时错误都被当成瞬时情况处理，因为这些情况随着时间的推移，是有可能消失的
	case NetworkPolicyResolutionTimeout, NetworkPolicyResolutionTemporaryError, NetworkPolicyResolutionError:
		return true
	default:
		return false
	}
}

// FQDNStatus defines the resolution status of a specific FQDN.
type FQDNStatus struct {
	// FQDN specifies the exact fully qualified domain name that this resolution status tracks.
	FQDN FQDN `json:"fqdn"`
	// FailingSince records the exact time the FQDN first started failing to resolve.
	// It is nil when the FQDN is resolved successfully.
	// This timestamp is used to calculate whether a continuous transient failure has exceeded the tolerance defined by NetworkPolicySpec.RetryTimeoutSeconds.
	FailingSince *metav1.Time `json:"failingSince,omitempty"`
	// LastTransitionTime is the last time the resolution reason transitioned from one state to another.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// Reason describes the specific condition or error encountered during the last resolution attempt.
	Reason NetworkPolicyResolutionReason `json:"reason,omitempty"`
	// Message is a human-readable description detailing the reason for the current status.
	Message string `json:"message,omitempty"`
	// Addresses is the list of resolved IP addresses for the given FQDN.
	// This list is cleared immediately upon a non-transient error, or if a transient error persists longer than the limit specified by NetworkPolicySpec.RetryTimeoutSeconds.
	Addresses []string `json:"addresses,omitempty"`
}

// NetworkPolicyStatus defines the observed state of NetworkPolicy.
type NetworkPolicyStatus struct {
	// FQDNs contains the detailed resolution status for each FQDN defined in the egress rules.
	FQDNs []FQDNStatus `json:"fqdns,omitempty"`
	// ActiveFQDNCount represents the number of FQDNs currently holding valid IPs (including cached ones).
	// +kubebuilder:validation:Optional
	ActiveFQDNCount int32 `json:"activeFQDNCount"`
	// FailingFQDNCount represents the number of FQDNs that failed to resolve and have no cached IPs.
	// +kubebuilder:validation:Optional
	FailingFQDNCount int32 `json:"failingFQDNCount"`
	// AppliedAddressCount is the number of unique IP addresses successfully applied to the underlying network policy.
	// +kubebuilder:validation:Optional
	AppliedAddressCount int32 `json:"appliedAddressCount"`
	// TotalAddressCount is the total number of IP addresses resolved from all FQDNs before filtering and deduplication.
	// +kubebuilder:validation:Optional
	TotalAddressCount int32 `json:"totalAddressCount"`
	// Conditions represents the latest available observations of the NetworkPolicy's current state.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// ObservedGeneration represents the most recent generation observed by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NetworkPolicy is the Schema for the networkpolicies API.
//
//   - Ensure that the target Pods selected by this NetworkPolicy have an independent policy allowing outbound traffic to their configured DNS servers. Once this NetworkPolicy takes effect, its implicit default-deny behavior for unspecified traffic will block DNS queries, disrupting workload connectivity.
//   - If no valid IP addresses can be resolved from the FQDNs defined in the Egress rules, this NetworkPolicy will default to blocking all outbound traffic. This strictly conforms with the default security posture of the native Kubernetes NetworkPolicy (networking.k8s.io/v1).
//
// +kubebuilder:resource:path=networkpolicies,singular=networkpolicy,scope=Namespaced,shortName={fe,fnp}
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready condition status"
// +kubebuilder:printcolumn:name="Resolved",type=string,JSONPath=`.status.conditions[?(@.type=="Resolved")].status`,description="Resolved condition status"
// +kubebuilder:printcolumn:name="Active FQDNs",type=integer,JSONPath=`.status.activeFQDNCount`,description="FQDNs with valid IPs"
// +kubebuilder:printcolumn:name="Resolved IPs",type=integer,JSONPath=`.status.totalAddressCount`,description="Number of resolved IPs"
// +kubebuilder:printcolumn:name="Applied IPs",type=integer,JSONPath=`.status.appliedAddressCount`,description="Number of applied IPs"
// +kubebuilder:printcolumn:name="Failing FQDNs",type=integer,JSONPath=`.status.failingFQDNCount`,description="FQDNs failing to resolve"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type NetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkPolicySpec   `json:"spec,omitempty"`
	Status NetworkPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkPolicyList contains a list of NetworkPolicy.
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkPolicy{}, &NetworkPolicyList{})
}
