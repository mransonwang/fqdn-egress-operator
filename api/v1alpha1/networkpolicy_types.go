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

// NetworkType defines the available ip address types to resolve
//
//   - Options are one of: 'all', 'ipv4', 'ipv6'
//
// +kubebuilder:validation:Enum=all;ipv4;ipv6
type NetworkType string

const (
	All  NetworkType = "all"
	IPv4 NetworkType = "ipv4"
	IPv6 NetworkType = "ipv6"
)

// ResolverString returns the string value that net.Resolver expects in LookupIP.
// Returns an empty string for unknown types.
func (n NetworkType) ResolverString() string {
	switch n {
	case All:
		return "ip"
	case IPv4:
		return "ip4"
	case IPv6:
		return "ip6"
	}
	return ""
}

// +kubebuilder:validation:Enum=vm.kubevirt.io/name;app.kubernetes.io/name
type Label string

const (
	LabelWithVirtualMachineName Label = "vm.kubevirt.io/name"
	LabelWithKubernetesAppName  Label = "app.kubernetes.io/name"
)

// Shadow MatchLabel struct
type MatchLabel struct {
	// Label is typically used to identify a pod.
	// +kubebuilder:default="vm.kubevirt.io/name"
	Label Label `json:"label"`
	// The value corresponding to the label.
	// +kubebuilder:validation:MinLength=1
	Value string `json:"value"`
}

// The value corresponding to the label.
// +kubebuilder:validation:MinLength=1
type LabelValue string

// Shadow LabelSelectorRequirement struct
type LabelSelectorRequirement struct {
	// Key is the label key that the selector applies to.
	// +kubebuilder:default="vm.kubevirt.io/name"
	// +kubebuilder:validation:Enum=vm.kubevirt.io/name;app.kubernetes.io/name
	Key string `json:"key"`
	// Operator represents a key's relationship to a set of values. Valid operators are In and NotIn.
	// +kubebuilder:default="In"
	// +kubebuilder:validation:Enum=In;NotIn
	Operator metav1.LabelSelectorOperator `json:"operator"`
	// Values is an array of string values. If the operator is In or NotIn, the values array must be non-empty.
	// +kubebuilder:validation:MaxItems=50
	// +listType=set
	Values []LabelValue `json:"values"`
}

// Shadow MultiNetworkPolicyPort struct
type MultiNetworkPolicyPort struct {
	// Protocol defines network protocols supported for things like container ports.
	// +kubebuilder:default="TCP"
	// +kubebuilder:validation:Enum=TCP;UDP;SCTP
	Protocol corev1.Protocol `json:"protocol"`
	// The specific port number to allow.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// FQDN is short for Fully Qualified Domain Name and represents a complete domain name that uniquely identifies a host on the internet. It must consist of one or more labels separated by dots (e.g., "api.example.com"), where each label can contain letters, digits, and hyphens, but cannot start or end with a hyphen. The FQDN must end with a top-level domain (e.g., ".com", ".org") of at least two characters.
//
// +kubebuilder:validation:Pattern=`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
type FQDN string

// EgressRule defines rules for outbound network traffic to the specified FQDNs on the specified ports.
// Each FQDNs IP's will be looked up periodically to update the underlying NetworkPolicy.
type EgressRule struct {
	// ToFQDNs are the FQDNs to which traffic is allowed (outgoing).
	// +kubebuilder:validation:MaxItems=50
	// +listType=set
	ToFQDNs []FQDN `json:"toFQDNs"`
	// Ports describes the ports to allow traffic on.
	// +kubebuilder:validation:MaxItems=10
	// +listType=map
	// +listMapKey=protocol
	// +listMapKey=port
	Ports []MultiNetworkPolicyPort `json:"ports"`
	// When set, overwrites the default behavior of the same field in NetworkPolicySpec.
	BlockPrivateIPs *bool `json:"blockPrivateIPs,omitempty"`
}

// NetworkPolicySpec defines the desired state of NetworkPolicy.
type NetworkPolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// TargetNetwork represents the network where the network policy is effective. If the list is empty, please confirm whether a NAD has been created in the current project.
	// +kubebuilder:validation:MinLength=1
	TargetNetwork string `json:"targetNetwork"`

	// MatchLabels defines which pods this network policy shall apply to.
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=label
	// +listMapKey=value
	MatchLabels []MatchLabel `json:"matchLabels,omitempty"`

	// MatchExpressions defines which pods this network policy shall apply to.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=30
	// +kubebuilder:validation:XValidation:rule="self.all(i, self.filter(j, i.key == j.key && i.operator == j.operator && j.values.exists(v, v in i.values)).size() == 1)",message="spec.matchExpressions in body should not contain overlapping values for the same key and operator"
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`

	// Egresses defines the outbound network traffic rules for the selected pods.
	// +kubebuilder:validation:MaxItems=30
	// +kubebuilder:validation:XValidation:rule="self.all(i, self.filter(j, j.toFQDNs.exists(f, f in i.toFQDNs) && j.ports.exists(p, p in i.ports)).size() == 1)",message="spec.egress in body should not contain overlapping toFQDNs and ports across different rules"	
	Egresses []EgressRule `json:"egress"`

	// EnabledNetworkType defines which type of IP addresses to allow.
	//
	//  - Options are one of: 'all', 'ipv4', 'ipv6'
	//  - Defaults to 'ipv4' if not specified
	//
	// +kubebuilder:default:=ipv4
	EnabledNetworkType NetworkType `json:"enabledNetworkType,omitempty"`

	// The timeout to use for lookups of the FQDNs.
	//
	//  - Defaults to 3 seconds if not specified
	//  - Maximum value is 60 seconds
	//  - Minimum value is 1 second
	//  - Must be less than TTLSeconds
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=60
	// +kubebuilder:default:=3
	ResolveTimeoutSeconds int32 `json:"resolveTimeoutSeconds,omitempty"`

	// How long the resolving of an individual FQDN should be retried in case of errors before being removed from the underlying network policy. This ensures intermittent failures in name resolution do not clear existing addresses causing unwanted service disruption.
	//
	//  - Defaults to 3600 (1 hour) if not specified (nil)
	//  - Maximum value is 86400 (24 hours)
	//
	// +kubebuilder:validation:Maximum=86400
	// +kubebuilder:default:=3600
	RetryTimeoutSeconds int32 `json:"retryTimeoutSeconds,omitempty"`

	// The interval at which the IP addresses of the FQDNs are re-evaluated.
	//
	//  - Defaults to 60 seconds if not specified
	//  - Maximum value is 1800 seconds
	//  - Minimum value is 5 seconds
	//  - Must be greater than ResolveTimeoutSeconds
	//
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=1800
	// +kubebuilder:default:=60
	TTLSeconds int32 `json:"ttlSeconds,omitempty"`

	// When set to true, all private IPs are omitted from the rules unless otherwise specified at the EgressRule level.
	//
	//  - Defaults to false if not specified
	BlockPrivateIPs bool `json:"blockPrivateIPs,omitempty"`
}

type NetworkPolicyConditionType string

const (
	NetworkPolicyReadyCondition    NetworkPolicyConditionType = "Ready"
	NetworkPolicyResolvedCondition NetworkPolicyConditionType = "Resolved"
)

type NetworkPolicyReadyConditionReason string

const (
	NetworkPolicyReady      NetworkPolicyReadyConditionReason = "Ready"
	NetworkPolicyEmptyRules NetworkPolicyReadyConditionReason = "EmptyRules"
	NetworkPolicyFailed     NetworkPolicyReadyConditionReason = "Failed"
)

type NetworkPolicyResolvedConditionReason string

const (
	NetworkPolicyResolveOtherError     NetworkPolicyResolvedConditionReason = "OTHER_ERROR"
	NetworkPolicyResolveInvalidDomain  NetworkPolicyResolvedConditionReason = "INVALID_DOMAIN"
	NetworkPolicyResolveDomainNotFound NetworkPolicyResolvedConditionReason = "NXDOMAIN"
	NetworkPolicyResolveTimeout        NetworkPolicyResolvedConditionReason = "TIMEOUT"
	NetworkPolicyResolveTemporaryError NetworkPolicyResolvedConditionReason = "TEMPORARY"
	NetworkPolicyResolveUnknown        NetworkPolicyResolvedConditionReason = "UNKNOWN"
	NetworkPolicyResolveSuccess        NetworkPolicyResolvedConditionReason = "SUCCESS"
)

func (r NetworkPolicyResolvedConditionReason) Priority() int {
	switch r {
	case NetworkPolicyResolveOtherError:
		return 6
	case NetworkPolicyResolveInvalidDomain:
		return 5
	case NetworkPolicyResolveDomainNotFound:
		return 4
	case NetworkPolicyResolveTimeout:
		return 3
	case NetworkPolicyResolveTemporaryError:
		return 2
	case NetworkPolicyResolveUnknown:
		return 1
	default:
		return 0
	}
}

func (r NetworkPolicyResolvedConditionReason) Transient() bool {
	switch r {
	case NetworkPolicyResolveInvalidDomain:
		return false
	case NetworkPolicyResolveDomainNotFound:
		return false
	default:
		return true
	}
}

// FQDNStatus defines the status of a given FQDN
type FQDNStatus struct {
	// FQDN is the FQDN this status refers to
	FQDN FQDN `json:"fqdn"`
	// LastSuccessfulTime is the last time the FQDN was resolved successfully. I.e. the last time the ResolveReason was NetworkPolicyResolveSuccess
	LastSuccessfulTime metav1.Time `json:"LastSuccessfulTime,omitempty"`
	// LastTransitionTime is the last time the reason changed
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// ResolveReason describes the last resolve status
	ResolveReason NetworkPolicyResolvedConditionReason `json:"resolvedReason,omitempty"`
	// ResolveMessage is a message describing the reason for the status
	ResolveMessage string `json:"resolveMessage,omitempty"`
	// Addresses is the list of resolved addresses for the given FQDN. The list is cleared if LastSuccessfulTime exceeds the time limit specified by NetworkPolicySpec.RetryTimeoutSeconds
	Addresses []string `json:"addresses,omitempty"`
}

// NetworkPolicyStatus defines the observed state of NetworkPolicy.
type NetworkPolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// LatestLookupTime is the last time the IPs were resolved
	LatestLookupTime metav1.Time `json:"latestLookupTime,omitempty"`

	// FQDNs lists the status of each FQDN in the network policy
	FQDNs []FQDNStatus `json:"fqdns,omitempty"`

	// AppliedAddressCount counts the number of unique IPs applied in the generated network policy
	AppliedAddressCount int32 `json:"appliedAddressCount,omitempty"`

	// TotalAddressCount is the number of total IPs resolved from the FQDNs before filtering
	TotalAddressCount int32 `json:"totalAddressesCount,omitempty"`

	Conditions         []metav1.Condition `json:"conditions"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NetworkPolicy is the Schema for the networkpolicies API.
//
//   - Please ensure the pods you apply this network policy to have a separate policy allowing access to CoreDNS / KubeDNS pods in your cluster. Without this, once this Network policy is applied, access to DNS will be blocked due to how network policies deny all unspecified traffic by default once applied.
//   - If no addresses are resolved from the FQDNs from the Egress rules that were specified, the default behavior is to block all Egress traffic. This conforms with the default behavior of network policies (networking.k8s.io/v1).
//
// +kubebuilder:resource:path=networkpolicies,singular=networkpolicy,scope=Namespaced,shortName={fenp,fnp}
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready condition status"
// +kubebuilder:printcolumn:name="Resolved",type=string,JSONPath=`.status.conditions[?(@.type=="Resolved")].status`,description="Resolved condition status"
// +kubebuilder:printcolumn:name="Resolved IPs",type=integer,JSONPath=`.status.totalAddressesCount`,description="Number of resolved IPs before filtering"
// +kubebuilder:printcolumn:name="Applied IPs",type=integer,JSONPath=`.status.appliedAddressCount`,description="Number of applied IPs"
// +kubebuilder:printcolumn:name="Last Lookup",type=date,JSONPath=`.status.latestLookupTime`,description="Time of last FQDN resolve"
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
