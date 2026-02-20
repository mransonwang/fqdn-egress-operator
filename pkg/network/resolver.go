package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
)

type lookupError struct {
	Reason  v1alpha1.NetworkPolicyResolvedConditionReason
	Message string
}

func (e lookupError) Error() string {
	return e.Message
}

// DNSResolverResult is the resulting outcome of a Resolver's DNS lookup
type DNSResolverResult struct {
	// FQDN that the lookup was for
	FQDN v1alpha1.FQDN
	// Error that the lookup may have caused
	Error error
	// Resolved status
	Status v1alpha1.NetworkPolicyResolvedConditionReason
	// Message for the reason
	Message string
	// CIDRs found for the given FQDN if no error occurred
	CIDRs []*v1alpha1.CIDR
}

func NewDNSResolverResult(
	fqdn v1alpha1.FQDN,
	cidrs []*v1alpha1.CIDR,
	error error) *DNSResolverResult {
	sort.SliceStable(cidrs, func(i, j int) bool {
		cmp := bytes.Compare(cidrs[i].IP, cidrs[j].IP)
		if cmp == 0 {
			return cidrs[i].Prefix < cidrs[j].Prefix
		}
		return cmp < 0
	})

	return &DNSResolverResult{
		FQDN:    fqdn,
		Error:   error,
		Message: resolvedMessage(error),
		Status:  resolvedReason(error),
		CIDRs:   cidrs,
	}
}

// resolvedReason returns the reason for the status of the resolved result
func resolvedReason(err error) v1alpha1.NetworkPolicyResolvedConditionReason {
	if err == nil {
		return v1alpha1.NetworkPolicyResolvedSuccess
	}
	var lookupErr *lookupError
	if errors.As(err, &lookupErr) {
		return lookupErr.Reason
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return v1alpha1.NetworkPolicyResolvedTimeout
	}
	if errors.Is(err, context.Canceled) {
		return v1alpha1.NetworkPolicyResolvedError
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return v1alpha1.NetworkPolicyResolvedError
	}
	if dnsErr.IsTimeout {
		return v1alpha1.NetworkPolicyResolvedTimeout
	}
	if dnsErr.IsNotFound {
		return v1alpha1.NetworkPolicyResolvedHostNotFound
	}
	if dnsErr.IsTemporary {
		return v1alpha1.NetworkPolicyResolvedTemporaryError
	}
	return v1alpha1.NetworkPolicyResolvedError
}

// resolvedMessage returns an error message for the given error
func resolvedMessage(err error) string {
	if err == nil {
		return "Resolved successfully"
	}
	var lookupErr *lookupError
	if errors.As(err, &lookupErr) {
		return lookupErr.Error()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "Timeout waiting for resolution task to complete"
	}
	if errors.Is(err, context.Canceled) {
		return "Resolution task was canceled by the system"
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return err.Error()
	}
	if dnsErr.IsTimeout {
		return "Timeout waiting for DNS server response"
	}
	if dnsErr.IsNotFound {
		return "Domain not found or no address records exist"
	}
	if dnsErr.IsTemporary {
		return "Temporary failure in name resolution"
	}
	return err.Error()
}

// DNSResolverResultList is a wrapper around DNSResolver result with helpful getter methods
type DNSResolverResultList []*DNSResolverResult

// CIDRs returns all the CIDRs in the result list
func (dlr DNSResolverResultList) CIDRs() []*v1alpha1.CIDR {
	total := 0
	for i := range dlr {
		total += len(dlr[i].CIDRs)
	}
	if total == 0 {
		return []*v1alpha1.CIDR{}
	}

	cidrs := make([]*v1alpha1.CIDR, 0, total)
	for i := range dlr {
		cidrs = append(cidrs, dlr[i].CIDRs...)
	}
	return cidrs
}

// AggregatedResolvedStatus returns the reason with the highest priority in the result list
func (dlr DNSResolverResultList) AggregatedResolvedStatus() v1alpha1.NetworkPolicyResolvedConditionReason {
	total := len(dlr)
	if total == 0 {
		return v1alpha1.NetworkPolicyResolvedSuccess
	}

	successCount := 0
	for i := range dlr {
		if dlr[i].Status == v1alpha1.NetworkPolicyResolvedSuccess {
			successCount++
		}
	}

	if successCount == total {
		return v1alpha1.NetworkPolicyResolvedSuccess
	}
	if successCount == 0 {
		return v1alpha1.NetworkPolicyResolvedFailure
	}
	return v1alpha1.NetworkPolicyResolvedPartialSuccess
}

// AggregatedResolvedMessage returns the message with the highest priority in the result list
func (dlr DNSResolverResultList) AggregatedResolvedMessage() string {
	total := len(dlr)
	if total == 0 {
		return "No FQDNs defined in the network policy."
	}

	successCount := 0
	var resultWithWorstError *DNSResolverResult

	for i := range dlr {
		result := dlr[i]
		if result.Status == v1alpha1.NetworkPolicyResolvedSuccess {
			successCount++
		} else {
			// 按照五种状态排优先级，取优先级最高的
			// Error > HostNotFound > InvalidFormat > Timeout > TemporaryError
			if resultWithWorstError == nil || result.Status.Priority() > resultWithWorstError.Status.Priority() {
				resultWithWorstError = result
			}
		}
	}

	if successCount == total {
		return fmt.Sprintf("All %d FQDNs resolved successfully.", total)
	}

	sampleMessage := "Unknown error"
	if resultWithWorstError != nil {
		// 需要将原生的信息显示出来，以利于排查
		sampleMessage = fmt.Sprintf("%s: %s", resolvedMessage(resultWithWorstError.Error), resultWithWorstError.Error.Error())
	}

	if successCount == 0 {
		return fmt.Sprintf("Failed to resolve any of the %d FQDNs. %s.", total, sampleMessage)
	}

	return fmt.Sprintf("Partially resolved (%d/%d FQDNs). %s.", successCount, total, sampleMessage)
}

// LookupTable returns a FQDN lookup table for the result list
func (dlr DNSResolverResultList) LookupTable() map[v1alpha1.FQDN]*DNSResolverResult {
	lookup := make(map[v1alpha1.FQDN]*DNSResolverResult, len(dlr))
	for i := range dlr {
		lookup[dlr[i].FQDN] = dlr[i]
	}
	return lookup
}

type Resolver interface {
	LookupIP(ctx context.Context, network string, host string) ([]net.IP, error)
}

// DNSResolver resolves FQDNs to IPs
type DNSResolver struct {
	resolver Resolver
}

// NewDNSResolver returns the default resolver to use for DNS lookup
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

// lookupIP resolves the host to its underlying IP addresses
func (r *DNSResolver) lookupIP(
	ctx context.Context,
	networkType v1alpha1.NetworkType,
	host v1alpha1.FQDN,
) ([]*v1alpha1.CIDR, error) {
	if !host.Valid() {
		return nil, &lookupError{
			Reason:  v1alpha1.NetworkPolicyResolvedInvalidFormat,
			Message: fmt.Sprintf("Received invalid FQDN '%s'", host),
		}
	}
	ips, err := r.resolver.LookupIP(ctx, networkType.ResolverString(), string(host))
	if err != nil {
		return nil, err
	}
	cidrs := make([]*v1alpha1.CIDR, 0, len(ips))
	for _, ip := range ips {
		prefix := 128
		if ip.To4() != nil {
			prefix = 32
		}
		cidrs = append(cidrs, &v1alpha1.CIDR{IP: ip, Prefix: prefix})
	}
	return cidrs, nil
}

// Resolve all the given fqdns to a DNSResolverResult
//   - maxConcurrent controls how many goroutines are spawned to resolve addresses from FQDNs
func (r *DNSResolver) Resolve(
	ctx context.Context,
	timeout time.Duration,
	maxConcurrent int,
	networkType v1alpha1.NetworkType,
	fqdns []v1alpha1.FQDN,
) DNSResolverResultList {
	numFQDNs := len(fqdns)
	if numFQDNs == 0 {
		return DNSResolverResultList{}
	}

	results := make(chan *DNSResolverResult, numFQDNs)
	sem := make(chan struct{}, maxConcurrent)

	var wg sync.WaitGroup
	for _, fqdn := range fqdns {
		wg.Add(1)
		go func(rFQDN v1alpha1.FQDN) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				// acquired a slot
				defer func() { <-sem }()
			case <-ctx.Done():
				// parent context cancelled before acquiring slot
				results <- NewDNSResolverResult(rFQDN, nil, &lookupError{
					Reason:  v1alpha1.NetworkPolicyResolvedError,
					Message: "Context canceled before resolution could start",
				})
				return
			}

			childCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			cidrs, err := r.lookupIP(childCtx, networkType, rFQDN)
			results <- NewDNSResolverResult(rFQDN, cidrs, err)
		}(fqdn)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	lookupResults := make(DNSResolverResultList, 0, numFQDNs)
	for res := range results {
		lookupResults = append(lookupResults, res)
	}
	return lookupResults
}

type FakeDNSResolver struct {
	Results DNSResolverResultList
}

func (r *FakeDNSResolver) Resolve(
	_ context.Context,
	_ time.Duration,
	_ int,
	_ v1alpha1.NetworkType,
	_ []v1alpha1.FQDN,
) DNSResolverResultList {
	return r.Results
}
