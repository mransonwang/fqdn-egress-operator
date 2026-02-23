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
	Reason  v1alpha1.NetworkPolicyResolutionReason
	Message string
}

func (e lookupError) Error() string {
	return e.Message
}

type DNSResolverResult struct {
	FQDN v1alpha1.FQDN
	Error error
	Status v1alpha1.NetworkPolicyResolutionReason
	Message string
	CIDRs []*v1alpha1.CIDR
}

func NewDNSResolverResult(
	fqdn v1alpha1.FQDN,
	cidrs []*v1alpha1.CIDR,
	err error) *DNSResolverResult {
	sort.SliceStable(cidrs, func(i, j int) bool {
		cmp := bytes.Compare(cidrs[i].IP.To16(), cidrs[j].IP.To16())
		if cmp == 0 {
			return cidrs[i].Prefix < cidrs[j].Prefix
		}
		return cmp < 0
	})

	return &DNSResolverResult{
		FQDN:    fqdn,
		Error:   err,
		Status:  resolutionReason(err),
		Message: resolutionMessage(err),
		CIDRs:   cidrs,
	}
}

func resolutionReason(err error) v1alpha1.NetworkPolicyResolutionReason {
	if err == nil {
		return v1alpha1.NetworkPolicyResolutionSuccess
	}
	var lookupErr *lookupError
	if errors.As(err, &lookupErr) {
		return lookupErr.Reason
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return v1alpha1.NetworkPolicyResolutionTimeout
	}
	if errors.Is(err, context.Canceled) {
		return v1alpha1.NetworkPolicyResolutionError
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return v1alpha1.NetworkPolicyResolutionError
	}
	if dnsErr.IsTimeout {
		return v1alpha1.NetworkPolicyResolutionTimeout
	}
	if dnsErr.IsNotFound {
		return v1alpha1.NetworkPolicyResolutionHostNotFound
	}
	if dnsErr.IsTemporary {
		return v1alpha1.NetworkPolicyResolutionTemporaryError
	}
	return v1alpha1.NetworkPolicyResolutionError
}

func resolutionMessage(err error) string {
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

type DNSResolverResultList []*DNSResolverResult

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

func (dlr DNSResolverResultList) AggregatedResolutionStatus() v1alpha1.NetworkPolicyResolutionReason {
	total := len(dlr)
	if total == 0 {
		return v1alpha1.NetworkPolicyResolutionSuccess
	}

	successCount := 0
	for i := range dlr {
		if dlr[i].Status == v1alpha1.NetworkPolicyResolutionSuccess {
			successCount++
		}
	}

	if successCount == total {
		return v1alpha1.NetworkPolicyResolutionSuccess
	}
	if successCount == 0 {
		return v1alpha1.NetworkPolicyResolutionFailure
	}
	return v1alpha1.NetworkPolicyResolutionPartialSuccess
}

func (dlr DNSResolverResultList) AggregatedResolutionMessage() string {
	total := len(dlr)
	// egress: []
	if total == 0 {
		return "Network policy has no FQDNs defined."
	}

	successCount := 0
	var resultWithWorstError *DNSResolverResult

	for i := range dlr {
		result := dlr[i]
		if result.Status == v1alpha1.NetworkPolicyResolutionSuccess {
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
		resMsg := resolutionMessage(resultWithWorstError.Error)
		// 需要将原生的信息显示出来，利于排查
		rawErr := resultWithWorstError.Error.Error()
		if resMsg == rawErr {
			sampleMessage = resMsg
		} else {
			sampleMessage = fmt.Sprintf("%s: %s", resMsg, rawErr)
		}		
	}

	if successCount == 0 {
		return fmt.Sprintf("Failed to resolve any of the %d FQDNs. %s.", total, sampleMessage)
	}

	return fmt.Sprintf("Partially resolved (%d/%d FQDNs). %s.", successCount, total, sampleMessage)
}

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

type DNSResolver struct {
	resolver Resolver
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		resolver: &net.Resolver{
			PreferGo: true,
		},
	}
}

func (r *DNSResolver) lookupIP(
	ctx context.Context,
	networkType v1alpha1.NetworkType,
	host v1alpha1.FQDN,
) ([]*v1alpha1.CIDR, error) {
	if !host.Valid() {
		return nil, &lookupError{
			Reason:  v1alpha1.NetworkPolicyResolutionInvalidFormat,
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
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- NewDNSResolverResult(rFQDN, nil, &lookupError{
					Reason:  v1alpha1.NetworkPolicyResolutionError,
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
