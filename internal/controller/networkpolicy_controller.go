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

package controller

import (
	"context"
	"fmt"
	"sort"
	"time"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/mransonwang/fqdn-egress-operator/pkg/network"
	"github.com/mransonwang/fqdn-egress-operator/pkg/utils"

	"k8s.io/client-go/tools/record"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/mransonwang/fqdn-egress-operator/api/v1alpha1"
)

type DNSResolver interface {
	Resolve(
		ctx context.Context,
		timeout time.Duration,
		maxConcurrent int,
		networkType v1alpha1.NetworkType,
		fqdns []v1alpha1.FQDN,
	) network.DNSResolverResultList
}

// AddressCacheEntry represents a single resolved IP address (CIDR) in the sliding window cache.
type AddressCacheEntry struct {
	LastSeen time.Time
	CIDR     *v1alpha1.CIDR
}

type NetworkPolicyReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	EventRecorder         record.EventRecorder
	DNSResolver           DNSResolver
	MaxConcurrentResolves int
	SlidingWindowCache    sync.Map
	UpstreamDNS           string
}

// +kubebuilder:rbac:groups=k8s.cni.cncf.io,resources=multi-networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.turbosimone.com,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.turbosimone.com,resources=networkpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.turbosimone.com,resources=networkpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the NetworkPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *NetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	np := &v1alpha1.NetworkPolicy{}
	if err := r.Get(ctx, req.NamespacedName, np); err != nil {
		if errors.IsNotFound(err) {
			// 策略删除后，要清空缓存
			r.SlidingWindowCache.Delete(req.Namespace + "/" + req.Name)
			return ctrl.Result{}, nil
		}	
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	previous := np.DeepCopy()

	resolutionTimeout := time.Duration(np.Spec.ResolutionTimeoutSeconds) * time.Second
	results := r.DNSResolver.Resolve(
		ctx, resolutionTimeout, r.MaxConcurrentResolves, np.Spec.EnabledNetworkType, np.FQDNs(),
	)

	// 增加滑动窗口缓存实现代码
	rawResolvedCount := int32(len(results.CIDRs()))
	
	windowDuration := time.Duration(0)
	// 如果取到值，ok为true，值放到val，否则ok为false，val为""
	if val, ok := np.Annotations["networking.turbosimone.com/sliding-window"]; ok {
		// 如果字符串val成功转换为数字，则err为nil，值放到d，否则err含错误信息
		if d, err := time.ParseDuration(val); err == nil {
			windowDuration = d
		} else {
			logf.FromContext(ctx).Info("Invalid sliding window annotation format, ignored", "value", val, "error", err.Error())
		}
	}

	if windowDuration > 0 {
		cacheKey := np.Namespace + "/" + np.Name
		
		/* policyCache是用于缓存解析记录的结构体，内部数据组织方式类似如下
		{
		  "open.feishu.cn": {
			"1.1.1.1": {
			"LastSeen": "10:00:00",
			"CIDR": <存放1.1.1.1所对应的CIDR格式解析结果的指针>
			},
			"2.2.2.2": {
			"LastSeen": "10:00:00",
			"CIDR": <存放2.2.2.2所对应的CIDR格式解析结果的指针>
			}
		  }
		}*/

		// map[v1alpha1.FQDN]对应于open.feish.cn
		// map[string]对应于1.1.1.1、2.2.2.2
		var policyCache map[v1alpha1.FQDN]map[string]AddressCacheEntry
		// 如果存在缓存，则取出来；如果没有缓存，意味着是第一次解析，构造一个和域名数量大小一样的缓存
		if v, ok := r.SlidingWindowCache.Load(cacheKey); ok {
			policyCache = v.(map[v1alpha1.FQDN]map[string]AddressCacheEntry)
		} else {
			policyCache = make(map[v1alpha1.FQDN]map[string]AddressCacheEntry, len(results))
		}

		now := time.Now()

		// 用于保存当前策略中还生效中的域名
		validFQDNs := make(map[v1alpha1.FQDN]struct{}, len(results))

		for _, result := range results {
			// 遇到网络超时或错误导致查询结果为0时，跳过滑动窗口，交给原生的RetryTimeoutSeconds机制兜底
			if len(result.CIDRs) == 0 {
				// 即使本次没有查询结果，它也是生效中的域名，必须登记并保活
				validFQDNs[result.FQDN] = struct{}{}
				continue
			}

			fqdn := result.FQDN
			// 正常查出有结果的生效中的域名，登记在册
			validFQDNs[fqdn] = struct{}{}
			// 还没有缓存，就把这次解析的结果放入缓存，开辟结果数量大小的缓存条目
			if policyCache[fqdn] == nil {
				policyCache[fqdn] = make(map[string]AddressCacheEntry, len(result.CIDRs))
			}

			// 这段代码有两个目的
			// 第一个目的是把这次查询获得的结果放入currentCIDRStrs，currentCIDRStrs相当于字典，可用于下一步的对比
			// 第二个目的是填充缓存，如果缓存中存在条目，则更新它，如果缓存中不存在条目，则追加它，这个是policyCache[fqdn][ipStr]代码精妙的地方
			currentCIDRStrs := make(map[string]struct{}, len(result.CIDRs))
			for _, cidr := range result.CIDRs {
				ipStr := cidr.IP.String()
				currentCIDRStrs[ipStr] = struct{}{}
				policyCache[fqdn][ipStr] = AddressCacheEntry{
					LastSeen: now,
					CIDR:     cidr,
				}
			}

			// 现在我们在policyCache中拥有全量的记录，每个记录都带着时间戳，而在currentCIDRStrs则是本次查询的记录

			// 这段代码有连个目的
			// 第一个目的是清理过期IP，已经超过设定时间再也没在查询中出现过的IP，一律删除
			// 第二个目的是把还没超过设定时间但不在本次查询记录中的IP，加回要返回的结果中，实现平滑过渡
			for ipStr, entry := range policyCache[fqdn] {
				if now.Sub(entry.LastSeen) > windowDuration {
					delete(policyCache[fqdn], ipStr)
				} else {
					if _, exists := currentCIDRStrs[ipStr]; !exists {
            			result.CIDRs = append(result.CIDRs, entry.CIDR)
        			}
				}
			}
		}

		// 循环结束，准备存入总池子前，清理掉被用户从策略中删掉的僵尸域名
		for cachedFQDN := range policyCache {
			if _, exists := validFQDNs[cachedFQDN]; !exists {
				delete(policyCache, cachedFQDN)
			}
		}		

		// 写回缓存
		r.SlidingWindowCache.Store(cacheKey, policyCache)
	}	

	// 增加结束

	np.Status.FQDNs = updateFQDNStatuses(
		r.EventRecorder, np, np.Status.FQDNs, results, int(np.Spec.RetryTimeoutSeconds),
	)

	mnp := np.ToMultiNetworkPolicy(np.Status.FQDNs)

	np.Status.TotalAddressCount = rawResolvedCount
	utils.RemoveDuplicateCIDRsInMultiNetworkPolicy(mnp)
	np.Status.AppliedAddressCount = int32(utils.CountUniqueAddresses(mnp))

	resolutionStatus := results.AggregatedResolutionStatus()
	np.SetResolvedCondition(
		resolutionStatus,
		results.AggregatedResolutionMessage(),
	)

	logger := logf.FromContext(ctx).WithValues(
		"status", resolutionStatus,
		"resolved", np.Status.TotalAddressCount,
		"applied", np.Status.AppliedAddressCount,
	)
	ctx = logf.IntoContext(ctx, logger)

	// egress: []
	if mnp == nil {
		if np.Status.ObservedGeneration == np.Generation {
			return ctrl.Result{}, nil
		}

		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyReadyFailure, "Network policy has no egress rules specified.")
		if err := r.updateStatusIfNeeded(ctx, np, previous); err != nil {
			return ctrl.Result{}, err
		}
		// 要去删除底层对应的MultiNetworkPolicy，因为有可能以前的策略中egress并不是空数组，那现在变成egress: []了，不能留着
		// 但对于第一次创建就使用egress: []的情况，这里实际上是没有底层的MultiNetworkPolicy可以删除的，被调用函数内部已自行做判断
		if err := r.reconcileNetworkPolicyDeletion(ctx, np); err != nil {
			return ctrl.Result{}, err
		}
		// 删除完底层的MultiNetworkPolicy后，自己静默直到被修改后唤醒
		logger.Info("Network policy has no egress rules specified, will not requeue until the policy is updated")
		return ctrl.Result{}, nil
	}

	// egress: [{...},{...}] 包含有正常的规则，进行正常处理就行
	if err := r.reconcileNetworkPolicyCreation(ctx, np, mnp); err != nil {
		formattedErr := fmt.Sprintf("Network policy failed to apply: %v.", err)
		np.SetReadyConditionFalse(v1alpha1.NetworkPolicyReadyFailure, formattedErr)
		if err := r.updateStatusIfNeeded(ctx, np, previous); err != nil {
			return ctrl.Result{}, err
		}
		// 创建底层MultiNetworkPolicy出错后固定每60秒重试一次
		logger.Info("Network policy failed to apply", "error", err.Error(), "requeueAfter", "60s")
		return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
	}

	// 无法解析出任何IP地址，因此无法构造egress: []中的内容，所以生成的底层MultiNetworkPolicy实质上没有egress元素
	// 没有egress元素实质上等同于egress: []的效果
	if utils.IsEmpty(mnp) {
		np.SetReadyConditionTrue(
			v1alpha1.NetworkPolicyReadyEmptyRules,
			"Network policy has no FQDNs resolved to valid IP addresses, the default egress deny-all is in effect.",
		)
		if err := r.updateStatusIfNeeded(ctx, np, previous); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("Network policy has no FQDNs resolved to valid IP addresses", "requeueAfter", np.Spec.TTLSeconds)
		return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
	}

	// Creation succeeded, update the status and requeue after TTL
	np.SetReadyConditionTrue(v1alpha1.NetworkPolicyReadySuccess, "Network policy was successfully applied.")
	if err := r.updateStatusIfNeeded(ctx, np, previous); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("Reconciliation succeeded", "requeueAfter", np.Spec.TTLSeconds)
	return ctrl.Result{RequeueAfter: time.Duration(np.Spec.TTLSeconds) * time.Second}, nil
}

func (r *NetworkPolicyReconciler) updateStatusIfNeeded(ctx context.Context, np *v1alpha1.NetworkPolicy, previous *v1alpha1.NetworkPolicy) error {
	logger := logf.FromContext(ctx)

	np.Status.ObservedGeneration = np.Generation

	var activeCount, failingCount int32
	for _, fqdnStatus := range np.Status.FQDNs {
		if len(fqdnStatus.Addresses) > 0 {
			activeCount++
		} else {
			failingCount++
		}
	}
	np.Status.ActiveFQDNCount = activeCount
	np.Status.FailingFQDNCount = failingCount

	sortStatus := func(status *v1alpha1.NetworkPolicyStatus) {
		sort.Slice(status.FQDNs, func(i, j int) bool {
			return string(status.FQDNs[i].FQDN) < string(status.FQDNs[j].FQDN)
		})
		for i := range status.FQDNs {
			sort.Strings(status.FQDNs[i].Addresses)
		}
	}

	sortStatus(&np.Status)
	sortStatus(&previous.Status)

	if equality.Semantic.DeepEqual(previous.Status, np.Status) {
		// logger.Info("Network policy status is unchanged")
		return nil
	}

	err := r.Client.Status().Update(ctx, np)
	if err != nil {
		if errors.IsConflict(err) {
			// 并发冲突通常是瞬时的，下次调和会修补，无需当作错误抛出
			return nil
		}
		return err
	}

	// 成功回写后打印日志
	logger.Info("Network policy status was updated")
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NetworkPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("fqdn-egress-operator").
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5,
		}).
		Complete(r)
}
