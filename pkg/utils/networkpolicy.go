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

	// 阶段0：容量预估
	// 未去重之前的IP地址总数
	totalPeers := 0
	for i := range networkPolicy.Spec.Egress {
		totalPeers += len(networkPolicy.Spec.Egress[i].To)
	}

	// 阶段1：原子化打散
	// 这里之所以还放一个MultiNetworkPolicyPort的结构体作为嵌套Map的值存在，是为了后面生成Egress规则时可以直接拿来使用
	// cidrToPortsMap填充后的表达类似如下
	// cidrToPortsMap[8.8.8.8/32][TCP:80] = {Protocol: TCP, Port: 80}
	// cidrToPortsMap[8.8.8.8/32][TCP:443] = {Protocol: TCP, Port: 443}
	// cidrToPortsMap是一个嵌套的Map，第一层键和第二层键的名称都是唯一的，从而达到了IP地址去重以及IP地址对应的端口去重的目的
	// totalPeers这里是为第一个键初始化容量
	cidrToPortsMap := make(map[string]map[string]mnetv1beta1.MultiNetworkPolicyPort, totalPeers)

	for i := range networkPolicy.Spec.Egress {
		rule := &networkPolicy.Spec.Egress[i]
		for j := range rule.To {
			peer := &rule.To[j]
			if peer.IPBlock == nil || peer.IPBlock.CIDR == "" {
				continue
			}
			cidr := peer.IPBlock.CIDR
			// 拿到了一个cidr，判断诸如cidrToPortsMap[cidr]是否存在
			if _, ok := cidrToPortsMap[cidr]; !ok {
				// 如果不存在，则添加第一层键，并初始化第二层的容量
				// 这里的容量是估出来的，因为一般IP地址开放的端口无非就是以下一些（只是举例说明）：
				// {Protocol: TCP, Port: 80}
				// {Protocol: TCP, Port: 443}
				// {Protocol: UDP, Port: 53}
				// {Protocol: TCP, Port: 8080}
				// {Protocol: TCP, Port: 22}
				// {Protocol: TCP, Port: 8181}
				// 所以总共可能的数量在10个以内（不需要计算这些情况的组合），不会太多，这里硬编码用16满足绝大部分场景的需求，或者更浪费一点用32也行
				cidrToPortsMap[cidr] = make(map[string]mnetv1beta1.MultiNetworkPolicyPort, 16)
			}

			// 把IP地址所对应的端口数组也进行遍历
			// 比如端口数组包含了
			// {Protocol: TCP, Port: 80}
			// {Protocol: TCP, Port: 443}
			// {Protocol: UDP, Port: 53}
			// 就要遍历3次
			for k := range rule.Ports {
				p := rule.Ports[k]
				// 把{Protocol: TCP, Port: 80}转换成诸如TCP:80这样的字符串
				pKey := getSinglePortKey(p)
				// 最终作为cidrToPartsMap[8.8.8.8/32][TCP:80] = {Protocol: TCP, Port: 80}这种形式在内存保存起来
				cidrToPortsMap[cidr][pKey] = p
			}
		}
	}

	// 阶段2：预计算与计数
	// 经过上面的处理，IP地址已经去重了，并且每个IP地址的放行端口也去重了
	// cidrGrouping中的数据格式为，cidr是8.8.8.8/32, fingerprint是TCP:80,TCP:443
	// 这里引入指纹的概念，它用于唯一标识放行端口，可以是一个端口，也可以是两个端口甚至更多端口
	type cidrGrouping struct {
		cidr string
		fingerprint string
	}

	// groupings的容量初始化为去重后的IP地址数量，这是一个切片，大小初始化为0
	groupings := make([]cidrGrouping, 0, len(cidrToPortsMap))
	// 记录每个指纹下有多少个IP地址，极端来说，有多少IP地址，最大可能的指纹数就等同于IP地址数量，也就是每个IP地址都有它自己的一组与众不同的放行端口组合
	// 但是这种极端情况是不可能发生的，根据现实情况可以估一个，因为绝大部分IP地址的指纹可能都是相同的
	// 这里就硬编码32个指纹，应该是可以满足绝大部分场景需求的
	fingerprintIPCounts := make(map[string]int, 32)

	// 指纹和MultiNetworkPolicyPort数组的对应关系
	// fingerprintToPortSlice[TCP:80,TCP:443] = [{Protocol: TCP, Port: 80}, {Protocol: TCP, Port: 443}]
	fingerprintToPortSlice := make(map[string][]mnetv1beta1.MultiNetworkPolicyPort, 32)

	// 遍历cidrToPortsMap
	// cidr就相当于8.8.8.8/32
	// portsMap就相当于[TCP:80] = {Protocol: TCP, Port: 80}, [TCP:443] = {Protocol: TCP, Port: 443}
	// cidrToPortsMap[8.8.8.8/32][TCP:80] = {Protocol: TCP, Port: 80}
	// cidrToPortsMap[8.8.8.8/32][TCP:443] = {Protocol: TCP, Port: 443}
	for cidr, portsMap := range cidrToPortsMap {
		// 根据portsMap的大小分配portSlice容量
		portSlice := make([]mnetv1beta1.MultiNetworkPolicyPort, 0, len(portsMap))
		for _, p := range portsMap {
			// portSlice的最终形态类似[{Protocol: TCP, Port: 80}, {Protocol: TCP, Port: 443}]
			portSlice = append(portSlice, p)
		}

		// 由于portsMap是一个Map，遍历顺序是随机的，放入portSlice的端口顺序也是随机的
		// 必须在这里对portSlice进行排序，否则底层更新时DeepEqual会因为数组乱序判定为不一致！
		sort.Slice(portSlice, func(i, j int) bool {
			return getSinglePortKey(portSlice[i]) < getSinglePortKey(portSlice[j])
		})		
		
		// 生成指纹，从[{Protocol: TCP, Port: 80}, {Protocol: TCP, Port: 443}]生成TCP:80,TCP:443
		f := getPortsFingerprint(portSlice)

		// groupings[0].cidr = 8.8.8.8/32
		// groupings[0].fingerprint = TCP:80,TCP:443
		groupings = append(groupings, cidrGrouping{
			cidr: cidr,
			fingerprint: f,
		})

		// 指纹计数自增1
		// fingerprintIPCounts[TCP:80,TCP:443]++
		fingerprintIPCounts[f]++
		
		// 判断诸如fingerprintToPortSlice[TCP:80,TCP:443]是否存在
		if _, ok := fingerprintToPortSlice[f]; !ok {
			// 如果不存在，则添加键，并将键值指向portSlice
			fingerprintToPortSlice[f] = portSlice
		}
	}

	// 阶段3：精确分配与填充
	// 此时我们已经有了“上帝视角”，知道每个指纹需要多大的容量
	numFingerprints := len(fingerprintIPCounts)
	// 每个指纹所包含的所有IP地址
	portsFingerprintToCidrs := make(map[string][]string, numFingerprints)
	// 遍历指纹Map，f相当于指纹键TCP:80,TCP:443，count相当于指纹包含的IP地址数量
	for f, count := range fingerprintIPCounts{
		// 为每一个指纹生成对应的Map，用于存放所对应的IP地址
		// 无论count是1还是1000，这里都只发生一次精确的内存分配
		portsFingerprintToCidrs[f] = make([]string, 0, count)
	}

	// 直接从groupings中取值填充
	for i := range groupings {
		group := &groupings[i]
		f := group.fingerprint
		portsFingerprintToCidrs[f] = append(portsFingerprintToCidrs[f], group.cidr)
	}

	// 阶段4：构造MultiNetworkPolicy对象
	newEgressRules := make([]mnetv1beta1.MultiNetworkPolicyEgressRule, 0, numFingerprints)
	
	sortedFingerprints := make([]string, 0, numFingerprints)
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
	for i := range ports {
		tmp[i] = getSinglePortKey(ports[i])
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
