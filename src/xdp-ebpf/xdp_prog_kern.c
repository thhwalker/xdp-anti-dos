/* SPDX-License-Identifier: GPL-2.0 */
#include "xdp_prog_kern.h"

/* Checks traffic destined for the current SPA Port. Passes all other Traffic. */
SEC("xdp_host_default")
int xdp_host_default_func(struct xdp_md *ctx)
{
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	/* Check for Valid Ethernet Packet */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return XDP_ABORTED;

	/* Determine whether IPv4/IPv6 and parse accordingly. */
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		return XDP_PASS;
	}

	/* Only need to check for SPA packets that are UDP, allow every other IP packet */
	if (ip_type != IPPROTO_UDP)
		return XDP_PASS; 

	/* Check for Valid UDP packet */
	if (parse_udphdr(&nh, data_end, &udphdr) < 0)
		return XDP_ABORTED;

	__u32 key = HOST_DOS_KEY;
	__u64 dest_port = bpf_ntohs(udphdr->dest);
	__u64 *counter = bpf_map_lookup_elem(&xdp_counter_map, &key);
	if (!counter)
		return XDP_ABORTED;

	struct spa_record *host_settings = bpf_map_lookup_elem(&xdp_settings_map, &key);
	if (!host_settings)
		return XDP_ABORTED;

	/* Pass all non-SPA destined UDP traffic */
	if (dest_port != host_settings->spa_port)
		return XDP_PASS;

	/* Calculate SPA payload length confirm it is the expected size of 135 bytes */ 
	__u64 payload_bytes = data_end - nh.pos;
	if (payload_bytes != 135)
		return XDP_DROP;

    ///* Log to /sys/kernel/debug/tracing/trace for debugging purposes */
    //const char fmt[] = "counter: %d\n";
    //bpf_trace_printk(fmt, sizeof(fmt), *counter);

	(*counter)++;
	return host_settings->override_action;
}

char _license[] SEC("license") = "GPL";
