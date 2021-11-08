// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/parsing_helpers.h>

#define bpf_debug(fmt, ...)                                        \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

SEC("xdp_pass")
int xdp_pass_fn(struct xdp_md *ctx)
{
    int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
    
    eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
        return XDP_ABORTED;
    
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

    __u64 data_length = data_end - data;

    __u64 new_length = data_end - nh.pos;
    bpf_debug("data_end - data: %u\n", data_length);
    bpf_debug("data: %u\n", data);
    bpf_debug("data_end: %u\n", data_end);
    bpf_debug("data_end: %u\n", new_length);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
