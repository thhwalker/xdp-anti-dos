#ifndef _XDP_PROG_KERN_H
#define _XDP_PROG_KERN_H

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/parsing_helpers.h>

#define HOST_DOS_KEY 0

struct spa_record {
	__u64 spa_port;
	__u64 override_action;
};

/* Keeps stats per xdp_action */
struct bpf_map_def SEC("maps") xdp_counter_map = {
	.type			= BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size		= sizeof(__u32),
	.value_size		= sizeof(__u64),
	.max_entries	= 1,
};

struct bpf_map_def SEC("maps") xdp_settings_map = {
	.type			= BPF_MAP_TYPE_ARRAY,
	.key_size		= sizeof(__u32),
	.value_size		= sizeof(struct spa_record),
	.max_entries	= 1,
};
#endif