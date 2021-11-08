/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP process\n"
	"Allows loading of BPF filter --filename onto Network Interface --dev\n"
	"Then polls the BPF map for connection info and detects potential DoS attacks\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/resource.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_defines.h"
#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#define HOST_DOS_KEY 0

/* This is the data record stored in the map */
struct spa_record {
	__u64 spa_port;
	__u64 override_action;
};

// static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"reuse-maps",  no_argument,		NULL, 'M' },
	 "Reuse pinned maps"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>", true},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif
