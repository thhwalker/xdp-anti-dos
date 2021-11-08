/* This common_user.h is used by userspace programs */
#ifndef __COMMON_PARAMS_H
#define __COMMON_PARAMS_H

#include <getopt.h>
#include "common_defines.h"

struct option_wrapper {
  struct option option;
  char *help;
  char *metavar;
  bool required;
};

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full);

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *long_options,
                        struct config *cfg, const char *doc);


static inline unsigned int bpf_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;
	int len, n, i, j = 0;

	fp = fopen(fcpu, "r");
	if (!fp) {
		printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
		exit(1);
	}

	if (!fgets(buff, sizeof(buff), fp)) {
		printf("Failed to read %s!\n", fcpu);
		exit(1);
	}

	len = strlen(buff);
	for (i = 0; i <= len; i++) {
		if (buff[i] == ',' || buff[i] == '\0') {
			buff[i] = '\0';
			n = sscanf(&buff[j], "%u-%u", &start, &end);
			if (n <= 0) {
				printf("Failed to retrieve # possible CPUs!\n");
				exit(1);
			} else if (n == 1) {
				end = start;
			}
			possible_cpus += end - start + 1;
			j = i + 1;
		}
	}

	fclose(fp);

	return possible_cpus;
}

#define __bpf_percpu_val_align	__attribute__((__aligned__(8)))

#define BPF_DECLARE_PERCPU(type, name)				\
	struct { type v; /* padding */ } __bpf_percpu_val_align	\
		name[bpf_num_possible_cpus()]
#define bpf_percpu(name, cpu) name[(cpu)].v

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#endif /* __COMMON_PARAMS_H */
