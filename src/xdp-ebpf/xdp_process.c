#include "xdp_process.h"

static __u32 process_stats(__u64 *stats_rec,
			  __u64 *stats_prev)
{
	__u32 dos = XDP_PASS;
	__u64 packets = *stats_rec - *stats_prev;
	/* Allow max rate of 5 SPA packets per ~500 ms interval */
	if (packets > 5)
		dos = XDP_DROP;

	return dos;
}

static int stats_poll(const char *pin_dir, int set_map_fd, __u32 set_id,
			  __u32 set_type, int count_map_fd, __u32 count_id, 
			  __u32 count_type, int interval, unsigned int num_cpus)
{
	__u64 prev, record = 0;
	struct spa_record host_settings = { 0 };
	__u64 per_cpu_rec[num_cpus];

	/* Set stdin to a non-blocking mode */
	fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
	char buffer[1024];
	int count;
	__u32 key = HOST_DOS_KEY;
	int spa_port = 31000; // Default spa_port
	int tmp;
	char *ptr;

	/* Initialise the counter table */
	memset(per_cpu_rec, 0, sizeof(per_cpu_rec));
	if (bpf_map_update_elem(count_map_fd, &key, per_cpu_rec, BPF_ANY) != 0) {
    	fprintf(stderr, "ERR: Failed to initialise counter map\n");
    	return -1;
	}

	/* Set the default override and use val to track state */
	__u32 current_override_action = XDP_PASS;
	__u32 new_override_action;
	host_settings.override_action = current_override_action;
	host_settings.spa_port = spa_port;

	/* Initialise the settings table */
	if (bpf_map_update_elem(set_map_fd, &key, &host_settings, BPF_ANY) != 0) {
    	fprintf(stderr, "ERR: Failed to initialise settings map\n");
    	return -1;
	}

	while (1) {

		/*Start polling of the BPF MAP*/
		prev = record; /* struct copy */
		record = 0; /* reset the count as we loop through the PERCPU array */

		/* Read STDIN for input, only expecting SPA port number i.e. integer between 1 and 65535 */
		count = read(0, buffer, 1024);
		if(count > 0){
			if (isdigit(*buffer)) {
				tmp=strtol(buffer, &ptr, 10);
				int in_range = (tmp - 1) * (65535 - tmp);
				if (in_range >= 0 && tmp != spa_port) {
					spa_port = tmp;
					host_settings.spa_port = spa_port;
					if (bpf_map_update_elem(set_map_fd, &key, &host_settings, BPF_ANY) != 0) {
						fprintf(stderr, "ERR: Failed to update map\n");
					}
					printf("INFO: Updated SPA Port to %d\n", tmp);
				} else {
					fprintf(stderr, "ERR: Invalid input - not a valid port number\n");
				}
			} else {
				fprintf(stderr, "ERR: Ending due to END Signal\n");
				return -1;
			}
			fflush(stdin);
		}
		/* Update record */
		if ((bpf_map_lookup_elem(count_map_fd, &key, per_cpu_rec)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		}
		for (int i = 0; i < num_cpus; i++) {
			record += per_cpu_rec[i];
			//printf("CPU: %d, counter: %d", i, per_cpu_rec[0]);
		}
		//printf("counter: %d\n", record);

		new_override_action = process_stats(&record, &prev);

		if (current_override_action != new_override_action) {
			printf("CHANGE:0x%X-0x%X\n", current_override_action, new_override_action);
			current_override_action = new_override_action;
			host_settings.override_action = current_override_action;
			if (bpf_map_update_elem(set_map_fd, &key, &host_settings, BPF_ANY) != 0) {
				fprintf(stderr, "ERR: Failed to update map\n");
			}
		}
		usleep(interval);
	}
	return 0;
}

const char *pin_basedir = "/sys/fs/bpf";
const char *settings_map_name = "xdp_settings_map";
const char *counter_map_name = "xdp_counter_map";

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg, const char *map_name)
{
	char map_filename[PATH_MAX];
	int err, len;

	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
			   pin_basedir, cfg->ifname, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
				   cfg->pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", cfg->pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	unsigned int num_cpus = bpf_num_possible_cpus();
	struct bpf_object *bpf_obj;
	int err, len;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};

	const struct bpf_map_info counter_map_expect = {
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(__u64),
		.max_entries = 1,
	};

	const struct bpf_map_info settings_map_expect = {
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct spa_record),
		.max_entries = 1,
	};

	struct bpf_map_info settings_info = { 0 };
	struct bpf_map_info counter_info = { 0 };

	int settings_map_fd;
	int counter_map_fd;
	int checks_per_second = 2; // Checks every 500 ms
	int verbose = 1;

	/* Set default BPF-ELF object file and BPF program name */
	// strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	
	if (cfg.do_unload) {
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	}

	len = snprintf(cfg.pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!cfg.reuse_maps) {
		err = pin_maps_in_bpf_object(bpf_obj, &cfg, settings_map_name);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
		err = pin_maps_in_bpf_object(bpf_obj, &cfg, counter_map_name);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}

	for ( ;; ) {
		settings_map_fd = open_bpf_map_file(cfg.pin_dir, "xdp_settings_map", &settings_info);
		if (settings_map_fd < 0) {
			return EXIT_FAIL_BPF;
		}

		counter_map_fd = open_bpf_map_file(cfg.pin_dir, "xdp_counter_map", &counter_info);
		if (settings_map_fd < 0) {
			return EXIT_FAIL_BPF;
		}

		/* check map info, e.g. spa_record is expected size */
		err = check_map_fd_info(&settings_info, &settings_map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			return err;
		}

		err = check_map_fd_info(&counter_info, &counter_map_expect);
		if (err) {
			fprintf(stderr, "ERR: map via FD not compatible\n");
			return err;
		}

		if (verbose) {
			printf(" - Polling BPF map (bpf_map_type:%d) id:%d name:%s"
				   " key_size:%d value_size:%d max_entries:%d\n",
				   settings_info.type, settings_info.id, settings_info.name,
				   settings_info.key_size, settings_info.value_size, settings_info.max_entries
				   );
			printf(" - Polling BPF map (bpf_map_type:%d) id:%d name:%s"
				   " key_size:%d value_size:%d max_entries:%d\n",
				   counter_info.type, counter_info.id, counter_info.name,
				   counter_info.key_size, counter_info.value_size, counter_info.max_entries
				   );
		}

		err = stats_poll(cfg.pin_dir, settings_map_fd, settings_info.id, settings_info.type, 
				  counter_map_fd, counter_info.id, counter_info.type, 1000000/checks_per_second, num_cpus);
		if (err < 0)
			return err;
	}

	return EXIT_OK;
}
