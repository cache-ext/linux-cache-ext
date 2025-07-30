#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <argp.h>
#include <limits.h>

#include "cache_ext_debug.skel.h"

char *USAGE = "Usage: ./cache_ext_debug\n";
struct cmdline_args {
	int cgroup_id;
};

static struct argp_option options[] = { { "cgroup_id", 'c', "ID", 0,
					  "Cgroup ID to monitor" },
					{ 0 } };

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'c':
		args->cgroup_id = atoi(arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct cache_ext_debug_bpf *skel;
	int ret;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { 0 };
	static struct argp argp = {
		.options = options,
		.parser = parse_opt,
		.args_doc = NULL,
		.doc = "Debug MGLRU"
	};
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// Open BPF skeleton
	skel = cache_ext_debug_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Set cgroup id
	printf("Setting cgroup id filter to %d\n", args.cgroup_id);
	skel->data->filter_memcg_id = args.cgroup_id;

	// Load & verify BPF programs
	ret = cache_ext_debug_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load and verify BPF programs\n");
		goto cleanup;
	}

	// Attach tracepoint handler
	ret = cache_ext_debug_bpf__attach(skel);
	if (ret) {
		fprintf(stderr, "Failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Successfully started! Press any key to exit\n");
	getchar();

cleanup:
	cache_ext_debug_bpf__destroy(skel);
	return ret;
}
