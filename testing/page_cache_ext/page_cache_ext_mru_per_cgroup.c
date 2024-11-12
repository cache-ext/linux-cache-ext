#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "page_cache_ext_mru.skel.h"
#include "dir_watcher.h"

char *USAGE =
	"Usage: ./page_cache_ext_mru <data_dir>\n";

struct cmdline_args {
	char *watch_dir;
	char *cgroup;
};

static struct argp_option options[] = { { "watch_dir", 'w', "DIR", 0, "Directory to watch" },
					{ "cgroup", 'c', "CGROUP", 0, "Cgroup to join" },
					{ 0 } };

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'w':
		args->watch_dir = arg;
		break;
	case 'c':
		args->cgroup = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	struct page_cache_ext_mru_bpf *skel;
	struct bpf_link *link;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { 0 };
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// Validate arguments
	if (args.watch_dir == NULL) {
		fprintf(stderr, "Missing required argument: watch_dir\n");
		return 1;
	}

	if (args.cgroup == NULL) {
		fprintf(stderr, "Missing required argument: cgroup\n");
		return 1;
	}

	// Does watch_dir exist?
	if (access(args.watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n",
			args.watch_dir);
		return 1;
	}
	// Get full path of watch_dir
	char watch_dir_full_path[PATH_MAX];
	if (realpath(args.watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}
	// TODO: Enable longer length
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	int cgroup_fd = open(args.cgroup, O_RDONLY);
	if (cgroup_fd < 0) {
		fprintf(stderr, "Failed to open cgroup: %s\n", strerror(errno));
		return 1;
	}

	// Open skel
	skel = page_cache_ext_mru_bpf__open();
	if (skel == NULL) {
		// Check errno for error
		fprintf(stderr, "Failed to open BPF skeleton: %s\n",
			strerror(errno));
		return 1;
	}

	// Load programs
	ret = page_cache_ext_mru_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load BPF skeleton: %s\n",
			strerror(errno));
		page_cache_ext_mru_bpf__destroy(skel);
		return 1;
	}

	// Initialize watch_dir map
	ret = initialize_watch_dir_map(watch_dir_full_path, bpf_map__fd(skel->maps.inode_watchlist), true);
	if (ret) {
		fprintf(stderr, "Failed to initialize watch_dir map: %s\n",
			strerror(errno));
		return 1;
	}

	// Load struct_ops map
	link = bpf_map__attach_cache_ext_ops(skel->maps.mru_ops, cgroup_fd);
	if (link == NULL) {
		fprintf(stderr, "Failed to attach BPF struct_ops map: %s\n",
			strerror(errno));
		page_cache_ext_mru_bpf__destroy(skel);
		return 1;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();

	// Exit
	bpf_link__destroy(link);
	page_cache_ext_mru_bpf__destroy(skel);
	return 0;
}
