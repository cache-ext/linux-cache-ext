#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "page_cache_ext_sampling.skel.h"

char *USAGE =
	"Usage: ./page_cache_ext_sampling\n";

__s64 get_inode_ino_from_path(char *path)
{
	struct stat sb;
	if (stat(path, &sb) == -1) {
		perror("stat");
		return -1;
	}
	return sb.st_ino;
}


int main(int argc, char **argv)
{
	int ret;
	struct page_cache_ext_sampling_bpf *skel;
	struct bpf_link *link;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	// Open skel
	skel = page_cache_ext_sampling_bpf__open();
	if (skel == NULL) {
		// Check errno for error
		fprintf(stderr, "Failed to open BPF skeleton: %s\n",
			strerror(errno));
		return 1;
	}
	__s64 test_ino = get_inode_ino_from_path("./testfile");
	if (test_ino == -1) {
		fprintf(stderr, "Failed to get inode number of testfile\n");
		page_cache_ext_sampling_bpf__destroy(skel);
		return 1;
	}
	skel->data->TEST_INODE_INO = test_ino;

	// Load programs
	ret = page_cache_ext_sampling_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load BPF skeleton: %s\n",
			strerror(errno));
		page_cache_ext_sampling_bpf__destroy(skel);
		return 1;
	}
	// Load struct_ops map
	link = bpf_map__attach_struct_ops(skel->maps.sampling_ops);
	if (link == NULL) {
		fprintf(stderr, "Failed to attach BPF struct_ops map: %s\n",
			strerror(errno));
		page_cache_ext_sampling_bpf__destroy(skel);
		return 1;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();

	// Exit
	bpf_link__destroy(link);
	page_cache_ext_sampling_bpf__destroy(skel);
	return 0;
}