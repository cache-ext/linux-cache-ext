#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cache_ext_simple.skel.h"

char *USAGE =
	"Usage: ./cache_ext_simple\n"
	"  Simple eviction test. Expects testfile in current directory.\n";

__u64 get_inode_ino_from_path(char *path)
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
	__u64 inode_ino;
	char *testfile_path = "./testfile";
	struct cache_ext_simple_bpf *skel;
	struct bpf_link *link;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	// Get inode_ino
	if (argc != 1) {
		fprintf(stderr, "%s", USAGE);
		return 1;
	}
	inode_ino = get_inode_ino_from_path(testfile_path);
	printf("Inode number of testfile: %llu\n", inode_ino);
	// Open skel
	skel = cache_ext_simple_bpf__open();
	if (skel == NULL) {
		// Check errno for error
		fprintf(stderr, "Failed to open BPF skeleton: %s\n",
			strerror(errno));
		return 1;
	}
	// Change global var TEST_INODE_INO
	skel->data->TEST_INODE_INO = inode_ino;
	// Load programs
	ret = cache_ext_simple_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load BPF skeleton: %s\n",
			strerror(errno));
		cache_ext_simple_bpf__destroy(skel);
		return 1;
	}
	// Load struct_ops map
	link = bpf_map__attach_struct_ops(skel->maps.simple_ops);
	if (link == NULL) {
		fprintf(stderr, "Failed to attach BPF struct_ops map: %s\n",
			strerror(errno));
		cache_ext_simple_bpf__destroy(skel);
		return 1;
	}

	// Wait for keyboard input
	printf("Press any key to exit...\n");
	getchar();

	// Exit
	bpf_link__destroy(link);
	cache_ext_simple_bpf__destroy(skel);
	return 0;
}
