#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include "page_cache_ext_simple.skel.h"

int main(int argc, char **argv)
{
	int ret;
	struct page_cache_ext_simple_bpf *skel;
	struct bpf_link *link;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	// Open skel
	skel = page_cache_ext_simple_bpf__open();
	if (skel == NULL) {
		// Check errno for error
		fprintf(stderr, "Failed to open BPF skeleton: %s\n",
			strerror(errno));
		return 1;
	}
	// Load programs
	ret = page_cache_ext_simple_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "Failed to load BPF skeleton: %s\n",
			strerror(errno));
		page_cache_ext_simple_bpf__destroy(skel);
		return 1;
	}
	// Load struct_ops map
	link = bpf_map__attach_struct_ops(skel->maps.simple_ops);
	if (link == NULL) {
		fprintf(stderr, "Failed to attach BPF struct_ops map: %s\n",
			strerror(errno));
		page_cache_ext_simple_bpf__destroy(skel);
		return 1;
	}

    // Wait for keyboard input
    printf("Press any key to exit...\n");
    getchar();

    // Exit
    bpf_link__destroy(link);
    page_cache_ext_simple_bpf__destroy(skel);
	return 0;
}