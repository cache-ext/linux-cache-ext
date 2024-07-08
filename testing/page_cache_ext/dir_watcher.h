#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int initialize_watch_dir_map(const char *path, int watch_dir_map_fd) {
	int ret;
	DIR *dir;
	struct dirent *ent;

	dir = opendir(path);
	if (dir == NULL) {
		perror("Error opening directory");
		return errno;
	}

	// TODO: handle nested directories
	while ((ent = readdir(dir)) != NULL) {
		if (strncmp(ent->d_name, ".", 1) == 0 || strncmp(ent->d_name, "..", 2) == 0)
			continue;

		char *filename = ent->d_name;
		char *filepath = (char *)malloc(strlen(path) + strlen(filename) + 2);
		sprintf(filepath, "%s/%s", path, filename);
		free(filepath);

		__u8 zero = 0;

		ret = bpf_map_update_elem(watch_dir_map_fd, &ent->d_ino, &zero, 0);
		if (ret) {
			perror("Failed to update watch_dir map");
			closedir(dir);
			return errno;
		}
	}

	closedir(dir);

	return 0;
}
