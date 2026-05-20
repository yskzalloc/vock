/* types_test — resolve trace.syz syscall args to BTF structs */
#include "types.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
	const char *btf_path = "/sys/kernel/btf/vmlinux";
	const char *trace_path = "trace.syz";

	if (argc > 1) trace_path = argv[1];
	if (argc > 2) btf_path = argv[2];

	struct vock_btf *btf = vock_btf_open(btf_path);
	if (!btf) {
		fprintf(stderr, "failed to open BTF: %s\n", btf_path);
		return 1;
	}
	printf("BTF: %u types from %s\n", vock_btf_type_count(btf) - 1, btf_path);

	struct vock_type_map map;
	int n = vock_types_resolve(btf, trace_path, &map);
	if (n < 0) {
		fprintf(stderr, "failed to parse trace: %s\n", trace_path);
		vock_btf_close(btf);
		return 1;
	}

	vock_types_dump(&map, btf);

	vock_types_free(&map);
	vock_btf_close(btf);
	return 0;
}
