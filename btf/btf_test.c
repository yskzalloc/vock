/* btf_test — parse /sys/kernel/btf/vmlinux and dump some structs */
#include "btf.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	const char *path = "/sys/kernel/btf/vmlinux";
	if (argc > 1) path = argv[1];

	struct vock_btf *btf = vock_btf_open(path);
	if (!btf) {
		fprintf(stderr, "failed to open BTF: %s\n", path);
		return 1;
	}

	uint32_t n = vock_btf_type_count(btf);
	printf("BTF: %u types loaded from %s\n\n", n - 1, path);

	/* Count by kind */
	int structs = 0, enums = 0, ints = 0;
	for (uint32_t i = 1; i < n; i++) {
		const struct vock_btf_type *t = vock_btf_type_by_id(btf, i);
		if (t->kind == BTF_KIND_STRUCT) structs++;
		else if (t->kind == BTF_KIND_ENUM) enums++;
		else if (t->kind == BTF_KIND_INT) ints++;
	}
	printf("  structs: %d\n  enums: %d\n  ints: %d\n\n", structs, enums, ints);

	/* Dump a few well-known kernel structs */
	const char *test_structs[] = {
		"sk_buff", "inode", "file", "task_struct", "sock", NULL
	};
	for (int i = 0; test_structs[i]; i++) {
		const struct vock_btf_type *t = vock_btf_find_struct(btf, test_structs[i]);
		if (t) {
			printf("--- %s (id=%u) ---\n", test_structs[i], t->id);
			vock_btf_dump_struct(btf, t, 0);
			printf("\n");
		} else {
			printf("--- %s: NOT FOUND ---\n\n", test_structs[i]);
		}
	}

	vock_btf_close(btf);
	return 0;
}
