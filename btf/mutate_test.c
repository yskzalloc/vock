/* mutate_test — demonstrate type-aware mutation on a real BTF struct */
#include "btf.h"
#include "mutate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void hexdump(const void *buf, int len)
{
	const uint8_t *p = buf;
	for (int i = 0; i < len; i++) {
		if (i && i % 16 == 0) printf("\n");
		printf("%02x ", p[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	const char *btf_path = "/sys/kernel/btf/vmlinux";
	const char *struct_name = "sock_common";
	if (argc > 1) struct_name = argv[1];
	if (argc > 2) btf_path = argv[2];

	srand(time(NULL));

	struct vock_btf *btf = vock_btf_open(btf_path);
	if (!btf) { fprintf(stderr, "failed to open BTF\n"); return 1; }

	const struct vock_btf_type *st = vock_btf_find_struct(btf, struct_name);
	if (!st) { fprintf(stderr, "struct '%s' not found in BTF\n", struct_name); vock_btf_close(btf); return 1; }

	printf("=== struct %s (%u bytes, %d fields) ===\n", struct_name, st->size, st->nmembers);
	vock_btf_dump_struct(btf, st, 0);
	printf("\n");

	/* Allocate buffer and fill with zeros (simulating initial struct) */
	void *buf = calloc(1, st->size);

	struct vock_btf_mutator m;
	vock_btf_mutator_init(&m, btf, st);

	printf("=== 20 mutations (simulating fuzz loop) ===\n\n");
	for (int i = 0; i < 20; i++) {
		int field = vock_btf_mutate(&m, buf, st->size);
		/* Simulate: 30% chance of "new coverage" → reward */
		int new_cov = (rand() % 100) < 30;
		if (new_cov) vock_btf_mutator_reward(&m, field);
		printf("  iter %2d: mutated field[%d] %-16s %s\n",
		       i, field,
		       field >= 0 ? st->members[field].name : "?",
		       new_cov ? "→ NEW SIGNAL" : "");
	}

	printf("\n=== Final buffer (first 64 bytes) ===\n");
	hexdump(buf, st->size < 64 ? st->size : 64);

	printf("\n=== Field weights (signal feedback) ===\n");
	vock_btf_mutator_dump(&m);

	vock_btf_mutator_free(&m);
	free(buf);
	vock_btf_close(btf);
	return 0;
}
