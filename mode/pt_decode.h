/*
 * pt_decode.h — Intel PT full decoder with TNT packet support.
 *
 * Decodes Intel PT trace by walking vmlinux disassembly:
 * - TIP packets give direct branch targets
 * - TNT packets encode taken/not-taken for conditional branches
 * - Walking the binary between TIPs using TNT bits gives full coverage
 */
#ifndef PT_DECODE_H
#define PT_DECODE_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

struct pt_decoder {
	/* vmlinux text section */
	uint8_t *text;
	uint64_t text_vaddr;
	size_t text_size;

	/* PT trace data */
	uint8_t *trace;
	size_t trace_len;
	size_t pos;

	/* State */
	uint64_t ip;
	uint64_t tnt_bits;
	int tnt_count;

	/* Output */
	FILE *output;
	int pc_count;
};

int pt_decoder_init(struct pt_decoder *d, const char *vmlinux,
		    uint8_t *trace, size_t trace_len, FILE *output);
int pt_decoder_run(struct pt_decoder *d);
void pt_decoder_fini(struct pt_decoder *d);

#endif
