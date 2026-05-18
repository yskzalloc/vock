/*
 * pt_decode.c — Intel PT decoder with TNT packet walking.
 *
 * Loads vmlinux ELF .text section, then decodes PT packets:
 * - TIP/FUP/TIP.PGE/TIP.PGD → direct IP updates
 * - TNT → walk conditional branches in vmlinux binary
 *
 * Uses a minimal x86-64 instruction length decoder to step through
 * the kernel binary and follow branches based on TNT bits.
 */
#define _GNU_SOURCE
#include "pt_decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* ─── Minimal x86-64 instruction decoder ─────────────────────────────────── */

/* Returns instruction length, sets *is_branch, *is_cond, *branch_target */
static int decode_insn(const uint8_t *code, size_t max_len,
		       int *is_branch, int *is_cond, int64_t *branch_rel)
{
	*is_branch = 0;
	*is_cond = 0;
	*branch_rel = 0;

	if (max_len < 1)
		return 0;

	const uint8_t *p = code;
	int len = 0;

	/* Skip prefixes */
	while (len < 15 && (size_t)len < max_len) {
		uint8_t b = p[len];
		if (b == 0x66 || b == 0x67 || b == 0xf0 || b == 0xf2 ||
		    b == 0xf3 || b == 0x2e || b == 0x3e || b == 0x26 ||
		    b == 0x64 || b == 0x65 || b == 0x36) {
			len++;
			continue;
		}
		/* REX prefix */
		if ((b & 0xf0) == 0x40) {
			len++;
			continue;
		}
		break;
	}

	if ((size_t)len >= max_len)
		return len ? len : 1;

	uint8_t op = p[len++];

	/* Jcc short (0x70-0x7F) */
	if (op >= 0x70 && op <= 0x7f) {
		if ((size_t)len < max_len) {
			*is_branch = 1;
			*is_cond = 1;
			*branch_rel = (int8_t)p[len];
			len++;
		}
		return len;
	}

	/* JMP short (0xEB) */
	if (op == 0xeb) {
		if ((size_t)len < max_len) {
			*is_branch = 1;
			*is_cond = 0;
			*branch_rel = (int8_t)p[len];
			len++;
		}
		return len;
	}

	/* CALL rel32 (0xE8) */
	if (op == 0xe8) {
		if ((size_t)len + 4 <= max_len) {
			*is_branch = 1;
			*is_cond = 0;
			int32_t rel;
			memcpy(&rel, &p[len], 4);
			*branch_rel = rel;
			len += 4;
		}
		return len;
	}

	/* JMP rel32 (0xE9) */
	if (op == 0xe9) {
		if ((size_t)len + 4 <= max_len) {
			*is_branch = 1;
			*is_cond = 0;
			int32_t rel;
			memcpy(&rel, &p[len], 4);
			*branch_rel = rel;
			len += 4;
		}
		return len;
	}

	/* RET (0xC3, 0xCB) */
	if (op == 0xc3 || op == 0xcb) {
		*is_branch = 1;
		*is_cond = 0;
		return len;
	}

	/* Two-byte opcode (0x0F) */
	if (op == 0x0f && (size_t)len < max_len) {
		uint8_t op2 = p[len++];
		/* Jcc near (0x0F 0x80-0x8F) */
		if (op2 >= 0x80 && op2 <= 0x8f) {
			if ((size_t)len + 4 <= max_len) {
				*is_branch = 1;
				*is_cond = 1;
				int32_t rel;
				memcpy(&rel, &p[len], 4);
				*branch_rel = rel;
				len += 4;
			}
			return len;
		}
		/* SYSCALL (0x0F 0x05), SYSRET (0x0F 0x07) */
		if (op2 == 0x05 || op2 == 0x07) {
			*is_branch = 1;
			*is_cond = 0;
			return len;
		}
		/* Skip other 0F xx instructions — approximate length */
		/* ModRM-based: add modrm length */
		if ((size_t)len < max_len) {
			uint8_t modrm = p[len];
			len++;
			int mod = (modrm >> 6) & 3;
			int rm = modrm & 7;
			if (mod == 0 && rm == 5) len += 4; /* RIP-relative */
			else if (mod == 0 && rm == 4) { len++; } /* SIB */
			else if (mod == 1) { len++; if (rm == 4) len++; }
			else if (mod == 2) { len += 4; if (rm == 4) len++; }
		}
		return len;
	}

	/* Indirect CALL/JMP (0xFF /2, /4) */
	if (op == 0xff && (size_t)len < max_len) {
		uint8_t modrm = p[len];
		int reg = (modrm >> 3) & 7;
		if (reg == 2 || reg == 4) {
			*is_branch = 1;
			*is_cond = 0;
		}
		len++;
		int mod = (modrm >> 6) & 3;
		int rm = modrm & 7;
		if (mod == 0 && rm == 5) len += 4;
		else if (mod == 0 && rm == 4) len++;
		else if (mod == 1) { len++; if (rm == 4) len++; }
		else if (mod == 2) { len += 4; if (rm == 4) len++; }
		return len;
	}

	/* Generic: approximate using ModRM if present */
	/* Most other instructions: just skip based on opcode patterns */
	if ((size_t)len < max_len && (
	    (op >= 0x00 && op <= 0x3f) || /* ALU with ModRM */
	    (op >= 0x80 && op <= 0x8f) || /* immediate ALU */
	    op == 0x63 || op == 0x69 || op == 0x6b ||
	    op == 0xc0 || op == 0xc1 || op == 0xc6 || op == 0xc7 ||
	    op == 0xd0 || op == 0xd1 || op == 0xd2 || op == 0xd3 ||
	    op == 0xf6 || op == 0xf7 || op == 0xfe)) {
		uint8_t modrm = p[len++];
		int mod = (modrm >> 6) & 3;
		int rm = modrm & 7;
		if (mod == 0 && rm == 5) len += 4;
		else if (mod == 0 && rm == 4) len++;
		else if (mod == 1) { len++; if (rm == 4) len++; }
		else if (mod == 2) { len += 4; if (rm == 4) len++; }
		/* Immediate bytes for 0x80-0x83, 0xC0-C1, 0xC6-C7 */
		if (op == 0x80 || op == 0x82 || op == 0xc0 || op == 0xc6)
			len++;
		else if (op == 0x81 || op == 0xc1 || op == 0xc7 || op == 0x69)
			len += 4;
		else if (op == 0x83 || op == 0x6b)
			len++;
	}

	return len ? len : 1; /* never return 0 */
}

/* ─── ELF loader ─────────────────────────────────────────────────────────── */

static int load_vmlinux_text(struct pt_decoder *d, const char *vmlinux)
{
	int fd;
	struct stat st;
	uint8_t *map;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;

	fd = open(vmlinux, O_RDONLY);
	if (fd < 0)
		return -1;
	fstat(fd, &st);
	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return -1;

	ehdr = (Elf64_Ehdr *)map;
	shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
	char *shstrtab = (char *)(map + shdr[ehdr->e_shstrndx].sh_offset);

	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (strcmp(&shstrtab[shdr[i].sh_name], ".text") == 0) {
			d->text_size = shdr[i].sh_size;
			d->text_vaddr = shdr[i].sh_addr;
			d->text = malloc(d->text_size);
			if (!d->text) {
				munmap(map, st.st_size);
				return -1;
			}
			memcpy(d->text, map + shdr[i].sh_offset, d->text_size);
			munmap(map, st.st_size);
			return 0;
		}
	}

	munmap(map, st.st_size);
	return -1;
}

/* ─── PT packet parser ───────────────────────────────────────────────────── */

static int pt_read_ip(struct pt_decoder *d, int enc, uint64_t *ip)
{
	int bytes = 0;
	switch (enc) {
	case 1: bytes = 2; break;
	case 2: bytes = 4; break;
	case 3: case 4: bytes = 6; break;
	case 6: bytes = 8; break;
	default: return 0;
	}
	if (d->pos + bytes > d->trace_len)
		return -1;

	uint64_t val = 0;
	for (int i = 0; i < bytes; i++)
		val |= (uint64_t)d->trace[d->pos++] << (8 * i);

	if (enc == 1)
		*ip = (*ip & ~0xFFFFULL) | val;
	else if (enc == 2)
		*ip = (*ip & ~0xFFFFFFFFULL) | val;
	else if (enc == 3) {
		*ip = val;
		if (val & (1ULL << 47))
			*ip |= 0xFFFF000000000000ULL;
	} else if (enc == 4)
		*ip = (*ip & ~0xFFFFFFFFFFFFULL) | val;
	else if (enc == 6)
		*ip = val;

	return bytes;
}

static void emit_ip(struct pt_decoder *d, uint64_t ip)
{
	if (ip >= 0xffff000000000000ULL) {
		fprintf(d->output, "0x%lx\n", (unsigned long)ip);
		d->pc_count++;
	}
}

/* Walk kernel binary from current IP using TNT bits */
static void walk_tnt(struct pt_decoder *d)
{
	/* Detect KASLR offset on first valid IP */
	if (d->ip >= 0xffff000000000000ULL && d->ip != 0 && d->text) {
		if (d->ip < d->text_vaddr || d->ip >= d->text_vaddr + d->text_size) {
			/* IP is outside vmlinux .text — compute KASLR offset */
			uint64_t offset = ((d->ip - d->text_vaddr) >> 21) << 21;
			if (offset > 0 && offset < 0x80000000ULL) {
				d->text_vaddr += offset;
			}
		}
	}

	while (d->tnt_count > 0 && d->ip >= d->text_vaddr &&
	       d->ip < d->text_vaddr + d->text_size) {
		size_t off = d->ip - d->text_vaddr;
		size_t remain = d->text_size - off;
		if (remain < 1)
			break;

		int is_branch, is_cond;
		int64_t branch_rel;
		int ilen = decode_insn(d->text + off, remain > 15 ? 15 : remain,
				       &is_branch, &is_cond, &branch_rel);
		if (ilen == 0)
			break;

		if (is_branch && is_cond) {
			/* Consume a TNT bit */
			int taken = (d->tnt_bits >> (d->tnt_count - 1)) & 1;
			d->tnt_count--;

			if (taken) {
				d->ip = d->ip + ilen + branch_rel;
			} else {
				d->ip += ilen;
			}
			emit_ip(d, d->ip);
		} else if (is_branch && !is_cond) {
			/* Unconditional branch — wait for TIP */
			if (branch_rel != 0 && ilen > 1) {
				/* Direct call/jmp: follow it */
				d->ip = d->ip + ilen + branch_rel;
				emit_ip(d, d->ip);
			} else {
				/* Indirect or ret — need TIP packet */
				break;
			}
		} else {
			/* Not a branch — advance */
			d->ip += ilen;
		}
	}
}

/* ─── Main decoder loop ──────────────────────────────────────────────────── */

int pt_decoder_init(struct pt_decoder *d, const char *vmlinux,
		    uint8_t *trace, size_t trace_len, FILE *output)
{
	memset(d, 0, sizeof(*d));
	d->trace = trace;
	d->trace_len = trace_len;
	d->output = output;

	if (!vmlinux)
		return 0; /* No vmlinux = TIP-only mode */

	return load_vmlinux_text(d, vmlinux);
}

int pt_decoder_run(struct pt_decoder *d)
{
	d->pos = 0;
	d->ip = 0;
	d->tnt_count = 0;
	d->pc_count = 0;

	while (d->pos < d->trace_len) {
		uint8_t b = d->trace[d->pos++];

		/* PAD */
		if (b == 0x00)
			continue;

		/* Short TNT: bit 0 = 1, bits[7:1] = TNT payload */
		if ((b & 0x01) && b != 0x99 && (b & 0x1f) != 0x0d &&
		    (b & 0x1f) != 0x1d && (b & 0x1f) != 0x11 &&
		    (b & 0x1f) != 0x01) {
			/* Find the stop bit (highest set bit) */
			uint8_t payload = b >> 1;
			int bits = 0;
			uint8_t tmp = payload;
			while (tmp > 1) { tmp >>= 1; bits++; }
			/* bits below the stop bit are TNT data */
			d->tnt_bits = payload & ((1 << bits) - 1);
			d->tnt_count = bits;
			if (d->text && d->ip)
				walk_tnt(d);
			continue;
		}

		/* PSB */
		if (b == 0x02 && d->pos < d->trace_len && d->trace[d->pos] == 0x82) {
			d->pos += 15; /* skip rest of PSB (16 bytes total) */
			continue;
		}

		/* TIP / FUP / TIP.PGE / TIP.PGD */
		uint8_t opcode = b & 0x1f;
		if (opcode == 0x0d || opcode == 0x1d ||
		    opcode == 0x11 || opcode == 0x01) {
			int enc = (b >> 5) & 0x7;
			if (enc > 0) {
				pt_read_ip(d, enc, &d->ip);
				emit_ip(d, d->ip);
				/* After TIP, try walking with any pending TNT */
				if (d->text && d->tnt_count > 0)
					walk_tnt(d);
			}
			continue;
		}

		/* Long TNT (0x02 0xA3) */
		if (b == 0x02 && d->pos < d->trace_len && d->trace[d->pos] == 0xa3) {
			d->pos++;
			if (d->pos + 6 <= d->trace_len) {
				uint64_t payload = 0;
				for (int i = 0; i < 6; i++)
					payload |= (uint64_t)d->trace[d->pos++] << (8 * i);
				/* Find stop bit */
				int bits = 0;
				uint64_t tmp = payload;
				while (tmp > 1) { tmp >>= 1; bits++; }
				d->tnt_bits = payload & ((1ULL << bits) - 1);
				d->tnt_count = bits;
				if (d->text && d->ip)
					walk_tnt(d);
			}
			continue;
		}

		/* Skip other packets */
	}

	return d->pc_count;
}

void pt_decoder_fini(struct pt_decoder *d)
{
	free(d->text);
}
