/*
 * vock native BTF parser — zero dependencies.
 * Reads /sys/kernel/btf/vmlinux directly, builds type table.
 */
#include "btf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* On-disk BTF header */
struct btf_header {
	uint16_t magic;
	uint8_t version;
	uint8_t flags;
	uint32_t hdr_len;
	uint32_t type_off;
	uint32_t type_len;
	uint32_t str_off;
	uint32_t str_len;
};

/* On-disk btf_type (12 bytes base) */
struct btf_type_raw {
	uint32_t name_off;
	uint32_t info;    /* kind=bits[28:24], vlen=bits[15:0] */
	union {
		uint32_t size;
		uint32_t type;
	};
};

/* On-disk member (12 bytes) */
struct btf_member_raw {
	uint32_t name_off;
	uint32_t type;
	uint32_t offset; /* bit offset (or bitfield encoding if kflag) */
};

/* On-disk array info */
struct btf_array_raw {
	uint32_t type;
	uint32_t index_type;
	uint32_t nelems;
};

/* On-disk enum value */
struct btf_enum_raw {
	uint32_t name_off;
	int32_t val;
};

/* On-disk enum64 value */
struct btf_enum64_raw {
	uint32_t name_off;
	uint32_t val_lo32;
	uint32_t val_hi32;
};

#define BTF_MAGIC 0xEB9F
#define BTF_INFO_KIND(info) (((info) >> 24) & 0x1f)
#define BTF_INFO_VLEN(info) ((info) & 0xffff)
#define BTF_INFO_KFLAG(info) ((info) >> 31)

struct vock_btf {
	struct vock_btf_type *types; /* indexed by type_id (0 = void) */
	uint32_t ntypes;
	char *str_section;
	uint32_t str_len;
	void *raw;  /* mmap'd or malloc'd file contents */
	size_t raw_len;
};

static const char *btf_str(struct vock_btf *btf, uint32_t off)
{
	if (off >= btf->str_len) return "";
	return btf->str_section + off;
}

struct vock_btf *vock_btf_open(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f) return NULL;

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (fsize < (long)sizeof(struct btf_header)) { fclose(f); return NULL; }

	void *raw = malloc(fsize);
	if (!raw) { fclose(f); return NULL; }
	if (fread(raw, 1, fsize, f) != (size_t)fsize) { free(raw); fclose(f); return NULL; }
	fclose(f);

	/* If ELF file, extract .BTF section */
	uint8_t *btf_data = raw;
	size_t btf_size = fsize;
	if (fsize > 64 && memcmp(raw, "\x7f" "ELF", 4) == 0) {
		typedef struct { uint8_t e_ident[16]; uint16_t e_type; uint16_t e_machine;
			uint32_t e_version; uint64_t e_entry; uint64_t e_phoff;
			uint64_t e_shoff; uint32_t e_flags; uint16_t e_ehsize;
			uint16_t e_phentsize; uint16_t e_phnum; uint16_t e_shentsize;
			uint16_t e_shnum; uint16_t e_shstrndx; } Elf64_Ehdr_local;
		typedef struct { uint32_t sh_name; uint32_t sh_type; uint64_t sh_flags;
			uint64_t sh_addr; uint64_t sh_offset; uint64_t sh_size;
			uint32_t sh_link; uint32_t sh_info; uint64_t sh_addralign;
			uint64_t sh_entsize; } Elf64_Shdr_local;

		Elf64_Ehdr_local *ehdr = (Elf64_Ehdr_local *)raw;
		if ((uint64_t)ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr_local) > (uint64_t)fsize) {
			free(raw); return NULL;
		}
		Elf64_Shdr_local *shdr = (Elf64_Shdr_local *)((uint8_t *)raw + ehdr->e_shoff);
		char *shstrtab = (char *)((uint8_t *)raw + shdr[ehdr->e_shstrndx].sh_offset);
		int found = 0;
		for (int i = 0; i < ehdr->e_shnum; i++) {
			if (strcmp(&shstrtab[shdr[i].sh_name], ".BTF") == 0) {
				btf_data = (uint8_t *)raw + shdr[i].sh_offset;
				btf_size = shdr[i].sh_size;
				found = 1;
				break;
			}
		}
		if (!found) { free(raw); return NULL; }
	}

	struct btf_header *hdr = (struct btf_header *)btf_data;
	if (btf_size < sizeof(struct btf_header) || hdr->magic != BTF_MAGIC) { free(raw); return NULL; }

	struct vock_btf *btf = calloc(1, sizeof(*btf));
	btf->raw = raw;
	btf->raw_len = fsize;

	uint8_t *base = btf_data + hdr->hdr_len;
	uint8_t *type_sec = base + hdr->type_off;
	uint32_t type_len = hdr->type_len;
	btf->str_section = (char *)(base + hdr->str_off);
	btf->str_len = hdr->str_len;

	/* First pass: count types */
	uint32_t count = 0;
	uint8_t *p = type_sec;
	uint8_t *end = type_sec + type_len;
	while (p < end) {
		struct btf_type_raw *t = (struct btf_type_raw *)p;
		uint16_t kind = BTF_INFO_KIND(t->info);
		uint16_t vlen = BTF_INFO_VLEN(t->info);
		p += sizeof(struct btf_type_raw);
		switch (kind) {
		case BTF_KIND_INT: p += 4; break;
		case BTF_KIND_ARRAY: p += sizeof(struct btf_array_raw); break;
		case BTF_KIND_STRUCT: case BTF_KIND_UNION:
			p += vlen * sizeof(struct btf_member_raw); break;
		case BTF_KIND_ENUM: p += vlen * sizeof(struct btf_enum_raw); break;
		case BTF_KIND_ENUM64: p += vlen * sizeof(struct btf_enum64_raw); break;
		case BTF_KIND_FUNC_PROTO: p += vlen * 8; break; /* params: name_off + type */
		case BTF_KIND_DATASEC: p += vlen * 12; break;
		default: break;
		}
		count++;
	}

	/* Allocate type array (id 0 = void, ids 1..count) */
	btf->ntypes = count + 1;
	btf->types = calloc(btf->ntypes, sizeof(struct vock_btf_type));
	btf->types[0].kind = 0; /* void */

	/* Second pass: populate types */
	p = type_sec;
	uint32_t id = 1;
	while (p < end && id < btf->ntypes) {
		struct btf_type_raw *t = (struct btf_type_raw *)p;
		uint16_t kind = BTF_INFO_KIND(t->info);
		uint16_t vlen = BTF_INFO_VLEN(t->info);
		int kflag = BTF_INFO_KFLAG(t->info);
		p += sizeof(struct btf_type_raw);

		struct vock_btf_type *out = &btf->types[id];
		out->id = id;
		out->kind = kind;
		out->name = btf_str(btf, t->name_off);

		switch (kind) {
		case BTF_KIND_INT: {
			out->size = t->size;
			uint32_t enc = *(uint32_t *)p;
			out->int_bits = enc & 0xff;
			out->int_signed = (enc >> 24) & 1;
			p += 4;
			break;
		}
		case BTF_KIND_PTR: case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE: case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT: case BTF_KIND_FWD:
			out->ref_type_id = t->type;
			break;
		case BTF_KIND_ARRAY: {
			struct btf_array_raw *a = (struct btf_array_raw *)p;
			out->array_type_id = a->type;
			out->array_nelems = a->nelems;
			p += sizeof(struct btf_array_raw);
			break;
		}
		case BTF_KIND_STRUCT: case BTF_KIND_UNION: {
			out->size = t->size;
			out->nmembers = vlen;
			out->members = calloc(vlen, sizeof(struct vock_btf_member));
			struct btf_member_raw *m = (struct btf_member_raw *)p;
			for (int i = 0; i < vlen; i++) {
				out->members[i].name = btf_str(btf, m[i].name_off);
				out->members[i].type_id = m[i].type;
				if (kflag)
					out->members[i].offset_bits = m[i].offset & 0xffffff;
				else
					out->members[i].offset_bits = m[i].offset;
			}
			p += vlen * sizeof(struct btf_member_raw);
			break;
		}
		case BTF_KIND_ENUM: {
			out->size = t->size;
			out->nenums = vlen;
			out->enums = calloc(vlen, sizeof(struct vock_btf_enum_val));
			struct btf_enum_raw *e = (struct btf_enum_raw *)p;
			for (int i = 0; i < vlen; i++) {
				out->enums[i].name = btf_str(btf, e[i].name_off);
				out->enums[i].val = e[i].val;
			}
			p += vlen * sizeof(struct btf_enum_raw);
			break;
		}
		case BTF_KIND_ENUM64: {
			out->size = t->size;
			out->nenums = vlen;
			out->enums = calloc(vlen, sizeof(struct vock_btf_enum_val));
			struct btf_enum64_raw *e = (struct btf_enum64_raw *)p;
			for (int i = 0; i < vlen; i++) {
				out->enums[i].name = btf_str(btf, e[i].name_off);
				out->enums[i].val = (int64_t)((uint64_t)e[i].val_hi32 << 32 | e[i].val_lo32);
			}
			p += vlen * sizeof(struct btf_enum64_raw);
			break;
		}
		case BTF_KIND_FUNC_PROTO:
			out->ref_type_id = t->type; /* return type */
			p += vlen * 8;
			break;
		case BTF_KIND_FUNC:
			out->ref_type_id = t->type;
			break;
		case BTF_KIND_VAR:
			out->ref_type_id = t->type;
			p += 4; /* linkage */
			break;
		case BTF_KIND_DATASEC:
			out->size = t->size;
			p += vlen * 12;
			break;
		case BTF_KIND_FLOAT:
			out->size = t->size;
			break;
		default:
			break;
		}
		id++;
	}

	return btf;
}

void vock_btf_close(struct vock_btf *btf)
{
	if (!btf) return;
	for (uint32_t i = 0; i < btf->ntypes; i++) {
		free(btf->types[i].members);
		free(btf->types[i].enums);
	}
	free(btf->types);
	free(btf->raw);
	free(btf);
}

uint32_t vock_btf_type_count(struct vock_btf *btf)
{
	return btf->ntypes;
}

const struct vock_btf_type *vock_btf_type_by_id(struct vock_btf *btf, uint32_t id)
{
	if (id >= btf->ntypes) return NULL;
	return &btf->types[id];
}

const struct vock_btf_type *vock_btf_find_struct(struct vock_btf *btf, const char *name)
{
	for (uint32_t i = 1; i < btf->ntypes; i++) {
		if ((btf->types[i].kind == BTF_KIND_STRUCT ||
		     btf->types[i].kind == BTF_KIND_UNION) &&
		    btf->types[i].name && strcmp(btf->types[i].name, name) == 0)
			return &btf->types[i];
	}
	return NULL;
}

static const char *kind_str(uint16_t kind)
{
	switch (kind) {
	case BTF_KIND_INT: return "int";
	case BTF_KIND_PTR: return "ptr";
	case BTF_KIND_ARRAY: return "array";
	case BTF_KIND_STRUCT: return "struct";
	case BTF_KIND_UNION: return "union";
	case BTF_KIND_ENUM: return "enum";
	case BTF_KIND_TYPEDEF: return "typedef";
	case BTF_KIND_CONST: return "const";
	case BTF_KIND_VOLATILE: return "volatile";
	case BTF_KIND_FLOAT: return "float";
	default: return "?";
	}
}

void vock_btf_dump_struct(struct vock_btf *btf, const struct vock_btf_type *t, int depth)
{
	if (!t || depth > 4) return;
	const char *kw = t->kind == BTF_KIND_UNION ? "union" : "struct";
	printf("%s %s { /* %u bytes */\n", kw, t->name ? t->name : "(anon)", t->size);
	for (int i = 0; i < t->nmembers; i++) {
		struct vock_btf_member *m = &t->members[i];
		const struct vock_btf_type *mt = vock_btf_type_by_id(btf, m->type_id);
		/* Chase qualifiers */
		while (mt && (mt->kind == BTF_KIND_CONST || mt->kind == BTF_KIND_VOLATILE ||
		             mt->kind == BTF_KIND_TYPEDEF || mt->kind == BTF_KIND_RESTRICT))
			mt = vock_btf_type_by_id(btf, mt->ref_type_id);
		printf("  +%3u.%u  %-20s  ", m->offset_bits / 8, m->offset_bits % 8,
		       m->name[0] ? m->name : "(anon)");
		if (!mt) { printf("void\n"); continue; }
		if (mt->kind == BTF_KIND_INT)
			printf("%s%u\n", mt->int_signed ? "s" : "u", mt->int_bits);
		else if (mt->kind == BTF_KIND_PTR)
			printf("ptr\n");
		else if (mt->kind == BTF_KIND_ENUM)
			printf("enum %s (%d vals)\n", mt->name ? mt->name : "", mt->nenums);
		else if (mt->kind == BTF_KIND_STRUCT || mt->kind == BTF_KIND_UNION)
			printf("%s %s (%u bytes)\n", kind_str(mt->kind),
			       mt->name ? mt->name : "(anon)", mt->size);
		else if (mt->kind == BTF_KIND_ARRAY)
			printf("array[%u]\n", mt->array_nelems);
		else
			printf("%s\n", kind_str(mt->kind));
	}
	printf("}\n");
}
