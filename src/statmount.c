/*
 * Copyright (c) 2024-2025 Dmitry V. Levin <ldv@strace.io>
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include <linux/mount.h>
#include "xlat/statmount_mask.h"
#include "xlat/statmount_sb_flags.h"
#include "xlat/statmount_mnt_propagation.h"

#define PRINT_FIELD_CSTRING_OFFSET(where_, field_, str_buf_, str_size_)		\
	do {									\
		tprints_field_name(#field_);					\
		if ((where_).field_ < (str_size_))				\
			print_quoted_cstring((str_buf_) + (where_).field_,	\
					     (str_size_) - (where_).field_);	\
		else								\
			PRINT_VAL_X((where_).field_);				\
	} while (0)

#define PRINT_FIELD_CSTRING_SEQUENCE(tcp_, where_, field_, num_,		\
				     str_buf_, str_size_)			\
	do {									\
		tprints_field_name(#field_);					\
		if ((where_).field_ < (str_size_))				\
			print_quoted_cstring_sequence((tcp_),			\
				(str_buf_) + (where_).field_, (where_).num_,	\
				(str_size_) - (where_).field_);			\
		else								\
			PRINT_VAL_X((where_).field_);				\
	} while (0)

static void
print_quoted_cstring_sequence(struct tcb *const tcp, const char *str,
			      unsigned int nelem, unsigned int size)
{
	unsigned int i;

	tprint_array_begin();

	for (i = 0; i < nelem && size > 0; ++i) {
		if (i)
			tprint_array_next();

		if (sequence_truncation_needed(tcp, i + 1)) {
			tprint_more_data_follows();
			tprint_array_end();
			return;
		}

		print_quoted_cstring(str, size);

		unsigned int len = strnlen(str, size);
		if (len < size)
			++len;
		str += len;
		size -= len;
	}

	if (i < nelem) {
		if (i)
			tprint_array_next();
		tprint_unavailable();
	}

	tprint_array_end();
}

static void
print_mnt_id_req(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct mnt_id_req req = { 0 };

	static_assert(offsetof(struct mnt_id_req, size) == 0,
		      "offsetof(struct mnt_id_req, size) > 0");
	if (umove_or_printaddr(tcp, addr, &req.size))
		return;

	tprint_struct_begin();
	PRINT_FIELD_U(req, size);

	if (req.size < MNT_ID_REQ_SIZE_VER0) {
		tprint_struct_end();
		return;
	}

	if (umoven(tcp, addr, MIN(sizeof(req), req.size), &req)) {
		tprint_struct_next();
		tprint_unavailable();
		tprint_struct_end();
		return;
	}

	if (req.spare) {
		tprint_struct_next();
		PRINT_FIELD_X(req, spare);
	}

	tprint_struct_next();
	PRINT_FIELD_X(req, mnt_id);

	tprint_struct_next();
	PRINT_FIELD_FLAGS(req, param, statmount_mask, "STATMOUNT_???");

	if (req.size >= offsetofend(struct mnt_id_req, mnt_ns_id)) {
		tprint_struct_next();
		PRINT_FIELD_X(req, mnt_ns_id);
	}

	if (req.size > MNT_ID_REQ_SIZE_VER1) {
		print_nonzero_bytes(tcp, tprint_struct_next, addr,
				    MNT_ID_REQ_SIZE_VER1,
				    MIN(req.size, get_pagesize()),
				    QUOTE_FORCE_HEX);
	}

	tprint_struct_end();
}

static void
print_statmount(struct tcb *const tcp, const kernel_ulong_t addr,
		const kernel_ulong_t size)
{
	struct statmount st = { 0 };
	size_t fetch_size = MIN(size, sizeof(st));

	if (fetch_size < sizeof(st.size)) {
		printaddr(addr);
		return;
	}

	if (umoven_or_printaddr(tcp, addr, fetch_size, &st))
		return;

	char str_buf[PATH_MAX * 3];
	size_t str_size =
		(st.size > sizeof(st) && st.size <= size)
		? MIN(st.size - sizeof(st), sizeof(str_buf)) : 0;

	if (umoven(tcp, addr + sizeof(st), str_size, str_buf))
		str_size = 0;

	tprint_struct_begin();
	PRINT_FIELD_U(st, size);

	if (st.mask & STATMOUNT_MNT_OPTS) {
		tprint_struct_next();
		PRINT_FIELD_CSTRING_OFFSET(st, mnt_opts, str_buf, str_size);
	}

	tprint_struct_next();
	PRINT_FIELD_FLAGS(st, mask, statmount_mask, "STATMOUNT_???");

	if (st.mask & STATMOUNT_SB_BASIC) {
		tprint_struct_next();
		PRINT_FIELD_U(st, sb_dev_major);

		tprint_struct_next();
		PRINT_FIELD_U(st, sb_dev_minor);

		tprint_struct_next();
		PRINT_FIELD_XVAL(st, sb_magic, fsmagic, NULL);

		tprint_struct_next();
		PRINT_FIELD_FLAGS(st, sb_flags, statmount_sb_flags, "MS_???");
	}

	if (st.mask & STATMOUNT_FS_TYPE) {
		tprint_struct_next();
		PRINT_FIELD_CSTRING_OFFSET(st, fs_type, str_buf, str_size);
	}

	if (st.mask & STATMOUNT_MNT_BASIC) {
		tprint_struct_next();
		PRINT_FIELD_X(st, mnt_id);

		tprint_struct_next();
		PRINT_FIELD_X(st, mnt_parent_id);

		tprint_struct_next();
		PRINT_FIELD_X(st, mnt_id_old);

		tprint_struct_next();
		PRINT_FIELD_X(st, mnt_parent_id_old);

		tprint_struct_next();
		PRINT_FIELD_FLAGS(st, mnt_attr, mount_attr_attr, "MOUNT_ATTR_???");

		tprint_struct_next();
		PRINT_FIELD_FLAGS(st, mnt_propagation, statmount_mnt_propagation, "MS_???");

		tprint_struct_next();
		PRINT_FIELD_X(st, mnt_peer_group);

		tprint_struct_next();
		PRINT_FIELD_X(st, mnt_master);
	}

	if (st.mask & STATMOUNT_PROPAGATE_FROM) {
		tprint_struct_next();
		PRINT_FIELD_X(st, propagate_from);
	}

	if (st.mask & STATMOUNT_MNT_ROOT) {
		tprint_struct_next();
		PRINT_FIELD_CSTRING_OFFSET(st, mnt_root, str_buf, str_size);
	}

	if (st.mask & STATMOUNT_MNT_POINT) {
		tprint_struct_next();
		PRINT_FIELD_CSTRING_OFFSET(st, mnt_point, str_buf, str_size);
	}

	if (st.mask & STATMOUNT_MNT_NS_ID) {
		tprint_struct_next();
		PRINT_FIELD_X(st, mnt_ns_id);
	}

	if (st.mask & STATMOUNT_FS_SUBTYPE) {
		tprint_struct_next();
		PRINT_FIELD_CSTRING_OFFSET(st, fs_subtype, str_buf, str_size);
	}

	if (st.mask & STATMOUNT_SB_SOURCE) {
		tprint_struct_next();
		PRINT_FIELD_CSTRING_OFFSET(st, sb_source, str_buf, str_size);
	}

	if (st.mask & STATMOUNT_OPT_ARRAY) {
		tprint_struct_next();
		PRINT_FIELD_U(st, opt_num);

		tprint_struct_next();
		PRINT_FIELD_CSTRING_SEQUENCE(tcp, st, opt_array, opt_num,
					     str_buf, str_size);
	}

	if (st.mask & STATMOUNT_OPT_SEC_ARRAY) {
		tprint_struct_next();
		PRINT_FIELD_U(st, opt_sec_num);

		tprint_struct_next();
		PRINT_FIELD_CSTRING_SEQUENCE(tcp, st, opt_sec_array, opt_sec_num,
					     str_buf, str_size);
	}

	if (st.mask & STATMOUNT_SUPPORTED_MASK) {
		tprint_struct_next();
		PRINT_FIELD_FLAGS(st, supported_mask, statmount_mask,
				  "STATMOUNT_???");
	}

	if (st.mask & STATMOUNT_MNT_UIDMAP) {
		tprint_struct_next();
		PRINT_FIELD_U(st, mnt_uidmap_num);

		tprint_struct_next();
		PRINT_FIELD_CSTRING_SEQUENCE(tcp, st, mnt_uidmap, mnt_uidmap_num,
					     str_buf, str_size);
	}

	if (st.mask & STATMOUNT_MNT_GIDMAP) {
		tprint_struct_next();
		PRINT_FIELD_U(st, mnt_gidmap_num);

		tprint_struct_next();
		PRINT_FIELD_CSTRING_SEQUENCE(tcp, st, mnt_gidmap, mnt_gidmap_num,
					     str_buf, str_size);
	}

	tprint_struct_end();
}

SYS_FUNC(statmount)
{
	const kernel_ulong_t req = tcp->u_arg[0];
	const kernel_ulong_t buf = tcp->u_arg[1];
	const kernel_ulong_t bufsize = tcp->u_arg[2];
	const unsigned int flags = tcp->u_arg[3];

	if (entering(tcp)) {
		print_mnt_id_req(tcp, req);
		tprint_arg_next();
		return 0;
	}

	print_statmount(tcp, buf, bufsize);
	tprint_arg_next();

	PRINT_VAL_U(bufsize);
	tprint_arg_next();

	PRINT_VAL_X(flags);

	return 0;
}
