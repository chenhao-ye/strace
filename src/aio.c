/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 1999-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "list.h"
#include <linux/aio_abi.h>
#include <stdint.h>
#include <stdlib.h>

#include "xlat/aio_cmds.h"

#ifdef HAVE_STRUCT_IOCB_AIO_FLAGS
# include "xlat/aio_iocb_flags.h"
#endif

struct aio_tag {
	// enumerate for easy naming
	uint64_t tag_id;
	// used to match io_submit and io_pgetevents
	uint64_t aio_data;
	// make a copy of iocb
	struct iocb cb;
	// make a copy of ready event
	struct io_event event;
	struct aio_tag* parent;
	// what other aio_tag that depend on the current one
	struct aio_tag* head_child;
	// other sibling nodes
	struct list_item sibling;
	// linked with other pending nodes (null if no longer pending)
	struct list_item pending;
	// linked with other ready nodes
	struct list_item ready;
};

struct aio_tag_ctx {
	// associated ctx with iocb
	aio_context_t ctx_id;

	// the aio that we just release; whatever new coming aio is its children
	struct aio_tag* curr_parent;
	// lists of aio_tag:
	struct list_item pending_list;
	struct list_item ready_list;

	// timestamp for the last io_submit (only continue after the drain timeout)
	struct timespec last_req_ts;

	// linked together with other aio_tag_ctx
	struct list_item peer;
};

static uint64_t next_aio_tag_id = 1;
static EMPTY_LIST(aio_ctx_list);
// set to the current aio_tag_ctx in io_submit when reading ctx_id
struct aio_tag_ctx* aio_ctx_curr = NULL;

struct timespec drain_timeout = { .tv_sec = 0, .tv_nsec = 100000 };

// check whether it has been timeout for draining
// if yes, reset the timer
bool
check_drain_timeout(void) {
	struct timespec ts_now, ts_diff;
	clock_gettime(CLOCK_MONOTONIC, &ts_now);
	ts_sub(&ts_diff, &ts_now, &aio_ctx_curr->last_req_ts);
	if (ts_cmp(&ts_diff, &drain_timeout) < 0) return false;
	aio_ctx_curr->last_req_ts = ts_now;
	return true;
}


// set the global variable aio_ctx_curr to the correct one
// assume ctx is the first argument
static void
set_curr_aio_ctx(struct tcb *tcp) {
	aio_context_t ctx_id = tcp->u_arg[0];
	aio_ctx_curr = NULL;
	struct aio_tag_ctx* i;
	list_foreach(i, &aio_ctx_list, peer) {
		if (i->ctx_id == ctx_id) {
			aio_ctx_curr = i;
			break;
		}
	}
	if (!aio_ctx_curr) {
		aio_ctx_curr = calloc(1, sizeof(struct aio_tag_ctx));
		aio_ctx_curr->ctx_id = ctx_id;
		list_append(&aio_ctx_list, &aio_ctx_curr->peer);
		list_init(&aio_ctx_curr->pending_list);
		list_init(&aio_ctx_curr->ready_list);
		// create a "fake" parent
		aio_ctx_curr->curr_parent = calloc(1, sizeof(struct aio_tag));
	}
}

// NOTE: we don't add aio_tag_ctx in io_setup but lazily on io_submit when the
// given ctx_id does not match, because we may miss io_setup when trace starts,
// and handling inside io_submit might be a better idea.

SYS_FUNC(io_setup)
{
	if (entering(tcp)) {
		/* nr_events */
		unsigned int nr_events = tcp->u_arg[0];
		PRINT_VAL_U(nr_events);
		tprint_arg_next();
	} else {
		/* ctx_idp */
		printnum_ptr(tcp, tcp->u_arg[1]);
	}
	return 0;
}

SYS_FUNC(io_destroy)
{
	/*** matching the corresponding context ***/
	set_curr_aio_ctx(tcp);

	/* ctx_id */
	printaddr(tcp->u_arg[0]);

	return RVAL_DECODED;
}

enum iocb_sub {
	SUB_NONE, SUB_COMMON, SUB_VECTOR, SUB_POLL
};

static enum iocb_sub
tprint_lio_opcode(unsigned int cmd)
{
	static const enum iocb_sub subs[] = {
		[IOCB_CMD_PREAD]	= SUB_COMMON,
		[IOCB_CMD_PWRITE]	= SUB_COMMON,
		[IOCB_CMD_FSYNC]	= SUB_NONE,
		[IOCB_CMD_FDSYNC]	= SUB_NONE,
		[IOCB_CMD_PREADX]	= SUB_NONE,
		[IOCB_CMD_POLL]		= SUB_POLL,
		[IOCB_CMD_NOOP]		= SUB_NONE,
		[IOCB_CMD_PREADV]	= SUB_VECTOR,
		[IOCB_CMD_PWRITEV]	= SUB_VECTOR,
	};

	printxval_ex(aio_cmds, cmd, "IOCB_CMD_???", XLAT_STYLE_FMT_U);

	return cmd < ARRAY_SIZE(subs) ? subs[cmd] : SUB_NONE;
}

static void
print_common_flags(struct tcb *tcp, const struct iocb *cb)
{
/* aio_flags and aio_resfd fields are available since v2.6.22-rc1~47 */
#ifdef HAVE_STRUCT_IOCB_AIO_FLAGS
	if (cb->aio_flags) {
		tprint_struct_next();
		PRINT_FIELD_FLAGS(*cb, aio_flags, aio_iocb_flags,
				  "IOCB_FLAG_???");
	}

	if (cb->aio_flags & IOCB_FLAG_RESFD) {
		tprint_struct_next();
		PRINT_FIELD_FD(*cb, aio_resfd, tcp);
	} else if (cb->aio_resfd) {
		tprint_struct_next();
		PRINT_FIELD_X(*cb, aio_resfd);
	}
#endif
}

static bool
iocb_is_valid(const struct iocb *cb)
{
	return cb->aio_buf == (unsigned long) cb->aio_buf &&
	       cb->aio_nbytes == (size_t) cb->aio_nbytes &&
	       (ssize_t) cb->aio_nbytes >= 0;
}

static enum iocb_sub
print_iocb_header(struct tcb *tcp, const struct iocb *cb)
{
	enum iocb_sub sub;

	PRINT_FIELD_X(*cb, aio_data);

	if (cb->aio_key) {
		tprint_struct_next();
		PRINT_FIELD_U(*cb, aio_key);
	}

#ifndef HAVE_STRUCT_IOCB_AIO_RW_FLAGS
# define aio_rw_flags aio_reserved1
#endif
	if (cb->aio_rw_flags) {
		tprint_struct_next();
		PRINT_FIELD_FLAGS(*cb, aio_rw_flags, rwf_flags, "RWF_???");
	}

	tprint_struct_next();
	tprints_field_name("aio_lio_opcode");
	sub = tprint_lio_opcode(cb->aio_lio_opcode);

	if (cb->aio_flags & IOCB_FLAG_IOPRIO) {
		tprint_struct_next();
		PRINT_FIELD_OBJ_U(*cb, aio_reqprio, print_ioprio);
	} else if (cb->aio_reqprio) {
		tprint_struct_next();
		PRINT_FIELD_D(*cb, aio_reqprio);
	}

	tprint_struct_next();
	PRINT_FIELD_FD(*cb, aio_fildes, tcp);

	return sub;
}

static void
print_iocb(struct tcb *tcp, const struct iocb *cb)
{
	/**
	 * Hijack iocb printing: it only gets called in io_submit, so we keep a record
	 * of all the iocb flowing through
	 */
	if (cb->aio_lio_opcode != IOCB_CMD_POLL && cb->aio_lio_opcode != IOCB_CMD_NOOP) {
		struct aio_tag* tag = calloc(1, sizeof(struct aio_tag));
		tag->tag_id = next_aio_tag_id++;
		tag->aio_data = cb->aio_data;
		tag->cb = *cb;
		tag->parent = aio_ctx_curr->curr_parent;
		tag->head_child = NULL;
		// add to the pending list
		list_append(&aio_ctx_curr->pending_list, &tag->pending);
		// add as a child of the current parent
		if (!aio_ctx_curr->curr_parent->head_child) {
			aio_ctx_curr->curr_parent->head_child = tag;
			list_init(&tag->sibling);
		} else {
			list_append(&aio_ctx_curr->curr_parent->head_child->sibling, &tag->sibling);
		}
		tprintf(" /**<tag-%ld>**/ ", tag->tag_id);
		// refresh timer
		clock_gettime(CLOCK_MONOTONIC, &aio_ctx_curr->last_req_ts);
		// activate draining
	}

	tprint_struct_begin();

	enum iocb_sub sub = print_iocb_header(tcp, cb);

	switch (sub) {
	case SUB_COMMON:
		if (cb->aio_lio_opcode == 1 && iocb_is_valid(cb)) {
			tprint_struct_next();
			PRINT_FIELD_OBJ_TCB_VAL(*cb, aio_buf, tcp,
				printstrn, cb->aio_nbytes);
		} else {
			tprint_struct_next();
			PRINT_FIELD_X(*cb, aio_buf);
		}
		tprint_struct_next();
		PRINT_FIELD_U(*cb, aio_nbytes);
		tprint_struct_next();
		PRINT_FIELD_D(*cb, aio_offset);
		print_common_flags(tcp, cb);
		break;
	case SUB_VECTOR:
		if (iocb_is_valid(cb)) {
			tprint_struct_next();
			tprints_field_name("aio_buf");
			tprint_iov(tcp, cb->aio_nbytes, cb->aio_buf,
				   cb->aio_lio_opcode == 8
				   ? iov_decode_str
				   : iov_decode_addr);
		} else {
			tprint_struct_next();
			PRINT_FIELD_X(*cb, aio_buf);
			tprint_struct_next();
			PRINT_FIELD_U(*cb, aio_nbytes);
		}
		tprint_struct_next();
		PRINT_FIELD_D(*cb, aio_offset);
		print_common_flags(tcp, cb);
		break;
	case SUB_POLL:
		tprint_struct_next();
		PRINT_FIELD_FLAGS(*cb, aio_buf, pollflags, "POLL???");
		print_common_flags(tcp, cb);
		break;
	case SUB_NONE:
		break;
	}

	tprint_struct_end();
}

static bool
print_iocbp(struct tcb *tcp, void *elem_buf, size_t elem_size, void *data)
{
	kernel_ulong_t addr;
	struct iocb cb;

	if (elem_size < sizeof(kernel_ulong_t)) {
		addr = *(unsigned int *) elem_buf;
	} else {
		addr = *(kernel_ulong_t *) elem_buf;
	}

	if (!umove_or_printaddr(tcp, addr, &cb))
		print_iocb(tcp, &cb);

	return true;
}

SYS_FUNC(io_submit)
{
	const kernel_ulong_t addr = tcp->u_arg[2];
	kernel_ulong_t iocbp;

	/*** matching the corresponding context ***/
	set_curr_aio_ctx(tcp);

	/* ctx_id */
	printaddr(tcp->u_arg[0]);
	tprint_arg_next();

	/* nr */
	const kernel_long_t nr =
		truncate_klong_to_current_wordsize(tcp->u_arg[1]);
	PRINT_VAL_D(nr);
	tprint_arg_next();

	/* iocbpp */
	if (nr < 0)
		printaddr(addr);
	else
		print_array(tcp, addr, nr, &iocbp, current_wordsize,
			    tfetch_mem, print_iocbp, 0);

	return RVAL_DECODED;
}

// collect ready io_events (already wrapped inside a comment)
static bool
collect_io_event(struct tcb *tcp, void *elem_buf, size_t elem_size, void *data) {
	struct io_event *event = elem_buf;

	/**
	 * Hijack io completion polling.
	 * Enable aio draining again and put a new parent.
	 */
	struct aio_tag* tag = NULL;
	struct aio_tag *curr, *tmp;
	list_foreach_safe(curr, &aio_ctx_curr->pending_list, pending, tmp) {
		if (curr->aio_data == event->data) {
			tag = curr;
			list_remove(&curr->pending);
			break;
		}
	}
	tprintf("<tag-%ld>", tag->tag_id);
	if (!tag) {
		tprintf("[ERR]: Fail to find io_event to collect!");
		return false;
	}
	// make a copy of the event
	tag->event = *event;
	list_append(&aio_ctx_curr->ready_list, &tag->ready);
	return true;
}

static void
release_io_event(struct aio_tag* tag) {
	struct aio_tag *curr;
	// dump the current parent's dependency
	if (aio_ctx_curr->curr_parent) {
		tprintf(" /**[DEP]: <tag-%ld>: [", aio_ctx_curr->curr_parent->tag_id);
		if (aio_ctx_curr->curr_parent->head_child) {
			tprintf("%ld", aio_ctx_curr->curr_parent->head_child->tag_id);
			list_foreach(curr, &aio_ctx_curr->curr_parent->head_child->sibling, sibling)
				tprintf(", %ld", curr->tag_id);
		}
		tprintf("]**/ ");
	}

	// set a new parent
	aio_ctx_curr->curr_parent = tag;
	// refresh timer
	clock_gettime(CLOCK_MONOTONIC, &aio_ctx_curr->last_req_ts);
}

static bool
release_and_print_io_event(struct tcb *tcp, kernel_ulong_t start_addr, size_t idx)
{
	struct aio_tag* tag = list_head(&aio_ctx_curr->ready_list, struct aio_tag, ready);
	if (!tag) {
		tprintf(" /**[ERR]: Fail to find io_event to print!**/ ");
		return false;
	}
	release_io_event(tag);
	struct io_event *event = &tag->event;

	tprintf(" /**[RELEASE]: <tag-%ld>**/ ", tag->tag_id);
	// copy io events back to the tracee's memory
	upoken(tcp, start_addr + sizeof(struct io_event) * idx, sizeof(struct io_event), event);

	tprint_struct_begin();
	PRINT_FIELD_X(*event, data);
	tprint_struct_next();
	PRINT_FIELD_X(*event, obj);
	tprint_struct_next();
	PRINT_FIELD_D(*event, res);
	tprint_struct_next();
	PRINT_FIELD_D(*event, res2);
	tprint_struct_end();

	// remove from the list
	list_remove(&tag->ready);

	return true;
}

static bool
print_io_event(struct tcb *tcp, void *elem_buf, size_t elem_size, void *data)
{
	struct io_event *event = elem_buf;

	tprint_struct_begin();
	PRINT_FIELD_X(*event, data);
	tprint_struct_next();
	PRINT_FIELD_X(*event, obj);
	tprint_struct_next();
	PRINT_FIELD_D(*event, res);
	tprint_struct_next();
	PRINT_FIELD_D(*event, res2);
	tprint_struct_end();
	return true;
}

SYS_FUNC(io_cancel)
{
	/*** matching the corresponding context ***/
	set_curr_aio_ctx(tcp);

	if (entering(tcp)) {
		/* ctx_id */
		printaddr(tcp->u_arg[0]);
		tprint_arg_next();

		/* iocb */
		struct iocb cb;
		if (!umove_or_printaddr(tcp, tcp->u_arg[1], &cb)) {
			tprint_struct_begin();
			print_iocb_header(tcp, &cb);
			tprint_struct_end();
		}
		tprint_arg_next();
	} else {
		/* result */
		struct io_event event;
		if (!umove_or_printaddr(tcp, tcp->u_arg[2], &event))
			print_io_event(tcp, &event, sizeof(event), 0);
	}
	return 0;
}

static int
print_io_getevents(struct tcb *const tcp, const print_obj_by_addr_fn print_ts,
		   const bool has_sig)
{
	/*** matching the corresponding context ***/
	set_curr_aio_ctx(tcp);

	if (entering(tcp)) {
		kernel_long_t nr;

		/* ctx_id */
		printaddr(tcp->u_arg[0]);
		tprint_arg_next();

		/* min_nr */
		nr = truncate_klong_to_current_wordsize(tcp->u_arg[1]);
		PRINT_VAL_D(nr);
		tprint_arg_next();

		/* nr */
		nr = truncate_klong_to_current_wordsize(tcp->u_arg[2]);
		PRINT_VAL_D(nr);
		tprint_arg_next();
	} else {
		/* events */
		struct io_event buf;
		// collect io events: u_rval has been tampered, so read from u_rval_old
		if (tcp->u_rval_old > 0) {
			tprints(" /**[COLLECT]: ");
			print_array(tcp, tcp->u_arg[3], tcp->u_rval_old, &buf, sizeof(buf),
						tfetch_mem, collect_io_event, 0);
			tprints("**/ ");
		} else {
			tprints(" /**[NO COLLECT]**/ ");
		}
		// then do printing according to (tampered) retval
		tprints("[");
		for (int i = 0; i < tcp->u_rval; ++i)
			release_and_print_io_event(tcp, tcp->u_arg[3], i);
		tprints("]");
		tprint_arg_next();

		/*
		 * Since the timeout and sig parameters are read by the kernel
		 * on entering syscall, it has to be decoded the same way
		 * whether the syscall has failed or not.
		 */
		temporarily_clear_syserror(tcp);

		/* timeout */
		print_ts(tcp, tcp->u_arg[4]);

		if (has_sig) {
			tprint_arg_next();

			/* sig */
			print_kernel_sigset(tcp, tcp->u_arg[5]);
		}

		restore_cleared_syserror(tcp);
	}
	return 0;
}

#if HAVE_ARCH_TIME32_SYSCALLS
SYS_FUNC(io_getevents_time32)
{
	return print_io_getevents(tcp, print_timespec32, false);
}
#endif

#if HAVE_ARCH_OLD_TIME64_SYSCALLS
SYS_FUNC(io_getevents_time64)
{
	return print_io_getevents(tcp, print_timespec64, false);
}
#endif

#if HAVE_ARCH_TIME32_SYSCALLS
SYS_FUNC(io_pgetevents_time32)
{
	return print_io_getevents(tcp, print_timespec32, true);
}
#endif

SYS_FUNC(io_pgetevents_time64)
{
	return print_io_getevents(tcp, print_timespec64, true);
}
