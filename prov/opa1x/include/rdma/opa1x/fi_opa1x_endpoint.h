/*
 * Copyright (C) 2016 by Argonne National Laboratory.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef _FI_PROV_OPA1X_ENDPOINT_H_
#define _FI_PROV_OPA1X_ENDPOINT_H_

#include <stdint.h>
#include <pthread.h>
#include <sys/uio.h>

#include "rdma/opa1x/fi_opa1x_domain.h"

#include "rdma/opa1x/fi_opa1x_internal.h"
#include "rdma/opa1x/fi_opa1x.h"
#include "rdma/opa1x/fi_opa1x_compiler.h"
#include "rdma/opa1x/fi_opa1x_hfi1.h"
#include "rdma/opa1x/fi_opa1x_reliability.h"
#include "ofi_shm2.h"

#include "rdma/opa1x/fi_opa1x_addr.h"

//#include "rdma/fi_tagged.h"

void fi_opa1x_cq_debug(struct fid_cq *cq, const int line);

#define IS_TAG (0)
#define IS_MSG (1)

// #define FI_OPA1X_TRACE 1
// #define FI_OPA1X_REMOTE_COMPLETION

/* #define IS_MATCH_DEBUG */

/* Macro indirection in order to support other macros as arguments
 * C requires another indirection for expanding macros since
 * operands of the token pasting operator are not expanded */

#define FI_OPA1X_MSG_SPECIALIZED_FUNC(LOCK,AV,CAPS,RELIABILITY)			\
	FI_OPA1X_MSG_SPECIALIZED_FUNC_(LOCK,AV,CAPS,RELIABILITY)

#define FI_OPA1X_MSG_SPECIALIZED_FUNC_(LOCK,AV,CAPS,RELIABILITY)		\
	static inline ssize_t							\
	fi_opa1x_send_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const void *buf, size_t len,		\
			void *desc, fi_addr_t dest_addr, void *context)		\
	{									\
		return fi_opa1x_ep_tx_send(ep, buf, len, desc,			\
				dest_addr, 0, context, 0,			\
				LOCK,	/* lock_required */			\
				AV,	/* av_type */				\
				1,	/* is_contiguous */			\
				0,	/* override_flags */			\
				0,	/* flags */				\
				CAPS | FI_MSG,					\
				RELIABILITY);					\
	}									\
	static inline ssize_t							\
	fi_opa1x_recv_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, void *buf, size_t len,			\
			void *desc, fi_addr_t src_addr, void *context)		\
	{									\
		return fi_opa1x_recv_generic(ep, buf, len, desc,		\
				src_addr, 0, (uint64_t)-1, context,		\
				LOCK, AV, FI_MSG, RELIABILITY);			\
	}									\
	static inline ssize_t							\
	fi_opa1x_inject_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const void *buf, size_t len,		\
			fi_addr_t dest_addr)					\
	{									\
		return fi_opa1x_ep_tx_inject(ep, buf, len,			\
				dest_addr, 0, 0,				\
				LOCK,	/* lock_required */			\
				AV,	/* av_type */				\
				CAPS | FI_MSG,					\
				RELIABILITY);					\
	}									\
	static inline ssize_t							\
	fi_opa1x_recvmsg_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const struct fi_msg *msg,			\
			uint64_t flags)						\
	{									\
		return fi_opa1x_recvmsg_generic(ep, msg, flags,			\
				LOCK, AV, RELIABILITY);				\
	}									\
	static inline ssize_t							\
	fi_opa1x_senddata_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const void *buf, size_t len,		\
			void *desc, uint64_t data, fi_addr_t dest_addr,		\
			void *context)						\
	{									\
		return fi_opa1x_ep_tx_send(ep, buf, len, desc,			\
				dest_addr, 0, context, data,			\
				LOCK,	/* lock_required */			\
				AV,	/* av_type */				\
				1,	/* is_contiguous */			\
				0,	/* override_flags */			\
				0,	/* flags */				\
				CAPS | FI_MSG,					\
				RELIABILITY);					\
	}									\
	static inline ssize_t							\
	fi_opa1x_injectdata_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const void *buf, size_t len,		\
			uint64_t data, fi_addr_t dest_addr)			\
	{									\
		return fi_opa1x_ep_tx_inject(ep, buf, len,			\
				dest_addr, 0, data,				\
				LOCK,	/* lock_required */			\
				AV,	/* av_type */				\
				CAPS | FI_MSG,					\
				RELIABILITY);					\
	}

#define FI_OPA1X_MSG_SPECIALIZED_FUNC_NAME(TYPE, LOCK, AV, CAPS, RELIABILITY)	\
	FI_OPA1X_MSG_SPECIALIZED_FUNC_NAME_(TYPE, LOCK, AV, CAPS, RELIABILITY)

#define FI_OPA1X_MSG_SPECIALIZED_FUNC_NAME_(TYPE, LOCK, AV, CAPS, RELIABILITY)	\
		fi_opa1x_ ## TYPE ## _ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY




enum fi_opa1x_ep_state {
	FI_OPA1X_EP_UNINITIALIZED = 0,
	FI_OPA1X_EP_INITITALIZED_DISABLED,
	FI_OPA1X_EP_INITITALIZED_ENABLED
};


/*
 * This structure layout ensures that the 'fi_tinject()' function will only
 * touch 2 cachelines - one from this structure and one to obtain the pio
 * state information.
 *
 * This structure layout ensures that the 'fi_tsend()' function will only
 * touch 3 cachelines - two from this structure and one to obtain the pio
 * state information. Additional cachelines will be touched if a completion
 * queue entry is requested.
 *
 * 'fi_inject()' -> 3 cachelines
 * 'fi_send()'   -> 4 cachelines
 */
struct fi_opa1x_ep_tx {

	/* == CACHE LINE 0,1 == */

	union fi_opa1x_hfi1_pio_state		pio_state;			/* 1 qw = 8 bytes */
	volatile uint64_t *			pio_scb_sop_first;
	uint64_t				unused_1;

	struct fi_opa1x_hfi1_txe_scb		inject;				/* qws 5,6, and 7 specified at runtime */

	volatile uint64_t *			pio_credits_addr;		/* const; only used to infrequently "refresh" credit information */
	volatile uint64_t *			pio_scb_first;			/* const; only eager and rendezvous */
	uint64_t				cq_bind_flags;
	struct fi_opa1x_context_slist *		cq_completed_ptr;
	uint32_t				do_cq_completion;
	uint32_t				unused;

	/* == CACHE LINE 2,3 == */

	struct fi_opa1x_hfi1_txe_scb		send;
	struct fi_opa1x_hfi1_txe_scb		rzv;

	/* == CACHE LINE 4 == */

	union fi_opa1x_addr *			av_addr;			/* only FI_ADDR_TABLE */
	uint64_t				av_count;			/* only FI_ADDR_TABLE */
	uint64_t				op_flags;
	uint64_t				caps;
	uint64_t				mode;
	struct fi_opa1x_context_slist *		cq_err_ptr;
	struct fi_opa1x_cq *			cq;
	struct fi_opa1x_context_slist *		cq_pending_ptr;			/* only rendezvous (typically) */

	/* == CACHE LINE 5, ... == */

	struct ofi_shm2_tx			shm;

} __attribute__((__aligned__(L2_CACHE_LINE_SIZE))) __attribute__((__packed__));


struct fi_opa1x_ep_rx {

	/* == CACHE LINE 0 == */

	/*
	 * NOTE: This cacheline is used when a thread is INITIATING
	 * receive operations
	 */
	uint64_t			op_flags;
	uint16_t			slid;
	uint16_t			unused_u16[3];
	uint64_t			unused_cacheline_0[4];
	uint64_t			av_count;
	union fi_opa1x_addr *		av_addr;

	/*
	 * NOTE: The following 2 cachelines are shared between the application-facing
	 * functions, such as 'fi_trecv()', and the progress functions, such as
	 * those invoked during 'fi_cq_read()'.
	 */

	/* == CACHE LINE 1 == */

	struct {
		struct fi_opa1x_context_slist		mq;	/* 2 qws */
		struct fi_opa1x_hfi1_ue_packet_slist	ue;	/* 2 qws */
	} queue[2];	/* 0 = FI_TAGGED, 1 = FI_MSG */

	/* == CACHE LINE 2 == */

	struct fi_opa1x_context_slist *			cq_pending_ptr;
	struct fi_opa1x_context_slist *			cq_completed_ptr;
	struct fi_opa1x_hfi1_ue_packet_slist		ue_free_pool;		/* 2 qws */

	uint64_t			unused_cacheline_2[4];

	/* == CACHE LINE 3 == */

	/*
	 * NOTE: This cacheline is used when a thread is making PROGRESS to
	 * process fabric events.
	 */

	struct ofi_shm2_poll_state	shm_poll;		/* 1 qw */

	struct fi_opa1x_hfi1_rxe_state	state;			/* 2 qws */

	struct {
		uint32_t *		rhf_base;
		volatile uint64_t *	head_register;
	} hdrq;

	struct {
		uint32_t *		base_addr;
		uint32_t		elemsz;
		uint32_t		last_egrbfr_index;
		volatile uint64_t *	head_register;
	} egrq __attribute__((__packed__));


	/* == CACHE LINE 4,5 == */

	/*
	 * NOTE: These cachelines are shared between the application-facing
	 * functions, such as 'fi_trecv()', and the progress functions, such as
	 * those invoked during 'fi_cq_read()'.
	 *
	 * This 'tx' information is used when sending acks, etc.
	 */
	struct {
		struct fi_opa1x_hfi1_txe_scb	dput;
		struct fi_opa1x_hfi1_txe_scb	cts;
	} tx;


	/* -- non-critical -- */
	uint64_t			min_multi_recv;
	struct fi_opa1x_domain *	domain;

	uint64_t			caps;
	uint64_t			mode;
	size_t				total_buffered_recv;	/* TODO - is this only used by receive operations? */
	struct fi_opa1x_ep		*srx;
	union fi_opa1x_addr		self;

	//ssize_t				index;

	struct fi_opa1x_context_slist *	cq_err_ptr;
//	struct slist *			cq_err_ptr;
	//fastlock_t *			cq_lock_ptr;
	struct fi_opa1x_cq *		cq;


	struct ofi_shm2_rx		shm;

	//fastlock_t			lock;

} __attribute__((__aligned__(L2_CACHE_LINE_SIZE))) __attribute__((__packed__));



/*
 * The 'fi_opa1x_ep' struct defines an endpoint with a single tx context and a
 * single rx context. The tx context is only valid if the FI_READ, FI_WRITE,
 * or FI_SEND capability is specified. The rx context is only valid if the
 * FI_RECV, FI_REMOTE_READ, or FI_REMOTE_WRITE flags are specified.
 *
 * A 'scalable tx context' is simply an endpoint structure with only the
 * tx flags specified, and a 'scalable rx context' is simply an endpoint
 * structure with only the rx flags specified.
 *
 * As such, multiple OFI 'classes' share this endpoint structure:
 *   FI_CLASS_EP
 *   FI_CLASS_TX_CTX
 *   --- no FI_CLASS_STX_CTX
 *   FI_CLASS_RX_CTX
 *   -- no FI_CLASS_SRX_CTX
 */
struct fi_opa1x_ep {

	struct fid_ep		ep_fid;						/* 3 qws + 6 qws = 72 bytes */
	struct fi_opa1x_reliability_client_state	reliability_state;	/* 14 qws = 112 bytes */
	uint64_t		unused;

	/* == L2 CACHE LINE == */

	struct fi_opa1x_ep_tx	tx;
	struct fi_opa1x_ep_rx	rx;

	struct fi_opa1x_reliability_service	reliability_service;		/* ONLOAD only */
	uint8_t					reliability_rx;			/* ONLOAD only */

	struct fi_opa1x_cntr	*read_cntr;
	struct fi_opa1x_cntr	*write_cntr;
	struct fi_opa1x_cntr	*send_cntr;
	struct fi_opa1x_cntr	*recv_cntr;

	struct fi_opa1x_domain	*domain;
	void			*mem;

	struct fi_opa1x_av	*av;

	struct fi_opa1x_hfi1_context *	hfi;


	struct {
		volatile uint64_t	enabled;
		volatile uint64_t	active;
		pthread_t		thread;
	} async;
	enum fi_opa1x_ep_state	state;

	uint32_t		threading;
	uint32_t		av_type;
	uint32_t		mr_mode;
	enum fi_ep_type		type;

	//fastlock_t		lock;

} __attribute((aligned(L2_CACHE_LINE_SIZE)));

void fi_opa1x_ep_tx_connect (struct fi_opa1x_ep *opa1x_ep, fi_addr_t peer/*, uint16_t slid_be16, uint16_t dlid_be16*/);

/*
 * =========================== begin: no-inline functions ===========================
 */

__attribute__((noinline))
void fi_opa1x_ep_rx_process_context_noinline (struct fi_opa1x_ep * opa1x_ep,
		const uint64_t static_flags,
		union fi_opa1x_context * context,
		const uint64_t rx_op_flags, const uint64_t is_context_ext,
		const int lock_required, const enum fi_av_type av_type,
		const enum ofi_reliability_kind reliability);

void fi_opa1x_ep_rx_process_header_tag (struct fid_ep *ep,
		const union fi_opa1x_hfi1_packet_hdr * const hdr,
		const uint8_t * const payload,
		const size_t payload_bytes,
		const uint8_t opcode,
		const unsigned is_intranode,
		const int lock_required,
		const enum ofi_reliability_kind reliability);

void fi_opa1x_ep_rx_process_header_msg (struct fid_ep *ep,
		const union fi_opa1x_hfi1_packet_hdr * const hdr,
		const uint8_t * const payload,
		const size_t payload_bytes,
		const uint8_t opcode,
		const unsigned is_intranode,
		const int lock_required,
		const enum ofi_reliability_kind reliability);

void fi_opa1x_ep_rx_reliability_process_packet (struct fid_ep *ep,
		const union fi_opa1x_hfi1_packet_hdr * const hdr,
		const uint8_t * const payload);

void fi_opa1x_ep_rx_append_ue_msg (struct fi_opa1x_ep_rx * const rx,
		const union fi_opa1x_hfi1_packet_hdr * const hdr,
		const union fi_opa1x_hfi1_packet_payload * const payload,
		const size_t payload_bytes);

void fi_opa1x_ep_rx_append_ue_tag (struct fi_opa1x_ep_rx * const rx,
		const union fi_opa1x_hfi1_packet_hdr * const hdr,
		const union fi_opa1x_hfi1_packet_payload * const payload,
		const size_t payload_bytes);

int fi_opa1x_ep_tx_check (struct fi_opa1x_ep_tx * tx, enum fi_av_type av_type);

#include "rdma/opa1x/fi_opa1x_fabric_transport.h"
/*
 * =========================== end: no-inline functions ===========================
 */


static inline
uint64_t is_match (const union fi_opa1x_hfi1_packet_hdr * const hdr, union fi_opa1x_context * context)
{

	const union fi_opa1x_addr src_addr = { .fi = context->src_addr };

	const fi_opa1x_uid_t origin_uid_fi = fi_opa1x_hfi1_packet_hdr_uid(hdr);

	const uint64_t ignore = context->ignore;
	const uint64_t target_tag = context->tag;
	const uint64_t origin_tag = hdr->match.ofi_tag;
	const uint64_t target_tag_and_not_ignore = target_tag & ~ignore;
	const uint64_t origin_tag_and_not_ignore = origin_tag & ~ignore;

	const uint64_t answer = ((origin_tag_and_not_ignore == target_tag_and_not_ignore) && ((context->src_addr == FI_ADDR_UNSPEC) || (origin_uid_fi == src_addr.uid.fi)));
#ifdef IS_MATCH_DEBUG
	fprintf(stderr, "%s:%s():%d context = %p, context->src_addr = 0x%016lx, context->ignore = 0x%016lx, context->tag = 0x%016lx, src_addr.uid.fi = 0x%08x\n", __FILE__, __func__, __LINE__,
		context, context->src_addr, context->ignore, context->tag, src_addr.uid.fi);
	fprintf(stderr, "%s:%s():%d hdr->match.slid = 0x%04x (%u), hdr->match.origin_cx = 0x%02x (%u), origin_uid_fi = 0x%08x\n", __FILE__, __func__, __LINE__,
		hdr->match.slid, hdr->match.slid, hdr->match.origin_cx, hdr->match.origin_cx, origin_uid_fi);
	fprintf(stderr, "%s:%s():%d hdr->match.ofi_tag = 0x%016lx, target_tag_and_not_ignore = 0x%016lx, origin_tag_and_not_ignore = 0x%016lx, FI_ADDR_UNSPEC = 0x%08lx\n", __FILE__, __func__, __LINE__,
		hdr->match.ofi_tag, target_tag_and_not_ignore, origin_tag_and_not_ignore, FI_ADDR_UNSPEC);
	fprintf(stderr, "%s:%s():%d answer = %lu\n", __FILE__, __func__, __LINE__, answer);
#endif
	return answer;
}




/**
 * \brief Complete a receive operation that has matched the packet header with
 * 		the match information
 *
 * \param[in]		rx	Receive endoint
 * \param[in]		hdr	MU packet header that matched
 * \param[in,out]	entry	Completion entry
 */
static inline
void complete_receive_operation (struct fid_ep *ep,
		const union fi_opa1x_hfi1_packet_hdr * const hdr,
		const union fi_opa1x_hfi1_packet_payload * const payload,
		const uint64_t origin_tag,
		union fi_opa1x_context * context,
		const uint8_t opcode,
		const unsigned is_context_ext,
		const unsigned is_multi_receive,
		const unsigned is_intranode,
		const int lock_required,
		const enum ofi_reliability_kind reliability) {

	struct fi_opa1x_ep * opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);
	struct fi_opa1x_ep_rx * const rx = &opa1x_ep->rx;

	FI_DBG(fi_opa1x_global.prov, FI_LOG_EP_DATA, "\n");

	const uint64_t recv_len = context->len;
	void * recv_buf = context->buf;

	if (opcode == FI_OPA1X_HFI_BTH_OPCODE_TAG_INJECT || opcode == FI_OPA1X_HFI_BTH_OPCODE_MSG_INJECT) {

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- INJECT (begin)\n");

		const uint64_t ofi_data = hdr->match.ofi_data;
		const uint64_t send_len = hdr->inject.message_length;

		if (is_multi_receive) {		/* branch should compile out */

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"INJECT is_multi_recv\n");

			if (send_len) memcpy(recv_buf, (void*)&hdr->inject.app_data_u8[0], send_len);

			union fi_opa1x_context * original_multi_recv_context = context;
			context = (union fi_opa1x_context *)((uintptr_t)recv_buf - sizeof(union fi_opa1x_context));
			assert((((uintptr_t)context) & 0x07) == 0);

			context->flags = FI_RECV | FI_MSG | FI_OPA1X_CQ_CONTEXT_MULTIRECV;
			context->buf = recv_buf;
			context->len = send_len;
			context->data = ofi_data;
			context->tag = 0;	/* tag is not valid for multi-receives */
			context->multi_recv_context = original_multi_recv_context;
			context->byte_counter = 0;

			/* the next 'fi_opa1x_context' must be 8-byte aligned */
			uint64_t bytes_consumed = ((send_len + 8) & (~0x07ull)) + sizeof(union fi_opa1x_context);
			original_multi_recv_context->len -= bytes_consumed;
			original_multi_recv_context->buf = (void*)((uintptr_t)(original_multi_recv_context->buf) + bytes_consumed);

			/* post a completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail(context, rx->cq_completed_ptr);

		} else if (likely(send_len <= recv_len)) {

			switch (send_len) {
				case 0:
					break;
				case 1:	*((uint8_t*)recv_buf) = hdr->inject.app_data_u8[0];
					break;
				case 2:	*((uint16_t*)recv_buf) = hdr->inject.app_data_u16[0];
					break;
				case 3:	memcpy(recv_buf, (void*)&hdr->inject.app_data_u8[0], send_len);
					break;
				case 4:	*((uint32_t*)recv_buf) = hdr->inject.app_data_u32[0];
					break;
				case 5:
				case 6:
				case 7:	memcpy(recv_buf, (void*)&hdr->inject.app_data_u8[0], send_len);
					break;
				case 8:	*((uint64_t*)recv_buf) = hdr->inject.app_data_u64[0];
					break;
				case 9:
				case 10:
				case 11:
				case 12:
				case 13:
				case 14:
				case 15: memcpy(recv_buf, (void*)&hdr->inject.app_data_u8[0], send_len);
					break;
				case 16:
					((uint64_t*)recv_buf)[0] = hdr->inject.app_data_u64[0];
					((uint64_t*)recv_buf)[1] = hdr->inject.app_data_u64[1];
					break;
				default:
					fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort();
					break;
			}
 
			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"INJECT send_len %lu <= recv_len %lu; enqueue cq (completed)\n", send_len, recv_len);

			context->flags = FI_RECV | FI_REMOTE_CQ_DATA | ((opcode == FI_OPA1X_HFI_BTH_OPCODE_TAG_INJECT) ? FI_TAGGED : FI_MSG);
			context->buf = NULL;
			context->len = send_len;
			context->data = ofi_data;
			context->tag = origin_tag;
			context->byte_counter = 0;
			context->next = NULL;

			/* post a completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail(context, rx->cq_completed_ptr);

		} else {	/* truncation - unlikely */

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"INJECT truncation - send_len %lu > recv_len %lu posting error\n", send_len, recv_len);

			struct fi_opa1x_context_ext * ext = NULL;
			if (is_context_ext) {
				ext = (struct fi_opa1x_context_ext *)context;
				ext->err_entry.op_context = ext->msg.op_context;
			} else {
				posix_memalign((void**)&ext, 32, sizeof(struct fi_opa1x_context_ext));
				ext->opa1x_context.flags = FI_OPA1X_CQ_CONTEXT_EXT;
				ext->err_entry.op_context = context;
			}

			ext->err_entry.flags = context->flags;
			ext->err_entry.len = recv_len;
			ext->err_entry.buf = recv_buf;
			ext->err_entry.data = ofi_data;
			ext->err_entry.tag = origin_tag;
			ext->err_entry.olen = send_len - recv_len;
			ext->err_entry.err = FI_ETRUNC;
			ext->err_entry.prov_errno = 0;
			ext->err_entry.err_data = NULL;

			ext->opa1x_context.byte_counter = 0;
			ext->opa1x_context.next = NULL;

			/* post an 'error' completion event for the receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail((union fi_opa1x_context*)ext, rx->cq_err_ptr);
		}

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- INJECT (end)\n");

	} else if (opcode == FI_OPA1X_HFI_BTH_OPCODE_TAG_EAGER || opcode == FI_OPA1X_HFI_BTH_OPCODE_MSG_EAGER) {

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- EAGER (begin)\n");

		const uint64_t ofi_data = hdr->match.ofi_data;
		const uint64_t send_len = hdr->send.xfer_bytes_tail + hdr->send.payload_qws_total * sizeof(uint64_t);

		FI_DBG(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"hdr->send.xfer_bytes_tail = %u, hdr->send.payload_qws_total = %u, send_len = %lu\n",
			hdr->send.xfer_bytes_tail, hdr->send.payload_qws_total, send_len);

		if (is_multi_receive) {		/* branch should compile out */

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"EAGER is_multi_recv\n");

			if (hdr->send.xfer_bytes_tail) {
				memcpy(recv_buf, (void*)&hdr->send.xfer_tail, hdr->send.xfer_bytes_tail);
				recv_buf = (void*)((uintptr_t)recv_buf + hdr->send.xfer_bytes_tail);
			}

			if (payload) {
				uint64_t * recv_buf_qw = (uint64_t *)recv_buf;
				uint64_t * payload_qw = (uint64_t *)payload;
				unsigned i;
				for (i=0; i<hdr->send.payload_qws_total; ++i) {
					recv_buf_qw[i] = payload_qw[i];
				}
			}

			union fi_opa1x_context * original_multi_recv_context = context;
			context = (union fi_opa1x_context *)((uintptr_t)recv_buf - sizeof(union fi_opa1x_context));
			assert((((uintptr_t)context) & 0x07) == 0);

			context->flags = FI_RECV | FI_MSG | FI_OPA1X_CQ_CONTEXT_MULTIRECV;
			context->buf = recv_buf;
			context->len = send_len;
			context->data = ofi_data;
			context->tag = 0;	/* tag is not valid for multi-receives */
			context->multi_recv_context = original_multi_recv_context;
			context->byte_counter = 0;

			/* the next 'fi_opa1x_context' must be 8-byte aligned */
			uint64_t bytes_consumed = ((send_len + 8) & (~0x07ull)) + sizeof(union fi_opa1x_context);
			original_multi_recv_context->len -= bytes_consumed;
			original_multi_recv_context->buf = (void*)((uintptr_t)(original_multi_recv_context->buf) + bytes_consumed);

			/* post a completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail(context, rx->cq_completed_ptr);

		} else if (likely(send_len <= recv_len)) {

			const size_t xfer_bytes_tail = hdr->send.xfer_bytes_tail;

			if (xfer_bytes_tail) {
				memcpy(recv_buf, (void*)&hdr->send.xfer_tail, xfer_bytes_tail);
				recv_buf = (void*)((uint8_t *)recv_buf + xfer_bytes_tail);
			}

			if (send_len != xfer_bytes_tail) {
				uint64_t * recv_buf_qw = (uint64_t *)recv_buf;
				uint64_t * payload_qw = (uint64_t *)payload;
				const unsigned payload_qws_total = hdr->send.payload_qws_total;
				unsigned i;
				for (i=0; i<payload_qws_total; ++i) {
					recv_buf_qw[i] = payload_qw[i];
				}
			}

			/* fi_opa1x_hfi1_dump_packet_hdr((union fi_opa1x_hfi1_packet_hdr *)hdr, __func__, __LINE__); */

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"EAGER send_len %lu <= recv_len %lu; enqueue cq (completed)\n", send_len, recv_len);

			context->flags = FI_RECV | FI_REMOTE_CQ_DATA | ((opcode == FI_OPA1X_HFI_BTH_OPCODE_TAG_EAGER) ? FI_TAGGED : FI_MSG);
			context->buf = NULL;
			context->len = send_len;
			context->data = ofi_data;
			context->tag = origin_tag;
			context->byte_counter = 0;
			context->next = NULL;

			/* post a completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail(context, rx->cq_completed_ptr);

		} else {	/* truncation - unlikely */

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"EAGER truncation - send_len %lu > recv_len %lu posting error\n", send_len, recv_len);

			struct fi_opa1x_context_ext * ext = NULL;
			if (is_context_ext) {
				ext = (struct fi_opa1x_context_ext *)context;
				ext->err_entry.op_context = ext->msg.op_context;
			} else {
				posix_memalign((void**)&ext, 32, sizeof(struct fi_opa1x_context_ext));
				ext->opa1x_context.flags = FI_OPA1X_CQ_CONTEXT_EXT;
				ext->err_entry.op_context = context;
			}

			ext->err_entry.flags = context->flags;
			ext->err_entry.len = recv_len;
			ext->err_entry.buf = recv_buf;
			ext->err_entry.data = ofi_data;
			ext->err_entry.tag = origin_tag;
			ext->err_entry.olen = send_len - recv_len;
			ext->err_entry.err = FI_ETRUNC;
			ext->err_entry.prov_errno = 0;
			ext->err_entry.err_data = NULL;

			ext->opa1x_context.byte_counter = 0;
			ext->opa1x_context.next = NULL;

			/* post an 'error' completion event for the receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail((union fi_opa1x_context*)ext, rx->cq_err_ptr);
		}

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- EAGER (end)\n");

	} else {			/* rendezvous packet */

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- RENDEZVOUS RTS (begin)\n");

		const uint64_t ofi_data = hdr->match.ofi_data;
		const uint64_t niov = hdr->rendezvous.niov;
		const uint64_t xfer_len = hdr->rendezvous.message_length;

		if (is_multi_receive) {		/* compile-time constant expression */
			FI_WARN(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"rendezvous multi-receive not implemented; abort\n");
			abort();

		} else if (likely(xfer_len <= recv_len)) {

			context->buf = NULL;
			context->len = xfer_len;
			context->data = ofi_data;
			context->tag = origin_tag;
			context->next = NULL;
			context->flags = FI_RECV | FI_REMOTE_CQ_DATA | ((opcode == FI_OPA1X_HFI_BTH_OPCODE_TAG_RZV_RTS) ? FI_TAGGED : FI_MSG);



			const uint8_t u8_rx = hdr->rendezvous.origin_rx;

			if (likely(niov == 1)) {
				assert(payload != NULL);

				uint8_t * rbuf = (uint8_t *)recv_buf;
				union fi_opa1x_hfi1_packet_payload *p = (union fi_opa1x_hfi1_packet_payload *)payload;
				const uint64_t immediate_byte_count = p->rendezvous.contiguous.immediate_byte_count;
				const uint64_t immediate_qw_count = p->rendezvous.contiguous.immediate_qw_count;
				const uint64_t immediate_block_count = p->rendezvous.contiguous.immediate_block_count;
				const uint64_t immediate_total = immediate_byte_count +
					immediate_qw_count * sizeof(uint64_t) +
					immediate_block_count * sizeof(union cacheline);

				context->byte_counter = xfer_len - immediate_total;
				uintptr_t target_byte_counter_vaddr = (uintptr_t)&context->byte_counter;


				FI_OPA1X_FABRIC_RX_RZV_RTS(ep,
						(const void * const)hdr,
						(const void * const)payload,
						u8_rx, 1,
						p->rendezvous.contiguous.origin_byte_counter_vaddr,
						target_byte_counter_vaddr,
						(uintptr_t)(rbuf + immediate_total),		/* receive buffer virtual address */
						p->rendezvous.contiguous.src_vaddr,		/* send buffer virtual address */
						p->rendezvous.contiguous.src_blocks << 6,	/* number of bytes to transfer */
						is_intranode,					/* compile-time constant expression */
						reliability);					/* compile-time constant expression */

				/*
				 * copy the immediate payload data
				 */
				unsigned i;

				if (immediate_byte_count) {
					const uint8_t * const immediate_byte = p->rendezvous.contiguous.immediate_byte;
					for (i=0; i<immediate_byte_count; ++i) {
						rbuf[i] = immediate_byte[i];
					}
					rbuf += immediate_byte_count;
				}

				if (immediate_qw_count) {
					const uint64_t * const immediate_qw = p->rendezvous.contiguous.immediate_qw;
					uint64_t * rbuf_qw = (uint64_t *)rbuf;
					for (i=0; i<immediate_qw_count; ++i) {
						rbuf_qw[i] = immediate_qw[i];
					}
					rbuf += immediate_qw_count * sizeof(uint64_t);
				}

				if (immediate_block_count) {
					const union cacheline * const immediate_block = p->rendezvous.contiguous.immediate_block;
					union cacheline * rbuf_block = (union cacheline *)rbuf;
					for (i=0; i<immediate_block_count; ++i) {
						rbuf_block[i] = immediate_block[i];
					};
				}

			} else {
				FI_WARN(fi_opa1x_global.prov, FI_LOG_EP_DATA,
					"rendezvous non-contiguous source data not implemented; abort\n");
				abort();
			}

			/* post a pending completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail(context, rx->cq_pending_ptr);


		} else {				/* truncation - unlikely */

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"RENDEZVOUS truncation - xfer_len %lu > recv_len %lu posting error\n", xfer_len, recv_len);

			struct fi_opa1x_context_ext * ext = NULL;
			if (is_context_ext) {
				ext = (struct fi_opa1x_context_ext *)context;
				ext->err_entry.op_context = ext->msg.op_context;
			} else {
				posix_memalign((void**)&ext, 32, sizeof(struct fi_opa1x_context_ext));
				ext->opa1x_context.flags = FI_OPA1X_CQ_CONTEXT_EXT;
				ext->err_entry.op_context = context;
			}

			ext->err_entry.flags = context->flags;
			ext->err_entry.len = recv_len;
			ext->err_entry.buf = recv_buf;
			ext->err_entry.data = ofi_data;
			ext->err_entry.tag = origin_tag;
			ext->err_entry.olen = xfer_len - recv_len;
			ext->err_entry.err = FI_ETRUNC;
			ext->err_entry.prov_errno = 0;
			ext->err_entry.err_data = NULL;

			ext->opa1x_context.byte_counter = 0;

			/* post an 'error' completion event for the receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail((union fi_opa1x_context*)ext, rx->cq_err_ptr);
		}

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- RENDEZVOUS RTS (end)\n");

	}	/* rendezvous packet */

	FI_DBG(fi_opa1x_global.prov, FI_LOG_EP_DATA, "\n");

	return;
}



static inline
void fi_opa1x_ep_rx_process_header (struct fid_ep *ep,
		const union fi_opa1x_hfi1_packet_hdr * const hdr,
		const union fi_opa1x_hfi1_packet_payload * const payload,
		const size_t payload_bytes,
		const uint64_t static_flags,
		const uint8_t opcode,
		const unsigned is_intranode,
		const int lock_required,
		const enum ofi_reliability_kind reliability)
{

	struct fi_opa1x_ep * opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);
//fprintf(stderr, "%s:%s():%d static_flags = 0x%016lx\n", __FILE__, __func__, __LINE__, static_flags);
	const uint64_t kind = (static_flags & FI_TAGGED) ? 0 : 1;

	FI_DBG(fi_opa1x_global.prov, FI_LOG_EP_DATA, "\n");

	if (unlikely (opcode < FI_OPA1X_HFI_BTH_OPCODE_MSG_INJECT)) {

		FI_DBG(fi_opa1x_global.prov, FI_LOG_EP_DATA, "\n");

		if (opcode == FI_OPA1X_HFI_BTH_OPCODE_RZV_CTS) {

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"===================================== RECV -- RENDEZVOUS CTS (begin)\n");

			assert(payload != NULL);
			const struct fi_opa1x_hfi1_dput_iov * const dput_iov = payload->cts.iov;
			const uint8_t u8_rx = hdr->cts.origin_rx;
			const uint32_t niov = hdr->cts.niov;
			const uintptr_t target_byte_counter_vaddr = hdr->cts.target_byte_counter_vaddr;
			uint64_t * origin_byte_counter = (uint64_t *)hdr->cts.origin_byte_counter_vaddr;

			FI_OPA1X_FABRIC_RX_RZV_CTS(ep, (const void * const) hdr, (const void * const) payload,
				u8_rx, niov, dput_iov, target_byte_counter_vaddr, origin_byte_counter,
				is_intranode,	/* compile-time constant expression */
				reliability);	/* compile-time constant expression */

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"===================================== RECV -- RENDEZVOUS CTS (end)\n");


		} else if (opcode == FI_OPA1X_HFI_BTH_OPCODE_RZV_DATA) {

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"===================================== RECV -- RENDEZVOUS DATA (begin)\n");

			assert(payload != NULL);

			uint64_t * const target_byte_counter_vaddr = (uint64_t *)hdr->dput.target_byte_counter_vaddr;
			uint64_t * rbuf_qws = (uint64_t *)hdr->dput.rbuf;
			const uint64_t * sbuf_qws = (uint64_t *)&payload->byte[0];
			const uint32_t bytes = hdr->dput.bytes;

			assert((bytes & 0x03Fu) == 0);			/* only full blocks are supported */
			assert(bytes <= FI_OPA1X_HFI1_PACKET_MTU);

			uint32_t n, blocks = bytes >> 6;
			for (n=0; n<blocks; ++n) {
				rbuf_qws[0] = sbuf_qws[0];
				rbuf_qws[1] = sbuf_qws[1];
				rbuf_qws[2] = sbuf_qws[2];
				rbuf_qws[3] = sbuf_qws[3];
				rbuf_qws[4] = sbuf_qws[4];
				rbuf_qws[5] = sbuf_qws[5];
				rbuf_qws[6] = sbuf_qws[6];
				rbuf_qws[7] = sbuf_qws[7];

				rbuf_qws += 8;
				sbuf_qws += 8;
			}

			const uint64_t value = *target_byte_counter_vaddr;
			*target_byte_counter_vaddr = value - bytes;

			FI_DBG(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"target_byte_counter_vaddr = %p, %lu -> %lu\n",
				target_byte_counter_vaddr, value, value - bytes);

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"===================================== RECV -- RENDEZVOUS DATA (end)\n");

		} else if (opcode == FI_OPA1X_HFI_BTH_OPCODE_ACK) {
			FI_WARN(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"unimplemented opcode (%u); abort\n", opcode);
			abort();
		} else if (opcode == FI_OPA1X_HFI_BTH_OPCODE_RMA) {
			FI_WARN(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"unimplemented opcode (%u); abort\n", opcode);
			abort();
		} else if (opcode == FI_OPA1X_HFI_BTH_OPCODE_ATOMIC) {
			FI_WARN(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"unimplemented opcode (%u); abort\n", opcode);
			abort();
		} else {
			FI_WARN(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"unimplemented opcode (%u); abort\n", opcode);
			abort();
		}

		return;
	}

//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	assert(opcode >= FI_OPA1X_HFI_BTH_OPCODE_MSG_INJECT);

	/* search the match queue */
	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA, "search the match queue\n");

//	struct slist * list = &rx->queue[kind].mq;
//	union fi_opa1x_context * context = container_of(list->head, union fi_opa1x_context, entry);
//	struct slist_entry * prev = NULL;

	union fi_opa1x_context * context = opa1x_ep->rx.queue[kind].mq.head;
	union fi_opa1x_context * prev = NULL;

//fprintf(stderr, "%s:%s():%d rx->queue[kind].mq = { %p, %p }, context = %p\n", __FILE__, __func__, __LINE__, list->head, list->tail, context);
	while (likely(context != NULL)) {
		FI_DBG(fi_opa1x_global.prov, FI_LOG_EP_DATA, "context = %p\n", context);

		const uint64_t rx_op_flags = context->flags;

		if (is_match(hdr, context)) {

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA, "found a match\n");

			if (likely((static_flags & FI_TAGGED) ||	/* branch will compile out for tag */
					((rx_op_flags | FI_MULTI_RECV) == 0))) {

//fprintf(stderr, "%s:%s():%d prev = %p, context->entry.next = %p\n", __FILE__, __func__, __LINE__, prev, context->entry.next);
				/* remove context from match queue */
#if 0
				if (list->head == list->tail) {
					list->head = list->tail = NULL;
				} else if (prev) {

				} else {

					/* remove first element from multi-element list */

				}
#endif

//fprintf(stderr, "%s:%s():%d ----- remove from match queue, rx->queue[kind].mq { %p, %p }, context = %p\n", __FILE__, __func__, __LINE__, rx->queue[kind].mq.head, rx->queue[kind].mq.tail, context);
				if (prev)
					prev->next = context->next;
				else
					opa1x_ep->rx.queue[kind].mq.head = context->next;

				if (context->next == NULL)
					opa1x_ep->rx.queue[kind].mq.tail = prev;

				context->next = NULL;
//fprintf(stderr, "%s:%s():%d            >> new match queue, rx->queue[kind].mq { %p, %p }, context = %p\n", __FILE__, __func__, __LINE__, rx->queue[kind].mq.head, rx->queue[kind].mq.tail, context);


//fprintf(stderr, "%s:%s():%d REMOVED FROM MATCH QUEUE --- rx->queue[kind].mq.head = %p, rx->queue[kind].mq.tail = %p\n", __FILE__, __func__, __LINE__, rx->queue[kind].mq.head, rx->queue[kind].mq.tail);


				const uint64_t is_context_ext = rx_op_flags & FI_OPA1X_CQ_CONTEXT_EXT;

//fprintf(stderr, "%s:%s():%d payload = %p\n", __FILE__, __func__, __LINE__, payload);
				complete_receive_operation(ep, hdr, payload,
					hdr->match.ofi_tag, context, opcode,
					is_context_ext,
					0,	/* is_multi_receive */
					is_intranode,
					lock_required,
					reliability);

//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
				return;

			} else {

//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
				/*
				 * verify that there is enough space available in
				 * the multi-receive buffer for the incoming data
				 */
				const uint64_t recv_len = context->len;
				const uint64_t send_len = fi_opa1x_hfi1_packet_hdr_message_length(hdr);

				if (send_len > recv_len) {

					/*
					 * there is not enough space available in
					 * the multi-receive buffer; continue as
					 * if "a match was not found" and advance
					 * to the next match entry
					 */
					//prev = &context->entry;
					//context = container_of(context->entry.next, union fi_opa1x_context, entry);
					prev = context;
					context = context->next;

				} else {

//fprintf(stderr, "%s:%s():%d payload = %p\n", __FILE__, __func__, __LINE__, payload);
					complete_receive_operation(ep, hdr, payload,
						0, context, opcode,
						0,	/* is_context_ext */
						1,	/* is_multi_receive */
						is_intranode,
						lock_required,
						reliability);

					if (recv_len < opa1x_ep->rx.min_multi_recv) {

						/* after processing this message there is not
						 * enough space available in the multi-receive
						 * buffer to receive the next message; post a
						 * 'FI_MULTI_RECV' event to the completion
						 * queue and return. */

						/* remove context from match queue */
						if (prev)
							prev->next = context->next;
						else
							opa1x_ep->rx.queue[kind].mq.head = context->next;

						if (context->next == NULL)
							opa1x_ep->rx.queue[kind].mq.tail = NULL;

						/* post a completion event for the multi-receive */
						context->byte_counter = 0;

						if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
						fi_opa1x_context_slist_insert_tail(context, opa1x_ep->rx.cq_completed_ptr);
					}
				}

				return;
			}

		} else {

			prev = context;
			context = context->next;
//			prev = &context->entry;
//			context = container_of(context->entry.next, union fi_opa1x_context, entry);
		}
	}

	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"did not find a match .. add this packet to the unexpected queue\n");

	/* reported in LRH as the number of 4-byte words in the packet; header + payload */
//	size_t total_bytes_to_copy = ((size_t)ntohs(hdr->stl.lrh.pktlen)) * 4;

	if (static_flags & FI_MSG)
		fi_opa1x_ep_rx_append_ue_msg(&opa1x_ep->rx, hdr, payload, payload_bytes);
	else if (static_flags & FI_TAGGED)
		fi_opa1x_ep_rx_append_ue_tag(&opa1x_ep->rx, hdr, payload, payload_bytes);
	else
		abort();

#if 0
	struct slist * ue_free_pool = &rx->ue_free_pool;
	if (unlikely(slist_empty(ue_free_pool))) {
//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

		/*
		 * the unexpected packet free list is empty - allocate
		 * another block of unexpected packets
		 */
		struct fi_opa1x_hfi1_ue_packet * block = NULL;

		int i, rc __attribute__ ((unused));
		rc = posix_memalign((void **)&block, 32,
			sizeof(struct fi_opa1x_hfi1_ue_packet) *
			FI_OPA1X_EP_RX_UEPKT_BLOCKSIZE);
		assert(rc==0);

		for (i=0; i<FI_OPA1X_EP_RX_UEPKT_BLOCKSIZE; ++i)
			slist_insert_tail(&block[i].entry, ue_free_pool);
	}
//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

	/* pop the free list, copy the packet, and add to the unexpected queue */
	struct fi_opa1x_hfi1_ue_packet *uepkt =
		container_of(slist_remove_head(ue_free_pool), struct fi_opa1x_hfi1_ue_packet, entry);

	/* reported in LRH as the number of 4-byte words in the packet; header + payload */
	size_t total_bytes_to_copy = ((size_t)ntohs(hdr->stl.lrh.pktlen)) * 4;

	memcpy((void *)&uepkt->hdr, (const void *)hdr, sizeof(union fi_opa1x_hfi1_packet_hdr));

//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	if (payload != NULL)
		memcpy((void *)&uepkt->payload.byte[0],
			payload,
			total_bytes_to_copy - sizeof(union fi_opa1x_hfi1_packet_hdr));

//fprintf(stderr, "%s:%s():%d Add to unexpected queue: rx->queue[kind].ue = { %p, %p }, uepkt = %p\n", __FILE__, __func__, __LINE__, rx->queue[kind].ue.head, rx->queue[kind].ue.tail, uepkt);
	uepkt->entry.next = NULL;
	slist_insert_tail(&uepkt->entry,  &rx->queue[kind].ue);
//fprintf(stderr, "%s:%s():%d                          rx->queue[kind].ue = { %p, %p }, uepkt = %p\n", __FILE__, __func__, __LINE__, rx->queue[kind].ue.head, rx->queue[kind].ue.tail, uepkt);
//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
#endif
	return;
}






#include "rdma/opa1x/fi_opa1x_fabric_progress.h"


static inline void fi_opa1x_ep_rx_poll (struct fid_ep *ep,
		const uint64_t caps,
		const enum ofi_reliability_kind reliability) {

	if (reliability == OFI_RELIABILITY_KIND_RUNTIME) {			/* constant compile-time expression */

		struct fi_opa1x_ep * opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);
		const enum ofi_reliability_kind kind = opa1x_ep->reliability_state.kind;

		if ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) != 0) {

			if (kind == OFI_RELIABILITY_KIND_NONE) {
				FI_OPA1X_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_NONE);
			} else if (kind == OFI_RELIABILITY_KIND_ONLOAD) {
				FI_OPA1X_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_ONLOAD);
			} else {
				FI_OPA1X_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_OFFLOAD);
			}

		} else {
			const uint64_t rx_caps = opa1x_ep->rx.caps & (FI_LOCAL_COMM | FI_REMOTE_COMM);

			if (kind == OFI_RELIABILITY_KIND_NONE) {
				FI_OPA1X_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_NONE);
			} else if (kind == OFI_RELIABILITY_KIND_ONLOAD) {
				FI_OPA1X_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_ONLOAD);
			} else {
				FI_OPA1X_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_OFFLOAD);
			}
		}

	} else if ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == 0) {		/* constant compile-time expression */

		struct fi_opa1x_ep * opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);
		const uint64_t rx_caps = opa1x_ep->rx.caps & (FI_LOCAL_COMM | FI_REMOTE_COMM);
		FI_OPA1X_FABRIC_POLL_MANY(ep, 0, rx_caps, reliability);

	} else {
		FI_OPA1X_FABRIC_POLL_MANY(ep, 0, caps, reliability);
	}
}


/* rx_op_flags is only checked for FI_PEEK | FI_CLAIM | FI_MULTI_RECV
 * rx_op_flags is only used if FI_PEEK | FI_CLAIM | cancel_context
 * is_context_ext is only used if FI_PEEK | cancel_context | iovec
 *
 * The "normal" data movement functions, such as fi_[t]recv(), can safely
 * specify '0' for cancel_context, rx_op_flags, and is_context_ext, in
 * order to reduce code path.
 *
 * TODO - use payload pointer? keep data in hfi eager buffer as long
 * as possible to avoid memcpy?
 */
int fi_opa1x_ep_rx_process_context (struct fi_opa1x_ep * opa1x_ep,
		const uint64_t static_flags,
		const uint64_t cancel_context, union fi_opa1x_context * context,
		const uint64_t rx_op_flags, const uint64_t is_context_ext,
		const int lock_required, const enum fi_av_type av_type,
		const enum ofi_reliability_kind reliability);



/*
 * =========================== Application-facing ===========================
 */

static inline
ssize_t fi_opa1x_ep_rx_recv (struct fi_opa1x_ep *opa1x_ep,
	       	void *buf, size_t len, void *desc,
		fi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context,
		const int lock_required, const enum fi_av_type av_type,
		const uint64_t static_flags,
		const enum ofi_reliability_kind reliability)
{
//fprintf(stderr, "%s:%s():%d static_flags = 0x%016lx\n", __FILE__, __func__, __LINE__, static_flags);
	assert(((static_flags & (FI_TAGGED | FI_MSG)) == FI_TAGGED) ||
		((static_flags & (FI_TAGGED | FI_MSG)) == FI_MSG));

	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"posting receive: context = %p\n", context);

	const uint64_t rx_op_flags = opa1x_ep->rx.op_flags;
	uint64_t rx_caps = opa1x_ep->rx.caps;

	assert(context);
	assert(((uintptr_t)context & 0x07ull) == 0);	/* must be 8 byte aligned */
	union fi_opa1x_context * opa1x_context = (union fi_opa1x_context *)context;
	opa1x_context->flags = rx_op_flags;
	opa1x_context->len = len;
	opa1x_context->buf = buf;

	if (rx_caps & FI_DIRECTED_RECV) {
		if (av_type == FI_AV_TABLE) {		/* constand compile-time expression */
			if (likely(src_addr != FI_ADDR_UNSPEC)) {
				opa1x_context->src_addr = opa1x_ep->rx.av_addr[src_addr].fi;
			} else {
				opa1x_context->src_addr = FI_ADDR_UNSPEC;
			}
		} else {
			opa1x_context->src_addr = src_addr;
		}
	} else {
		opa1x_context->src_addr = FI_ADDR_UNSPEC;
	}

#ifdef FI_OPA1X_TRACE
	fprintf(stderr,"fi_opa1x_recv_generic from source addr:\n");
	FI_OPA1X_ADDR_DUMP(&opa1x_context->src_addr);
#endif

	opa1x_context->tag = tag;
	opa1x_context->ignore = ignore;
	opa1x_context->byte_counter = (uint64_t)-1;

	if (IS_PROGRESS_MANUAL(opa1x_ep->domain)) {

		if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"process context (check unexpected queue, append match queue)\n");

		fi_opa1x_ep_rx_process_context(opa1x_ep, static_flags, 0, context, 0, 0, lock_required, av_type, reliability);

	} else {

		FI_WARN(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"FI_PROGRESS_AUTO is not implemented; abort\n");
		abort();
	}

	return 0;
}

/*
 * \note The opa1x provider asserts the following mode bits which affect
 * 	the behavior of this routine:
 *
 * 	- 'FI_ASYNC_IOV' mode bit which requires the application to maintain
 * 	  the 'msg->msg_iov' iovec array until the operation completes
 *
 * 	- 'FI_LOCAL_MR' mode bit which allows the provider to ignore the 'desc'
 * 	  parameter .. no memory regions are required to access the local
 * 	  memory
 */
static inline
ssize_t fi_opa1x_ep_rx_recvmsg (struct fi_opa1x_ep *opa1x_ep,
		const struct fi_msg *msg, uint64_t flags,
		const int lock_required, const enum fi_av_type av_type,
		const enum ofi_reliability_kind reliability)
{
//	fprintf(stderr, "%s:%s():%d rx = %p\n", __FILE__, __func__, __LINE__, rx);
	uint64_t context_rsh3b = 0;
	uint64_t rx_op_flags = 0;

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	if (flags | FI_MULTI_RECV) {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

		assert(msg->context);
		assert(((uintptr_t)msg->context & 0x07ull) == 0);	/* must be 8 byte aligned */
		union fi_opa1x_context * opa1x_context =
			(union fi_opa1x_context *) msg->context;

		uint64_t len = msg->msg_iov[0].iov_len;
		void * base = msg->msg_iov[0].iov_base;

		assert(msg->iov_count == 1);
		assert(base != NULL);
		if ((uintptr_t)base & 0x07ull) {
			uintptr_t new_base = (((uintptr_t)base + 8) & (~0x07ull));
			len -= (new_base - (uintptr_t)base);
			base = (void *)new_base;
		}
		assert(((uintptr_t)base & 0x07ull) == 0);
		assert(len >= (sizeof(union fi_opa1x_context) + opa1x_ep->rx.min_multi_recv));
		opa1x_context->flags = FI_MULTI_RECV;
		opa1x_context->len = len - sizeof(union fi_opa1x_context);
		opa1x_context->buf = (void *)((uintptr_t)base + sizeof(union fi_opa1x_context));

		if (av_type == FI_AV_TABLE) {	/* constant compile-time expression */
			const fi_addr_t msg_addr = msg->addr;
			opa1x_context->src_addr =
				(likely(msg_addr != FI_ADDR_UNSPEC)) ?
					opa1x_ep->rx.av_addr[msg_addr].fi :
					(fi_addr_t)-1;
		} else {
			opa1x_context->src_addr = msg->addr;
		}
		opa1x_context->byte_counter = 0;
		opa1x_context->multi_recv_next = (union fi_opa1x_context *)base;
		opa1x_context->ignore = (uint64_t)-1;

		context_rsh3b = (uint64_t)opa1x_context >> 3;
		rx_op_flags = flags;

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	} else if (msg->iov_count == 0) {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

		assert(msg->context);
		assert(((uintptr_t)msg->context & 0x07ull) == 0);	/* must be 8 byte aligned */

		union fi_opa1x_context * opa1x_context =
			(union fi_opa1x_context *) msg->context;
		opa1x_context->flags = flags;
		opa1x_context->len = 0;
		opa1x_context->buf = NULL;

		if (av_type == FI_AV_TABLE) {	/* constant compile-time expression */
			const fi_addr_t msg_addr = msg->addr;
			opa1x_context->src_addr =
				(likely(msg_addr != FI_ADDR_UNSPEC)) ?
					opa1x_ep->rx.av_addr[msg_addr].fi :
					(fi_addr_t)-1;
		} else {
			opa1x_context->src_addr = msg->addr;
		}
		opa1x_context->tag = 0;
		opa1x_context->ignore = (uint64_t)-1;
		opa1x_context->byte_counter = (uint64_t)-1;

		context_rsh3b = (uint64_t)opa1x_context >> 3;
		rx_op_flags = flags;

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	} else if (msg->iov_count == 1) {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
		assert(msg->context);
		assert(((uintptr_t)msg->context & 0x07ull) == 0);	/* must be 8 byte aligned */

		union fi_opa1x_context * opa1x_context =
			(union fi_opa1x_context *) msg->context;
		opa1x_context->flags = flags;
		opa1x_context->len = msg->msg_iov[0].iov_len;
		opa1x_context->buf = msg->msg_iov[0].iov_base;

		if (av_type == FI_AV_TABLE) {	/* constand compile-time expression */
			const fi_addr_t msg_addr = msg->addr;
			opa1x_context->src_addr =
				(likely(msg_addr != FI_ADDR_UNSPEC)) ?
					opa1x_ep->rx.av_addr[msg_addr].fi :
					(fi_addr_t)-1;
		} else {
			opa1x_context->src_addr = msg->addr;
		}
		opa1x_context->tag = 0;
		opa1x_context->ignore = (uint64_t)-1;
		opa1x_context->byte_counter = (uint64_t)-1;

		context_rsh3b = (uint64_t)opa1x_context >> 3;
		rx_op_flags = flags;

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	} else {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
		struct fi_opa1x_context_ext * ext;
		posix_memalign((void**)&ext, 32, sizeof(struct fi_opa1x_context_ext));

		ext->opa1x_context.flags = flags | FI_OPA1X_CQ_CONTEXT_EXT;
		ext->opa1x_context.byte_counter = (uint64_t)-1;

		if (av_type == FI_AV_TABLE) {	/* constant compile-time expression */
			const fi_addr_t msg_addr = msg->addr;
			ext->opa1x_context.src_addr =
				(likely(msg_addr != FI_ADDR_UNSPEC)) ?
					opa1x_ep->rx.av_addr[msg_addr].fi :
					(fi_addr_t)-1;
		} else {
			ext->opa1x_context.src_addr = msg->addr;
		}
		ext->opa1x_context.tag = 0;
		ext->opa1x_context.ignore = (uint64_t)-1;
		ext->msg.op_context = (struct fi_context *)msg->context;
		ext->msg.iov_count = msg->iov_count;
		ext->msg.iov = (struct iovec *)msg->msg_iov;

		context_rsh3b = (uint64_t)ext >> 3;
		rx_op_flags = flags | FI_OPA1X_CQ_CONTEXT_EXT;
		if (IS_PROGRESS_MANUAL(opa1x_ep->rx.domain)) {

			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }

			fi_opa1x_ep_rx_process_context(opa1x_ep,
				FI_MSG,
				0,  /* cancel_context */
				(union fi_opa1x_context *)(context_rsh3b << 3),
				rx_op_flags,
				1,  /* is_context_ext */
				lock_required,
				av_type,
				reliability);

			return 0;
		}
	//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	}
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

	if (IS_PROGRESS_MANUAL(opa1x_ep->rx.domain)) {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

		if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
		fi_opa1x_ep_rx_process_context(opa1x_ep,
			FI_MSG,
			0,  /* cancel_context */
			(union fi_opa1x_context *)(context_rsh3b << 3),
			rx_op_flags,
			0,  /* is_context_ext */
			lock_required,
			av_type,
			reliability);
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	} else {
		abort();
#if 0
		/* the *only* difference between a 'tagged' and 'non-tagged' recv is
		 * the L2 atomic fifo used to post the receive information */
		struct l2atomic_fifo_producer * fifo = &opa1x_ep->rx.post.match[1];	/* TODO - use enum */

		while (l2atomic_fifo_produce(fifo, context_rsh3b) != 0);		/* spin loop! */
#endif
	}
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

	return 0;
}

static inline
ssize_t fi_opa1x_ep_tx_inject (struct fid_ep *ep,
		const void *buf,
		size_t len,
		fi_addr_t dest_addr,
		uint64_t tag,
		const uint32_t data,
		const int lock_required,
		const enum fi_av_type av_type,
		const uint64_t caps,
		const enum ofi_reliability_kind reliability)
{
	assert(len <= FI_OPA1X_HFI1_PACKET_IMM);

	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"===================================== INJECT (begin)\n");

	struct fi_opa1x_ep *opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);

#ifndef NDEBUG
	ssize_t ret;
	ret = fi_opa1x_ep_tx_check(&opa1x_ep->tx, av_type);
	if (ret) return ret;
#endif
	assert(dest_addr != FI_ADDR_UNSPEC);

	const union fi_opa1x_addr addr = {
		.fi = (av_type == FI_AV_TABLE) ?	/* constant compile-time expression */
			opa1x_ep->tx.av_addr[dest_addr].fi :
			dest_addr
	};

	const ssize_t rc = FI_OPA1X_FABRIC_TX_INJECT(ep, buf, len, addr.fi, tag, data,
			lock_required, addr.hfi1_rx, caps, reliability);

	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"===================================== INJECT (end)\n");

	return rc;
}


static inline
ssize_t fi_opa1x_ep_tx_send (struct fid_ep *ep,
		const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, uint64_t tag, void *context,
		const uint32_t data,
		const int lock_required,
		const enum fi_av_type av_type,
		const unsigned is_contiguous,
		const unsigned override_flags,
		uint64_t tx_op_flags,
		const uint64_t caps,
		const enum ofi_reliability_kind reliability)
{
	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"===================================== SEND (begin)\n");

	assert(is_contiguous == 0 || is_contiguous == 1);

	struct fi_opa1x_ep *opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);

#ifndef NDEBUG
	ssize_t ret;
	ret = fi_opa1x_ep_tx_check(&opa1x_ep->tx, av_type);
	if (ret) return ret;
#endif

	assert(dest_addr != FI_ADDR_UNSPEC);

	const union fi_opa1x_addr addr = {
		.fi = (av_type == FI_AV_TABLE) ?	/* constant compile-time expression */
			opa1x_ep->tx.av_addr[dest_addr].fi :
			dest_addr
	};

	ssize_t rc = 0;
	if (likely(len <= FI_OPA1X_HFI1_PACKET_MTU)) {

		rc = FI_OPA1X_FABRIC_TX_SEND_EGR(ep, buf, len,
			desc, addr.fi, tag, context, data,
			lock_required, is_contiguous,
			override_flags, tx_op_flags, addr.hfi1_rx,
			caps, reliability);

		/*
		 * ==== NOTE_SELECTIVE_COMPLETION ====
		 *
		 * FI_SELECTIVE_COMPLETION essentially changes the default from:
		 *
		 *   "generate a completion of some kind if FI_TRANSMIT is
		 *   also specified"
		 *
		 * to
		 *
		 *   "only generate a completion of some kind if FI_TRANSMIT
		 *   and FI_COMPLETION are also specified".
		 *
		 * and as specified in commit 8bf9bf74b719f265186a7dea1c1e1f26a24bfb5a:
		 *
		 *   "FI_COMPLETION is only needed in cases where an endpoint was
		 *   bound to a CQ or counter with the FI_SELECTIVE_COMPLETION flag."
		 */

		const uint64_t selective_completion =
			FI_SELECTIVE_COMPLETION | FI_TRANSMIT | FI_COMPLETION;

		const uint64_t do_cq_completion = override_flags == 0 ?
			opa1x_ep->tx.do_cq_completion :		/* calculated at bind */
			((((tx_op_flags | opa1x_ep->tx.cq_bind_flags) & selective_completion) == selective_completion) ||
			 (((tx_op_flags | opa1x_ep->tx.cq_bind_flags) & (FI_SELECTIVE_COMPLETION | FI_TRANSMIT)) == FI_TRANSMIT));


		/*
		 * ==== NOTE_COMPLETION_TYPES ====
		 *
		 * FI_INJECT_COMPLETE generates the completion entry when the
		 * source buffer can be reused. This can be immedately done if
		 * the entire source buffer is copied into the reliability
		 * replay buffer(s). Otherwise the completion should not be
		 * generated until the reliability protocol completes.
		 *
		 * FI_TRANSMIT_COMPLETE completion entry should only be generated
		 * when "the operation is no longer dependent on local resources".
		 * Does this means that it should be delivered only when the
		 * reliability protocol has completed? If so, then the completion
		 * may be delayed significantly, or the reliability protocol
		 * needs to be enhanced for the target to do an 'immediate ack'
		 * when this packet is received. Regardless, MPICH only uses
		 * this completion type when performing a 'dynamic process
		 * disconnect' so it is not critical for this completion type
		 * to have good performance at this time.
		 *
		 * FI_DELIVERY_COMPLETE is not supposed to generate a completion
		 * event until the send has been "processed by the destination
		 * endpoint(s)". The reliability protocol has nothing to do with
		 * that acknowledgement.
		 *
		 * If a completion type is not specified, but a completion is
		 * required to be generated, then the completion type is
		 * provider-specific? If so, default to FI_INJECT_COMPLETE.
		 *
		 * TODO - Integrate reliability protocol completions with
		 * FI_TRANSMIT_COMPLETE operations. Without it FI_TRANSMIT_COMPLETE
		 * will behave identical to FI_INJECT_COMPLETE.
		 *
		 * TODO - Implement the remote ack for FI_DELIVERY_COMPLETE.
		 * Without it FI_DELIVERY_COMPLETE will behave identical to
		 * FI_INJECT_COMPLETE.
		 */

		if (likely(do_cq_completion != 0) && rc == FI_SUCCESS) {

			/*
			 * Currently all completion types revert to the behavior
			 * of FI_INJECT_COMPLETE until additional features are
			 * implemented.
			 *
			 * See NOTE_COMPLETION_TYPES for more information.
			 */

			/* initialize the completion entry */
			assert(context);
			assert(((uintptr_t)context & 0x07ull) == 0);	/* must be 8 byte aligned */
			union fi_opa1x_context * opa1x_context = (union fi_opa1x_context *)context;
			opa1x_context->flags =  FI_SEND | (caps & (FI_TAGGED | FI_MSG));
			opa1x_context->len = len;
			opa1x_context->buf = NULL;
			opa1x_context->byte_counter = len;
			opa1x_context->tag = tag;
			opa1x_context->next = NULL;

			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail(opa1x_context, opa1x_ep->tx.cq_completed_ptr);
		}

	} else {

		/* See NOTE_SELECTIVE_COMPLETION for more information */
		const uint64_t selective_completion =
			FI_SELECTIVE_COMPLETION | FI_TRANSMIT | FI_COMPLETION;

		const uint64_t do_cq_completion = override_flags == 0 ?
			opa1x_ep->tx.do_cq_completion :		/* calculated at bind */
			((((tx_op_flags | opa1x_ep->tx.cq_bind_flags) & selective_completion) == selective_completion) ||
			 (((tx_op_flags | opa1x_ep->tx.cq_bind_flags) & (FI_SELECTIVE_COMPLETION | FI_TRANSMIT)) == FI_TRANSMIT));


		if (likely(do_cq_completion != 0)) {

			assert(context);
			assert(((uintptr_t)context & 0x07ull) == 0);	/* must be 8 byte aligned */
			union fi_opa1x_context * opa1x_context = (union fi_opa1x_context *)context;

			rc = FI_OPA1X_FABRIC_TX_SEND_RZV(ep,
				buf, len, desc, addr.fi, tag,
				context, data, lock_required,
				is_contiguous,
				override_flags, tx_op_flags,
				addr.hfi1_rx,
				(uintptr_t)&opa1x_context->byte_counter,
				(uint64_t *)&opa1x_context->byte_counter,
				caps,
				reliability);

			if(rc != FI_SUCCESS) {
				fprintf(stderr, "FATAL:	 rendezvous protocol isn't properly handling EAGAIN\n");
				fprintf(stderr, " This will cause the application to re-enqueue the operation, causing a double post.  Aborting application\n");
				abort();
			}

			/* initialize the completion entry */
			opa1x_context->flags =  FI_SEND | (caps & (FI_TAGGED | FI_MSG));
			opa1x_context->len = len;
			opa1x_context->buf = NULL;
			opa1x_context->tag = tag;
			opa1x_context->next = NULL;

			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opa1x_context_slist_insert_tail(opa1x_context, opa1x_ep->tx.cq_pending_ptr);

		} else {
			uint64_t tmp;
			rc = FI_OPA1X_FABRIC_TX_SEND_RZV(ep,
				buf, len, desc, addr.fi, tag, context,
				data, lock_required,
				is_contiguous, override_flags,
				tx_op_flags, addr.hfi1_rx,
				(uintptr_t)NULL, &tmp,
				caps,
				reliability);
		}
	}


	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"===================================== SEND (end)\n");

	return rc;
}







static inline
ssize_t fi_opa1x_recv_generic(struct fid_ep *ep,
	       	void *buf, size_t len, void *desc,
		fi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context,
		const int lock_required, const enum fi_av_type av_type,
		const uint64_t static_flags,
		const enum ofi_reliability_kind reliability)
{
	struct fi_opa1x_ep *opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);

	return fi_opa1x_ep_rx_recv(opa1x_ep, buf, len, desc, src_addr, tag,
			ignore, context, lock_required, av_type, static_flags,
			reliability);
}

static inline
ssize_t fi_opa1x_recvmsg_generic(struct fid_ep *ep,
		const struct fi_msg *msg, uint64_t flags,
		const int lock_required, const enum fi_av_type av_type,
		const enum ofi_reliability_kind reliability)
{
	struct fi_opa1x_ep *opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);

//	fprintf(stderr, "%s:%s():%d ep = %p, opa1x_ep = %p, &opa1x_ep->rx = %p\n", __FILE__, __func__, __LINE__, ep, opa1x_ep, &opa1x_ep->rx);
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, rx) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, rx));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx));
//printf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.pio_state) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.pio_state));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.pio_scb_first) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.pio_scb_first));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.trzv) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.trzv));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.op_flags) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.op_flags));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.exclusive_stx) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.exclusive_stx));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.exclusive_stx.hfi) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.exclusive_stx.hfi));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.exclusive_stx.rxe_state) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.exclusive_stx.rxe_state));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.exclusive_stx.ref_cnt) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.exclusive_stx.ref_cnt));
//fprintf(stderr, "%s:%s():%d offsetof(struct fi_opa1x_ep, tx.lock) = %zu\n", __FILE__, __func__, __LINE__, offsetof(struct fi_opa1x_ep, tx.lock));

//fprintf(stderr, "%s:%s():%d sizeof(ofi_atomic32_t) = %zu\n", __FILE__, __func__, __LINE__, sizeof(ofi_atomic32_t));
//fprintf(stderr, "%s:%s():%d sizeof(struct fi_opa1x_ep_tx) = %zu\n", __FILE__, __func__, __LINE__, sizeof(struct fi_opa1x_ep_tx));

	return fi_opa1x_ep_rx_recvmsg(opa1x_ep, msg, flags, lock_required, av_type, reliability);
}


#endif /* _FI_PROV_OPA1X_ENDPOINT_H_ */
