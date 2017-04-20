/*
 * Copyright (C) 2016 by Argonne National Laboratory.
 * Copyright (C) 2021 Cornelis Networks.
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
#ifndef _FI_PROV_OPX_ENDPOINT_H_
#define _FI_PROV_OPX_ENDPOINT_H_

#include <stdint.h>
#include <pthread.h>
#include <sys/uio.h>

#include "rdma/opx/fi_opx_domain.h"

#include "rdma/opx/fi_opx_internal.h"
#include "rdma/opx/fi_opx.h"
#include "rdma/opx/fi_opx_compiler.h"
#include "rdma/opx/fi_opx_hfi1.h"
#include "rdma/opx/fi_opx_reliability.h"
#include "rdma/opx/fi_opx_rma_ops.h"

#include "opx_shm.h"

#include "rdma/opx/fi_opx_addr.h"

//#include "rdma/fi_tagged.h"

void fi_opx_cq_debug(struct fid_cq *cq, char *func, const int line);

#define IS_TAG (0)
#define IS_MSG (1)

// #define FI_OPX_TRACE 1
// #define FI_OPX_REMOTE_COMPLETION

/* #define IS_MATCH_DEBUG */

/* Macro indirection in order to support other macros as arguments
 * C requires another indirection for expanding macros since
 * operands of the token pasting operator are not expanded */

#define FI_OPX_MSG_SPECIALIZED_FUNC(LOCK,AV,CAPS,RELIABILITY)			\
	FI_OPX_MSG_SPECIALIZED_FUNC_(LOCK,AV,CAPS,RELIABILITY)

#define FI_OPX_MSG_SPECIALIZED_FUNC_(LOCK,AV,CAPS,RELIABILITY)		\
	static inline ssize_t							\
	fi_opx_send_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const void *buf, size_t len,		\
			void *desc, fi_addr_t dest_addr, void *context)		\
	{									\
		return fi_opx_ep_tx_send(ep, buf, len, desc,			\
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
	fi_opx_recv_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, void *buf, size_t len,			\
			void *desc, fi_addr_t src_addr, void *context)		\
	{									\
		return fi_opx_recv_generic(ep, buf, len, desc,			\
				src_addr, 0, (uint64_t)-1, context,		\
				LOCK, AV, FI_MSG, RELIABILITY);			\
	}									\
	static inline ssize_t							\
	fi_opx_inject_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const void *buf, size_t len,		\
			fi_addr_t dest_addr)					\
	{									\
		return fi_opx_ep_tx_inject(ep, buf, len,			\
				dest_addr, 0, 0,				\
				LOCK,	/* lock_required */			\
				AV,	/* av_type */				\
				CAPS | FI_MSG,					\
				RELIABILITY);					\
	}									\
	static inline ssize_t							\
	fi_opx_recvmsg_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const struct fi_msg *msg,			\
			uint64_t flags)						\
	{									\
		return fi_opx_recvmsg_generic(ep, msg, flags,			\
				LOCK, AV, RELIABILITY);				\
	}									\
	static inline ssize_t							\
	fi_opx_senddata_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const void *buf, size_t len,		\
			void *desc, uint64_t data, fi_addr_t dest_addr,		\
			void *context)						\
	{									\
		return fi_opx_ep_tx_send(ep, buf, len, desc,			\
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
	fi_opx_injectdata_ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY	\
		(struct fid_ep *ep, const void *buf, size_t len,		\
			uint64_t data, fi_addr_t dest_addr)			\
	{									\
		return fi_opx_ep_tx_inject(ep, buf, len,			\
				dest_addr, 0, data,				\
				LOCK,	/* lock_required */			\
				AV,	/* av_type */				\
				CAPS | FI_MSG,					\
				RELIABILITY);					\
	}

#define FI_OPX_MSG_SPECIALIZED_FUNC_NAME(TYPE, LOCK, AV, CAPS, RELIABILITY)	\
	FI_OPX_MSG_SPECIALIZED_FUNC_NAME_(TYPE, LOCK, AV, CAPS, RELIABILITY)

#define FI_OPX_MSG_SPECIALIZED_FUNC_NAME_(TYPE, LOCK, AV, CAPS, RELIABILITY)	\
		fi_opx_ ## TYPE ## _ ## LOCK ## _ ## AV ## _ ## CAPS ## _ ## RELIABILITY




enum fi_opx_ep_state {
	FI_OPX_EP_UNINITIALIZED = 0,
	FI_OPX_EP_INITITALIZED_DISABLED,
	FI_OPX_EP_INITITALIZED_ENABLED
};

struct fi_opx_stx {

	/* == CACHE LINE 0,1,2 == */

	struct fid_stx				stx_fid;	/* 80 bytes */
	struct fi_opx_domain *		domain;
	struct fi_tx_attr			attr;		/* 72 bytes */
	struct fi_opx_hfi1_context *		hfi;
	uint64_t				unused_cacheline_2[2];

	/* == CACHE LINE 3 == */

    struct fi_opx_reliability_client_state	reliability_state;	/* 56 bytes */
	struct fi_opx_reliability_service	reliability_service;		/* ONLOAD only */
	uint8_t					reliability_rx;			/* ONLOAD only */

	/* == CACHE LINE 4,5,6 == */

	struct {
		struct fi_opx_hfi1_txe_scb	inject;
		struct fi_opx_hfi1_txe_scb	send;
		struct fi_opx_hfi1_txe_scb	rzv;
	} tx;

	/* == CACHE LINE 7 == */

	struct fi_opx_hfi1_rxe_state		rxe_state;	/* ignored for ofi tx */
	int64_t				ref_cnt;
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
struct fi_opx_ep_tx {

	/* == CACHE LINE 0,1 == */

	volatile union fi_opx_hfi1_pio_state	*pio_state;			/* 1 qw = 8 bytes */
	volatile uint64_t *			pio_scb_sop_first;
	uint64_t				unused_1;

	struct fi_opx_hfi1_txe_scb		inject;				/* qws 5,6, and 7 specified at runtime */

	volatile uint64_t *			pio_credits_addr;		/* const; only used to infrequently "refresh" credit information */
	volatile uint64_t *			pio_scb_first;			/* const; only eager and rendezvous */
	uint64_t				cq_bind_flags;
	struct fi_opx_context_slist *		cq_completed_ptr;
	uint32_t				do_cq_completion;
	uint16_t 				pio_max_eager_tx_bytes;
	uint8_t					force_credit_return;
	uint8_t					unused;

	/* == CACHE LINE 2,3 == */

	struct fi_opx_hfi1_txe_scb		send;
	struct fi_opx_hfi1_txe_scb		rzv;

	/* == CACHE LINE 4 == */

	union fi_opx_addr *			av_addr;			/* only FI_ADDR_TABLE */
	uint64_t				av_count;			/* only FI_ADDR_TABLE */
	uint64_t				op_flags;
	uint64_t				caps;
	uint64_t				mode;
	struct fi_opx_context_slist *		cq_err_ptr;
	struct fi_opx_cq *			cq;
	struct fi_opx_context_slist *		cq_pending_ptr;			/* only rendezvous (typically) */

	/* == CACHE LINE 5, ... == */

	struct opx_shm_tx			shm;
	struct fi_opx_stx *		stx;
	struct fi_opx_stx			exclusive_stx;
	struct slist                work_pending;
	struct ofi_bufpool         *work_pending_pool;
	struct ofi_bufpool         *rma_payload_pool;

    void                       *mem;
    int64_t	ref_cnt;
} __attribute__((__aligned__(L2_CACHE_LINE_SIZE))) __attribute__((__packed__));


struct fi_opx_ep_rx {

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
	union fi_opx_addr *		av_addr;

	/*
	 * NOTE: The following 2 cachelines are shared between the application-facing
	 * functions, such as 'fi_trecv()', and the progress functions, such as
	 * those invoked during 'fi_cq_read()'.
	 */

	/* == CACHE LINE 1 == */

	struct {
		struct fi_opx_context_slist		mq;	/* 2 qws */
		struct fi_opx_hfi1_ue_packet_slist	ue;	/* 2 qws */
	} queue[2];	/* 0 = FI_TAGGED, 1 = FI_MSG */

	/* == CACHE LINE 2 == */

	struct fi_opx_context_slist *			cq_pending_ptr;
	struct fi_opx_context_slist *			cq_completed_ptr;
	struct fi_opx_hfi1_ue_packet_slist		ue_free_pool;		/* 2 qws */

	uint64_t			unused_cacheline_2[4];

	/* == CACHE LINE 3 == */

	/*
	 * NOTE: This cacheline is used when a thread is making PROGRESS to
	 * process fabric events.
	 */
	struct fi_opx_hfi1_rxe_state	state;			/* 2 qws */

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
		struct fi_opx_hfi1_txe_scb	dput;
		struct fi_opx_hfi1_txe_scb	cts;
	} tx;


	/* -- non-critical -- */
	uint64_t			min_multi_recv;
	struct fi_opx_domain *	domain;

	uint64_t			caps;
	uint64_t			mode;
	size_t				total_buffered_recv;	/* TODO - is this only used by receive operations? */
	union fi_opx_addr		self;

	struct fi_opx_context_slist *	cq_err_ptr;
	struct fi_opx_cq *		cq;


	struct opx_shm_rx		shm;
    void *mem;
    int64_t	ref_cnt;
	//fastlock_t			lock;

} __attribute__((__aligned__(L2_CACHE_LINE_SIZE))) __attribute__((__packed__));



struct fi_opx_ep_reliability {
        struct fi_opx_reliability_client_state state;	/* 14 qws = 112 bytes */
        struct fi_opx_reliability_service	service;	/* ONLOAD only */
        uint8_t	rx;			/* ONLOAD only */
        void *mem;
        int64_t	ref_cnt;
};

/*
 * The 'fi_opx_ep' struct defines an endpoint with a single tx context and a
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
struct fi_opx_ep {
	struct fid_ep		ep_fid;
	struct fi_opx_ep_tx	*tx;
	struct fi_opx_ep_rx	*rx;
    struct fi_opx_ep_reliability *reliability;
	struct fi_opx_cntr	*read_cntr;
	struct fi_opx_cntr	*write_cntr;
	struct fi_opx_cntr	*send_cntr;
	struct fi_opx_cntr	*recv_cntr;
	struct fi_opx_domain	*domain;
	struct ofi_bufpool  *rma_counter_pool;
    void			    *mem;

	struct fi_opx_av	*av;
    struct fi_opx_sep *sep;
	struct fi_opx_hfi1_context *	hfi;
    int				 sep_index;


	struct {
		volatile uint64_t	enabled;
		volatile uint64_t	active;
		pthread_t		thread;
	} async;
	enum fi_opx_ep_state	state;

	uint32_t		threading;
	uint32_t		av_type;
	uint32_t		mr_mode;
	enum fi_ep_type		type;
    // Only used for initialization
    // free these flags
    struct fi_info       *common_info;
    struct fi_info       *tx_info;
    struct fi_info       *rx_info;
    uint64_t              cq_bflags;
    struct fi_opx_cq   *init_cq;
    struct fi_opx_cntr *init_read_cntr;
	struct fi_opx_cntr *init_write_cntr;
	struct fi_opx_cntr *init_send_cntr;
	struct fi_opx_cntr *init_recv_cntr;
	bool                is_cq_bound;
	fastlock_t 		lock;

} __attribute((aligned(L2_CACHE_LINE_SIZE)));


/*
 * A 'scalable endpoint' may not be directly specified in a data movement
 * functions, such as fi_tsend(), as it is only a container for multiple
 * tx and rx contexts.
 *
 * The scalable contexts share certain resources, such as the address vector.
 */
struct fi_opx_sep {
	struct fid_ep		ep_fid;

	struct fi_opx_domain	*domain;
	struct fi_opx_av	*av;
	struct fi_info		*info;
	void			*memptr;
    struct fi_opx_ep	*ep[FI_OPX_ADDR_SEP_RX_MAX];
    struct fi_opx_hfi1_context *hfi1[FI_OPX_ADDR_SEP_RX_MAX];
    struct fi_opx_ep_reliability *reliability[FI_OPX_ADDR_SEP_RX_MAX];
    struct fi_opx_ep_tx *tx[FI_OPX_ADDR_SEP_RX_MAX];
    struct fi_opx_ep_rx *rx[FI_OPX_ADDR_SEP_RX_MAX];

        int64_t		ref_cnt;

} __attribute((aligned(L2_CACHE_LINE_SIZE)));


/*
 * =========================== begin: no-inline functions ===========================
 */

__attribute__((noinline))
void fi_opx_ep_rx_process_context_noinline (struct fi_opx_ep * opx_ep,
		const uint64_t static_flags,
		union fi_opx_context * context,
		const uint64_t rx_op_flags, const uint64_t is_context_ext,
		const int lock_required, const enum fi_av_type av_type,
		const enum ofi_reliability_kind reliability);

void fi_opx_ep_rx_process_header_tag (struct fid_ep *ep,
		const union fi_opx_hfi1_packet_hdr * const hdr,
		const uint8_t * const payload,
		const size_t payload_bytes,
		const uint8_t opcode,
		const unsigned is_intranode,
		const int lock_required,
		const enum ofi_reliability_kind reliability);

void fi_opx_ep_rx_process_header_msg (struct fid_ep *ep,
		const union fi_opx_hfi1_packet_hdr * const hdr,
		const uint8_t * const payload,
		const size_t payload_bytes,
		const uint8_t opcode,
		const unsigned is_intranode,
		const int lock_required,
		const enum ofi_reliability_kind reliability);

void fi_opx_ep_rx_reliability_process_packet (struct fid_ep *ep,
		const union fi_opx_hfi1_packet_hdr * const hdr,
		const uint8_t * const payload);

void fi_opx_ep_rx_append_ue_msg (struct fi_opx_ep_rx * const rx,
		const union fi_opx_hfi1_packet_hdr * const hdr,
		const union fi_opx_hfi1_packet_payload * const payload,
		const size_t payload_bytes);

void fi_opx_ep_rx_append_ue_tag (struct fi_opx_ep_rx * const rx,
		const union fi_opx_hfi1_packet_hdr * const hdr,
		const union fi_opx_hfi1_packet_payload * const payload,
		const size_t payload_bytes);

int fi_opx_ep_tx_check (struct fi_opx_ep_tx * tx, enum fi_av_type av_type);

/*
 * =========================== end: no-inline functions ===========================
 */

__OPX_FORCE_INLINE_AND_FLATTEN__
void fi_opx_ep_clear_credit_return(struct fi_opx_ep *opx_ep) {
	if (OFI_UNLIKELY(opx_ep->tx->force_credit_return)) {
		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
					"======================================= Forced a credit return\n");
		opx_ep->tx->force_credit_return = 0;
	}
}

#define FI_OPX_HFI1_CLEAR_CREDIT_RETURN(opx_ep) fi_opx_ep_clear_credit_return(opx_ep)

#include "rdma/opx/fi_opx_fabric_transport.h"

static inline
uint64_t is_match (const union fi_opx_hfi1_packet_hdr * const hdr, union fi_opx_context * context)
{

	const union fi_opx_addr src_addr = { .fi = context->src_addr };

	const fi_opx_uid_t origin_uid_fi = fi_opx_hfi1_packet_hdr_uid(hdr);

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
__OPX_FORCE_INLINE_AND_FLATTEN__
void complete_receive_operation (struct fid_ep *ep,
		const union fi_opx_hfi1_packet_hdr * const hdr,
		const union fi_opx_hfi1_packet_payload * const payload,
		const uint64_t origin_tag,
		union fi_opx_context * context,
		const uint8_t opcode,
		const unsigned is_context_ext,
		const unsigned is_multi_receive,
		const unsigned is_intranode,
		const int lock_required,
		const enum ofi_reliability_kind reliability) {

	struct fi_opx_ep * opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);
	struct fi_opx_ep_rx * const rx = opx_ep->rx;

	FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	const uint64_t recv_len = context->len;
	void * recv_buf = context->buf;

	if (opcode == FI_OPX_HFI_BTH_OPCODE_TAG_INJECT || opcode == FI_OPX_HFI_BTH_OPCODE_MSG_INJECT) {

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- INJECT (begin)\n");

		const uint64_t ofi_data = hdr->match.ofi_data;
		const uint64_t send_len = hdr->inject.message_length;

		if (is_multi_receive) {		/* branch should compile out */

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"INJECT is_multi_recv\n");

			if (send_len) memcpy(recv_buf, (void*)&hdr->inject.app_data_u8[0], send_len);

			union fi_opx_context * original_multi_recv_context = context;
			context = (union fi_opx_context *)((uintptr_t)recv_buf - sizeof(union fi_opx_context));
			assert((((uintptr_t)context) & 0x07) == 0);

			context->flags = FI_RECV | FI_MSG | FI_OPX_CQ_CONTEXT_MULTIRECV;
			context->buf = recv_buf;
			context->len = send_len;
			context->data = ofi_data;
			context->tag = 0;	/* tag is not valid for multi-receives */
			context->multi_recv_context = original_multi_recv_context;
			context->byte_counter = 0;

			/* the next 'fi_opx_context' must be 8-byte aligned */
			uint64_t bytes_consumed = ((send_len + 8) & (~0x07ull)) + sizeof(union fi_opx_context);
			original_multi_recv_context->len -= bytes_consumed;
			original_multi_recv_context->buf = (void*)((uintptr_t)(original_multi_recv_context->buf) + bytes_consumed);

			/* post a completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail(context, rx->cq_completed_ptr);

		} else if (OFI_LIKELY(send_len <= recv_len)) {

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
					FI_WARN(fi_opx_global.prov, FI_LOG_EP_CTRL, "Invalid send length for inject: %lu\n", send_len);
					abort();
					break;
			}
 
			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"INJECT send_len %lu <= recv_len %lu; enqueue cq (completed)\n", send_len, recv_len);

			context->flags = FI_RECV | FI_REMOTE_CQ_DATA | ((opcode == FI_OPX_HFI_BTH_OPCODE_TAG_INJECT) ? FI_TAGGED : FI_MSG);
			context->buf = NULL;
			context->len = send_len;
			context->data = ofi_data;
			context->tag = origin_tag;
			context->byte_counter = 0;
			context->next = NULL;

			/* post a completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail(context, rx->cq_completed_ptr);

		} else {	/* truncation - unlikely */

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"INJECT truncation - send_len %lu > recv_len %lu posting error\n", send_len, recv_len);

			struct fi_opx_context_ext * ext = NULL;
			if (is_context_ext) {
				ext = (struct fi_opx_context_ext *)context;
				ext->err_entry.op_context = ext->msg.op_context;
			} else {
				posix_memalign((void**)&ext, 32, sizeof(struct fi_opx_context_ext));
				ext->opx_context.flags = FI_OPX_CQ_CONTEXT_EXT;
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
			ext->err_entry.err_data_size = 0;

			ext->opx_context.byte_counter = 0;
			ext->opx_context.next = NULL;

			/* post an 'error' completion event for the receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail((union fi_opx_context*)ext, rx->cq_err_ptr);
		}

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- INJECT (end)\n");

	} else if (opcode == FI_OPX_HFI_BTH_OPCODE_TAG_EAGER || opcode == FI_OPX_HFI_BTH_OPCODE_MSG_EAGER) {

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- EAGER (begin)\n");

		const uint64_t ofi_data = hdr->match.ofi_data;
		const uint64_t send_len = hdr->send.xfer_bytes_tail + hdr->send.payload_qws_total * sizeof(uint64_t);

		FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA,
			"hdr->send.xfer_bytes_tail = %u, hdr->send.payload_qws_total = %u, send_len = %lu\n",
			hdr->send.xfer_bytes_tail, hdr->send.payload_qws_total, send_len);

		if (is_multi_receive) {		/* branch should compile out */

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"EAGER is_multi_recv\n");

			union fi_opx_context * original_multi_recv_context = context;
			//assert(original_multi_recv_context->next == NULL);
			context = (union fi_opx_context *)((uintptr_t)recv_buf - sizeof(union fi_opx_context));
			assert((((uintptr_t)context) & 0x07) == 0);
			context->flags = FI_RECV | FI_MSG | FI_OPX_CQ_CONTEXT_MULTIRECV;
			context->buf = recv_buf;
			context->len = send_len;
			context->data = ofi_data;
			context->tag = 0;	/* tag is not valid for multi-receives */
			context->multi_recv_context = original_multi_recv_context;
			context->byte_counter = 0;
			context->next = NULL;

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

			/* the next 'fi_opx_context' must be 8-byte aligned */
			uint64_t bytes_consumed = ((send_len + 8) & (~0x07ull)) + sizeof(union fi_opx_context);
			original_multi_recv_context->len -= bytes_consumed;
			original_multi_recv_context->buf = (void*)((uintptr_t)(original_multi_recv_context->buf) + bytes_consumed);

			assert(context->next == NULL);
			/* post a completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail(context, rx->cq_completed_ptr);

		} else if (OFI_LIKELY(send_len <= recv_len)) {

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

			/* fi_opx_hfi1_dump_packet_hdr((union fi_opx_hfi1_packet_hdr *)hdr, __func__, __LINE__); */

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"EAGER send_len %lu <= recv_len %lu; enqueue cq (completed)\n", send_len, recv_len);

			context->flags = FI_RECV | FI_REMOTE_CQ_DATA | ((opcode == FI_OPX_HFI_BTH_OPCODE_TAG_EAGER) ? FI_TAGGED : FI_MSG);
			context->buf = NULL;
			context->len = send_len;
			context->data = ofi_data;
			context->tag = origin_tag;
			context->byte_counter = 0;
			context->next = NULL;

			/* post a completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail(context, rx->cq_completed_ptr);

		} else {	/* truncation - unlikely */

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"EAGER truncation - send_len %lu > recv_len %lu posting error\n", send_len, recv_len);

			struct fi_opx_context_ext * ext = NULL;
			if (is_context_ext) {
				ext = (struct fi_opx_context_ext *)context;
				ext->err_entry.op_context = ext->msg.op_context;
			} else {
				posix_memalign((void**)&ext, 32, sizeof(struct fi_opx_context_ext));
				ext->opx_context.flags = FI_OPX_CQ_CONTEXT_EXT;
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
			ext->err_entry.err_data_size = 0;

			ext->opx_context.byte_counter = 0;
			ext->opx_context.next = NULL;

			/* post an 'error' completion event for the receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail((union fi_opx_context*)ext, rx->cq_err_ptr);
		}

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- EAGER (end)\n");

	} else {			/* rendezvous packet */

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- RENDEZVOUS RTS (begin)\n");

		const uint64_t ofi_data = hdr->match.ofi_data;
		const uint64_t niov = hdr->rendezvous.niov;
		const uint64_t xfer_len = hdr->rendezvous.message_length;

		if (is_multi_receive) {		/* compile-time constant expression */
			const uint8_t u8_rx = hdr->rendezvous.origin_rx;
			union fi_opx_context * original_multi_recv_context = context;
			context = (union fi_opx_context *)((uintptr_t)recv_buf - sizeof(union fi_opx_context));

			assert((((uintptr_t)context) & 0x07) == 0);
			context->flags = FI_RECV | FI_MSG | FI_OPX_CQ_CONTEXT_MULTIRECV;
			context->buf = recv_buf;
			context->len = xfer_len;
			context->data = ofi_data;
			context->tag = 0;	/* tag is not valid for multi-receives */
			context->multi_recv_context = original_multi_recv_context;
			context->byte_counter = xfer_len;
			context->next = NULL;
			uint8_t * rbuf = (uint8_t *)recv_buf;
			union fi_opx_hfi1_packet_payload *p = (union fi_opx_hfi1_packet_payload *)payload;
			uintptr_t target_byte_counter_vaddr = (uintptr_t)&context->byte_counter;
			FI_OPX_FABRIC_RX_RZV_RTS(opx_ep,
									 (const void * const)hdr,
									 (const void * const)payload,
									 u8_rx, niov,
									 p->rendezvous.noncontiguous.origin_byte_counter_vaddr,
									 target_byte_counter_vaddr,
									 (uintptr_t)(rbuf),		            /* receive buffer virtual address */
									 p->rendezvous.noncontiguous.iov,	/* send buffer virtual address */
									 FI_OPX_HFI_DPUT_OPCODE_RZV_NONCONTIG,
									 is_intranode,					    /* compile-time constant expression */
									 reliability);					    /* compile-time constant expression */


			uint64_t bytes_consumed = ((xfer_len + 8) & (~0x07ull)) + sizeof(union fi_opx_context);
			original_multi_recv_context->len -= bytes_consumed;
			original_multi_recv_context->byte_counter++;  // re-using the byte counter as a "pending flag"
			original_multi_recv_context->tag = (uintptr_t)opx_ep;  // re-using tag to store the ep
			original_multi_recv_context->buf = (void*)((uintptr_t)(original_multi_recv_context->buf) + bytes_consumed);
			assert(context->next == NULL);
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail(context, rx->cq_pending_ptr);

		} else if (OFI_LIKELY(xfer_len <= recv_len)) {

			context->buf = NULL;
			context->len = xfer_len;
			context->data = ofi_data;
			context->tag = origin_tag;
			context->next = NULL;
			context->flags = FI_RECV | FI_REMOTE_CQ_DATA | ((opcode == FI_OPX_HFI_BTH_OPCODE_TAG_RZV_RTS) ? FI_TAGGED : FI_MSG);



			const uint8_t u8_rx = hdr->rendezvous.origin_rx;

			if (OFI_LIKELY(niov == 1)) {
				assert(payload != NULL);

				uint8_t * rbuf = (uint8_t *)recv_buf;
				union fi_opx_hfi1_packet_payload *p = (union fi_opx_hfi1_packet_payload *)payload;
				const uint64_t immediate_byte_count = p->rendezvous.contiguous.immediate_byte_count;
				const uint64_t immediate_qw_count = p->rendezvous.contiguous.immediate_qw_count;
				const uint64_t immediate_block_count = p->rendezvous.contiguous.immediate_block_count;
				const uint64_t immediate_total = immediate_byte_count +
					immediate_qw_count * sizeof(uint64_t) +
					immediate_block_count * sizeof(union cacheline);

				context->byte_counter = xfer_len - immediate_total;
				uintptr_t target_byte_counter_vaddr = (uintptr_t)&context->byte_counter;
				const struct iovec dst_iov = { (void*)p->rendezvous.contiguous.src_vaddr,      /* send buffer virtual address */
											   p->rendezvous.contiguous.src_blocks << 6 /* number of bytes to transfer */
				};
				FI_OPX_FABRIC_RX_RZV_RTS(opx_ep,
						(const void * const)hdr,
						(const void * const)payload,
						u8_rx, 1,
						p->rendezvous.contiguous.origin_byte_counter_vaddr,
						target_byte_counter_vaddr,
						(uintptr_t)(rbuf + immediate_total),		/* receive buffer virtual address */
						&dst_iov,
						FI_OPX_HFI_DPUT_OPCODE_RZV,
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
				FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
					"rendezvous non-contiguous source data not implemented; abort\n");
				abort();
			}

			/* post a pending completion event for the individual receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail(context, rx->cq_pending_ptr);


		} else {				/* truncation - unlikely */

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"RENDEZVOUS truncation - xfer_len %lu > recv_len %lu posting error\n", xfer_len, recv_len);

			/* Post a CTS Truncation error (FI_OPX_HFI_DPUT_OPCODE_RZV_ETRUNC) to unblock the Tx of RTS */

			context->buf = NULL;
			context->len = xfer_len;
			context->data = ofi_data;
			context->tag = origin_tag;
			context->next = NULL;
			context->byte_counter = 0;
			context->flags = FI_RECV | FI_REMOTE_CQ_DATA | ((opcode == FI_OPX_HFI_BTH_OPCODE_TAG_RZV_RTS) ? FI_TAGGED : FI_MSG);
			const uint8_t u8_rx = hdr->rendezvous.origin_rx;
			assert(payload != NULL);
			uint8_t * rbuf = (uint8_t *)recv_buf;
			union fi_opx_hfi1_packet_payload *p = (union fi_opx_hfi1_packet_payload *)payload;
			uintptr_t target_byte_counter_vaddr = (uintptr_t)&context->byte_counter;

			const struct iovec dst_iov = { (void*)p->rendezvous.contiguous.src_vaddr,      /* send buffer virtual address */
											p->rendezvous.contiguous.src_blocks  << 6 /* number of bytes to transfer */
			};

			FI_OPX_FABRIC_RX_RZV_RTS(opx_ep,
					(const void * const)hdr,
					(const void * const)payload,
					u8_rx, 1,
					p->rendezvous.contiguous.origin_byte_counter_vaddr,
					target_byte_counter_vaddr,
					(uintptr_t)(rbuf),		/* receive buffer virtual address */
					&dst_iov,
					FI_OPX_HFI_DPUT_OPCODE_RZV_ETRUNC,
					is_intranode,					/* compile-time constant expression */
					reliability);					/* compile-time constant expression */

			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail(context, rx->cq_pending_ptr);

			/* Post a E_TRUNC to our local RX error queue because a client called receive 
			with too small a buffer.  Tell them about it via the error cq */ 

			struct fi_opx_context_ext * ext = NULL;
			if (is_context_ext) {
				ext = (struct fi_opx_context_ext *)context;
				ext->err_entry.op_context = ext->msg.op_context;
			} else {
				posix_memalign((void**)&ext, 32, sizeof(struct fi_opx_context_ext));
				ext->opx_context.flags = FI_OPX_CQ_CONTEXT_EXT;
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
			ext->err_entry.err_data_size = 0;

			ext->opx_context.byte_counter = 0;
			ext->opx_context.next = NULL;

			/* post an 'error' completion event */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail((union fi_opx_context*)ext, rx->cq_err_ptr);
		}

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV -- RENDEZVOUS RTS (end)\n");

	}	/* rendezvous packet */

	FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	return;
}

static inline
void fi_opx_shm_dynamic_tx_connect(const unsigned is_intranode,
								   struct fi_opx_ep * opx_ep,
								   const unsigned rx_id) {
	if(is_intranode && opx_ep->tx->shm.fifo[rx_id] == NULL) {
		char buffer[128];
		snprintf(buffer,sizeof(buffer),"%s-%02x",
				 opx_ep->domain->unique_job_key_str, 0);
		opx_shm_tx_connect(&opx_ep->tx->shm, (const char * const)buffer,
						   rx_id, FI_OPX_SHM_FIFO_SIZE, FI_OPX_SHM_PACKET_SIZE);
	}
}


static inline void fi_opx_atomic_completion_action(union fi_opx_hfi1_deferred_work * work_state) {
    // TODO:  This function should be written for atomic access
    // It's technically not correct to memory copy the values out because
    // it's possible the instructions generated will lead to torn reads from the buffer
    // Implement a FI_OPX_FABRIC_RX_RZV_CTS "atomic" version that is op/dt aware
	struct fi_opx_hfi1_dput_params *params = &work_state->dput;
	uint64_t* rbuf_qws = (uint64_t *)((char*)params->opx_mr->buf + params->dput_iov->sbuf);
	const uint64_t *sbuf_qws = (uint64_t*)&work_state->work_elem.payload_copy->byte[sizeof(struct fi_opx_hfi1_dput_iov)];
	if(params->op == (FI_NOOP-1) &&
	   params->dt == (FI_VOID-1)) {
		memcpy(rbuf_qws, sbuf_qws, params->dput_iov->bytes);
	} else {
		fi_opx_rx_atomic_dispatch(sbuf_qws, rbuf_qws,
								  params->dput_iov->bytes,
								  params->dt,
								  params->op);
	}
}

static inline
void fi_opx_ep_rx_process_header (struct fid_ep *ep,
		const union fi_opx_hfi1_packet_hdr * const hdr,
		const union fi_opx_hfi1_packet_payload * const payload,
		const size_t payload_bytes,
		const uint64_t static_flags,
		const uint8_t opcode,
		const unsigned is_intranode,
		const int lock_required,
		const enum ofi_reliability_kind reliability)
{

	struct fi_opx_ep * opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);
	const uint64_t kind = (static_flags & FI_TAGGED) ? 0 : 1;

	FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	if (OFI_UNLIKELY (opcode < FI_OPX_HFI_BTH_OPCODE_MSG_INJECT)) {

		FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

		if (opcode == FI_OPX_HFI_BTH_OPCODE_RZV_CTS) {

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"===================================== RECV -- RENDEZVOUS CTS (begin)\n");

			assert(payload != NULL);
			const uint8_t u8_rx = hdr->cts.origin_rx;

			switch(hdr->cts.target.opcode) {
			case FI_OPX_HFI_DPUT_OPCODE_RZV:
					{
					const struct fi_opx_hfi1_dput_iov * const dput_iov = payload->cts.iov;
					const uintptr_t target_byte_counter_vaddr = hdr->cts.target.vaddr.target_byte_counter_vaddr;
					const uint32_t niov = hdr->cts.target.vaddr.niov;
					uint64_t * origin_byte_counter = (uint64_t *)hdr->cts.target.vaddr.origin_byte_counter_vaddr;
					FI_OPX_FABRIC_RX_RZV_CTS(opx_ep, NULL, (const void * const) hdr, (const void * const) payload, 0,
											 u8_rx, niov, dput_iov, target_byte_counter_vaddr, origin_byte_counter,
											 FI_OPX_HFI_DPUT_OPCODE_RZV, NULL,
											 is_intranode,	/* compile-time constant expression */
											 reliability);	/* compile-time constant expression */
					}
					break;
			case FI_OPX_HFI_DPUT_OPCODE_RZV_NONCONTIG:
			{
				const struct fi_opx_hfi1_dput_iov * const dput_iov = payload->cts.iov;
				const uintptr_t target_byte_counter_vaddr = hdr->cts.target.vaddr.target_byte_counter_vaddr;
				const uint32_t niov = hdr->cts.target.vaddr.niov;
				uint64_t * origin_byte_counter = (uint64_t *)hdr->cts.target.vaddr.origin_byte_counter_vaddr;
				FI_OPX_FABRIC_RX_RZV_CTS(opx_ep, NULL, (const void * const) hdr, (const void * const) payload, 0,
										 u8_rx, niov, dput_iov, target_byte_counter_vaddr, origin_byte_counter,
										 FI_OPX_HFI_DPUT_OPCODE_RZV_NONCONTIG,
										 NULL,
										 is_intranode,	/* compile-time constant expression */
										 reliability);	/* compile-time constant expression */
			}
			break;
			case FI_OPX_HFI_DPUT_OPCODE_RZV_ETRUNC:
			{
				uint64_t * origin_byte_counter = (uint64_t *)hdr->cts.target.vaddr.origin_byte_counter_vaddr;
				*origin_byte_counter = 0;
			}
			break;
			case FI_OPX_HFI_DPUT_OPCODE_GET:
			        {
					const struct fi_opx_hfi1_dput_iov * const dput_iov = payload->cts.iov;
					const uintptr_t target_completion_counter_vaddr = hdr->cts.target.mr.target_completion_counter_vaddr;
					struct fi_opx_mr *opx_mr = NULL;
					const uint32_t niov = hdr->cts.target.mr.niov;
					HASH_FIND(hh, opx_ep->domain->mr_hashmap,
							  &hdr->cts.target.mr.key,
							  sizeof(hdr->cts.target.mr.key),
							  opx_mr);
					// Permissions (TODO)
					// check MR permissions
					// nack on failed lookup
					// TODO:  When DPUT is an atomic read, we need to have an atomic version FI_OPX_FABRIC_RX_RZV_CTS that reads
					// the variables atomically to fill the egress buffers (memcpy/8 byte qw reads likely are't sufficient to guarantee untorn reads)
					assert(opx_mr != NULL);
					FI_OPX_FABRIC_RX_RZV_CTS(opx_ep, opx_mr, (const void * const) hdr, (const void * const) payload, 0,
											 u8_rx, niov, dput_iov, target_completion_counter_vaddr, NULL, /* No origin byte counter here */
											 FI_OPX_HFI_DPUT_OPCODE_GET,
											 NULL,
											 is_intranode,	/* compile-time constant expression */
											 reliability);	/* compile-time constant expression */
					}
					break;
			case FI_OPX_HFI_DPUT_OPCODE_FENCE:
			{
					assert(payload != NULL);
					struct fi_opx_completion_counter *cc = (struct fi_opx_completion_counter *)hdr->dput.target.fence.completion_counter;
					const uint64_t bytes_to_fence = hdr->dput.target.fence.bytes_to_fence;
					const union fi_opx_hfi1_packet_hdr * const hfi1_hdr =
							(const union fi_opx_hfi1_packet_hdr * const) hdr;

					const uint64_t lrh_dlid = (hfi1_hdr->stl.lrh.qw[0] & 0xFFFF000000000000ul) >> 32;
					const uint64_t bth_rx = (uint64_t)u8_rx << 56;
					const uint64_t pbc_dws = 2 + /* pbc */
							2 + /* lrh */
							3 + /* bth */
							9 + /* kdeth; from "RcvHdrSize[i].HdrSize" CSR */
							(0 << 4);
					const uint16_t lrh_dws = htons(pbc_dws - 1);

					fi_opx_shm_dynamic_tx_connect(is_intranode, opx_ep, u8_rx);
					uint64_t pos;
					union fi_opx_hfi1_packet_hdr *const tx_hdr =
						opx_shm_tx_next(&opx_ep->tx->shm, u8_rx, &pos);
					while(!tx_hdr) {
						// TODO:  It's possible this could hang forever
						// Add the ability to defer the fence operation
						opx_shm_tx_next(&opx_ep->tx->shm, u8_rx, &pos);
					}
					tx_hdr->qw[0] = opx_ep->rx->tx.dput.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);
					tx_hdr->qw[1] = opx_ep->rx->tx.dput.hdr.qw[1] | bth_rx;
					tx_hdr->qw[2] = opx_ep->rx->tx.dput.hdr.qw[2];
					tx_hdr->qw[3] = opx_ep->rx->tx.dput.hdr.qw[3];
					tx_hdr->qw[4] = opx_ep->rx->tx.dput.hdr.qw[4] | FI_OPX_HFI_DPUT_OPCODE_FENCE | (0ULL << 32);
					tx_hdr->qw[5] = (uint64_t)cc;
					tx_hdr->qw[6] = bytes_to_fence;

					opx_shm_tx_advance(&opx_ep->tx->shm, (void *)tx_hdr, pos);
			}
			break;
			default:
					abort();
					break;
			}

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"===================================== RECV -- RENDEZVOUS CTS (end)\n");


		} else if (opcode == FI_OPX_HFI_BTH_OPCODE_RZV_DATA) {
				FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
							 "===================================== RECV -- RENDEZVOUS DATA (begin)\n");
				switch(hdr->dput.target.opcode) {
				case FI_OPX_HFI_DPUT_OPCODE_RZV:
				{
						assert(payload != NULL);
						uint64_t* target_byte_counter_vaddr = (uint64_t *)hdr->dput.target.vaddr.target_byte_counter_vaddr;
						uint64_t* rbuf_qws = (uint64_t *)hdr->dput.target.vaddr.rbuf;
						const uint64_t *sbuf_qws = (uint64_t*)&payload->byte[0];
						const uint32_t bytes = hdr->dput.target.vaddr.bytes;

						if(bytes > FI_OPX_HFI1_PACKET_MTU) {
							fprintf(stderr, "bytes is %d\n", bytes);
							fflush(stderr);
						}
						assert(bytes <= FI_OPX_HFI1_PACKET_MTU);
						memcpy(rbuf_qws, sbuf_qws, bytes);

						if(target_byte_counter_vaddr != NULL) {
								const uint64_t value = *target_byte_counter_vaddr;
								*target_byte_counter_vaddr = value - bytes;
								FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA,
									   "target_byte_counter_vaddr = %p, %lu -> %lu\n",
									   target_byte_counter_vaddr, value, value - bytes);
						}
				}
				break;
				case FI_OPX_HFI_DPUT_OPCODE_RZV_NONCONTIG:
				{
						assert(payload != NULL);
						uint64_t* target_byte_counter_vaddr = (uint64_t *)hdr->dput.target.vaddr.target_byte_counter_vaddr;
						uint64_t* rbuf_qws = (uint64_t *)hdr->dput.target.vaddr.rbuf;
						const uint64_t *sbuf_qws = (uint64_t*)&payload->byte[0];
						const uint32_t bytes = hdr->dput.target.vaddr.bytes;

						assert(bytes <= FI_OPX_HFI1_PACKET_MTU);
						memcpy(rbuf_qws, sbuf_qws, bytes);
						if(target_byte_counter_vaddr != NULL) {
								const uint64_t value = *target_byte_counter_vaddr;
								*target_byte_counter_vaddr = value - bytes;
								FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA,
									   "target_byte_counter_vaddr = %p, %lu -> %lu\n",
									   target_byte_counter_vaddr, value, value - bytes);
						}
				}
				break;
				case FI_OPX_HFI_DPUT_OPCODE_PUT:
				{
						const uint64_t *sbuf_qws = (uint64_t*)&payload->byte[0];
						uint32_t bytes = hdr->dput.target.mr.bytes;
						struct fi_opx_mr *opx_mr = NULL;
						HASH_FIND(hh, opx_ep->domain->mr_hashmap,
								  &hdr->dput.target.mr.key,
								  sizeof(hdr->dput.target.mr.key),
								  opx_mr);
						assert(opx_mr != NULL);
						assert(bytes <= FI_OPX_HFI1_PACKET_MTU);
						uint64_t* rbuf_qws = (uint64_t *)((char*)opx_mr->buf + hdr->dput.target.mr.offset);
						// Optimize Memcpy
						if(hdr->dput.target.mr.op == FI_NOOP - 1 &&
						   hdr->dput.target.mr.dt == FI_VOID - 1) {
							memcpy(rbuf_qws, sbuf_qws, bytes);
						} else {
							fi_opx_rx_atomic_dispatch(sbuf_qws, rbuf_qws, bytes,
													  hdr->dput.target.mr.dt,
													  hdr->dput.target.mr.op);
						}
				}
				break;
				case FI_OPX_HFI_DPUT_OPCODE_GET:
				{
					assert(payload != NULL);
					struct fi_opx_completion_counter *cc =
						(struct fi_opx_completion_counter *)hdr->dput.target.vaddr.target_byte_counter_vaddr;
					uint64_t* rbuf_qws = (uint64_t *)hdr->dput.target.vaddr.rbuf;
					const uint64_t *sbuf_qws = (uint64_t*)&payload->byte[0];
					const uint32_t bytes = hdr->dput.target.vaddr.bytes;
					assert(cc);
					assert(bytes <= FI_OPX_HFI1_PACKET_MTU);
					// Optimize Memcpy
					memcpy(rbuf_qws, sbuf_qws, bytes);
					cc->byte_counter -= bytes;
					assert(cc->byte_counter >= 0);

					if(cc->byte_counter == 0) {
						cc->hit_zero(cc);
					}
				}
				break;
				case FI_OPX_HFI_DPUT_OPCODE_ATOMIC_FETCH:
				{
					const uint8_t u8_rx = hdr->dput.origin_rx;
					const uint64_t *sbuf_qws = (uint64_t*)&payload->byte[sizeof(struct fi_opx_hfi1_dput_iov)];
					struct fi_opx_mr *opx_mr = NULL;

					uint64_t key = hdr->dput.target.mr_atomic.key;
					HASH_FIND(hh, opx_ep->domain->mr_hashmap,
							  &key,
							  sizeof(key),
							  opx_mr);
					assert(opx_mr != NULL);
					const struct fi_opx_hfi1_dput_iov *dput_iov = (struct fi_opx_hfi1_dput_iov *)&payload->byte[0];
					uint64_t* rbuf_qws = (uint64_t *)((char*)opx_mr->buf + dput_iov->sbuf);
					// Optimize Memcpy
					uintptr_t target_completion_counter_vaddr = hdr->dput.target.mr_atomic.target_counter_vaddr;

					assert(dput_iov->bytes <= FI_OPX_HFI1_PACKET_MTU - sizeof(*dput_iov));

					union fi_opx_hfi1_deferred_work *work =
					FI_OPX_FABRIC_RX_RZV_CTS(opx_ep, opx_mr, (const void * const) hdr, (const void * const) payload, payload_bytes,
											 u8_rx, 1, dput_iov, target_completion_counter_vaddr, NULL,
											 FI_OPX_HFI_DPUT_OPCODE_GET,
											 fi_opx_atomic_completion_action,
											 is_intranode,
											 reliability);
					if(work == NULL) {
						if(hdr->dput.target.mr_atomic.op == (FI_NOOP-1) &&
						   hdr->dput.target.mr_atomic.dt == (FI_VOID-1)) {
							memcpy(rbuf_qws, sbuf_qws, dput_iov->bytes);
						} else {
							fi_opx_rx_atomic_dispatch(sbuf_qws, rbuf_qws, dput_iov->bytes,
													  hdr->dput.target.mr_atomic.dt,
													  hdr->dput.target.mr_atomic.op);
						}
					} else {
						struct fi_opx_hfi1_dput_params *params = &work->dput;
						params->op = hdr->dput.target.mr_atomic.op;
						params->dt = hdr->dput.target.mr_atomic.dt;
					}
				}
				break;
				case FI_OPX_HFI_DPUT_OPCODE_ATOMIC_COMPARE_FETCH:
				{
					const uint8_t u8_rx = hdr->dput.origin_rx;
					const uint64_t *sbuf_qws = (uint64_t*)&payload->byte[sizeof(struct fi_opx_hfi1_dput_iov)];
					struct fi_opx_mr *opx_mr = NULL;

					uint64_t key = hdr->dput.target.mr_atomic.key;
					HASH_FIND(hh, opx_ep->domain->mr_hashmap,
							  &key,
							  sizeof(key),
							  opx_mr);
					assert(opx_mr != NULL);
					struct fi_opx_hfi1_dput_iov dput_iov = *((struct fi_opx_hfi1_dput_iov *)&payload->byte[0]);
					uint64_t* rbuf_qws = (uint64_t *)((char*)opx_mr->buf + dput_iov.sbuf);
					// Optimize Memcpy
					uintptr_t target_completion_counter_vaddr = hdr->dput.target.mr_atomic.target_counter_vaddr;

					assert(dput_iov.bytes <= FI_OPX_HFI1_PACKET_MTU - sizeof(dput_iov));

					dput_iov.bytes /= 2;
					union fi_opx_hfi1_deferred_work *work =
					FI_OPX_FABRIC_RX_RZV_CTS(opx_ep, opx_mr, (const void * const) hdr, (const void * const) payload,
											 payload_bytes,
											 u8_rx, 1, &dput_iov, target_completion_counter_vaddr, NULL,
											 FI_OPX_HFI_DPUT_OPCODE_GET,
											 fi_opx_atomic_completion_action,
											 is_intranode,
											 reliability);
					if(work == NULL) {
						if(hdr->dput.target.mr_atomic.op == (FI_NOOP-1) &&
						   hdr->dput.target.mr_atomic.dt == (FI_VOID-1)) {
							assert(0);
						} else {
							fi_opx_rx_atomic_dispatch(sbuf_qws, rbuf_qws, dput_iov.bytes,
													  hdr->dput.target.mr_atomic.dt,
													  hdr->dput.target.mr_atomic.op);
						}
					} else {
						struct fi_opx_hfi1_dput_params *params = &work->dput;
						params->op = hdr->dput.target.mr_atomic.op;
						params->dt = hdr->dput.target.mr_atomic.dt;
					}
				}
				break;
				case FI_OPX_HFI_DPUT_OPCODE_FENCE:
				{
						assert(payload != NULL);
						struct fi_opx_completion_counter *cc =
								(struct fi_opx_completion_counter *)hdr->dput.target.fence.completion_counter;
						const uint32_t bytes = hdr->dput.target.fence.bytes_to_fence;

						assert(cc);
						cc->byte_counter -= bytes;
						assert(cc->byte_counter == 0);
						cc->hit_zero(cc);
				}
				break;
			default:
					abort();
					break;
			}


			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"===================================== RECV -- RENDEZVOUS DATA (end)\n");

		} else if (opcode == FI_OPX_HFI_BTH_OPCODE_ACK) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"unimplemented opcode (%u); abort\n", opcode);
			abort();
		} else if (opcode == FI_OPX_HFI_BTH_OPCODE_RMA) {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"unimplemented opcode (%u); abort\n", opcode);
			abort();
		} else if (opcode == FI_OPX_HFI_BTH_OPCODE_ATOMIC) {
				FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
						"unimplemented opcode (%u); abort\n", opcode);
				abort();
		} else if (opcode == FI_OPX_HFI_BTH_OPCODE_UD) {
				FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
						"reliability exception with opcode %d, dropped\n", opcode);
		} else {
			FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
				"unimplemented opcode (%u); abort\n", opcode);
			abort();
		}

		return;
	}

	assert(opcode >= FI_OPX_HFI_BTH_OPCODE_MSG_INJECT);

	/* search the match queue */
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "search the match queue\n");

//	struct slist * list = &rx->queue[kind].mq;
//	union fi_opx_context * context = container_of(list->head, union fi_opx_context, entry);
//	struct slist_entry * prev = NULL;

	union fi_opx_context * context = opx_ep->rx->queue[kind].mq.head;
	union fi_opx_context * prev = NULL;

	while (OFI_LIKELY(context != NULL)) {
		FI_DBG(fi_opx_global.prov, FI_LOG_EP_DATA, "context = %p\n", context);

		const uint64_t rx_op_flags = context->flags;

		if (is_match(hdr, context)) {

			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "found a match\n");

			if (OFI_LIKELY((static_flags & FI_TAGGED) ||	/* branch will compile out for tag */
					((rx_op_flags | FI_MULTI_RECV) == 0))) {

				if (prev)
					prev->next = context->next;
				else
					opx_ep->rx->queue[kind].mq.head = context->next;

				if (context->next == NULL)
					opx_ep->rx->queue[kind].mq.tail = prev;

				context->next = NULL;

				const uint64_t is_context_ext = rx_op_flags & FI_OPX_CQ_CONTEXT_EXT;

				complete_receive_operation(ep, hdr, payload,
					hdr->match.ofi_tag, context, opcode,
					is_context_ext,
					0,	/* is_multi_receive */
					is_intranode,
					lock_required,
					reliability);

				return;

			} else {

				/*
				 * verify that there is enough space available in
				 * the multi-receive buffer for the incoming data
				 */
				const uint64_t recv_len = context->len;
				const uint64_t send_len = fi_opx_hfi1_packet_hdr_message_length(hdr);

				if (send_len > recv_len) {

					/*
					 * there is not enough space available in
					 * the multi-receive buffer; continue as
					 * if "a match was not found" and advance
					 * to the next match entry
					 */
					//prev = &context->entry;
					//context = container_of(context->entry.next, union fi_opx_context, entry);
					prev = context;
					context = context->next;

				} else {

					complete_receive_operation(ep, hdr, payload,
						0, context, opcode,
						0,	/* is_context_ext */
						1,	/* is_multi_receive */
						is_intranode,
						lock_required,
						reliability);

					if (context->len < opx_ep->rx->min_multi_recv) {
						/* after processing this message there is not
						 * enough space available in the multi-receive
						 * buffer to receive the next message; post a
						 * 'FI_MULTI_RECV' event to the completion
						 * queue and return. */

						/* remove context from match queue */
						if (prev)
							prev->next = context->next;
						else
							opx_ep->rx->queue[kind].mq.head = context->next;

						if (context->next == NULL)
							opx_ep->rx->queue[kind].mq.tail = NULL;

						context->next = NULL;

						// Signaling the userneeds to be deferred until the op is completed for rendezvous
						// reusing byte counter as a pending flag
						// to ensure that any pending ops are completed (eg rendezvous multi-receive)
						if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
						if(context->byte_counter == 0) {
							fi_opx_context_slist_insert_tail(context, opx_ep->rx->cq_completed_ptr);
						}
					}
				}

				return;
			}

		} else {

			prev = context;
			context = context->next;
//			prev = &context->entry;
//			context = container_of(context->entry.next, union fi_opx_context, entry);
		}
	}

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
		"did not find a match .. add this packet to the unexpected queue\n");

	/* reported in LRH as the number of 4-byte words in the packet; header + payload */
//	size_t total_bytes_to_copy = ((size_t)ntohs(hdr->stl.lrh.pktlen)) * 4;

	if (static_flags & FI_MSG)
		fi_opx_ep_rx_append_ue_msg(opx_ep->rx, hdr, payload, payload_bytes);
	else if (static_flags & FI_TAGGED)
		fi_opx_ep_rx_append_ue_tag(opx_ep->rx, hdr, payload, payload_bytes);
	else
		abort();

	return;
}






#include "rdma/opx/fi_opx_fabric_progress.h"


static inline void fi_opx_ep_rx_poll (struct fid_ep *ep,
		const uint64_t caps,
		const enum ofi_reliability_kind reliability,
		const uint64_t hdrq_mask) {

	struct fi_opx_ep * opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);
	const enum ofi_reliability_kind kind = opx_ep->reliability->state.kind;


	const uintptr_t work_pending = (const uintptr_t)opx_ep->tx->work_pending.head;
	if (work_pending) {
		union fi_opx_hfi1_deferred_work *work = (union fi_opx_hfi1_deferred_work *)slist_remove_head(&opx_ep->tx->work_pending);
		work->work_elem.slist_entry.next = NULL;
		int rc = work->work_elem.work_fn(work);
		if(rc == FI_SUCCESS) {
			if(work->work_elem.completion_action) {
				work->work_elem.completion_action(work);
			}
			if(work->work_elem.payload_copy) {
				ofi_buf_free(work->work_elem.payload_copy);
			}
			ofi_buf_free(work);
		} else {
			assert(work->work_elem.slist_entry.next == NULL);
			slist_insert_head(&work->work_elem.slist_entry, &opx_ep->tx->work_pending);
		}
	}

	if ( (reliability == OFI_RELIABILITY_KIND_RUNTIME) && (hdrq_mask == FI_OPX_HDRQ_MASK_2048) ) {			/* constant compile-time expression */
		if ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) != 0) {

			if (kind == OFI_RELIABILITY_KIND_NONE) {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_NONE, FI_OPX_HDRQ_MASK_2048);
			} else if (kind == OFI_RELIABILITY_KIND_ONLOAD) {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_ONLOAD, FI_OPX_HDRQ_MASK_2048);
			} else {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_OFFLOAD, FI_OPX_HDRQ_MASK_2048);
			}

		} else {
			const uint64_t rx_caps = opx_ep->rx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM);

			if (kind == OFI_RELIABILITY_KIND_NONE) {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_NONE, FI_OPX_HDRQ_MASK_2048);
			} else if (kind == OFI_RELIABILITY_KIND_ONLOAD) {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_ONLOAD, FI_OPX_HDRQ_MASK_2048);
			} else {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_OFFLOAD, FI_OPX_HDRQ_MASK_2048);
			}
		}

	} else if ( (reliability == OFI_RELIABILITY_KIND_RUNTIME) && (hdrq_mask == FI_OPX_HDRQ_MASK_8192) ) {			/* constant compile-time expression */

		if ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) != 0) {

			if (kind == OFI_RELIABILITY_KIND_NONE) {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_NONE, FI_OPX_HDRQ_MASK_8192);
			} else if (kind == OFI_RELIABILITY_KIND_ONLOAD) {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_ONLOAD, FI_OPX_HDRQ_MASK_8192);
			} else {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, caps, OFI_RELIABILITY_KIND_OFFLOAD, FI_OPX_HDRQ_MASK_8192);
			}

		} else {
			const uint64_t rx_caps = opx_ep->rx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM);

			if (kind == OFI_RELIABILITY_KIND_NONE) {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_NONE, FI_OPX_HDRQ_MASK_8192);
			} else if (kind == OFI_RELIABILITY_KIND_ONLOAD) {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_ONLOAD, FI_OPX_HDRQ_MASK_8192);
			} else {
				FI_OPX_FABRIC_POLL_MANY(ep, 0, rx_caps, OFI_RELIABILITY_KIND_OFFLOAD, FI_OPX_HDRQ_MASK_8192);
			}
		}

	} else if ( ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == 0) && (hdrq_mask == FI_OPX_HDRQ_MASK_2048) ) {		/* constant compile-time expression */

		struct fi_opx_ep * opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);
		const uint64_t rx_caps = opx_ep->rx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM);
		FI_OPX_FABRIC_POLL_MANY(ep, 0, rx_caps, reliability, FI_OPX_HDRQ_MASK_2048);

	} else if ( ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == 0) && (hdrq_mask == FI_OPX_HDRQ_MASK_8192) ) {		/* constant compile-time expression */

		struct fi_opx_ep * opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);
		const uint64_t rx_caps = opx_ep->rx->caps & (FI_LOCAL_COMM | FI_REMOTE_COMM);
		FI_OPX_FABRIC_POLL_MANY(ep, 0, rx_caps, reliability, FI_OPX_HDRQ_MASK_8192);

	} else {
		FI_OPX_FABRIC_POLL_MANY(ep, 0, caps, reliability, hdrq_mask);
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
__OPX_FORCE_INLINE__
int fi_opx_ep_rx_process_context (struct fi_opx_ep * opx_ep,
		const uint64_t static_flags,
		const uint64_t cancel_context, union fi_opx_context * context,
		const uint64_t rx_op_flags, const uint64_t is_context_ext,
		const int lock_required, const enum fi_av_type av_type,
		const enum ofi_reliability_kind reliability) {

	const uint64_t kind = (static_flags & FI_TAGGED) ? 0 : 1;

	struct fid_ep * ep = &opx_ep->ep_fid;

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	if (cancel_context) {	/* branch should compile out */
		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA, "unimplemented; abort\n"); abort();

		const uint64_t compare_context = is_context_ext ?
			(uint64_t)(((struct fi_opx_context_ext *)context)->msg.op_context) :
			(uint64_t)context;

		if (compare_context == cancel_context) {

			struct fi_opx_context_ext * ext;
			if (is_context_ext) {
				ext = (struct fi_opx_context_ext *)context;
			} else {
				posix_memalign((void**)&ext, 32, sizeof(struct fi_opx_context_ext));
				ext->opx_context.flags = FI_OPX_CQ_CONTEXT_EXT;
			}

			ext->opx_context.byte_counter = 0;
			ext->err_entry.op_context = (void *)cancel_context;
			ext->err_entry.flags = rx_op_flags;
			ext->err_entry.len = 0;
			ext->err_entry.buf = 0;
			ext->err_entry.data = 0;
			ext->err_entry.tag = context->tag;
			ext->err_entry.olen = 0;
			ext->err_entry.err = FI_ECANCELED;
			ext->err_entry.prov_errno = 0;
			ext->err_entry.err_data = NULL;

			/* post an 'error' completion event for the canceled receive */
			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail((union fi_opx_context*)ext, opx_ep->rx->cq_err_ptr);

			return FI_ECANCELED;
		}
	}

	if (OFI_LIKELY((rx_op_flags & (FI_PEEK | FI_CLAIM | FI_MULTI_RECV)) == 0)) {

		/*
		 * search the unexpected packet queue
		 */
		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"searching unexpected queue\n");

		struct fi_opx_hfi1_ue_packet *uepkt = opx_ep->rx->queue[kind].ue.head;

		if (uepkt) {
			FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
				"uepkt = %p\n", uepkt);

			if (is_match(&uepkt->hdr, context)) {

				FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
					"found a match\n");

				const unsigned is_intranode = (uepkt->hdr.stl.lrh.slid == opx_ep->rx->slid);

				complete_receive_operation(ep,
					&uepkt->hdr,
					&uepkt->payload,
					uepkt->hdr.match.ofi_tag,
					context,
					uepkt->hdr.stl.bth.opcode,
					0,	/* is_context_ext */
					0,	/* is_multi_receive */
					is_intranode,
					lock_required,
					reliability);

				/* remove */
				opx_ep->rx->queue[kind].ue.head = uepkt->next;
				if (!uepkt->next) opx_ep->rx->queue[kind].ue.tail = NULL;

				/* add uepkt to ue free pool */
				if (!opx_ep->rx->ue_free_pool.head) opx_ep->rx->ue_free_pool.tail = uepkt;
				uepkt->next = opx_ep->rx->ue_free_pool.head;
				opx_ep->rx->ue_free_pool.head = uepkt;

				FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");
				return 0;

			} else {
				struct fi_opx_hfi1_ue_packet *prev = uepkt;
				uepkt = uepkt->next;

				while (uepkt) {
					FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
						"uepkt = %p\n", uepkt);

					if (is_match(&uepkt->hdr, context)) {

						FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
							"found a match\n");

						const unsigned is_intranode = (uepkt->hdr.stl.lrh.slid == opx_ep->rx->slid);

						complete_receive_operation(ep,
							&uepkt->hdr,
							&uepkt->payload,
							uepkt->hdr.match.ofi_tag,
							context,
							uepkt->hdr.stl.bth.opcode,
							0,	/* is_context_ext */
							0,	/* is_multi_receive */
							is_intranode,
							lock_required,
							reliability);

						/* remove */
						prev->next = uepkt->next;
						if (!uepkt->next) opx_ep->rx->queue[kind].ue.tail = prev;

						/* add uepkt to ue free pool */
						if (!opx_ep->rx->ue_free_pool.head) opx_ep->rx->ue_free_pool.tail = uepkt;
						uepkt->next = opx_ep->rx->ue_free_pool.head;
						opx_ep->rx->ue_free_pool.head = uepkt;

						FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");
						return 0;
					}
					prev = uepkt;
					uepkt = uepkt->next;
				}
			}
		}

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"nothing found on unexpected queue; adding to match queue\n");

		/*
		 * no unexpected headers were matched; add this match information
		 * (context) to the appropriate match queue
		 */
		context->next = NULL;
		if (!opx_ep->rx->queue[kind].mq.tail) {
			opx_ep->rx->queue[kind].mq.head = context;
			opx_ep->rx->queue[kind].mq.tail = context;
		} else {
			opx_ep->rx->queue[kind].mq.tail->next = context;
			opx_ep->rx->queue[kind].mq.tail = context;

		}

	} else {

		/*
		 * Not for critical path: peek, or claim, or multi-receive
		 * context information
		 */
		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"process peek, claim, or multi-receive context\n");

		fi_opx_ep_rx_process_context_noinline(opx_ep, static_flags,
			context, rx_op_flags, is_context_ext, lock_required, av_type, reliability);
	}

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");
	return 0;
}



/*
 * =========================== Application-facing ===========================
 */

__OPX_FORCE_INLINE_AND_FLATTEN__
ssize_t fi_opx_ep_rx_recv_internal (struct fi_opx_ep *opx_ep,
	       	void *buf, size_t len, void *desc,
		fi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context,
		const int lock_required, const enum fi_av_type av_type,
		const uint64_t static_flags,
		const enum ofi_reliability_kind reliability)
{
	assert(((static_flags & (FI_TAGGED | FI_MSG)) == FI_TAGGED) ||
		((static_flags & (FI_TAGGED | FI_MSG)) == FI_MSG));

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
		"posting receive: context = %p\n", context);

	const uint64_t rx_op_flags = opx_ep->rx->op_flags;
	uint64_t rx_caps = opx_ep->rx->caps;

	assert(context);
	assert(((uintptr_t)context & 0x07ull) == 0);	/* must be 8 byte aligned */
	union fi_opx_context * opx_context = (union fi_opx_context *)context;
	opx_context->flags = rx_op_flags;
	opx_context->len = len;
	opx_context->buf = buf;

	if (rx_caps & FI_DIRECTED_RECV) {
		if (av_type == FI_AV_TABLE) {		/* constand compile-time expression */
			if (OFI_LIKELY(src_addr != FI_ADDR_UNSPEC)) {
				opx_context->src_addr = opx_ep->rx->av_addr[src_addr].fi;
			} else {
				opx_context->src_addr = FI_ADDR_UNSPEC;
			}
		} else {
			opx_context->src_addr = src_addr;
		}
	} else {
		opx_context->src_addr = FI_ADDR_UNSPEC;
	}

#ifdef FI_OPX_TRACE
	fprintf(stderr,"fi_opx_recv_generic from source addr:\n");
	FI_OPX_ADDR_DUMP(&opx_context->src_addr);
#endif

	opx_context->tag = tag;
	opx_context->ignore = ignore;
	opx_context->byte_counter = (uint64_t)-1;

	if (IS_PROGRESS_MANUAL(opx_ep->domain)) {

		if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }

		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
			"process context (check unexpected queue, append match queue)\n");

		fi_opx_ep_rx_process_context(opx_ep, static_flags, 0, context, 0, 0, lock_required, av_type, reliability);

	} else {

		FI_WARN(fi_opx_global.prov, FI_LOG_EP_DATA,
			"FI_PROGRESS_AUTO is not implemented; abort\n");
		abort();
	}

	return 0;
}

/*
 * \note The opx provider asserts the following mode bits which affect
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
ssize_t fi_opx_ep_rx_recvmsg_internal (struct fi_opx_ep *opx_ep,
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
		union fi_opx_context * opx_context =
			(union fi_opx_context *) msg->context;

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
		assert(len >= (sizeof(union fi_opx_context) + opx_ep->rx->min_multi_recv));
		opx_context->flags = FI_MULTI_RECV;
		opx_context->len = len - sizeof(union fi_opx_context);
		opx_context->buf = (void *)((uintptr_t)base + sizeof(union fi_opx_context));
		opx_context->next = NULL;
		if (av_type == FI_AV_TABLE) {	/* constant compile-time expression */
			const fi_addr_t msg_addr = msg->addr;
			opx_context->src_addr =
				(OFI_LIKELY(msg_addr != FI_ADDR_UNSPEC)) ?
					opx_ep->rx->av_addr[msg_addr].fi :
					(fi_addr_t)-1;
		} else {
			opx_context->src_addr = msg->addr;
		}
		opx_context->byte_counter = 0;
		opx_context->multi_recv_next = (union fi_opx_context *)base;
		opx_context->ignore = (uint64_t)-1;

		context_rsh3b = (uint64_t)opx_context >> 3;
		rx_op_flags = flags;

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	} else if (msg->iov_count == 0) {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

		assert(msg->context);
		assert(((uintptr_t)msg->context & 0x07ull) == 0);	/* must be 8 byte aligned */

		union fi_opx_context * opx_context =
			(union fi_opx_context *) msg->context;
		opx_context->flags = flags;
		opx_context->len = 0;
		opx_context->buf = NULL;
		opx_context->next = NULL;

		if (av_type == FI_AV_TABLE) {	/* constant compile-time expression */
			const fi_addr_t msg_addr = msg->addr;
			opx_context->src_addr =
				(OFI_LIKELY(msg_addr != FI_ADDR_UNSPEC)) ?
					opx_ep->rx->av_addr[msg_addr].fi :
					(fi_addr_t)-1;
		} else {
			opx_context->src_addr = msg->addr;
		}
		opx_context->tag = 0;
		opx_context->ignore = (uint64_t)-1;
		opx_context->byte_counter = (uint64_t)-1;

		context_rsh3b = (uint64_t)opx_context >> 3;
		rx_op_flags = flags;

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	} else if (msg->iov_count == 1) {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
		assert(msg->context);
		assert(((uintptr_t)msg->context & 0x07ull) == 0);	/* must be 8 byte aligned */

		union fi_opx_context * opx_context =
			(union fi_opx_context *) msg->context;
		opx_context->flags = flags;
		opx_context->len = msg->msg_iov[0].iov_len;
		opx_context->buf = msg->msg_iov[0].iov_base;

		if (av_type == FI_AV_TABLE) {	/* constand compile-time expression */
			const fi_addr_t msg_addr = msg->addr;
			opx_context->src_addr =
				(OFI_LIKELY(msg_addr != FI_ADDR_UNSPEC)) ?
					opx_ep->rx->av_addr[msg_addr].fi :
					(fi_addr_t)-1;
		} else {
			opx_context->src_addr = msg->addr;
		}
		opx_context->tag = 0;
		opx_context->ignore = (uint64_t)-1;
		opx_context->byte_counter = (uint64_t)-1;

		context_rsh3b = (uint64_t)opx_context >> 3;
		rx_op_flags = flags;

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	} else {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
		struct fi_opx_context_ext * ext;
		posix_memalign((void**)&ext, 32, sizeof(struct fi_opx_context_ext));

		ext->opx_context.flags = flags | FI_OPX_CQ_CONTEXT_EXT;
		ext->opx_context.byte_counter = (uint64_t)-1;

		if (av_type == FI_AV_TABLE) {	/* constant compile-time expression */
			const fi_addr_t msg_addr = msg->addr;
			ext->opx_context.src_addr =
				(OFI_LIKELY(msg_addr != FI_ADDR_UNSPEC)) ?
					opx_ep->rx->av_addr[msg_addr].fi :
					(fi_addr_t)-1;
		} else {
			ext->opx_context.src_addr = msg->addr;
		}
		ext->opx_context.tag = 0;
		ext->opx_context.ignore = (uint64_t)-1;
		ext->msg.op_context = (struct fi_context *)msg->context;
		ext->msg.iov_count = msg->iov_count;
		ext->msg.iov = (struct iovec *)msg->msg_iov;

		context_rsh3b = (uint64_t)ext >> 3;
		rx_op_flags = flags | FI_OPX_CQ_CONTEXT_EXT;
		if (IS_PROGRESS_MANUAL(opx_ep->rx->domain)) {

			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }

			fi_opx_ep_rx_process_context(opx_ep,
				FI_MSG,
				0,  /* cancel_context */
				(union fi_opx_context *)(context_rsh3b << 3),
				rx_op_flags,
				1,  /* is_context_ext */
				lock_required,
				av_type,
				reliability);

			return 0;
		}
	}
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

	if (IS_PROGRESS_MANUAL(opx_ep->rx->domain)) {
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

		if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
		fi_opx_ep_rx_process_context(opx_ep,
			FI_MSG,
			0,  /* cancel_context */
			(union fi_opx_context *)(context_rsh3b << 3),
			rx_op_flags,
			0,  /* is_context_ext */
			lock_required,
			av_type,
			reliability);
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	} else {
		abort();
	}
//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

	return 0;
}

#ifndef FI_OPX_EP_TX_SEND_EAGER_MAX_RETRIES
#define FI_OPX_EP_TX_SEND_EAGER_MAX_RETRIES 0x200000
#endif

__OPX_FORCE_INLINE_AND_FLATTEN__
ssize_t fi_opx_ep_tx_send_try_eager(struct fid_ep *ep,
				const void *buf, size_t len, void *desc,
				const union fi_opx_addr addr, uint64_t tag, void *context,
				const struct iovec *local_iov, size_t niov, size_t total_len,
				const uint32_t data,
				const int lock_required,
				const unsigned is_contiguous,
				const unsigned override_flags,
				uint64_t tx_op_flags,
				const uint64_t caps,
				const enum ofi_reliability_kind reliability)
{
	ssize_t rc;

	if(is_contiguous) {
		rc = FI_OPX_FABRIC_TX_SEND_EGR(ep, buf, len,
						desc, addr.fi, tag, context, data,
						lock_required,
						override_flags, tx_op_flags, addr.hfi1_rx,
						caps, reliability);
	} else {
		rc = FI_OPX_FABRIC_TX_SENDV_EGR(ep, local_iov, niov, total_len,
						desc, addr.fi, tag, context, data,
						lock_required,
						override_flags, tx_op_flags, addr.hfi1_rx,
						caps, reliability);
	}

	if (OFI_LIKELY(rc != -FI_ENOBUFS)) {
		return rc;
	}

	fi_opx_force_credit_return(ep, addr.fi, addr.hfi1_rx, caps);

	uint64_t loop = 0;
	do {
		if(is_contiguous) {
			rc = FI_OPX_FABRIC_TX_SEND_EGR(ep, buf, len,
							desc, addr.fi, tag, context, data,
							lock_required,
							override_flags, tx_op_flags, addr.hfi1_rx,
							caps, reliability);
		} else {
			rc = FI_OPX_FABRIC_TX_SENDV_EGR(ep, local_iov, niov, total_len,
							desc, addr.fi, tag, context, data,
							lock_required,
							override_flags, tx_op_flags, addr.hfi1_rx,
							caps, reliability);
		}
	} while (rc == -FI_ENOBUFS && loop++ < FI_OPX_EP_TX_SEND_EAGER_MAX_RETRIES);

	if (rc == -FI_ENOBUFS) {
		return -FI_EAGAIN;
	}

	return rc;
}

static inline
ssize_t fi_opx_ep_tx_send_internal (struct fid_ep *ep,
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
	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
		"===================================== SEND (begin)\n");

	assert(is_contiguous == 0 || is_contiguous == 1);

	struct fi_opx_ep *opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);

#ifndef NDEBUG
	ssize_t ret;
	ret = fi_opx_ep_tx_check(opx_ep->tx, av_type);
	if (ret) return ret;
#endif

	assert(dest_addr != FI_ADDR_UNSPEC);

	const union fi_opx_addr addr = {
		.fi = (av_type == FI_AV_TABLE) ?	/* constant compile-time expression */
			opx_ep->tx->av_addr[dest_addr].fi :
			dest_addr
	};
	size_t total_len = len;
	const struct iovec *local_iov = NULL;
	size_t niov = 0;
	if(!is_contiguous) { /* constant compile time expression */
		ssize_t i;
		local_iov = buf;
		niov = len;
		total_len = 0;
		for(i=0; i < niov; i++) {
			total_len += local_iov[i].iov_len;
		}
	}

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

	const uint64_t selective_completion = FI_SELECTIVE_COMPLETION | FI_TRANSMIT | FI_COMPLETION;

	const uint64_t do_cq_completion = override_flags == 0 ?
			opx_ep->tx->do_cq_completion :		/* calculated at bind */
			((((tx_op_flags | opx_ep->tx->cq_bind_flags) & selective_completion) == selective_completion) ||
			 (((tx_op_flags | opx_ep->tx->cq_bind_flags) & (FI_SELECTIVE_COMPLETION | FI_TRANSMIT)) == FI_TRANSMIT));

	ssize_t rc = 0;

	if (total_len <= opx_ep->tx->pio_max_eager_tx_bytes) {

		rc = fi_opx_ep_tx_send_try_eager(ep, buf, len, desc, addr, tag, context, local_iov,
						niov, total_len, data, lock_required, is_contiguous,
						override_flags, tx_op_flags, caps, reliability);
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

		if (OFI_LIKELY(do_cq_completion != 0) && rc == FI_SUCCESS) {
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
			union fi_opx_context * opx_context = (union fi_opx_context *)context;
			opx_context->flags =  FI_SEND | (caps & (FI_TAGGED | FI_MSG));
			opx_context->len = total_len;
			opx_context->buf = NULL;
			opx_context->byte_counter = total_len;
			opx_context->tag = tag;
			opx_context->next = NULL;

			if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
			fi_opx_context_slist_insert_tail(opx_context, opx_ep->tx->cq_completed_ptr);

			return rc;
		} else if (OFI_LIKELY(rc == FI_SUCCESS)) {
			return rc;
		}
	}

	uintptr_t byte_counter_ptr;
	uint64_t *byte_counter;
	uint64_t tmp;

	union fi_opx_context * opx_context = (union fi_opx_context *)context;

	if (OFI_LIKELY(do_cq_completion != 0)) {
		assert(context);
		assert(((uintptr_t)context & 0x07ull) == 0);	/* must be 8 byte aligned */

		byte_counter_ptr = (uintptr_t) &opx_context->byte_counter;
		byte_counter = (uint64_t *) &opx_context->byte_counter;
	} else {
		byte_counter_ptr = (uintptr_t) NULL;
		byte_counter = (uint64_t *) &tmp;
	}

	do {
		if (is_contiguous) {
			rc = FI_OPX_FABRIC_TX_SEND_RZV(
				ep, buf, len, desc, addr.fi, tag, context, data,
				lock_required, override_flags, tx_op_flags, addr.hfi1_rx,
				byte_counter_ptr,
				byte_counter,
				caps, reliability);
		} else {
			rc = FI_OPX_FABRIC_TX_SENDV_RZV(
				ep, local_iov, niov, total_len, desc, addr.fi, tag,
				context, data, lock_required, override_flags, tx_op_flags,
				addr.hfi1_rx,
				byte_counter_ptr,
				byte_counter,
				caps, reliability);
		}
		if (OFI_UNLIKELY(rc == -EAGAIN)) {
			fi_opx_ep_rx_poll(&opx_ep->ep_fid, 0, OPX_RELIABILITY, FI_OPX_HDRQ_MASK_RUNTIME);
		}
	} while (rc == -EAGAIN);

	if (OFI_LIKELY(do_cq_completion != 0)) {
		/* initialize the completion entry */
		opx_context->flags =  FI_SEND | (caps & (FI_TAGGED | FI_MSG));
		opx_context->len = len;
		opx_context->buf = NULL;
		opx_context->tag = tag;
		opx_context->next = NULL;

		if (lock_required) { fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort(); }
		fi_opx_context_slist_insert_tail(opx_context, opx_ep->tx->cq_pending_ptr);

	}

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
		"===================================== SEND (end)\n");

	return rc;
}

__OPX_FORCE_INLINE__
ssize_t fi_opx_ep_tx_send(struct fid_ep *ep,
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
	struct fi_opx_ep *opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);

	fi_opx_lock_if_required(&opx_ep->lock, lock_required);

	ssize_t rc = fi_opx_ep_tx_send_internal(ep, buf, len, desc, dest_addr,
						tag, context, data, FI_OPX_LOCK_NOT_REQUIRED, av_type,
						is_contiguous, override_flags,
						tx_op_flags, caps, reliability);

	fi_opx_unlock_if_required(&opx_ep->lock, lock_required);

	return rc;
}


__OPX_FORCE_INLINE__
ssize_t fi_opx_ep_tx_inject_internal (struct fid_ep *ep,
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
	// This message check is a workaround for some versions of MPI
	// that do not check or enforce inject limits for FI_MSG
	// Remove this workaround when MPI's are upgraded to obey these limits
	if(caps & FI_MSG && len > FI_OPX_HFI1_PACKET_IMM) {
		FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
					 "Downgrading inject to eager due to > inject limit (begin)\n");

		return fi_opx_ep_tx_send_internal (ep, buf, len, NULL, dest_addr, tag,
						   NULL, // context
						   0, // data
						   lock_required,
						   av_type,
						   1, //contiguous
						   1, // override for now completion
						   FI_SELECTIVE_COMPLETION, // op flags to turn off context
						   caps,
						   reliability);
	} else {
		assert(len <= FI_OPX_HFI1_PACKET_IMM);
	}

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
		"===================================== INJECT (begin)\n");

	struct fi_opx_ep *opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);

#ifndef NDEBUG
	ssize_t ret;
	ret = fi_opx_ep_tx_check(opx_ep->tx, av_type);
	if (ret) return ret;
#endif
	assert(dest_addr != FI_ADDR_UNSPEC);

	const union fi_opx_addr addr = {
		.fi = (av_type == FI_AV_TABLE) ?	/* constant compile-time expression */
			opx_ep->tx->av_addr[dest_addr].fi :
			dest_addr
	};

	const ssize_t rc = FI_OPX_FABRIC_TX_INJECT(ep, buf, len, addr.fi, tag, data,
			lock_required, addr.hfi1_rx, caps, reliability);

	if (OFI_UNLIKELY(rc == -EAGAIN)) {
		// In this case we are probably out of replay buffers. To deal
		// with this, we do a poll which may send a ping and will
		// process any incoming ACKs, hopefully releasing a buffer for
		// reuse.
		fi_opx_ep_rx_poll(&opx_ep->ep_fid, 0, OPX_RELIABILITY,
			FI_OPX_HDRQ_MASK_RUNTIME);
	}    

	FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA,
		"===================================== INJECT (end)\n");

	return rc;
}

__OPX_FORCE_INLINE__
ssize_t fi_opx_ep_tx_inject(struct fid_ep *ep,
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
	struct fi_opx_ep *opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);

	fi_opx_lock_if_required(&opx_ep->lock, lock_required);

	ssize_t rc = fi_opx_ep_tx_inject_internal(ep, buf, len, dest_addr, tag,
						  data, FI_OPX_LOCK_NOT_REQUIRED, av_type,
						  caps, reliability);

	fi_opx_unlock_if_required(&opx_ep->lock, lock_required);

	return rc;
}

__OPX_FORCE_INLINE_AND_FLATTEN__
ssize_t fi_opx_recv_generic(struct fid_ep *ep,
			    void *buf, size_t len, void *desc,
			    fi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context,
			    const int lock_required, const enum fi_av_type av_type,
			    const uint64_t static_flags,
			    const enum ofi_reliability_kind reliability)
{
	struct fi_opx_ep *opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);

	fi_opx_lock_if_required(&opx_ep->lock, lock_required);
	ssize_t rc = fi_opx_ep_rx_recv_internal(opx_ep, buf, len, desc, src_addr, tag,
						ignore, context, FI_OPX_LOCK_NOT_REQUIRED, av_type,
						static_flags, reliability);
	fi_opx_unlock_if_required(&opx_ep->lock, lock_required);

	return rc;
}

__OPX_FORCE_INLINE_AND_FLATTEN__
ssize_t fi_opx_recvmsg_generic(struct fid_ep *ep,
			       const struct fi_msg *msg, uint64_t flags,
			       const int lock_required, const enum fi_av_type av_type,
			       const enum ofi_reliability_kind reliability)
{
	struct fi_opx_ep *opx_ep = container_of(ep, struct fi_opx_ep, ep_fid);

	fi_opx_lock_if_required(&opx_ep->lock, lock_required);
	ssize_t rc = fi_opx_ep_rx_recvmsg_internal(opx_ep, msg, flags, FI_OPX_LOCK_NOT_REQUIRED, av_type, reliability);
	fi_opx_unlock_if_required(&opx_ep->lock, lock_required);

	return rc;
}


#endif /* _FI_PROV_OPX_ENDPOINT_H_ */
