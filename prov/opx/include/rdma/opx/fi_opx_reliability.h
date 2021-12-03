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
#ifndef _FI_PROV_OPX_RELIABILITY_H_
#define _FI_PROV_OPX_RELIABILITY_H_

#include "rdma/opx/fi_opx.h"
#include "rdma/opx/fi_opx_hfi1.h"
#include "rbtree.h"
#include "ofi_lock.h"
#include <ofi_mem.h>
#include "uthash.h"

#include "rdma/opx/fi_opx_atomic_fifo.h"
#include "rdma/opx/fi_opx_timer.h"

enum ofi_reliability_kind {
	OFI_RELIABILITY_KIND_NONE = 0,
	OFI_RELIABILITY_KIND_OFFLOAD,
	OFI_RELIABILITY_KIND_ONLOAD,
	OFI_RELIABILITY_KIND_RUNTIME,
	OFI_RELIABILITY_KIND_COUNT,
	OFI_RELIABILITY_KIND_UNSET,
};

/* #define SKIP_RELIABILITY_PROTOCOL_RX */
/* #define SKIP_RELIABILITY_PROTOCOL_TX */
/* #define OPX_RELIABILITY_DEBUG */
/* #define OPX_RELIABILITY_TEST */

#ifdef OPX_RELIABILITY_TEST
#define FI_OPX_RELIABILITY_RX_DROP_PACKET(x,y)	fi_opx_reliability_rx_drop_packet(x,y)
#else
#define FI_OPX_RELIABILITY_RX_DROP_PACKET(x,y)	(0)
#endif

#define PENDING_RX_RELIABLITY_COUNT_MAX (1024)  // Max depth of the pending Rx reliablity pool

/* This controls how many packets are sequentially delivered in a flow
   before proactively acking the sender back.  This should throttle
   the sender's request for flow reconsiliation at intervals and allow
   us to use exponential backoff of the timer on the sender
   The current value (16) is chosen from best practices in UDP
   (see examples like UDT) and other unreliable protocols, but may
   need further tuning or application level controls for best performance
   all around
*/
#define FI_OPX_NORMAL_ACK_RATE (16)

struct fi_opx_completion_counter {
		ssize_t byte_counter;
		struct fi_opx_cntr *cntr;
		struct fi_opx_cq *cq;
		union fi_opx_context *context;
		void (*hit_zero)(struct fi_opx_completion_counter*);
};

struct fi_opx_reliability_service {

	struct fi_opx_atomic_fifo			fifo;		/* 27 qws = 216 bytes */
	uint32_t					usec_max;
	uint64_t					usec_next;
	uint8_t						fifo_max;
	uint8_t						hfi1_max;

	struct {
		union fi_opx_timer_state		timer;		/*  2 qws =  16 bytes */
		RbtHandle				flow;		/*  1 qw  =   8 bytes */
		union fi_opx_timer_stamp		timestamp;

	/* == CACHE LINE == */

		struct {
			union fi_opx_hfi1_pio_state *	pio_state;
			volatile uint64_t *		pio_scb_sop_first;
			volatile uint64_t *		pio_credits_addr;
			volatile uint64_t *		pio_scb_first;
			struct fi_opx_hfi1_txe_scb	ping_model;	/* first 4 qws of this scb model are in 'CACHE LINE x' */
			struct fi_opx_hfi1_txe_scb	ack_model;	/* first 4 qws of this scb model are in 'CACHE LINE y' */
			struct fi_opx_hfi1_txe_scb	nack_model;	/* first 4 qws of this scb model are in 'CACHE LINE z' */

			uint64_t			unused_cacheline[4];
		} hfi1;
	} tx;

	/* == CACHE LINE == */

	struct {

		RbtHandle				flow;		/*  1 qw  =   8 bytes */
		struct {

			struct fi_opx_hfi1_rxe_state	state;		/*  2 qws =  16 bytes */

			struct {
				uint32_t *		rhf_base;
				volatile uint64_t *	head_register;
			} hdrq;

			/* -- not critical; can be moved to another cacheline */

			struct {
				uint32_t *		base_addr;
				uint32_t		elemsz;
				uint32_t		last_egrbfr_index;
				volatile uint64_t *	head_register;
			} egrq;
		} hfi1;
	} rx;

	struct fi_opx_hfi1_context *	context;
	volatile uint64_t		enabled;
	volatile uint64_t		active;
	pthread_t			thread;
	int				is_backoff_enabled;
	uint64_t			backoff_period;
	enum ofi_reliability_kind	reliability_kind;
	uint32_t			lid_be;
	struct ofi_bufpool 			*pending_rx_reliability_pool;
	struct fi_opx_pending_rx_reliability_op		*pending_rx_reliability_ops_hashmap;

} __attribute__((__aligned__(64)));


union fi_opx_reliability_service_flow_key {
	uint64_t		value;
	uint32_t		value32b[2];
	struct {
		uint32_t	slid	: 24;
		uint32_t	tx	:  8;
		uint32_t	dlid	: 24;
		uint32_t	rx	:  8;
	} __attribute__((__packed__));
};


struct fi_opx_reliability_flow {
	//fastlock_t					lock;
	uint64_t					next_psn;
	union fi_opx_reliability_service_flow_key	key;
	struct fi_opx_reliability_rx_uepkt *		uepkt;
};

struct fi_opx_pending_rx_reliability_op_key {
	uint64_t		key;
	uint64_t 		psn_start;
};

struct fi_opx_pending_rx_reliability_op {
	struct fi_opx_pending_rx_reliability_op_key key;
	uint64_t 		psn_count;
	uint64_t 		psn_count_coalesce;
	uint64_t		slid;
	uint64_t 		rx;
	uint64_t		ud_opcode;  // Only needs to be uint8_t
	UT_hash_handle 	hh;         /* makes this structure hashable */
};


struct fi_opx_reliability_tx_replay {
	struct fi_opx_reliability_tx_replay		*next;
	struct fi_opx_reliability_tx_replay		*prev;
	uint64_t target_reliability_rx;
	uint64_t unused; 
	union fi_opx_reliability_tx_psn *psn_ptr;
	struct fi_opx_completion_counter  *cc_ptr;
	uint64_t					cc_dec;

	/* --- MUST BE 64 BYTE ALIGNED --- */

	struct fi_opx_hfi1_txe_scb			scb;
	uint64_t					payload[1024+8];

} __attribute__((__aligned__(64)));

// Begin rbtree implementation
// Import and inline data structures from the red-black tree implementation
// The RBTree functions cause a fairly large loss of message rate
// as the message rate code is instruction bound and the out of line implementations
// are small  These data structures mirror the out of line implementations
// but if those ever change, we need to update our copies of this
// or lobby for an interface change to rb tree to allow for inline implementations
// On skylake 18 core pairs, the rbtree implementation leads to a loss of about
// 10 mmps by not being in lined
// These substitute inline functions are copies of the implementation in rbtree.c
typedef enum { BLACK, RED } NodeColor;

typedef struct NodeTag {
        struct NodeTag *left;       // left child
        struct NodeTag *right;      // right child
        struct NodeTag *parent;     // parent
        NodeColor color;            // node color (BLACK, RED)
        void *key;                  // key used for searching
        void *val;                // user data
} NodeType;

typedef struct RbtTag {
        NodeType *root;   // root of red-black tree
        NodeType sentinel;
        int (*compare)(void *a, void *b);    // compare keys
} RbtType;

__OPX_FORCE_INLINE__
int fi_opx_reliability_compare (void *a, void *b) {

        const uintptr_t a_key = (uintptr_t)a;
        const uintptr_t b_key = (uintptr_t)b;

        if (a_key > b_key) return 1;
        if (a_key < b_key) return -1;

        return 0;
}

__OPX_FORCE_INLINE__
void *fi_opx_rbt_find(RbtHandle h, void *key) {
        RbtType *rbt = h;
        NodeType *current;
        current = rbt->root;
        while(current != &rbt->sentinel) {
                int rc = fi_opx_reliability_compare(key, current->key);
                if (rc == 0) return current;
                current = (rc < 0) ? current->left : current->right;
        }
        return NULL;
}

__OPX_FORCE_INLINE__
void ** fi_opx_rbt_value_ptr(RbtHandle h, RbtIterator it) {
        NodeType *i = it;

        return &i->val;
}

__OPX_FORCE_INLINE__
RbtIterator fi_opx_rbt_begin(RbtHandle h) {
        RbtType *rbt = h;

        // return pointer to first value
        NodeType *i;
        for (i = rbt->root; i->left != &rbt->sentinel; i = i->left);
        return i != &rbt->sentinel ? i : NULL;
}

__OPX_FORCE_INLINE__
void fi_opx_rbt_key_value(RbtHandle h, RbtIterator it, void **key, void **val) {
        NodeType *i = it;

        *key = i->key;
        *val = i->val;
}

/*
 * Initialize the reliability service - and pthread
 *
 * \return reliability service hfi1 rx identifier
 */
uint8_t fi_opx_reliability_service_init (struct fi_opx_reliability_service * service, uuid_t unique_job_key,
		struct fi_opx_hfi1_context * hfi1,
		const enum ofi_reliability_kind reliability_kind);
void fi_opx_reliability_service_fini (struct fi_opx_reliability_service * service);

void fi_reliability_service_ping_remote (struct fid_ep *ep, struct fi_opx_reliability_service * service);
unsigned fi_opx_reliability_service_poll_hfi1 (struct fid_ep *ep, struct fi_opx_reliability_service * service);

static inline
void fi_reliability_service_process_command (struct fi_opx_reliability_service * service,
		struct fi_opx_reliability_tx_replay * replay) {

	union fi_opx_reliability_service_flow_key key = {
		.slid = replay->scb.hdr.stl.lrh.slid,
		.tx = replay->scb.hdr.reliability.origin_tx,
		.dlid = replay->scb.hdr.stl.lrh.dlid,
		.rx = replay->scb.hdr.stl.bth.rx
	};

	void * itr = NULL;

#ifdef OPX_RELIABILITY_DEBUG
	fprintf(stderr, "(tx) packet %016lx %08u posted.\n", key.value, replay->scb.hdr.reliability.psn);
#endif

	/* search for existing unack'd flows */
	itr = fi_opx_rbt_find(service->tx.flow, (void*)key.value);
	if (OFI_UNLIKELY((itr == NULL))) {

		/* did not find an existing flow */
		replay->prev = replay;
		replay->next = replay;

		rbtInsert(service->tx.flow, (void*)key.value, (void*)replay);

	} else {

		struct fi_opx_reliability_tx_replay ** value_ptr =
			(struct fi_opx_reliability_tx_replay **) fi_opx_rbt_value_ptr(service->tx.flow, itr);

		struct fi_opx_reliability_tx_replay * head = *value_ptr;

		if (head == NULL) {

			/* the existing flow does not have any un-ack'd replay buffers */
			replay->prev = replay;
			replay->next = replay;
			*value_ptr = replay;

		} else {

			/* insert this replay at the end of the list */
			replay->prev = head->prev;
			replay->next = head;
			head->prev->next = replay;
			head->prev = replay;
		}
	}

	return;
}



#define RX_CMD	(0x0000000000000008ul)
#define TX_CMD	(0x0000000000000010ul)


#define FI_OPX_RELIABILITY_EXCEPTION	(0)
#define FI_OPX_RELIABILITY_EXPECTED	(1)


struct fi_opx_reliability_rx_uepkt {
	struct fi_opx_reliability_rx_uepkt *	prev;
	struct fi_opx_reliability_rx_uepkt *	next;
	uint64_t				psn;
	uint64_t				unused_0[5];

	/* == CACHE LINE == */

	uint64_t				unused_1;
	union fi_opx_hfi1_packet_hdr		hdr;	/* 56 bytes */

	/* == CACHE LINE == */

	uint8_t					payload[0];

} __attribute__((__packed__)) __attribute__((aligned(64)));

union fi_opx_reliability_tx_psn {
	uint64_t value;
	struct {
	uint64_t				psn:24;
	uint64_t				throttle:8;
	uint64_t				nack_count:8;
	uint64_t                bytes_outstanding:24;
	} psn;
} __attribute__((__packed__));
 
// TODO - make these tunable.
#define FI_OPX_RELIABILITY_TX_REPLAY_BLOCKS		(2048)
#define FI_OPX_RELIABILITY_TX_RESERVE_BLOCKS	(64)

struct fi_opx_reliability_client_state {

	union {
		enum ofi_reliability_kind		kind;			/* runtime check for fi_cq_read(), etc */
		uint64_t				pad;
	};
	// 8 bytes
	struct fi_opx_atomic_fifo_producer		fifo;			/* 6 qws = 48 bytes; only for OFI_RELIABILITY_KIND_OFFLOAD */
	// 56 bytes
	RbtHandle					tx_flow_rbtree;
	// 64 bytes
	RbtHandle					rx_flow_rbtree;
	// 72 bytes
	struct ofi_bufpool *		replay_pool; // for main data path
	struct ofi_bufpool *		reserve_pool; // when you can't EAGAIN.
	// 88 bytes
	struct fi_opx_reliability_service *		service;
	void (*process_fn)(struct fid_ep *, const union fi_opx_hfi1_packet_hdr * const, const uint8_t * const);
	// 104 bytes
	uint32_t					lid_be;
	uint8_t						tx;
	uint8_t						rx;
	// 110 bytes
	/* -- not critical; only for debug, init/fini, etc. -- */
	uint16_t					drop_count;
	uint16_t					drop_mask;
	enum ofi_reliability_kind			reliability_kind;
	// 118 bytes
} __attribute__((__packed__)) __attribute__((aligned(64)));

void fi_opx_reliability_client_init (struct fi_opx_reliability_client_state * state,
		struct fi_opx_reliability_service * service,
		const uint8_t rx,
		const uint8_t tx,
		void (*process_fn)(struct fid_ep *ep, const union fi_opx_hfi1_packet_hdr * const hdr, const uint8_t * const payload));

unsigned fi_opx_reliability_client_active (struct fi_opx_reliability_client_state * state);

void fi_opx_reliability_client_fini (struct fi_opx_reliability_client_state * state);


#ifdef OPX_RELIABILITY_TEST

#define FI_PSN_TO_DROP 0xfffff0

// Debugging tool that deliberately drops packets.
static inline
uint16_t fi_opx_reliability_rx_drop_packet (struct fi_opx_reliability_client_state * state,
	const union fi_opx_hfi1_packet_hdr *const hdr)
{
/*
 * Two variations of when to drop packets. The first drops a percentage of the
 * incoming packets. The other drops 1 specific packet every 2^24 packets (i.e.
 * according to the incoming PSN.) When debugging a reliability issue you can
 * use either of these or code up something different depending on what you're
 * trying to debug.
 */
#if 0
	// drops a percentage of the packets based on drop_mask.
	const uint16_t tmp = state->drop_count & state->drop_mask;

	if (tmp == 0)
		FI_WARN(fi_opx_global.prov,FI_LOG_EP_DATA, 
			"DEBUG: discarding packet %hu\n", state->drop_count);

	state->drop_count = tmp + 1;
	return !tmp;
#else
	// drops every other version of this packet(so reliability can shove it through)
	const uint64_t psn = hdr->reliability.psn;
	if (psn == FI_PSN_TO_DROP && (state->drop_count == 0)) {
		fprintf(stderr, "Dropping packet %lx\n", psn);
		state->drop_count++;
		return 1;
	} else if (psn == FI_PSN_TO_DROP) {
		fprintf(stderr, "Allowing replay packet %lx\n", psn);
		state->drop_count=0;
	}
	return 0;
#endif
}
#endif

#ifdef OPX_PING_DEBUG
void dump_ping_counts();
#endif

/*
 * returns !0 if this packet is expected (success)
 * returns 0 on exception
 */
static inline
unsigned fi_opx_reliability_rx_check (struct fi_opx_reliability_client_state * state,
		uint64_t slid, uint64_t origin_tx, uint32_t psn)
{
	struct fi_opx_reliability_flow *flow;

	void *itr, *key_ptr;

	const union fi_opx_reliability_service_flow_key key = {
		.slid = slid,
		.tx = origin_tx,
		.dlid = state->lid_be,
		.rx = state->rx
	};

	itr = fi_opx_rbt_find(state->rx_flow_rbtree, (void*)key.value);
	if (OFI_LIKELY((itr != NULL))) {
        fi_opx_rbt_key_value(state->rx_flow_rbtree, itr, &key_ptr, (void **)&flow);

		if (((flow->next_psn & MAX_PSN) == psn) && (flow->uepkt == NULL)) {
#ifdef OPX_RELIABILITY_DEBUG
			fprintf(stderr, "(rx) packet %016lx %08u received.\n", key.value, psn);
#endif
			flow->next_psn += 1;
			return FI_OPX_RELIABILITY_EXPECTED;
		}
	}
	return FI_OPX_RELIABILITY_EXCEPTION;
}








void fi_opx_hfi1_rx_reliability_ping (struct fid_ep *ep,
		struct fi_opx_reliability_service * service,
		const uint64_t key, uint64_t psn_count, uint64_t psn_start,
		const uint64_t slid, const uint64_t rx);


void fi_opx_hfi1_rx_reliability_ack (struct fid_ep *ep,
		struct fi_opx_reliability_service * service,
		const uint64_t key, const uint64_t psn_count, const uint64_t psn_start);

void fi_opx_hfi1_rx_reliability_nack (struct fid_ep *ep,
		struct fi_opx_reliability_service * service,
		const uint64_t key, const uint64_t psn_count, const uint64_t psn_start);













void fi_opx_reliability_rx_exception (struct fi_opx_reliability_client_state * state,
		uint64_t slid, uint64_t origin_tx, uint32_t psn,
		struct fid_ep *ep, const union fi_opx_hfi1_packet_hdr * const hdr, const uint8_t * const payload);

void fi_opx_hfi1_rx_reliability_normal_flow(struct fid_ep *ep, const uint64_t dlid,
					    const uint64_t reliability_rx, const uint64_t psn_start,
					    const uint64_t psn_count,
					    const union fi_opx_hfi1_packet_hdr *const hdr);

__OPX_FORCE_INLINE__
void fi_opx_hfi1_rx_normal_flow(struct fid_ep *ep, const uint64_t dlid,
				const uint64_t reliability_rx,
				const union fi_opx_hfi1_packet_hdr *const hdr)
{
#if 0
	// We have estabalished that these ACKs do not get delivered correctly
	// and only waste bandwidth. Until we figure out how to correctly generate
	// the correct key to use when sending an ACK without a ping, we need
	// to leave this disabled.
	if ((hdr->reliability.psn % FI_OPX_NORMAL_ACK_RATE) == 0 && hdr->reliability.psn > 0) {
		fi_opx_hfi1_rx_reliability_normal_flow(
			ep, dlid, reliability_rx,
			hdr->reliability.psn - FI_OPX_NORMAL_ACK_RATE, /* psn_start */
			FI_OPX_NORMAL_ACK_RATE, /* psn_count */
			hdr);
	}
#endif
}


__OPX_FORCE_INLINE__
int32_t fi_opx_reliability_tx_max_outstanding () {
	// Eager buffer size is 32*262144
	// We'll do 28 * 262144 as a starting point
	// Empirically this survives a message rate test
	// with no packet loss with a single pair
	// in biband
	// TODO:  fetch this from the context info
	// TODO:  This buffer should be dynamically adjusted
	// back when we get a nack, and dyamically adjusted
	// forward when we have nothing outstanding as
	// a starting point for per destination windowing
	// max outstanding could be adjusted to zero until
	// all the packets are replayed, then this can
	// be adjusted back to it's base value.
	// Either way, there should be knobs and controls
	// to make this dynamic when packets are lost
	return 28*262144;
}

__OPX_FORCE_INLINE__
int32_t fi_opx_reliability_tx_max_nacks () {
	// TODO, make this tunable.
	return 0;
}

#ifdef OPX_PING_DEBUG
extern unsigned long throttled;
#define INC_THROTTLE_COUNT throttled++;
#else
#define INC_THROTTLE_COUNT    do {} while(0)
#endif

__OPX_FORCE_INLINE__
int32_t fi_opx_reliability_tx_next_psn (struct fi_opx_reliability_client_state * state,
										 uint64_t lid, uint64_t rx,
										 union fi_opx_reliability_tx_psn **psn_ptr)
{
	uint32_t psn = 0;

	union fi_opx_reliability_service_flow_key key;
	key.slid = state->lid_be;
	key.tx = state->tx;
	key.dlid = lid;
	key.rx = rx;

	void * itr = fi_opx_rbt_find(state->tx_flow_rbtree, (void*)key.value);
	if (!itr) {
		union fi_opx_reliability_tx_psn value;
		value.value = 0; // Initializes the whole union.
		value.psn.psn = 1;
		rbtInsert(state->tx_flow_rbtree, (void*)key.value, (void*)value.value);
		itr = fi_opx_rbt_find(state->tx_flow_rbtree, (void*)key.value);
		*psn_ptr = (union fi_opx_reliability_tx_psn *)fi_opx_rbt_value_ptr(state->tx_flow_rbtree, itr);
	} else {
		*psn_ptr = (union fi_opx_reliability_tx_psn *)fi_opx_rbt_value_ptr(state->tx_flow_rbtree, itr);
		union fi_opx_reliability_tx_psn  psn_value = **psn_ptr;

		/*
		 * We can leverage the fact athat every packet needs a packet sequence
		 * number before it can be sent to implement some simply throttling.
		 *
		 * If the throttle is on, or if the # of bytes outstanding exceeds
		 * a threshold, return an error.
		 */
		if(OFI_UNLIKELY((*psn_ptr)->psn.throttle != 0)) {
			return -1;
		}
		if(OFI_UNLIKELY((*psn_ptr)->psn.nack_count > fi_opx_reliability_tx_max_nacks())) {
			(*psn_ptr)->psn.throttle = 1;
			INC_THROTTLE_COUNT;
			return -1;
		}
		if(OFI_UNLIKELY((*psn_ptr)->psn.bytes_outstanding >
			fi_opx_reliability_tx_max_outstanding())) {
			(*psn_ptr)->psn.throttle = 1;
			INC_THROTTLE_COUNT;
			return -1;
		}

		psn = psn_value.psn.psn;
		(*psn_ptr)->psn.psn = (psn_value.psn.psn + 1) & MAX_PSN;
	}

	return psn;
}

static inline
struct fi_opx_reliability_tx_replay *
fi_opx_reliability_client_replay_allocate(struct fi_opx_reliability_client_state * state,
	const bool allow_grow)
{
	struct fi_opx_reliability_tx_replay * return_value = (struct fi_opx_reliability_tx_replay *)ofi_buf_alloc(state->replay_pool);

	if (OFI_UNLIKELY(return_value == NULL) && allow_grow) {
		return_value = (struct fi_opx_reliability_tx_replay *)ofi_buf_alloc(state->reserve_pool);
	}

	return return_value;
}

static inline
void fi_opx_reliability_client_replay_deallocate(struct fi_opx_reliability_client_state *state __attribute__((unused)),
	struct fi_opx_reliability_tx_replay * replay)
{
#ifdef OPX_RELIABILITY_DEBUG
	replay->next = replay->prev = 0;
#endif
	ofi_buf_free(replay);
}

static inline
void fi_opx_reliability_client_replay_register_no_update (struct fi_opx_reliability_client_state * state,
		const uint16_t dlid, const uint8_t rs, const uint8_t rx, union fi_opx_reliability_tx_psn *psn_ptr,
		struct fi_opx_reliability_tx_replay * replay,
		const enum ofi_reliability_kind reliability_kind)
{
	const uint16_t lrh_pktlen_le = ntohs(replay->scb.hdr.stl.lrh.pktlen);
	const size_t total_bytes = (lrh_pktlen_le - 1) * 4;	/* do not copy the trailing icrc */
	psn_ptr->psn.bytes_outstanding += total_bytes;
	replay->target_reliability_rx = rs;
	replay->psn_ptr = psn_ptr;

	replay->cc_ptr = NULL;
	replay->cc_dec = 0;

	if (reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {			/* constant compile-time expression */

#ifndef NDEBUG
		if ((uint64_t)replay & TX_CMD) { fprintf(stderr, "%s():%d abort\n", __func__, __LINE__); abort(); }
#endif
		/*
		 * ok to block .. the reliability service is completely non-blocking
		 * and will always consume from this atomic fifo
		 */
		fi_opx_atomic_fifo_produce(&state->fifo, (uint64_t)replay | TX_CMD);

	} else if (reliability_kind == OFI_RELIABILITY_KIND_ONLOAD  || reliability_kind == OFI_RELIABILITY_KIND_RUNTIME) {		/* constant compile-time expression */

		fi_reliability_service_process_command(state->service, replay);

	} else {
		fprintf(stderr, "%s():%d abort\n", __func__, __LINE__); abort();
	}

	return;
}


static inline
void fi_opx_reliability_client_replay_register_with_update (struct fi_opx_reliability_client_state * state,
		const uint16_t dlid, const uint8_t rs, const uint8_t rx, union fi_opx_reliability_tx_psn *psn_ptr,
		struct fi_opx_reliability_tx_replay * replay,
		struct fi_opx_completion_counter * counter, uint64_t value,
		const enum ofi_reliability_kind reliability_kind)
{
	const uint16_t lrh_pktlen_le = ntohs(replay->scb.hdr.stl.lrh.pktlen);
	const size_t total_bytes = (lrh_pktlen_le - 1) * 4;	/* do not copy the trailing icrc */
	psn_ptr->psn.bytes_outstanding += total_bytes;
	replay->target_reliability_rx = rs;
	replay->psn_ptr = psn_ptr;
	replay->cc_ptr = counter;
	replay->cc_dec = value;
	/* constant compile-time expression */
	if (reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {

#ifndef NDEBUG
		if ((uint64_t)replay & TX_CMD) { fprintf(stderr, "%s():%d abort\n", __func__, __LINE__); abort(); }
#endif
		/*
		 * ok to block .. the reliability service is completely non-blocking
		 * and will always consume from this atomic fifo
		 */
		fi_opx_atomic_fifo_produce(&state->fifo, (uint64_t)replay | TX_CMD);

	} else if (reliability_kind == OFI_RELIABILITY_KIND_ONLOAD  || reliability_kind == OFI_RELIABILITY_KIND_RUNTIME) {		/* constant compile-time expression */

		fi_reliability_service_process_command(state->service, replay);

	} else {
		fprintf(stderr, "%s():%d abort\n", __func__, __LINE__); abort();
	}

	return;
}

void fi_opx_reliability_service_do_replay (struct fi_opx_reliability_service * service,
										   struct fi_opx_reliability_tx_replay * replay);


void fi_opx_hfi_rx_reliablity_process_requests(struct fid_ep *ep, int max_to_send);



#endif /* _FI_PROV_OPX_RELIABILITY_H_ */
