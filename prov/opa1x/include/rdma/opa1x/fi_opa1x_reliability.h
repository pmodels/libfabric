#ifndef _FI_PROV_OPA1X_RELIABILITY_H_
#define _FI_PROV_OPA1X_RELIABILITY_H_

#include "rdma/opa1x/fi_opa1x_hfi1.h"
#include "rbtree.h"
#include "ofi_lock.h"

#include "rdma/opa1x/fi_opa1x_atomic_fifo.h"
#include "rdma/opa1x/fi_opa1x_timer.h"

enum ofi_reliability_kind {
	OFI_RELIABILITY_KIND_NONE = 0,
	OFI_RELIABILITY_KIND_OFFLOAD,
	OFI_RELIABILITY_KIND_ONLOAD,
	OFI_RELIABILITY_KIND_RUNTIME,
	OFI_RELIABILITY_KIND_COUNT,
	OFI_RELIABILITY_KIND_UNSET,
};


#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif




/* #define SKIP_RELIABILITY_PROTOCOL_RX */
/* #define SKIP_RELIABILITY_PROTOCOL_TX */
/* #define OPA1X_RELIABILITY_DEBUG */
/* #define DO_RELIABILITY_TEST */

#ifdef DO_RELIABILITY_TEST
#define FI_OPA1X_RELIABILITY_RX_DROP_PACKET(x)	fi_opa1x_reliability_rx_drop_packet(x)
#else
#define FI_OPA1X_RELIABILITY_RX_DROP_PACKET(x)	(0)
#endif



struct fi_opa1x_reliability_service {

	struct fi_opa1x_atomic_fifo			fifo;		/* 27 qws = 216 bytes */
	uint16_t					usec_max;
	uint8_t						fifo_max;
	uint8_t						hfi1_max;
	uint8_t						unused[5];

	struct {
		union fi_opa1x_timer_state		timer;		/*  2 qws =  16 bytes */
		RbtHandle				flow;		/*  1 qw  =   8 bytes */
		union fi_opa1x_timer_stamp		timestamp;

	/* == CACHE LINE == */

		struct {
			union fi_opa1x_hfi1_pio_state *	pio_state;
			volatile uint64_t *		pio_scb_sop_first;
			volatile uint64_t *		pio_credits_addr;
			volatile uint64_t *		pio_scb_first;
			struct fi_opa1x_hfi1_txe_scb	ping_model;	/* first 4 qws of this scb model are in 'CACHE LINE x' */
			struct fi_opa1x_hfi1_txe_scb	ack_model;	/* first 4 qws of this scb model are in 'CACHE LINE y' */
			struct fi_opa1x_hfi1_txe_scb	nack_model;	/* first 4 qws of this scb model are in 'CACHE LINE z' */

			uint64_t			unused_cacheline[4];
		} hfi1;
	} tx;

	/* == CACHE LINE == */

	struct {

		RbtHandle				flow;		/*  1 qw  =   8 bytes */
		struct {

			struct fi_opa1x_hfi1_rxe_state	state;		/*  2 qws =  16 bytes */

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

	struct fi_opa1x_hfi1_context *	context;
	volatile uint64_t		enabled;
	volatile uint64_t		active;
	pthread_t			thread;
	int				is_backoff_enabled;
	uint64_t			backoff_period;
	enum ofi_reliability_kind	reliability_kind;
	uint32_t			lid_be;

} __attribute__((__aligned__(64)));


union fi_opa1x_reliability_service_flow_key {
	uint64_t		value;
	uint32_t		value32b[2];
	struct {
		uint32_t	slid	: 24;
		uint32_t	tx	:  8;
		uint32_t	dlid	: 24;
		uint32_t	rx	:  8;
	} __attribute__((__packed__));
};


struct fi_opa1x_reliability_flow {
	fastlock_t					lock;
	uint64_t					next_psn;
	union fi_opa1x_reliability_service_flow_key	key;
	struct fi_opa1x_reliability_rx_uepkt *		uepkt;
};


struct fi_opa1x_reliability_tx_replay {
	struct fi_opa1x_reliability_tx_replay		*next;
	struct fi_opa1x_reliability_tx_replay		*prev;
	volatile uint64_t				active;
	uint64_t					target_reliability_rx;
	uint64_t					nack_count;
	uint64_t					unused;

	volatile uint64_t *				cc_ptr;
	uint64_t					cc_dec;

	/* --- MUST BE 64 BYTE ALIGNED --- */

	struct fi_opa1x_hfi1_txe_scb			scb;
	uint64_t					payload[1024+8];

} __attribute__((__aligned__(64)));













/*
 * Initialize the reliability service - and pthread
 *
 * \return reliability service hfi1 rx identifier
 */
uint8_t fi_opa1x_reliability_service_init (struct fi_opa1x_reliability_service * service, uuid_t unique_job_key,
		struct fi_opa1x_hfi1_context * hfi1,
		const enum ofi_reliability_kind reliability_kind);
void fi_opa1x_reliability_service_fini (struct fi_opa1x_reliability_service * service);

void fi_reliability_service_ping_remote (struct fid_ep *ep, struct fi_opa1x_reliability_service * service);
unsigned fi_opa1x_reliability_service_poll_hfi1 (struct fid_ep *ep, struct fi_opa1x_reliability_service * service);

static inline
void fi_reliability_service_process_command (struct fi_opa1x_reliability_service * service,
		struct fi_opa1x_reliability_tx_replay * replay) {

	union fi_opa1x_reliability_service_flow_key key = {
		.slid = replay->scb.hdr.stl.lrh.slid,
		.tx = replay->scb.hdr.reliability.origin_tx,
		.dlid = replay->scb.hdr.stl.lrh.dlid,
		.rx = replay->scb.hdr.stl.bth.rx
	};

	void * itr = NULL;

#ifdef OPA1X_RELIABILITY_DEBUG
	fprintf(stderr, "(tx) packet %016lx %08u posted.\n", key.value, replay->scb.hdr.reliability.psn);
#endif

	/* search for existing unack'd flows */
	itr = rbtFind(service->tx.flow, (void*)key.value);
	if (unlikely((itr == NULL))) {

		/* did not find an existing flow */
		replay->prev = replay;
		replay->next = replay;

		rbtInsert(service->tx.flow, (void*)key.value, (void*)replay);

	} else {

		struct fi_opa1x_reliability_tx_replay ** value_ptr =
			(struct fi_opa1x_reliability_tx_replay **) rbtValuePtr(service->tx.flow, itr);

		struct fi_opa1x_reliability_tx_replay * head = *value_ptr;

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


#define FI_OPA1X_RELIABILITY_EXCEPTION	(0)
#define FI_OPA1X_RELIABILITY_EXPECTED	(1)


struct fi_opa1x_reliability_rx_uepkt {
	struct fi_opa1x_reliability_rx_uepkt *	prev;
	struct fi_opa1x_reliability_rx_uepkt *	next;
	uint64_t				psn;
	uint64_t				unused_0[5];

	/* == CACHE LINE == */

	uint64_t				unused_1;
	union fi_opa1x_hfi1_packet_hdr		hdr;	/* 56 bytes */

	/* == CACHE LINE == */

	uint8_t					payload[0];

} __attribute__((__packed__)) __attribute__((aligned(64)));





#define FI_OPA1X_RELIABILITY_TX_REPLAY_BLOCKSIZE	(2048)


struct fi_opa1x_reliability_client_state {					/* 14 qws = 112 bytes */

	union {
		enum ofi_reliability_kind		kind;			/* runtime check for fi_cq_read(), etc */
		uint64_t				pad;
	};
	uint32_t					lid_be;
	uint8_t						tx;
	uint8_t						rx;
	uint16_t					replay_head;
	RbtHandle					tx_flow_rbtree;
	RbtHandle					rx_flow_rbtree;
	struct fi_opa1x_reliability_tx_replay *		replay_large;

	struct fi_opa1x_reliability_service *		service;
	void (*process_fn)(struct fid_ep *, const union fi_opa1x_hfi1_packet_hdr * const, const uint8_t * const);

	struct fi_opa1x_atomic_fifo_producer		fifo;			/* 6 qws = 48 bytes; only for OFI_RELIABILITY_KIND_OFFLOAD */

	/* -- not critical; only for debug, init/fini, etc. -- */
	uint16_t					drop_count;
	uint16_t					drop_mask;
	enum ofi_reliability_kind			reliability_kind;
} __attribute__((__packed__));








void fi_opa1x_reliability_client_init (struct fi_opa1x_reliability_client_state * state,
		struct fi_opa1x_reliability_service * service,
		const uint8_t rx,
		const uint8_t tx,
		void (*process_fn)(struct fid_ep *ep, const union fi_opa1x_hfi1_packet_hdr * const hdr, const uint8_t * const payload));

unsigned fi_opa1x_reliability_client_active (struct fi_opa1x_reliability_client_state * state);

void fi_opa1x_reliability_client_fini (struct fi_opa1x_reliability_client_state * state);




static inline
uint16_t fi_opa1x_reliability_rx_drop_packet (struct fi_opa1x_reliability_client_state * state)
{
	const uint16_t tmp = state->drop_count & state->drop_mask;

	if (tmp == 0)
		fprintf(stderr, "%s:%s():%d %s packet %hu\n", __FILE__, __func__, __LINE__, (tmp == 0) ? "drop" : "keep", state->drop_count);

	state->drop_count = tmp + 1;
	return !tmp;
}







/*
 * returns !0 if this packet is expected (success)
 * returns 0 on exception
 */
static inline
unsigned fi_opa1x_reliability_rx_check (struct fi_opa1x_reliability_client_state * state,
		uint64_t slid, uint64_t origin_tx, uint32_t psn)
{
	struct fi_opa1x_reliability_flow *flow;

	void *itr, *key_ptr;

	const union fi_opa1x_reliability_service_flow_key key = {
		.slid = slid,
		.tx = origin_tx,
		.dlid = state->lid_be,
		.rx = state->rx
	};

	itr = rbtFind(state->rx_flow_rbtree, (void*)key.value);
	if (likely((itr != NULL))) {
		rbtKeyValue(state->rx_flow_rbtree, itr, &key_ptr, (void **)&flow);

		if ((flow->next_psn == psn) && (flow->uepkt == NULL)) {
#ifdef OPA1X_RELIABILITY_DEBUG
			fprintf(stderr, "(rx) packet %016lx %08u received.\n", key.value, psn);
#endif
			flow->next_psn += 1;
			return FI_OPA1X_RELIABILITY_EXPECTED;
		}
	}

	return FI_OPA1X_RELIABILITY_EXCEPTION;
}








void fi_opa1x_hfi1_rx_reliability_ping (struct fid_ep *ep,
		struct fi_opa1x_reliability_service * service,
		const uint64_t key, uint64_t psn_count, uint64_t psn_start,
		const uint64_t slid, const uint64_t rx);


void fi_opa1x_hfi1_rx_reliability_ack (struct fid_ep *ep,
		struct fi_opa1x_reliability_service * service,
		const uint64_t key, const uint64_t psn_count, const uint64_t psn_start);

void fi_opa1x_hfi1_rx_reliability_nack (struct fid_ep *ep,
		struct fi_opa1x_reliability_service * service,
		const uint64_t key, const uint64_t psn_count, const uint64_t psn_start);













void fi_opa1x_reliability_rx_exception (struct fi_opa1x_reliability_client_state * state,
		uint64_t slid, uint64_t origin_tx, uint32_t psn,
		struct fid_ep *ep, const union fi_opa1x_hfi1_packet_hdr * const hdr, const uint8_t * const payload);
























static inline
uint32_t fi_opa1x_reliability_tx_next_psn (struct fi_opa1x_reliability_client_state * state,
		uint64_t lid, uint64_t rx)
{
	uint32_t psn = 0;

	union fi_opa1x_reliability_service_flow_key key;
	key.slid = state->lid_be;
	key.tx = state->tx;
	key.dlid = lid;
	key.rx = rx;

	void * itr = rbtFind(state->tx_flow_rbtree, (void*)key.value);
	if (!itr) {
		uintptr_t value = 1;
		rbtInsert(state->tx_flow_rbtree, (void*)key.value, (void*)value);

	} else {
		uintptr_t * const psn_ptr = (uintptr_t *)rbtValuePtr(state->tx_flow_rbtree, itr);
		const uintptr_t psn_value = *psn_ptr;

		psn = (uint32_t) psn_value;
		*psn_ptr = psn_value + 1;

		if (psn == 0x00FFFFFFu) {	/* TODO - how to handle overflow? */
			fprintf(stderr, "%s:%s():%d psn overflow\n", __FILE__, __func__, __LINE__);
			abort();
		}
	}

	return psn;
}


/* #define DONT_BLOCK_REPLAY_ALLOCATE */
static inline
struct fi_opa1x_reliability_tx_replay *
fi_opa1x_reliability_client_replay_allocate(struct fi_opa1x_reliability_client_state * state)
{
	const uint64_t head = state->replay_head;
	state->replay_head = (head + 1) & (FI_OPA1X_RELIABILITY_TX_REPLAY_BLOCKSIZE-1);

	struct fi_opa1x_reliability_tx_replay * replay = &state->replay_large[head];

	/*
	 * FIXME
	 *
	 * DO NOT BLOCK - the fabric may be congested and require this thread
	 * to advance its receive context to pull packets off the wire so the
	 * reliability service threads can inject replay packets, etc!
	 */
#ifdef DONT_BLOCK_REPLAY_ALLOCATE
	unsigned loop = 0;
#endif
	while (replay->active) {
#ifdef DONT_BLOCK_REPLAY_ALLOCATE
		if (++loop > 100000) {
			fprintf(stderr, "%s:%s():%d abort! abort!\n", __FILE__, __func__, __LINE__);
			abort();
		}
#endif
		fi_opa1x_compiler_msync_writes();
	}
	replay->active = 1;

	return replay;
}


static inline
void fi_opa1x_reliability_client_replay_register_no_update (struct fi_opa1x_reliability_client_state * state,
		const uint16_t dlid, const uint8_t rs, const uint8_t rx, const uint64_t psn,
		struct fi_opa1x_reliability_tx_replay * replay,
		const enum ofi_reliability_kind reliability_kind)
{
	replay->target_reliability_rx = rs;
	replay->nack_count = 0;

	replay->cc_ptr = &replay->cc_dec;
	replay->cc_dec = 0;

	if (reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {			/* constant compile-time expression */

#ifndef NDEBUG
		if ((uint64_t)replay & TX_CMD) { fprintf(stderr, "%s():%d abort\n", __func__, __LINE__); abort(); }
#endif
		/*
		 * ok to block .. the reliability service is completely non-blocking
		 * and will always consume from this atomic fifo
		 */
		fi_opa1x_atomic_fifo_produce(&state->fifo, (uint64_t)replay | TX_CMD);

	} else if (reliability_kind == OFI_RELIABILITY_KIND_ONLOAD) {		/* constant compile-time expression */

		fi_reliability_service_process_command(state->service, replay);

	} else {
		fprintf(stderr, "%s():%d abort\n", __func__, __LINE__); abort();
	}

	return;
}


static inline
void fi_opa1x_reliability_client_replay_register_with_update (struct fi_opa1x_reliability_client_state * state,
		const uint16_t dlid, const uint8_t rs, const uint8_t rx, const uint64_t psn,
		struct fi_opa1x_reliability_tx_replay * replay, uint64_t * payload_replay,
		size_t payload_qws_replay, size_t payload_qws_immediate,
		volatile uint64_t * counter, uint64_t value,
		const enum ofi_reliability_kind reliability_kind)
{
	replay->target_reliability_rx = rs;
	replay->nack_count = 0;

	replay->cc_ptr = counter;
	replay->cc_dec = value;

	if (reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {			/* constant compile-time expression */

#ifndef NDEBUG
		if ((uint64_t)replay & TX_CMD) { fprintf(stderr, "%s():%d abort\n", __func__, __LINE__); abort(); }
#endif
		/*
		 * ok to block .. the reliability service is completely non-blocking
		 * and will always consume from this atomic fifo
		 */
		fi_opa1x_atomic_fifo_produce(&state->fifo, (uint64_t)replay | TX_CMD);

	} else if (reliability_kind == OFI_RELIABILITY_KIND_ONLOAD) {		/* constant compile-time expression */

		fi_reliability_service_process_command(state->service, replay);

	} else {
		fprintf(stderr, "%s():%d abort\n", __func__, __LINE__); abort();
	}

	return;
}




#endif /* _FI_PROV_OPA1X_RELIABILITY_H_ */
