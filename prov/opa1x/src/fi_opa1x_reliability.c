
#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

#include "rdma/opa1x/fi_opa1x_reliability.h"

#include "rdma/opa1x/fi_opa1x_compiler.h"


#include <pthread.h>
#include <unistd.h>	/* sleep */
#include <inttypes.h>

#include "rdma/opa1x/fi_opa1x_hfi1.h"
#include "rdma/opa1x/fi_opa1x_endpoint.h"

/* #define SKIP_RELIABILITY_PROTOCOL_RX_IMPL */
/* #define SKIP_RELIABILITY_PROTOCOL_TX_IMPL */

#include <execinfo.h>

#ifndef MIN
#define MIN(a,b) (b^((a^b)&-(a<b)))
#endif


static inline
void dump_backtrace () {

	fprintf(stderr, "==== BACKTRACE ====\n");
	void * addr[100];
	backtrace_symbols_fd(addr, backtrace(addr, 100), 2);
	fprintf(stderr, "==== BACKTRACE ====\n");
	

#if 0
	char ** names;
	names = backtrace_symbols(addr, count);

	fprintf(stderr, "got %zu stack frames\n", count);

	unsigned i;
	for (i=0; i<count; ++i) {
		fprintf(stderr, "  [%016p] %s\n", addr[i], names[i]);
	}

	free(names);
#endif
	return;
}





struct fi_opa1x_reliability_service_range {
	uint64_t		begin;
	uint64_t		end;
};



int fi_opa1x_reliability_compare (void *a, void *b) {

	const uintptr_t a_key = (uintptr_t)a;
	const uintptr_t b_key = (uintptr_t)b;

	if (a_key > b_key) return 1;
	if (a_key < b_key) return -1;

	return 0;
}


/*
 * NOT THREAD-SAFE
 *
 * must acquire the flow lock, via fastlock_acquire(),
 * before reading the uepkt queue.
 */
static inline
void dump_flow_rx (struct fi_opa1x_reliability_flow * flow, const int line) {

	const uint64_t key = flow->key.value;
	uint64_t next_psn = flow->next_psn;

	char debug[2048];
	char * str = debug;
	int size = sizeof(debug)-1;

	debug[0] = 0;
	if (flow->uepkt == NULL) {

		int c = snprintf(str, size, "(empty)");
		str += c;
		size -= c;

	} else {

		struct fi_opa1x_reliability_rx_uepkt * head = flow->uepkt;	/* read again now that queue is locked */

		int c = snprintf(str, size, "%08lu", head->psn);
		str += c;
		size -= c;

		uint64_t start_psn = head->psn;
		uint64_t stop_psn = start_psn;

		struct fi_opa1x_reliability_rx_uepkt * uepkt = head->next;
		while (uepkt != head) {
			if (uepkt->psn != (stop_psn + 1)) {

				if (start_psn != stop_psn) {
					c = snprintf(str, size, "..%08lu, %08lu", stop_psn, uepkt->psn);
				} else {
					c = snprintf(str, size, ", %08lu", uepkt->psn);
				}
				str += c;
				size -= c;

				start_psn = stop_psn = uepkt->psn;

			} else if (uepkt->next == head) {
				if (start_psn != uepkt->psn) {
					c = snprintf(str, size, "..%08lu", uepkt->psn);
				} else {
					c = snprintf(str, size, ", %08lu", uepkt->psn);
				}
				str += c;
				size -= c;

			} else {
				stop_psn++;
			}

			uepkt = uepkt->next;
		}

	}

	if (line) {
		fprintf(stderr, "flow__ %016lx (%d) next_psn = %lu, list: %s\n", key, line, next_psn, debug);
	} else {
		fprintf(stderr, "flow__ %016lx next_psn = %lu, list: %s\n", key, next_psn, debug);
	}
}


static inline
void dump_flow_list (uint64_t key, struct fi_opa1x_reliability_tx_replay * head, int line) {

	char debug[2048];
	char * str = debug;
	int size = sizeof(debug)-1;

	debug[0] = 0;

	if (!head) {

		int c = snprintf(str, size, "(empty)");
		str += c;
		size -= c;

	} else {

		int c = snprintf(str, size, "%08u", (uint32_t)head->scb.hdr.reliability.psn);
		str += c;
		size -= c;

		uint32_t next_psn = (uint32_t)head->scb.hdr.reliability.psn + 1;
		struct fi_opa1x_reliability_tx_replay * replay = head->next;
		while (replay != head) {

			if ((uint32_t)replay->scb.hdr.reliability.psn == next_psn) {
				if (replay->next == head) {

					c = snprintf(str, size, "..%08u", next_psn);
					str += c;
					size -= c;
				}
				next_psn += 1;
			} else {

				c = snprintf(str, size, "..%08u, %08u", next_psn, (uint32_t)replay->scb.hdr.reliability.psn);
				str += c;
				size -= c;
				next_psn = (uint32_t)replay->scb.hdr.reliability.psn + 1;
			}

			replay = replay->next;
		}
	}

	if (line) {
		fprintf(stderr, "flow__ %016lx (%d) list: %s\n", key, line, debug);
	} else {
		fprintf(stderr, "flow__ %016lx list: %s\n", key, debug);
	}
}


static inline
void fi_reliability_service_print_replay_ring (struct fi_opa1x_reliability_tx_replay * head,
		const char * func, const int line) {

	fprintf(stderr, "%s():%d == head = %p\n", func, line, head);
	if (head == NULL) return;

	struct fi_opa1x_reliability_tx_replay * tmp = head;

	do {
		fprintf(stderr, "%s():%d ==  ->    %p (p:%p, n:%p, psn:%u)\n", func, line, tmp, tmp->prev, tmp->next, (uint32_t)tmp->scb.hdr.reliability.psn);
		tmp = tmp->next;
	} while (tmp != head);

	fprintf(stderr, "%s():%d == tail = %p\n", func, line, head->prev);

	return;
}


void fi_opa1x_hfi1_tx_reliability_inject (struct fid_ep *ep,
		const uint64_t key, const uint64_t dlid, const uint64_t reliability_rx,
		const uint64_t psn_start, const uint64_t psn_count,
		const uint64_t opcode)
{
	struct fi_opa1x_ep * opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);

	union fi_opa1x_hfi1_pio_state pio_state = opa1x_ep->tx.pio_state;
	if (unlikely(FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state) < 1)) {
		FI_OPA1X_HFI1_UPDATE_CREDITS(pio_state, opa1x_ep->tx.pio_credits_addr);
		if (FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state) < 1) {

			/*
			 * no credits available
			 *
			 * DO NOT BLOCK - instead, drop this request and allow
			 * the reliability protocol to time out and retransmit
			 */
#ifdef OPA1X_RELIABILITY_DEBUG
			if (opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_PING) {
				fprintf(stderr, "(tx) flow__ %016lx inj ping dropped; no credits\n", key);
			} else if (opcode == FI_OPA1X_UD_BTH_OPCODE_RELIABILITY_ACK) {
				fprintf(stderr, "(rx) flow__ %016lx inj ack dropped; no credits\n", key);
			} else if (opcode == FI_OPA1X_UD_BTH_OPCODE_RELIABILITY_NACK) {
				fprintf(stderr, "(rx) flow__ %016lx inj nack dropped; no credits\n", key);
			} else {
				fprintf(stderr, "%s:%s():%d bad opcode (%lu) .. abort\n", __FILE__, __func__, __LINE__, opcode);
			}
#endif
			return;
		}
	}

#ifdef OPA1X_RELIABILITY_DEBUG
//	fprintf(stderr, "%s():%d psn_start = %lu, psn_count = %lu, opcode = %lu\n", __func__, __LINE__, psn_start, psn_count, opcode);

	const uint64_t psn_stop = psn_start + psn_count - 1;

	if (psn_start > psn_stop) {
		if (opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_PING) {
			fprintf(stderr, "%s:%s():%d (%016lx) invalid inject ping; psn_start = %lu, psn_count = %lu, psn_stop = %lu\n", __FILE__, __func__, __LINE__, key, psn_start, psn_count, psn_stop);
		} else if (opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_ACK) {
			fprintf(stderr, "%s:%s():%d (%016lx) invalid inject ack; psn_start = %lu, psn_count = %lu, psn_stop = %lu\n", __FILE__, __func__, __LINE__, key, psn_start, psn_count, psn_stop);
		} else if (opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_NACK) {
			fprintf(stderr, "%s:%s():%d (%016lx) invalid inject nack; psn_start = %lu, psn_count = %lu, psn_stop = %lu\n", __FILE__, __func__, __LINE__, key, psn_start, psn_count, psn_stop);
		} else {
			fprintf(stderr, "%s:%s():%d bad opcode (%lu) .. abort\n", __FILE__, __func__, __LINE__, opcode);
		}
		abort();
	}

	if (opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_PING) {
		fprintf(stderr, "(tx) flow__ %016lx inj ping %08lu..%08lu\n", key, psn_start, psn_stop);
	} else if (opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_ACK) {
		fprintf(stderr, "(rx) flow__ %016lx inj ack %08lu..%08lu\n", key, psn_start, psn_stop);
	} else if (opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_NACK) {
		fprintf(stderr, "(rx) flow__ %016lx inj nack %08lu..%08lu\n", key, psn_start, psn_stop);
	} else {
		fprintf(stderr, "%s:%s():%d bad opcode (%lu) .. abort\n", __FILE__, __func__, __LINE__, opcode);
	}
#endif

	volatile uint64_t * const scb =
		FI_OPA1X_HFI1_PIO_SCB_HEAD(opa1x_ep->tx.pio_scb_sop_first, pio_state);

	const uint64_t lrh_dlid = dlid << 16;
	const uint64_t bth_rx = reliability_rx << 56;

	const struct fi_opa1x_hfi1_txe_scb * const model =	/* constant compile-time expression */
			opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_PING ?
				&opa1x_ep->reliability_service.tx.hfi1.ping_model :
				( opcode == FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_ACK ?
					&opa1x_ep->reliability_service.tx.hfi1.ack_model :
					&opa1x_ep->reliability_service.tx.hfi1.nack_model );

	//uint64_t tmp[8];
	//tmp[0] =
		scb[0] = model->qw0;
	//tmp[1] =
		scb[1] = model->hdr.qw[0] | lrh_dlid;
	//tmp[2] =
		scb[2] = model->hdr.qw[1] | bth_rx;
	//tmp[3] =
		scb[3] = model->hdr.qw[2];
	//tmp[4] =
		scb[4] = model->hdr.qw[3];
	//tmp[5] =
		scb[5] = psn_count;				/* service.psn_count */
	//tmp[6] =
		scb[6] = psn_start;				/* service.psn_start */
	//tmp[7] =
		scb[7] = key;					/* service.key */

	//fprintf(stderr, "%s():%d pbc: 0x%016lx\n", __func__, __LINE__, tmp[0]);
	//fi_opa1x_hfi1_dump_stl_packet_hdr((struct fi_opa1x_hfi1_stl_packet_hdr *)&tmp[1], __func__, __LINE__);

	fi_opa1x_compiler_msync_writes();

	FI_OPA1X_HFI1_CHECK_CREDITS_FOR_ERROR(opa1x_ep->tx.pio_credits_addr);

	/* consume one credit for the packet header */
	FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

	/* save the updated txe state */
	opa1x_ep->tx.pio_state.qw0 = pio_state.qw0;
}


void fi_opa1x_hfi1_rx_reliability_ping (struct fid_ep *ep,
		struct fi_opa1x_reliability_service * service,
		const uint64_t key, uint64_t psn_count, uint64_t psn_start,
		const uint64_t slid, const uint64_t rx)
{


#ifdef OPA1X_RELIABILITY_DEBUG
	fprintf(stderr, "(rx) flow__ %016lx rcv ping %08lu..%08lu\n", key, hdr->reliability.psn_start, hdr->reliability.psn_start + hdr->reliability.psn_count - 1);
#endif
	void * itr = NULL;
	itr = rbtFind(service->rx.flow, (void*)key);

	if (unlikely((itr == NULL))) {

		/* did not find this flow .... send NACK for psn 0 */
		fi_opa1x_hfi1_tx_reliability_inject(ep,
				key, slid, rx,
				0,	/* psn_start */
				1,	/* psn_count */
				FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_NACK);
		return;
	}

	struct fi_opa1x_reliability_flow ** value_ptr =
		(struct fi_opa1x_reliability_flow **) rbtValuePtr(service->rx.flow, itr);

	struct fi_opa1x_reliability_flow * flow = *value_ptr;

	uint64_t ping_psn_count = psn_count;
	uint64_t ping_start_psn = psn_start;
	const uint64_t ping_stop_psn = ping_start_psn + ping_psn_count - 1;

	struct fi_opa1x_reliability_service_range ping;
	ping.begin = ping_start_psn;
	ping.end = ping_stop_psn;


	if (likely(flow->uepkt == NULL)) {

		/* fast path - no unexpected packets were received */

		//uint64_t ack_start_psn = 0;
		uint64_t ack_stop_psn = flow->next_psn - 1;

//		fprintf(stderr, "%s():%d ping = (%lu, %lu, %lu), ack = (%lu, %lu, %lu)\n", __func__, __LINE__,
//			ping_start_psn, ping_stop_psn, ping_psn_count,
//			ack_start_psn, ack_stop_psn, ack_stop_psn - ack_start_psn + 1);

		if (ping_start_psn <= ack_stop_psn) {

			/* need to ack some, or all, packets in the range
			 * requested by the ping */

			const uint64_t ack_count = ack_stop_psn - ping_start_psn + 1;

//			fprintf(stderr, "%s():%d fast first ack; ping_start_psn = %lu, ack_count = %lu\n", __func__, __LINE__, ping_start_psn, ack_count);

			fi_opa1x_hfi1_tx_reliability_inject(ep,
					key, slid, rx,
					ping_start_psn,		/* psn_start */
					ack_count,		/* psn_count */
					FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_ACK);

			uint64_t update_count = MIN(ack_count, ping_psn_count);	/* do not underflow 'ping_psn_count' */

			ping_start_psn += update_count;
			ping_psn_count -= update_count;
		}


//		fprintf(stderr, "%s():%d ping = (%lu, %lu, %lu)\n", __func__, __LINE__,
//			ping_start_psn, ping_stop_psn, ping_psn_count);

		if (ping_psn_count > 0) {

			/* no unexpected packets have been received; nack the remaining
			 * portion of the range requested by the ping and return */

//			fprintf(stderr, "%s():%d first (and last) nack; ping_start_psn = %lu, ping_psn_count = %lu\n",
//				__func__, __LINE__, ping_start_psn, ping_psn_count);

			fi_opa1x_hfi1_tx_reliability_inject(ep,
					key, slid, rx,
					ping_start_psn,		/* psn_start */
					ping_psn_count,		/* psn_count */
					FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_NACK);
		}

//		fprintf(stderr, "%s():%d fast ping response done\n", __func__, __LINE__);
		return;
	}














//	fi_opa1x_reliability_ticketlock_acquire(&flow->lock);			/* LOCK */
	fastlock_acquire(&flow->lock);

	fi_opa1x_compiler_msync_reads();


	const uint64_t flow_next_psn = flow->next_psn;

	/*dump_flow_rx(flow, __LINE__);*/


	/*
	 * odd index == nack range
	 * even index == ack range
	 */

	const unsigned range_max = 10;
	struct fi_opa1x_reliability_service_range range[range_max];

	unsigned range_count = 1;

	/* initial ack range */
	range[0].begin = 0;
	range[0].end = flow_next_psn - 1;

	const struct fi_opa1x_reliability_rx_uepkt * const head = flow->uepkt;	/* read head again now that queue is locked; avoid race */


//	fprintf(stderr, "%s():%d ping = (%lu, %lu), range[0] = (%lu, %lu), range_count = %u\n", __func__, __LINE__,
//			ping.begin, ping.end, range[0].begin, range[0].end, range_count);

	if (head == NULL) {

		range_count = 2;
		range[1].begin = flow_next_psn;
		range[1].end = (uint64_t)-1;

//		fprintf(stderr, "%s():%d ping = (%lu, %lu), range[%u] = (%lu, %lu), range_count = %u\n", __func__, __LINE__,
//				ping.begin, ping.end, range_count-1, range[range_count-1].begin, range[range_count-1].end, range_count);
	} else {

		struct fi_opa1x_reliability_rx_uepkt * uepkt =
			(struct fi_opa1x_reliability_rx_uepkt *) head;

		/* initial nack range */
		range[range_count].begin = range[range_count-1].end + 1;
		range[range_count].end = uepkt->psn - 1;
		range_count++;
//		fprintf(stderr, "%s():%d ping = (%lu, %lu), range[%u] = (%lu, %lu), range_count = %u\n", __func__, __LINE__,
//				ping.begin, ping.end, range_count-1, range[range_count-1].begin, range[range_count-1].end, range_count);

		/* start next ack range */
		range[range_count].begin = uepkt->psn;
		range[range_count].end = uepkt->psn;
		uepkt = uepkt->next;
//		fprintf(stderr, "%s():%d ping = (%lu, %lu), range[%u] = (%lu, %lu), range_count = %u, uepkt = %p, head = %p\n", __func__, __LINE__,
//				ping.begin, ping.end, range_count, range[range_count].begin, range[range_count].end, range_count, uepkt, head);

		while ((uepkt != head) && (range_count < range_max)) {

			if (uepkt->psn == (range[range_count].end + 1)) {
				range[range_count].end++;
//				fprintf(stderr, "%s():%d ping = (%lu, %lu), range[%u] = (%lu, %lu), range_count = %u, uepkt = %p, head = %p\n", __func__, __LINE__,
//						ping.begin, ping.end, range_count, range[range_count].begin, range[range_count].end, range_count, uepkt, head);
			} else {
				/* nack range */
				range_count++;
				range[range_count].begin = range[range_count-1].end + 1;
				range[range_count].end = uepkt->psn - 1;

//				fprintf(stderr, "%s():%d ping = (%lu, %lu), range[%u] = (%lu, %lu), range_count = %u, range_max = %u\n", __func__, __LINE__,
//						ping.begin, ping.end, range_count, range[range_count].begin, range[range_count].end, range_count, range_max);

				if (range_count < range_max) {
					/* start next ack range */
					range_count++;
					range[range_count].begin = uepkt->psn;
					range[range_count].end = uepkt->psn;
//					fprintf(stderr, "%s():%d ping = (%lu, %lu), range[%u] = (%lu, %lu), range_count = %u, range_max = %u\n", __func__, __LINE__,
//							ping.begin, ping.end, range_count, range[range_count].begin, range[range_count].end, range_count, range_max);
				}
			}
			uepkt = uepkt->next;
		}

		range_count++;

//		fprintf(stderr, "%s():%d range_count = %u, range_max = %u, uepkt = %p, head = %p\n", __func__, __LINE__,
//				range_count, range_max, uepkt, head);

		if ((uepkt == head) && (range_count < range_max)) {

			/* tail nack range */
			range[range_count].begin = range[range_count-1].end + 1;
			range[range_count].end = (uint64_t)-1;
			range_count++;
//			fprintf(stderr, "%s():%d ping = (%lu, %lu), range[%u] = (%lu, %lu), range_count = %u, range_max = %u\n", __func__, __LINE__,
//					ping.begin, ping.end, range_count, range[range_count].begin, range[range_count].end, range_count, range_max);
		}
	}

//	fi_opa1x_reliability_ticketlock_release(&flow->lock);			/* UNLOCK */
	fastlock_release(&flow->lock);

	/* first ack range begins at psn 0 */
	unsigned index = 0;
	uint64_t ping_count = ping.end - ping.begin + 1;


//	fprintf(stderr, "%s():%d ping = (%lu, %lu), index = %u, ping_count = %lu, range_count = %u\n", __func__, __LINE__,
//			ping.begin, ping.end, index, ping_count, range_count);
	

	while ((ping_count > 0) && (index < range_count)) {

//		fprintf(stderr, "%s():%d ping = (%lu, %lu), range[%u] = (%lu, %lu)\n", __func__, __LINE__,
//				ping.begin, ping.end, index, range[index].begin, range[index].end);

		if (ping.begin <= range[index].end) {
			const uint64_t start = ping.begin;
			const uint64_t stop = MIN(ping.end, range[index].end);
			const uint64_t count = stop - start + 1;

			if ((index & 0x01u) == 0) {

				/* even index == ack */
//				fprintf(stderr, "%s():%d ack = (%lu, %lu), count = %lu\n", __func__, __LINE__, start, stop, count);

				fi_opa1x_hfi1_tx_reliability_inject(ep,
						key, slid, rx,
						start,		/* psn_start */
						count,		/* psn_count */
						FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_ACK);
			} else {

				/* odd index == nack */
//				fprintf(stderr, "%s():%d nack = (%lu, %lu), count = %lu\n", __func__, __LINE__, start, stop, count);

				fi_opa1x_hfi1_tx_reliability_inject(ep,
						key, slid, rx,
						start,		/* psn_start */
						count,		/* psn_count */
						FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_NACK);
			}

			ping.begin += count;
			ping_count -= count;
		}

		index++;
	}

//	fprintf(stderr, "%s():%d ping response done\n", __func__, __LINE__);

	return;
}


void fi_opa1x_hfi1_rx_reliability_ack (struct fid_ep *ep,
		struct fi_opa1x_reliability_service * service,
		const uint64_t key, const uint64_t psn_count, const uint64_t psn_start)
{

	const uint64_t stop_psn = psn_start + psn_count - 1;

	//fprintf(stderr, "%s():%d key = %016lx, psn_start = %lu, psn_count = %lu, stop_psn = %lu\n", __func__, __LINE__, key, psn_start, psn_count, stop_psn);

#ifdef OPA1X_RELIABILITY_DEBUG
	fprintf(stderr, "(tx) flow__ %016lx rcv ack  %08lu..%08lu\n", key, psn_start, stop_psn);
#endif
	void * itr = NULL;

	/* search for existing unack'd flows */
	itr = rbtFind(service->tx.flow, (void*)key);
	if (likely((itr != NULL))) {

		struct fi_opa1x_reliability_tx_replay ** value_ptr =
			(struct fi_opa1x_reliability_tx_replay **) rbtValuePtr(service->tx.flow, itr);

		struct fi_opa1x_reliability_tx_replay * head = *value_ptr;

//fprintf(stderr, "%s():%d psn_count = %lu, psn_start = %lu, stop_psn = %lu\n", __func__, __LINE__, psn_count, psn_start, stop_psn);
		if (unlikely(head == NULL)) {

//fprintf(stderr, "%s():%d\n", __func__, __LINE__);
			/*
			 * there are no unack'd elements in the replay queue;
			 * do nothing and return
			 */
			return;
		}

		struct fi_opa1x_reliability_tx_replay * tail = head->prev;

		/*
		 * check for "fast path" - retire all elements in the queue
		 */
//fprintf(stderr, "%s():%d head = %p, head->psn = %lu\n", __func__, __LINE__, head, head->psn);
//fprintf(stderr, "%s():%d tail = %p, tail->psn = %lu\n", __func__, __LINE__, tail, tail->psn);
		if ((head->scb.hdr.reliability.psn >= psn_start) && (tail->scb.hdr.reliability.psn <= stop_psn)) {

			/* retire all queue elements */
			*value_ptr = NULL;
//fprintf(stderr, "%s():%d *value_ptr = %p\n", __func__, __LINE__, *value_ptr);

			struct fi_opa1x_reliability_tx_replay * next = NULL;
			struct fi_opa1x_reliability_tx_replay * tmp = head;

			do {
//fprintf(stderr, "%s():%d tmp = %p\n", __func__, __LINE__, tmp);
#ifdef OPA1X_RELIABILITY_DEBUG
				fprintf(stderr, "(tx) packet %016lx %08u retired.\n", key, tmp->scb.hdr.reliability.psn);
#endif
				next = tmp->next;

				const uint64_t dec = tmp->cc_dec;
				volatile uint64_t * cc_ptr = tmp->cc_ptr;
				*cc_ptr -= dec;

				tmp->active = 0;
				tmp = next;

			} while (tmp != head);
//fprintf(stderr, "%s():%d\n", __func__, __LINE__);

			return;
		}

		/*
		 * find the first replay to ack
		 */

		struct fi_opa1x_reliability_tx_replay * start = head;
//fprintf(stderr, "%s():%d head = %p, head->psn = %lu\n", __func__, __LINE__, head, head->psn);
//fprintf(stderr, "%s():%d tail = %p, tail->psn = %lu\n", __func__, __LINE__, tail, tail->psn);
//fprintf(stderr, "%s():%d start = %p, start->psn = %lu\n", __func__, __LINE__, start, start->psn);
		while ((start->scb.hdr.reliability.psn < psn_start) && (start != tail)) {
//fprintf(stderr, "%s():%d start = %p, start->psn = %lu\n", __func__, __LINE__, start, start->psn);
			start = start->next;
		}

//fprintf(stderr, "%s():%d start = %p, start->psn = %lu\n", __func__, __LINE__, start, start->psn);
		if (unlikely(start->scb.hdr.reliability.psn < psn_start)) {

//fprintf(stderr, "%s():%d\n", __func__, __LINE__);
			/*
			 * all elements in replay queue are 'younger' than the
			 * first psn to retire; do nothing and return
			 */
			return;
		}

		/*
		 * find the last replay to ack
		 */

		struct fi_opa1x_reliability_tx_replay * stop = start;
//fprintf(stderr, "%s():%d head  = %p, head->psn  = %lu\n", __func__, __LINE__, head, head->psn);
//fprintf(stderr, "%s():%d tail  = %p, tail->psn  = %lu\n", __func__, __LINE__, tail, tail->psn);
//fprintf(stderr, "%s():%d start = %p, start->psn = %lu\n", __func__, __LINE__, start, start->psn);
//fprintf(stderr, "%s():%d stop  = %p, stop->psn  = %lu\n", __func__, __LINE__, stop, stop->psn);
		while ((stop->next != head) && (stop->next->scb.hdr.reliability.psn <= stop_psn)) {
//fprintf(stderr, "%s():%d stop  = %p, stop->psn  = %lu\n", __func__, __LINE__, stop, stop->psn);
			stop = stop->next;
		}
//fprintf(stderr, "%s():%d stop  = %p, stop->psn  = %lu\n", __func__, __LINE__, stop, stop->psn);

		if (unlikely(stop->scb.hdr.reliability.psn > stop_psn)) {

//fprintf(stderr, "%s():%d\n", __func__, __LINE__);
			/*
			 * all elements in the replay queue are 'older' than the
			 * last psn to retire; do nothing an return
			 */
			return;
		}


		const struct fi_opa1x_reliability_tx_replay * const halt = stop->next;

		if (start == head) {
			*value_ptr = (struct fi_opa1x_reliability_tx_replay *)halt;
		}
//fprintf(stderr, "%s():%d *value_ptr = %p\n", __func__, __LINE__, *value_ptr);

		/* remove the psn range to ack from the queue */
		start->prev->next = stop->next;
		stop->next->prev = start->prev;

		/*
		 * retire all replay packets between start and stop, inclusive
		 */

		struct fi_opa1x_reliability_tx_replay * tmp = start;
		do {
//fprintf(stderr, "%s():%d tmp = %p\n", __func__, __LINE__, tmp);
#ifdef OPA1X_RELIABILITY_DEBUG
			fprintf(stderr, "(tx) packet %016lx %08u retired.\n", key, tmp->scb.hdr.reliability.psn);
#endif
			struct fi_opa1x_reliability_tx_replay * next = tmp->next;

			const uint64_t dec = tmp->cc_dec;
			volatile uint64_t * cc_ptr = tmp->cc_ptr;
			*cc_ptr -= dec;

			tmp->active = 0;
			tmp = next;

		} while (tmp != halt);
//fprintf(stderr, "%s():%d\n", __func__, __LINE__);
	}
//fprintf(stderr, "%s():%d\n", __func__, __LINE__);

	fi_opa1x_compiler_msync_writes();
}



static inline
void fi_opa1x_reliability_service_do_replay (struct fi_opa1x_reliability_service * service,
		struct fi_opa1x_reliability_tx_replay * replay) {

	/* reported in LRH as the number of 4-byte words in the packet; header + payload + icrc */
	const uint16_t lrh_pktlen_le = ntohs(replay->scb.hdr.stl.lrh.pktlen);
	const size_t total_bytes_to_copy = (lrh_pktlen_le - 1) * 4;	/* do not copy the trailing icrc */
	const size_t payload_bytes_to_copy = total_bytes_to_copy - sizeof(union fi_opa1x_hfi1_packet_hdr);

	uint16_t payload_credits_needed =
		(payload_bytes_to_copy >> 6) +				/* number of full 64-byte blocks of payload */
		((payload_bytes_to_copy & 0x000000000000003Ful) != 0);	/* number of partial 64-byte blocks of payload */

	union fi_opa1x_hfi1_pio_state pio_state;
	uint64_t * const pio_state_ptr = (uint64_t*)service->tx.hfi1.pio_state;
	pio_state.qw0 = *pio_state_ptr;

	FI_OPA1X_HFI1_UPDATE_CREDITS(pio_state, service->tx.hfi1.pio_credits_addr);

#ifdef OPA1X_RELIABILITY_DEBUG
	union fi_opa1x_reliability_service_flow_key key;
	key.slid = (uint32_t)replay->scb.hdr.stl.lrh.slid;
	key.tx = (uint32_t)replay->scb.hdr.reliability.origin_tx;
	key.dlid = (uint32_t)replay->scb.hdr.stl.lrh.dlid;
	key.rx = (uint32_t)replay->scb.hdr.stl.bth.rx;

	//fprintf(stderr, "%s():%d FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state) = %u, payload_credits_needed = %u\n", __func__, __LINE__, FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state), payload_credits_needed);
#endif


	/*
	 * if not enough credits are available, spin a few time and wait for
	 * more credits to free up. if the replay has 8192 bytes of payload
	 * then it will need 129 credits in total, but the total number of
	 * credits is around 160.
	 *
	 * it is ok to pause, it is not ok to block
	 */
	const uint16_t total_credits_needed = payload_credits_needed + 1;
	uint16_t total_credits_available = FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state);
	unsigned loop = 0;
	while ((total_credits_available < total_credits_needed) && (loop++ < 1000)) {
		FI_OPA1X_HFI1_UPDATE_CREDITS(pio_state, service->tx.hfi1.pio_credits_addr);
		total_credits_available = FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state);
	}

	if (FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state) < total_credits_needed) {

		/*
		 * not enough credits available
		 *
		 * DO NOT BLOCK - instead, drop this request and allow the
		 * reliability protocol to time out and try again
		 */
#ifdef OPA1X_RELIABILITY_DEBUG
		fprintf(stderr, "(tx) packet %016lx %08u replay dropped (no credits)\n", key.value, (uint32_t)replay->scb.hdr.reliability.psn);
#endif
		return;
	}

#ifdef OPA1X_RELIABILITY_DEBUG
	fprintf(stderr, "(tx) packet %016lx %08u replay injected\n", key.value, (uint32_t)replay->scb.hdr.reliability.psn);
#endif

	volatile uint64_t * const scb =
		FI_OPA1X_HFI1_PIO_SCB_HEAD(service->tx.hfi1.pio_scb_sop_first, pio_state);

	//uint64_t tmp[8];
	//tmp[0] =
		scb[0] = replay->scb.qw0;
	//tmp[1] =
		scb[1] = replay->scb.hdr.qw[0];
	//tmp[2] =
		scb[2] = replay->scb.hdr.qw[1];
	//tmp[3] =
		scb[3] = replay->scb.hdr.qw[2];
	//tmp[4] =
		scb[4] = replay->scb.hdr.qw[3];
	//tmp[5] =
		scb[5] = replay->scb.hdr.qw[4];
	//tmp[6] =
		scb[6] = replay->scb.hdr.qw[5];
	//tmp[7] =
		scb[7] = replay->scb.hdr.qw[6];

	//fprintf(stderr, "%s():%d pbc: 0x%016lx\n", __func__, __LINE__, tmp[0]);
	//fi_opa1x_hfi1_dump_stl_packet_hdr((struct fi_opa1x_hfi1_stl_packet_hdr *)&tmp[1], __func__, __LINE__);

	fi_opa1x_compiler_msync_writes();

	FI_OPA1X_HFI1_CHECK_CREDITS_FOR_ERROR((service->tx.hfi1.pio_credits_addr));
//fi_opa1x_hfi1_check_credits_for_error(service->tx.hfi1.pio_credits_addr, __FILE__, __func__, __LINE__);

	/* consume one credit for the packet header */
	--total_credits_available;
	FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

	uint64_t * buf_qws = replay->payload;

	while (payload_credits_needed > 0) {

		volatile uint64_t * scb_payload =
			FI_OPA1X_HFI1_PIO_SCB_HEAD(service->tx.hfi1.pio_scb_first, pio_state);

		const uint16_t contiguous_scb_until_wrap =
			(uint16_t)(pio_state.credits_total - pio_state.scb_head_index);

		const uint16_t contiguous_credits_available =
			MIN(total_credits_available, contiguous_scb_until_wrap);

		const uint16_t contiguous_full_blocks_to_write =
			MIN(payload_credits_needed, contiguous_credits_available);

		uint16_t i;
		for (i=0; i<contiguous_full_blocks_to_write; ++i) {

			scb_payload[0] = buf_qws[0];
			scb_payload[1] = buf_qws[1];
			scb_payload[2] = buf_qws[2];
			scb_payload[3] = buf_qws[3];
			scb_payload[4] = buf_qws[4];
			scb_payload[5] = buf_qws[5];
			scb_payload[6] = buf_qws[6];
			scb_payload[7] = buf_qws[7];

			scb_payload += 8;
			buf_qws += 8;
		}
//fi_opa1x_compiler_msync_writes();

//FI_OPA1X_HFI1_CHECK_CREDITS_FOR_ERROR((service->tx.hfi1.pio_credits_addr));
//fi_opa1x_hfi1_check_credits_for_error(service->tx.hfi1.pio_credits_addr, __FILE__, __func__, __LINE__);

		payload_credits_needed -= contiguous_full_blocks_to_write;
		total_credits_available -= contiguous_full_blocks_to_write;
		FI_OPA1X_HFI1_CONSUME_CREDITS(pio_state, contiguous_full_blocks_to_write);
	}

	/* save the updated txe state */
	*pio_state_ptr = pio_state.qw0;

	fi_opa1x_compiler_msync_writes();
}


void fi_opa1x_hfi1_rx_reliability_nack (struct fid_ep *ep,
		struct fi_opa1x_reliability_service * service,
		const uint64_t key, const uint64_t psn_count, const uint64_t psn_start)
{
	const uint64_t stop_psn = psn_start + psn_count - 1;

	uint64_t inject_count = 0;
	const uint64_t inject_max = 10;

	if (psn_start > stop_psn) {
		fprintf(stderr, "%s:%s():%d (%016lx) invalid nack received; psn_start = %lu, psn_count = %lu, stop_psn = %lu\n",
			__FILE__, __func__, __LINE__, key, psn_start, psn_count, stop_psn);
		abort();
	}


#ifdef OPA1X_RELIABILITY_DEBUG
	fprintf(stderr, "(tx) flow__ %016lx rcv nack %08lu..%08lu\n", key, psn_start, stop_psn);
#endif
	void * itr = NULL;

	/* search for existing unack'd flows */
	itr = rbtFind(service->tx.flow, (void*)key);
	if (unlikely((itr == NULL))) {

		/*
		 * the flow identified by the key is invalid ...?
		 */
		fprintf(stderr, "%s:%s():%d invalid key (%016lx)\n", __FILE__, __func__, __LINE__, key);
		abort();
	}

	struct fi_opa1x_reliability_tx_replay ** value_ptr =
		(struct fi_opa1x_reliability_tx_replay **) rbtValuePtr(service->tx.flow, itr);

	struct fi_opa1x_reliability_tx_replay * head = *value_ptr;

//fprintf(stderr, "%s():%d head = %p\n", __func__, __LINE__, head);
	if (unlikely(head == NULL)) {
//fprintf(stderr, "%s():%d head = %p\n", __func__, __LINE__, head);

		/*
		 * there are no unack'd elements in the replay queue;
		 * do nothing and return
		 */
		return;
	}

	struct fi_opa1x_reliability_tx_replay * tail = head->prev;

	/*
	 * find the first replay to retransmit
	 */

	struct fi_opa1x_reliability_tx_replay * start = head;
//fprintf(stderr, "%s():%d tail = %p, start = %p, start->psn = %lu, psn_start = %lu\n", __func__, __LINE__, tail, start, start->psn, psn_start);
	while ((start->scb.hdr.reliability.psn < psn_start) && (start != tail)) {
//fprintf(stderr, "%s():%d tail = %p, start = %p, start->psn = %lu, psn_start = %lu\n", __func__, __LINE__, tail, start, start->psn, psn_start);
		start = start->next;
	}
//fprintf(stderr, "%s():%d tail = %p, start = %p, start->psn = %lu, psn_start = %lu\n", __func__, __LINE__, tail, start, start->psn, psn_start);

	if (unlikely(start->scb.hdr.reliability.psn < psn_start)) {

		/*
		 * all elements in replay queue are 'younger' than the
		 * first psn to retransmit; do nothing and return
		 */
//fprintf(stderr, "%s():%d\n", __func__, __LINE__);
		return;
	}

	/*
	 * find the last replay to retransmit
	 */

	struct fi_opa1x_reliability_tx_replay * stop = start;
//fprintf(stderr, "%s():%d head = %p, stop = %p, stop->next = %p, start->next->psn = %lu, stop_psn = %lu\n", __func__, __LINE__, head, stop, stop->next, stop->next->psn, stop_psn);
	while ((stop->next != head) && (stop->next->scb.hdr.reliability.psn <= stop_psn)) {
//fprintf(stderr, "%s():%d head = %p, stop = %p, stop->next = %p, start->next->psn = %lu, stop_psn = %lu\n", __func__, __LINE__, head, stop, stop->next, stop->next->psn, stop_psn);
		stop = stop->next;
	}
//fprintf(stderr, "%s():%d head = %p, stop = %p, stop->next = %p, start->next->psn = %lu, stop_psn = %lu\n", __func__, __LINE__, head, stop, stop->next, stop->next->psn, stop_psn);

	if (unlikely(stop->scb.hdr.reliability.psn > stop_psn)) {

		/*
		 * all elements in the replay queue are 'older' than the
		 * last psn to retransmit; do nothing an return
		 */
//fprintf(stderr, "%s():%d\n", __func__, __LINE__);
		return;
	}

	const struct fi_opa1x_reliability_tx_replay * const halt = stop->next;
	struct fi_opa1x_reliability_tx_replay * replay = start;

	do {
		if ((inject_count < inject_max) && ((replay->nack_count)++ > 0)) {
			inject_count++;
			fi_opa1x_reliability_service_do_replay(service, replay);
#ifdef OPA1X_RELIABILITY_DEBUG
		} else {
			union fi_opa1x_reliability_service_flow_key key;
			key.slid = (uint32_t)replay->scb.hdr.stl.lrh.slid;
			key.tx = (uint32_t)replay->scb.hdr.reliability.origin_tx;
			key.dlid = (uint32_t)replay->scb.hdr.stl.lrh.dlid;
			key.rx = (uint32_t)replay->scb.hdr.stl.bth.rx;

			fprintf(stderr, "(tx) packet %016lx %08u replay skipped (nack count)\n", key.value, (uint32_t)replay->scb.hdr.reliability.psn);
#endif
		}
		replay = replay->next;

	} while (replay != halt);
//fprintf(stderr, "%s():%d\n", __func__, __LINE__);
}

#if 0
unsigned fi_opa1x_reliability_service_poll_hfi1 (struct fi_opa1x_reliability_service * service) {

	const uint64_t hdrq_offset = service->rx.hfi1.state.hdrq.head & 0x000000000000FFE0ul;
	volatile uint32_t * rhf_ptr = (uint32_t *)service->rx.hfi1.hdrq.rhf_base + hdrq_offset;
	const uint32_t rhf_lsb = rhf_ptr[0];
	const uint32_t rhf_msb = rhf_ptr[1];

	/*
	 * Check for receive errors
	 */
	if (unlikely((rhf_msb & 0xFFE00000u) != 0)) {

		fprintf(stderr, "%s:%s():%d === RECEIVE ERROR: rhf_msb = 0x%08x, rhf_lsb = 0x%08x\n", __FILE__, __func__, __LINE__, rhf_msb, rhf_lsb);
		fprintf(stderr, "%s:%s():%d === RHF.ICRCErr    = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 31) & 0x01u);
		fprintf(stderr, "%s:%s():%d === RHF.Reserved   = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 30) & 0x01u);
		fprintf(stderr, "%s:%s():%d === RHF.EccErr     = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 29) & 0x01u);
		fprintf(stderr, "%s:%s():%d === RHF.LenErr     = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 28) & 0x01u);
		fprintf(stderr, "%s:%s():%d === RHF.TIDErr     = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 27) & 0x01u);
		fprintf(stderr, "%s:%s():%d === RHF.RcvTypeErr = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 24) & 0x07u);
		fprintf(stderr, "%s:%s():%d === RHF.DcErr      = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 23) & 0x01u);
		fprintf(stderr, "%s:%s():%d === RHF.DcUncErr   = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 22) & 0x01u);
		fprintf(stderr, "%s:%s():%d === RHF.KHdrLenErr = %u\n", __FILE__, __func__, __LINE__, (rhf_msb >> 21) & 0x01u);

		abort();
	}

	/*
	 * The RHF.RcvSeq field is located in bits [31:28] and values are in
	 * the range of (1..13) inclusive. A new packet is available when the
	 * expected sequence number in the next header queue element matches
	 * the RHF.RcvSeq field.
	 *
	 * Instead of shifting and masking the RHF bits to read the sequence
	 * number in the range of 1..13 (or, 0x1..0xD) use only a bit mask to
	 * obtain the RHF sequence in the range of 0x10000000..0xD0000000.
	 * In this scheme the expected sequence number is incremented by
	 * 0x10000000 instead of 0x1.
	 */
	const uint32_t rhf_seq = service->rx.hfi1.state.hdrq.rhf_seq;
	if (rhf_seq == (rhf_lsb & 0xF0000000u)) {

		const uint64_t hdrq_offset_dws = (rhf_msb >> 12) & 0x01FFu;

		uint32_t * pkt = (uint32_t *)rhf_ptr -
			32 +	/* header queue entry size in dw */
			2 +	/* rhf field size in dw */
			hdrq_offset_dws;

		const union fi_opa1x_reliability_service_hfi1_packet_hdr * const hdr =
			(union fi_opa1x_reliability_service_hfi1_packet_hdr *)pkt;

		const uint8_t opcode = hdr->stl.bth.opcode;

		if (opcode == FI_OPA1X_HFI_BTH_OPCODE_RELIABILITY_PING) {

			assert((rhf_lsb & 0x00008000u) != 0x00008000u);	/* ping packets NEVER have 'eager' payload data */

			/* "header only" packet - no payload */

			const uint64_t slid = (uint64_t)hdr->stl.lrh.slid;
			const uint64_t rx = (uint64_t)hdr->reliability.origin_reliability_rx;

			const uint64_t key = hdr->reliability.key.value;
			const uint64_t psn_count = hdr->reliability.psn_count;
			const uint64_t psn_start = hdr->reliability.psn_start;

			fi_opa1x_hfi1_rx_reliability_ping(NULL, service,
				key, slid, rx, psn_count, psn_start);

		} else if (opcode == FI_OPA1X_HFI_BTH_OPCODE_RELIABILITY_ACK) {

			assert((rhf_lsb & 0x00008000u) != 0x00008000u);

			/* "header only" packet - no payload */

			const uint64_t key = hdr->reliability.key.value;
			const uint64_t psn_count = hdr->reliability.psn_count;
			const uint64_t psn_start = hdr->reliability.psn_start;

			fi_opa1x_hfi1_rx_reliability_ack(NULL, service,
				key, psn_count, psn_start);

		} else if (opcode == FI_OPA1X_HFI_BTH_OPCODE_RELIABILITY_NACK) {

			assert((rhf_lsb & 0x00008000u) != 0x00008000u);

			/* "header only" packet - no payload */

			const uint64_t key = hdr->reliability.key.value;
			const uint64_t psn_count = hdr->reliability.psn_count;
			const uint64_t psn_start = hdr->reliability.psn_start;

			fi_opa1x_hfi1_rx_reliability_nack(NULL, service,
				key, psn_count, psn_start);
		}

		service->rx.hfi1.state.hdrq.rhf_seq = (rhf_seq < 0xD0000000u) * rhf_seq + 0x10000000u;
		service->rx.hfi1.state.hdrq.head = hdrq_offset + 32;	/* 32 dws == 128 bytes, the maximum header queue entry size */

		/*
		 * Notify the hfi that this packet has been processed ..
		 * but only do this every 1024 hdrq elements because the hdrq
		 * size is 2048 and the update is expensive.
		 */
		if (unlikely((hdrq_offset & 0x7FFFul) == 0x0020ul)) {
			*service->rx.hfi1.hdrq.head_register = hdrq_offset - 32;
		}

		return 1;	/* one packet was processed */
	}

	return 0;
}
#endif

void fi_reliability_service_ping_remote (struct fid_ep *ep,
		struct fi_opa1x_reliability_service * service)
{

	/* for each flow in the rbtree ... */
	RbtIterator itr = rbtBegin(service->tx.flow);

	while (itr) {

		struct fi_opa1x_reliability_tx_replay ** value_ptr =
			(struct fi_opa1x_reliability_tx_replay **)rbtValuePtr(service->tx.flow, itr);

		struct fi_opa1x_reliability_tx_replay * head = *value_ptr;

		if (likely(head != NULL)) {

			const union fi_opa1x_reliability_service_flow_key key = {
				.slid = (uint32_t)head->scb.hdr.stl.lrh.slid,
				.tx = (uint32_t)head->scb.hdr.reliability.origin_tx,
				.dlid = (uint32_t)head->scb.hdr.stl.lrh.dlid,
				.rx = (uint32_t)head->scb.hdr.stl.bth.rx,
			};

			const uint64_t dlid = (uint64_t)head->scb.hdr.stl.lrh.dlid;
			const uint64_t rx = (uint64_t)head->target_reliability_rx;

			uint64_t psn_start = head->scb.hdr.reliability.psn;
			uint64_t psn_count = 1;

			struct fi_opa1x_reliability_tx_replay * replay = head->next;

			while (replay != head) {

				if (replay->scb.hdr.reliability.psn == (psn_start + psn_count)) {
					++psn_count;
				} else {
					fi_opa1x_hfi1_tx_reliability_inject(ep,
							key.value, dlid, rx,
							psn_start,		/* psn_start */
							psn_count,		/* psn_count */
							FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_PING);
					psn_start = replay->scb.hdr.reliability.psn;
					psn_count = 1;
				}
				replay = replay->next;

			}

			fi_opa1x_hfi1_tx_reliability_inject(ep,			/* FIXME .. isn't it possible here that an extra 'ping' request could be sent? */
					key.value, dlid, rx,
					psn_start,
					psn_count,
					FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_PING);
#if 0
			/*
			 * TEST ONLY - retire all replay buffers now
			 */

			*value_ptr = NULL;
			head->prev->next = NULL;
			do {
				struct fi_opa1x_reliability_tx_replay * next = head->next;

				head->next = NULL;
				head->prev = NULL;
				head->active = 0;
				head = next;

			} while (head != NULL);
#endif
		}

		/* advance to the next dlid */
		itr = rbtNext(service->tx.flow, itr);
	}
}

#if 0
static inline
void fi_opa1x_reliability_service_poll (struct fid_ep *ep, struct fi_opa1x_reliability_service * service) {

	/* process incoming tx replay packets */
	struct fi_opa1x_atomic_fifo * fifo = &service->fifo;

	double elapsed_usec;
	union fi_opa1x_timer_state * timer = &service->tx.timer;
	union fi_opa1x_timer_stamp *timestamp = &service->tx.timestamp;

	const double   usec_max = (double)((uint64_t)service->usec_max);
	const unsigned fifo_max = (unsigned) service->fifo_max;
	//const unsigned hfi1_max = (unsigned) service->hfi1_max;

	volatile uint64_t * enabled_ptr = &service->enabled;

	uint64_t spin_count = 0;

	while (*enabled_ptr) {

		elapsed_usec = fi_opa1x_timer_elapsed_usec(timestamp, timer);
		if (unlikely(elapsed_usec > usec_max)) {

			fi_reliability_service_ping_remote(ep, service);

			/* reset the timer */
			fi_opa1x_timer_now(timestamp, timer);
		}

		unsigned count = 0;
		uint64_t data = 0;
		while ((count++ < fifo_max) && (0 == fi_opa1x_atomic_fifo_consume(fifo, &data))) {

			if (likely((data & TX_CMD) != 0)) {

				/* process this replay buffer */
				struct fi_opa1x_reliability_tx_replay * replay =
					(struct fi_opa1x_reliability_tx_replay *) (data & ~TX_CMD);

				fi_reliability_service_process_command(service, replay);

			} else if (data & RX_CMD) {

				/* process this new rx flow */
				struct fi_opa1x_reliability_flow * flow =
					(struct fi_opa1x_reliability_flow *) (data & ~RX_CMD);

				rbtInsert(service->rx.flow, (void*)flow->key.value, (void*)flow);

			} else {
				fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort();
			}

		}

//		count = 0;
//		while ((count++ < hfi1_max) && (0 != fi_opa1x_reliability_service_poll_hfi1(service)));

		if (service->is_backoff_enabled) {
			__asm__ __volatile__ ( "pause" );
			spin_count++;
			if (spin_count % service->backoff_period == 0) {
				sched_yield();
			}
		}
	}

	return;
}
#endif

void fi_opa1x_reliability_service_cleanup (struct fi_opa1x_reliability_service * service) {


	/*
	 * the application must not care about any un-acked replay packets;
	 * mark all flows as complete
	 */
	RbtIterator itr = rbtBegin(service->tx.flow);
	while (itr) {

		struct fi_opa1x_reliability_tx_replay ** value_ptr =
			(struct fi_opa1x_reliability_tx_replay **)rbtValuePtr(service->tx.flow, itr);

		struct fi_opa1x_reliability_tx_replay * head = *value_ptr;

		if (likely(head != NULL)) {
			struct fi_opa1x_reliability_tx_replay * tail = head->prev;

			tail->next = NULL;
			do {

				struct fi_opa1x_reliability_tx_replay * next = head->next;

				const uint64_t dec = head->cc_dec;
				volatile uint64_t * cc_ptr = head->cc_ptr;
				*cc_ptr -= dec;

				head->next = NULL;
				head->prev = NULL;
				head->active = 0;

				head = next;

			} while (head != NULL);

			*value_ptr = NULL;
		}

		/* advance to the next dlid */
		itr = rbtNext(service->tx.flow, itr);
	}

	/*
	 * process, and respond to, any incoming packets from remote
	 * reliability services until no packets are received
	 */

	union fi_opa1x_timer_stamp *timestamp = &service->tx.timestamp;
	union fi_opa1x_timer_state * timer = &service->tx.timer;

	unsigned n = 0;
	while (fi_opa1x_timer_elapsed_usec(timestamp, timer) < 10000.0) {

//		n = fi_opa1x_reliability_service_poll_hfi1(service);
		if (n > 0) {
			/* reset the timer */
			fi_opa1x_timer_now(timestamp, timer);
		}
	}
}

#if 0
void * pthread_start_routine (void * arg) {


	struct fi_opa1x_reliability_service * service =
		(struct fi_opa1x_reliability_service *)arg;

	service->active = 1;
	while (service->enabled > 0) {
		fi_opa1x_reliability_service_poll(service);
	}
	fi_opa1x_reliability_service_cleanup(service);
	service->active = 0;

	return NULL;
}
#endif

uint8_t fi_opa1x_reliability_service_init (struct fi_opa1x_reliability_service * service,
		uuid_t unique_job_key,
		struct fi_opa1x_hfi1_context * hfi1,
		const enum ofi_reliability_kind reliability_kind)
{
	uint8_t origin_reliability_rx = (uint8_t)-1;

	if (OFI_RELIABILITY_KIND_OFFLOAD == reliability_kind) {

		if (hfi1 != NULL) abort();

		service->reliability_kind = reliability_kind;

		service->context = fi_opa1x_hfi1_context_open(unique_job_key);
		hfi1 = service->context;
		init_hfi1_rxe_state(hfi1, &service->rx.hfi1.state);

		service->lid_be = (uint32_t)htons(hfi1->lid);

		/*
		 * COPY the rx static information from the hfi context structure.
		 * This is to improve cache layout.
		 */
		service->rx.hfi1.hdrq.rhf_base = hfi1->info.rxe.hdrq.rhf_base;
		service->rx.hfi1.hdrq.head_register = hfi1->info.rxe.hdrq.head_register;
		service->rx.hfi1.egrq.base_addr = hfi1->info.rxe.egrq.base_addr;
		service->rx.hfi1.egrq.elemsz = hfi1->info.rxe.egrq.elemsz;
		service->rx.hfi1.egrq.last_egrbfr_index = 0;
		service->rx.hfi1.egrq.head_register = hfi1->info.rxe.egrq.head_register;


		/* the 'state' fields will change after every tx operation */
		service->tx.hfi1.pio_state = &hfi1->state.pio;

		/* the 'info' fields do not change; the values can be safely copied */
		service->tx.hfi1.pio_scb_sop_first = hfi1->info.pio.scb_sop_first;
		service->tx.hfi1.pio_scb_first = hfi1->info.pio.scb_first;
		service->tx.hfi1.pio_credits_addr = hfi1->info.pio.credits_addr;

		origin_reliability_rx = hfi1->info.rxe.id;

	} else if (OFI_RELIABILITY_KIND_ONLOAD == reliability_kind) {

		if (hfi1 == NULL) abort();

		service->lid_be = (uint32_t)htons(hfi1->lid);
		service->reliability_kind = reliability_kind;
		origin_reliability_rx = hfi1->info.rxe.id;

	} else if (OFI_RELIABILITY_KIND_NONE == reliability_kind) {

		service->lid_be = (uint32_t)-1;
		service->reliability_kind = reliability_kind;
		return origin_reliability_rx;

	} else {

		/* invalid reliability kind */
		fprintf(stderr, "%s:%s():%d invalid reliability kind: %u\n", __FILE__, __func__, __LINE__, reliability_kind);
		abort();
	}



	/* 'ping' pio send model */
	{
		/* PBC */
		const uint64_t pbc_dws =
			2 +	/* pbc */
			2 +	/* lrh */
			3 +	/* bth */
			9;	/* kdeth; from "RcvHdrSize[i].HdrSize" CSR */

		service->tx.hfi1.ping_model.qw0 = (0 | pbc_dws |
			((hfi1->vl & FI_OPA1X_HFI1_PBC_VL_MASK) << FI_OPA1X_HFI1_PBC_VL_SHIFT) |
			(((hfi1->sc >> FI_OPA1X_HFI1_PBC_SC4_SHIFT) & FI_OPA1X_HFI1_PBC_SC4_MASK) << FI_OPA1X_HFI1_PBC_DCINFO_SHIFT));

		/* LRH */
		service->tx.hfi1.ping_model.hdr.stl.lrh.flags =
			htons(FI_OPA1X_HFI1_LRH_BTH |
			((hfi1->sl & FI_OPA1X_HFI1_LRH_SL_MASK) << FI_OPA1X_HFI1_LRH_SL_SHIFT) |
			((hfi1->sc & FI_OPA1X_HFI1_LRH_SC_MASK) << FI_OPA1X_HFI1_LRH_SC_SHIFT));

		service->tx.hfi1.ping_model.hdr.stl.lrh.dlid = 0;			/* set at runtime */
		service->tx.hfi1.ping_model.hdr.stl.lrh.pktlen = htons(pbc_dws-1);	/* does not include pbc (8 bytes), but does include icrc (4 bytes) */
		service->tx.hfi1.ping_model.hdr.stl.lrh.slid = htons(hfi1->lid);

		/* BTH */
		service->tx.hfi1.ping_model.hdr.stl.bth.opcode = FI_OPA1X_HFI_BTH_OPCODE_UD;
		service->tx.hfi1.ping_model.hdr.stl.bth.bth_1 = 0;
		service->tx.hfi1.ping_model.hdr.stl.bth.pkey = htons(FI_OPA1X_HFI1_DEFAULT_P_KEY);
		service->tx.hfi1.ping_model.hdr.stl.bth.ecn = 0;
		service->tx.hfi1.ping_model.hdr.stl.bth.qp = hfi1->bthqp;
		service->tx.hfi1.ping_model.hdr.stl.bth.unused = 0;
		service->tx.hfi1.ping_model.hdr.stl.bth.rx = 0;			/* set at runtime */

		/* KDETH */
		service->tx.hfi1.ping_model.hdr.stl.kdeth.offset_ver_tid = KDETH_VERSION << FI_OPA1X_HFI1_KHDR_KVER_SHIFT;
		service->tx.hfi1.ping_model.hdr.stl.kdeth.jkey = hfi1->jkey;
		service->tx.hfi1.ping_model.hdr.stl.kdeth.hcrc = 0;
		service->tx.hfi1.ping_model.hdr.stl.kdeth.unused = 0;

		/* reliability service */
		union fi_opa1x_hfi1_packet_hdr * hdr =
			(union fi_opa1x_hfi1_packet_hdr *)&service->tx.hfi1.ping_model.hdr;
//		union fi_opa1x_reliability_service_hfi1_packet_hdr * hdr =
//			(union fi_opa1x_reliability_service_hfi1_packet_hdr *)&service->tx.hfi1.ping_model.hdr;

		hdr->ud.opcode = FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_PING;

		hdr->service.origin_reliability_rx = hfi1->info.rxe.id;
		hdr->service.range_count = 0;
		hdr->service.unused = 0;
		hdr->service.psn_count = 0;
		hdr->service.psn_start = 0;
		hdr->service.key = 0;
	}

	/* 'ack' pio send model */
	{
		service->tx.hfi1.ack_model = service->tx.hfi1.ping_model;
		service->tx.hfi1.ack_model.hdr.ud.opcode = FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_ACK;
	}

	/* 'nack' pio send model */
	{
		service->tx.hfi1.nack_model = service->tx.hfi1.ping_model;
		service->tx.hfi1.nack_model.hdr.ud.opcode = FI_OPA1X_HFI_UD_OPCODE_RELIABILITY_NACK;
	}



	fi_opa1x_timer_init(&service->tx.timer);
	fi_opa1x_timer_now(&service->tx.timestamp, &service->tx.timer);

	service->tx.flow = rbtNew(fi_opa1x_reliability_compare);
	service->rx.flow = rbtNew(fi_opa1x_reliability_compare);

	char * env = getenv("OPA1X_DEBUG");
	int is_debug = 0;
	if (env) {
		is_debug = 1;
	}

	/*
	 * When to yeild() the reliability thread.
	 *
	 * OFFLOAD only
	 */
	env = getenv("RELIABILITY_SERVICE_BACKOFF_PERIOD");
	service->is_backoff_enabled = 0;
	service->backoff_period = 1;
	if (env) {
		unsigned long period = strtoul(env, NULL, 10);
		if (is_debug) {
			fprintf(stderr, "%s():%d RELIABILITY_SERVICE_BACKOFF_PERIOD = '%s' (%lu)\n", __func__, __LINE__, env, period);
		}
		service->is_backoff_enabled = 1;
		service->backoff_period=(uint64_t)period;
	}

	/*
	 * How often to send ping requests
	 *
	 * OFFLOAD and ONLOAD
	 */
	env = getenv("RELIABILITY_SERVICE_USEC_MAX");
	service->usec_max = 600;
	if (env) {
		unsigned long usec = strtoul(env, NULL, 10);
		if (is_debug) {
			fprintf(stderr, "%s():%d RELIABILITY_SERVICE_USEC_MAX = '%s' (%lu)\n", __func__, __LINE__, env, usec);
		}
		service->usec_max = (uint16_t)usec;
	}

	/*
	 * Maximum number of commands to process from atomic fifo before
	 * stopping to do something else
	 *
	 * OFFLOAD only
	 */
	env = getenv("RELIABILITY_SERVICE_FIFO_MAX");
	service->fifo_max = 1;
	if (env) {
		unsigned long max = strtoul(env, NULL, 10);
		if (is_debug) {
			fprintf(stderr, "%s():%d RELIABILITY_SERVICE_FIFO_MAX = '%s' (%lu)\n", __func__, __LINE__, env, max);
		}
		service->fifo_max = (uint8_t)max;
	}

	/*
	 * Maximum number of packets to process from hfi1 rx fifo before
	 * stopping to do something else
	 *
	 * OFFLOAD only
	 */
	env = getenv("RELIABILITY_SERVICE_HFI1_MAX");
	service->hfi1_max = 1;
	if (env) {
		unsigned long max = strtoul(env, NULL, 10);
		if (is_debug) {
			fprintf(stderr, "%s():%d RELIABILITY_SERVICE_HFI1_MAX = '%s' (%lu)\n", __func__, __LINE__, env, max);
		}
		service->hfi1_max = (uint8_t)max;
	}

	/*
	 * Placement of reliability service thread
	 *
	 * OFFLOAD only
	 */
	int local_ranks = 1;
	int local_rank_id = 0;
	int is_local_rank_mode = 0;

	env = getenv("RELIABILITY_SERVICE_MPI_LOCALRANK_MODE");

	if (env) {
		char * local_ranks_env = getenv("MPI_LOCALNRANKS");
		char * local_rank_id_env = getenv("MPI_LOCALRANKID");

		if (local_ranks_env && local_rank_id_env) {
			is_local_rank_mode = 1;
			local_ranks = (int)strtoul(local_ranks_env, NULL, 10);
			local_rank_id = (int)strtoul(local_rank_id_env, NULL, 10);
		}
	}

	pthread_attr_t attr;
	pthread_attr_init(&attr);

	env = getenv("RELIABILITY_SERVICE_CPU");

	if (env) {
		long cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
		cpu_set_t cpu_set;

		CPU_ZERO(&cpu_set);

		unsigned long cpu_id = 0;
		unsigned long cpu_id_range_begin = 0;
		unsigned long cpu_id_range_end = 0;

		char * service_cpu_str_save = NULL;
		char * service_cpu_sub_str_save = NULL;

		char * service_cpu_sub_str = NULL;
		char * service_cpu_sub_str_iter = NULL;

		char * service_cpu_str = strdup(env);
		char * service_cpu_str_iter = strtok_r(service_cpu_str, ",", &service_cpu_str_save);

		while (service_cpu_str_iter != NULL) {
			service_cpu_sub_str = strdup(service_cpu_str_iter);
			service_cpu_sub_str_iter = strtok_r(service_cpu_sub_str, "-", &service_cpu_sub_str_save);

			cpu_id_range_begin = strtoul(service_cpu_sub_str_iter, NULL, 10);
			cpu_id_range_end = cpu_id_range_begin;

			service_cpu_sub_str_iter = strtok_r(NULL, "-", &service_cpu_sub_str_save);

			if (service_cpu_sub_str_iter) {
				cpu_id_range_end = strtoul(service_cpu_sub_str_iter, NULL, 10);
			}

			for (cpu_id = cpu_id_range_begin; cpu_id <= cpu_id_range_end; cpu_id++) {
				CPU_SET(cpu_id, &cpu_set);
			}

			service_cpu_str_iter = strtok_r(NULL, ",", &service_cpu_str_save);
			free(service_cpu_sub_str);
		}

		free(service_cpu_str);

		if (is_local_rank_mode) {
			int cpu_num_used_total = CPU_COUNT(&cpu_set);
			int cpu_num_used_max = 1;
			int cpu_num_used = 0;

			if (local_ranks < cpu_num_used_total) {
				cpu_num_used_max = cpu_num_used_total / local_ranks;
			}

			int cpu_num_used_offset = local_rank_id % cpu_num_used_total;

			if (is_debug) {
				fprintf(stderr, "%s():%d cpu_num_used_offset = %d, cpu_num_used_max = %d, cpu_num_used_total = %d\n",
						__func__, __LINE__, cpu_num_used_offset, cpu_num_used_max, cpu_num_used_total);
			}

			for (cpu_id = 0; cpu_id < cpu_num; cpu_id++) {
				if (CPU_ISSET(cpu_id, &cpu_set)) {
					if (cpu_num_used_offset) {
						CPU_CLR(cpu_id, &cpu_set); /* clear head */
						cpu_num_used_offset--;
					} else {
						if (cpu_num_used != cpu_num_used_max) {
							cpu_num_used++; /* leave body */
						} else {
							CPU_CLR(cpu_id, &cpu_set); /* clear tail */
						}
					}
				}
			}
		}

		const int cpu_mask_chunk_bits_size = 64; /* uint64_t bits */
		const int cpu_mask_chunk_hex_size = cpu_mask_chunk_bits_size / 4;

		int cpu_mask_chunk_num  = cpu_num / cpu_mask_chunk_bits_size + (cpu_num % cpu_mask_chunk_bits_size ? 1 : 0);

		uint64_t cpu_mask[cpu_mask_chunk_num];
		memset(cpu_mask, 0, sizeof(cpu_mask));

		int i = 0;
		int j = 0;

		for (i = 0; i < cpu_mask_chunk_num; i++) {
			for (j = 0; j < cpu_mask_chunk_bits_size; j++) {
				cpu_mask[i] |= CPU_ISSET(i * cpu_mask_chunk_bits_size + j, &cpu_set) << j;
			}
		}

		char cpu_mask_str[cpu_mask_chunk_num * (cpu_mask_chunk_hex_size + 1 /* space */) + 1 /* null */];

		for (i = 0; i < cpu_mask_chunk_num; i++) {
			sprintf(cpu_mask_str + i * (cpu_mask_chunk_hex_size + 1), "%016" PRIX64 " ", cpu_mask[i]);
		}

		cpu_mask_str[cpu_mask_chunk_num * cpu_mask_chunk_hex_size] = '\0';

		if (is_debug) {
			fprintf(stderr, "%s():%d RELIABILITY_SERVICE_CPU: (%s) & (rank_mode = %s) == (%s)\n", __func__, __LINE__, env,
					is_local_rank_mode ? "TRUE" : "FALSE", cpu_mask_str);
		}

		size_t cpu_set_size = CPU_ALLOC_SIZE(cpu_num);
		pthread_attr_setaffinity_np(&attr, cpu_set_size, &cpu_set);
	}

	service->enabled = 1;

	if (reliability_kind == OFI_RELIABILITY_KIND_ONLOAD) {
		service->active = 1;

	} else if (reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {

		fprintf(stderr, "%s:%s():%d OFI_RELIABILITY_KIND_OFFLOAD is not supported any more. Perhaps this should instead be implemented as \"FI_PROGRESS_AUTO + OFI_RELIABILITY_KIND_ONLOAD\"?\n", __FILE__, __func__, __LINE__);
		abort();

		//service->active = 0;
		//fi_opa1x_atomic_fifo_init(&service->fifo, 1024*16);

		//int rc = pthread_create(&service->thread, &attr, pthread_start_routine, (void *)service);
		//if (rc != 0) {
		//	fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__); abort();
		//}
	}

	return origin_reliability_rx;
}


void fi_opa1x_reliability_service_fini (struct fi_opa1x_reliability_service * service) {

	service->enabled = 0;
	fi_opa1x_compiler_msync_writes();
	while (service->active != 0) {
		fi_opa1x_compiler_msync_reads();
	}

	if (service->reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {
		fi_opa1x_atomic_fifo_fini(&service->fifo);
	}

	return;
}


void fi_opa1x_reliability_client_init (struct fi_opa1x_reliability_client_state * state,
		struct fi_opa1x_reliability_service * service,
		const uint8_t rx,
		const uint8_t tx,
		void (*process_fn)(struct fid_ep *ep, const union fi_opa1x_hfi1_packet_hdr * const hdr, const uint8_t * const payload))
{

	state->reliability_kind = service->reliability_kind;

	state->service = service;

	if (service->reliability_kind == OFI_RELIABILITY_KIND_NONE)
		return;

	/* ---- rx and tx ----*/
	if (service->reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {
		fi_opa1x_atomic_fifo_producer_init(&state->fifo, &service->fifo);
	}
	state->lid_be = service->lid_be;


	/* ---- rx only ---- */
	state->process_fn = process_fn;
	state->rx_flow_rbtree = rbtNew(fi_opa1x_reliability_compare);
	state->rx = rx;


	/* ---- tx only ---- */
	state->tx = tx;
	state->tx_flow_rbtree = rbtNew(fi_opa1x_reliability_compare);

	void * block = NULL;
	int i, rc __attribute__ ((unused));
	rc = posix_memalign((void **)&block, 64,
		sizeof(struct fi_opa1x_reliability_tx_replay) * FI_OPA1X_RELIABILITY_TX_REPLAY_BLOCKSIZE);
	assert(rc==0);

	state->replay_large =
		(struct fi_opa1x_reliability_tx_replay *) block;

	for (i=0; i<FI_OPA1X_RELIABILITY_TX_REPLAY_BLOCKSIZE; ++i) {
		state->replay_large[i].active = 0;
	}
	state->replay_head = 0;


	/* ---- debug only ---- */
	state->drop_count = 0;
	state->drop_mask = 0x00FF;	/* default: drop every 256'th packet */
	char * env = getenv("RELIABILITY_SERVICE_DROP_PACKET_MASK");
	if (env) {
		uint16_t mask = (uint16_t)strtoul(env, NULL, 16);
		fprintf(stderr, "%s():%d RELIABILITY_SERVICE_DROP_PACKET_MASK = '%s' (0x%04hx)\n", __func__, __LINE__, env, mask);
		state->drop_mask = mask;
	}

	return;
}


unsigned fi_opa1x_reliability_client_active (struct fi_opa1x_reliability_client_state * state)
{
	if (state->service->reliability_kind == OFI_RELIABILITY_KIND_NONE)
		return 0;

	unsigned i;
	for (i=0; i<FI_OPA1X_RELIABILITY_TX_REPLAY_BLOCKSIZE; ++i) {
		if (state->replay_large[i].active != 0) {
			fi_opa1x_compiler_msync_reads();
			return 1;
		}
	}

	return 0;
}

void fi_opa1x_reliability_client_fini (struct fi_opa1x_reliability_client_state * state)
{

	if (state->reliability_kind == OFI_RELIABILITY_KIND_NONE)
		return;

	if (state->reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {
		fi_opa1x_atomic_fifo_producer_fini(&state->fifo);

		/* wait until all replay buffers are ack'd because the reliability
		 * service maintains pointers to unack'd reply buffers and can't
		 * free until service is finished
		 */
		while (fi_opa1x_reliability_client_active(state)) {
			fi_opa1x_compiler_msync_reads();
		}
	}



	free(state->replay_large);
	state->replay_large = NULL;


	/* TODO - delete rbtree and flows, but first have to notify
	 * reliability service of the tear-down */
}


void fi_opa1x_reliability_rx_exception (struct fi_opa1x_reliability_client_state * state,
		uint64_t slid, uint64_t origin_tx, uint32_t psn,
		struct fid_ep *ep, const union fi_opa1x_hfi1_packet_hdr * const hdr, const uint8_t * const payload) {

	/* reported in LRH as the number of 4-byte words in the packet; header + payload + icrc */
	const uint16_t lrh_pktlen_le = ntohs(hdr->stl.lrh.pktlen);
	const size_t total_bytes_to_copy = (lrh_pktlen_le - 1) * 4;	/* do not copy the trailing icrc */
	const size_t payload_bytes_to_copy = total_bytes_to_copy - sizeof(union fi_opa1x_hfi1_packet_hdr);

	union fi_opa1x_reliability_service_flow_key key;
	key.slid = slid;
	key.tx = origin_tx;
	key.dlid = state->lid_be;
	key.rx = state->rx;

	void * itr = rbtFind(state->rx_flow_rbtree, (void*)key.value);
	if (unlikely(itr == NULL)) {

		if (psn != 0) {

			/* the first packet in this flow was not delivered.
			 * do not create a new rbtree flow node and drop this
			 * packet
			 */

			fprintf(stderr, "%s:%s():%d first packet in flow exception!\n", __FILE__, __func__, __LINE__);

			/* TODO - send nack ? */

			return;
		}

		/* allocate a new rbtree node and insert */

		/* TODO - allocate from a pool of flow objects instead for better memory utilization */
		int rc __attribute__ ((unused));
		struct fi_opa1x_reliability_flow * flow = NULL;
		rc = posix_memalign((void **)&flow, 32, sizeof(*flow));
		assert(rc==0);

		flow->next_psn = 1;
		flow->key.value = key.value;
		flow->uepkt = NULL;
		fastlock_init(&flow->lock);

		rbtInsert(state->rx_flow_rbtree, (void*)key.value, (void*)flow);

#ifdef OPA1X_RELIABILITY_DEBUG
		fprintf(stderr, "(rx) packet %016lx %08u received.\n", key.value, psn);
#endif
		state->process_fn(ep, hdr, payload);

		if (state->service->reliability_kind == OFI_RELIABILITY_KIND_OFFLOAD) {

			fi_opa1x_atomic_fifo_produce(&state->fifo, (uint64_t)flow | RX_CMD);

		} else if (state->service->reliability_kind == OFI_RELIABILITY_KIND_ONLOAD) {

			/* process this new rx flow */
			rbtInsert(state->service->rx.flow, (void*)flow->key.value, (void*)flow);
		}

		return;
	}

	struct fi_opa1x_reliability_flow ** value_ptr =
		(struct fi_opa1x_reliability_flow **) rbtValuePtr(state->rx_flow_rbtree, itr);

	struct fi_opa1x_reliability_flow * flow = *value_ptr;

	uint64_t next_psn = flow->next_psn;

	if (psn < next_psn) {

		/*
		 * old packet .. drop it
		 */
#ifdef OPA1X_RELIABILITY_DEBUG
		fprintf(stderr, "(rx) packet %016lx %08u dropped (duplicate).\n", key.value, psn);
#endif
		return;
	}

	if (next_psn == psn) {

		/*
		 * deliver this packet and the next contiguous sequence of
		 * previously queued unexpected packets
		 */

#ifdef OPA1X_RELIABILITY_DEBUG
		fprintf(stderr, "(rx) packet %016lx %08u received (process out-of-order).\n", key.value, psn);
#endif
		state->process_fn(ep, hdr, payload);
		next_psn += 1;

		flow->next_psn = next_psn;

		struct fi_opa1x_reliability_rx_uepkt * head = flow->uepkt;
		if (head != NULL) {

			fastlock_acquire(&flow->lock);

			head = flow->uepkt;	/* check again now that lock is acquired */

			struct fi_opa1x_reliability_rx_uepkt * uepkt = head;

			while ((uepkt != NULL) && (next_psn == uepkt->psn)) {

				state->process_fn(ep, &uepkt->hdr, uepkt->payload);
#ifdef OPA1X_RELIABILITY_DEBUG
				fprintf(stderr, "(rx) packet %016lx %08lu delivered.\n", key.value, next_psn);
#endif
				next_psn += 1;

				struct fi_opa1x_reliability_rx_uepkt * next = uepkt->next;
				if (next == uepkt) {
					/* only one element in the list */
					assert(uepkt->prev == uepkt);
					next = NULL;
				}

				uepkt->prev->next = uepkt->next;
				uepkt->next->prev = uepkt->prev;
				free(uepkt);
				head = next;
				uepkt = next;
			};

			flow->uepkt = head;

			
			flow->next_psn = next_psn;
			fastlock_release(&flow->lock);
		}


	} else if (flow->uepkt == NULL) {

		/*
		 * add the out-of-order packet to the empty unexpected queue
		 */

		struct fi_opa1x_reliability_rx_uepkt * uepkt = NULL;

		int rc __attribute__ ((unused));
		rc = posix_memalign((void **)&uepkt, 64,
			sizeof(*uepkt) + payload_bytes_to_copy);
		assert(rc==0);

		uepkt->prev = uepkt;
		uepkt->next = uepkt;
		uepkt->psn = psn;
		memcpy((void*)&uepkt->hdr, hdr, sizeof(union fi_opa1x_hfi1_packet_hdr));

		if (payload_bytes_to_copy > 0)
			memcpy((void*)&uepkt->payload[0], (const void *)payload, payload_bytes_to_copy);

		fastlock_acquire(&flow->lock);

		flow->uepkt = uepkt;

		fastlock_release(&flow->lock);

#ifdef OPA1X_RELIABILITY_DEBUG
		fprintf(stderr, "(rx) packet %016lx %08u queued.\n", key.value, psn);
#endif

		/* TODO - nack flow->psn ? */

	} else {
		/*
		 * insert the out-of-order packet into the unexpected queue;
		 * check for duplicates
		 *
		 * generally if one packet is received out-of-order with psn 'N'
		 * then the next packet received out-of-order will be psn 'N+1'.
		 *
		 * search the unexpected queue in reverse to find the insert
		 * point for this packet.
		 */
		struct fi_opa1x_reliability_rx_uepkt * head = flow->uepkt;
		struct fi_opa1x_reliability_rx_uepkt * tail = head->prev;
		struct fi_opa1x_reliability_rx_uepkt * uepkt = tail;

		do {
			const uint64_t uepkt_psn = uepkt->psn;

			if (uepkt_psn < psn) {

				/* insert after this element */
				struct fi_opa1x_reliability_rx_uepkt * tmp = NULL;

				int rc __attribute__ ((unused));
				rc = posix_memalign((void **)&tmp, 64,
					sizeof(*tmp) + payload_bytes_to_copy);
				assert(rc==0);

				tmp->prev = uepkt;
				tmp->next = uepkt->next;
				tmp->psn = psn;
				memcpy((void*)&tmp->hdr, hdr, sizeof(union fi_opa1x_hfi1_packet_hdr));
				if (payload_bytes_to_copy > 0)
					memcpy((void*)&tmp->payload[0], (const void *)payload, payload_bytes_to_copy);

				fastlock_acquire(&flow->lock);

				uepkt->next->prev = tmp;
				uepkt->next = tmp;

				fastlock_release(&flow->lock);

#ifdef OPA1X_RELIABILITY_DEBUG
				fprintf(stderr, "(rx) packet %016lx %08u queued.\n", key.value, psn);
#endif
				break;

			} else if (uepkt_psn == psn) {

				/* drop this duplicate */
#ifdef OPA1X_RELIABILITY_DEBUG
				fprintf(stderr, "(rx) packet %016lx %08u dropped (duplicate).\n", key.value, psn);
#endif
				break;

			}

			/* move forward */
			uepkt = uepkt->prev;

		} while (uepkt != head);
	}

	return;
}
