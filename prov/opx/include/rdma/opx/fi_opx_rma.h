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
#ifndef _FI_PROV_OPX_RMA_H_
#define _FI_PROV_OPX_RMA_H_

#include "rdma/opx/fi_opx_internal.h"
#include "rdma/opx/fi_opx_eq.h"
#include "rdma/opx/fi_opx_rma_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

int fi_opx_check_rma(struct fi_opx_ep *opx_ep);

static inline void fi_opx_hit_zero(struct fi_opx_completion_counter *cc)
{
	if (cc->cntr) {
		ofi_atomic_inc64(&cc->cntr->std);
	}
	if (cc->cq && cc->context) {
		assert(cc->context);
		union fi_opx_context * opx_context = (union fi_opx_context *)cc->context;
		opx_context->next = NULL;
		opx_context->len = 0;
		opx_context->buf = NULL;
		opx_context->byte_counter = 0;
		opx_context->tag = 0;

		fi_opx_cq_enqueue_completed(cc->cq, cc->context, 0);
	}
	ofi_buf_free(cc);
}


static inline bool fi_opx_rma_dput_is_intranode(uint64_t caps, const union fi_opx_addr addr,
												struct fi_opx_ep *opx_ep)
{
	/* compile-time constant expression if caps are a constant */
	if (((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == FI_LOCAL_COMM) ||
	    (((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == (FI_LOCAL_COMM | FI_REMOTE_COMM)) &&
	     (opx_ep->rx->tx.dput.hdr.stl.lrh.slid == addr.uid.lid)))
		return true;
	return false;
}

static inline void fi_opx_readv_internal(struct fi_opx_ep *opx_ep, const struct iovec *iov,
				  const size_t niov, const union fi_opx_addr opx_target_addr,
				  const uint64_t *addr_offset, const uint64_t *key,
				  union fi_opx_context *opx_context, const uint64_t tx_op_flags,
				  const struct fi_opx_cq *opx_cq,
				  const struct fi_opx_cntr *opx_cntr,
				  struct fi_opx_completion_counter *cc,
				  enum fi_datatype dt, enum fi_op op,
				  const uint32_t opcode,
				  const int lock_required, const uint64_t caps,
				  const enum ofi_reliability_kind reliability)
{
	// This clears any shm conditions

	fi_opx_ep_rx_poll(&opx_ep->ep_fid, 0, OPX_RELIABILITY, FI_OPX_HDRQ_MASK_RUNTIME);
	assert(niov <= 1); // TODO, support something ... bigger
	const unsigned is_intranode = fi_opx_rma_dput_is_intranode(caps, opx_target_addr, opx_ep);

	const uint64_t dest_rx = opx_target_addr.hfi1_rx;
	const uint64_t lrh_dlid = FI_OPX_ADDR_TO_HFI1_LRH_DLID(opx_target_addr.fi);
	const uint64_t bth_rx = dest_rx << 56;
	const uint64_t pbc_dws = 2 + /* pbc */
				 2 + /* lrh */
				 3 + /* bth */
				 9 + /* kdeth; from "RcvHdrSize[i].HdrSize" CSR */
				 16; /* one "struct fi_opx_hfi1_dput_iov", padded to cache line */
	const uint16_t lrh_dws = htons(pbc_dws - 1);
	if (is_intranode) { /* compile-time constant expression */

		fi_opx_shm_dynamic_tx_connect(is_intranode, opx_ep, dest_rx);

		uint64_t pos;
		union fi_opx_hfi1_packet_hdr * tx_hdr = opx_shm_tx_next(
			&opx_ep->tx->shm, dest_rx, &pos);
		while(OFI_UNLIKELY(tx_hdr == NULL)) {
			fi_opx_shm_poll_once(&opx_ep->ep_fid, 0);
			tx_hdr = opx_shm_tx_next(
				&opx_ep->tx->shm, dest_rx, &pos);
		}
		uint64_t op64 = (op == FI_NOOP) ? FI_NOOP-1 : op;
		uint64_t dt64 = (dt == FI_VOID) ? FI_VOID-1 : dt;
		assert(FI_OPX_HFI_DPUT_OPCODE_GET == opcode); // double check packet type
		tx_hdr->qw[0] = opx_ep->rx->tx.cts.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);
		tx_hdr->qw[1] = opx_ep->rx->tx.cts.hdr.qw[1] | bth_rx;
		tx_hdr->qw[2] = opx_ep->rx->tx.cts.hdr.qw[2];
		tx_hdr->qw[3] = opx_ep->rx->tx.cts.hdr.qw[3];
		tx_hdr->qw[4] = opx_ep->rx->tx.cts.hdr.qw[4] | opcode | (dt64 << 32) | (op64 << 40)| (niov << 48);
		tx_hdr->qw[5] = (uintptr_t)cc;
		tx_hdr->qw[6] = (key == NULL) ? -1 : *key;

		union fi_opx_hfi1_packet_payload *const tx_payload =
			(union fi_opx_hfi1_packet_payload *)(tx_hdr + 1);

		tx_payload->cts.iov[0].rbuf = (uintptr_t)iov[0].iov_base; /* receive buffer virtual address */
		tx_payload->cts.iov[0].sbuf = addr_offset[0]; /* send buffer virtual address */
		tx_payload->cts.iov[0].bytes = iov[0].iov_len; /* number of bytes to transfer */

		opx_shm_tx_advance(&opx_ep->tx->shm, (void *)tx_hdr, pos);
	} else {
		/* compile-time constant expression */
		struct fi_opx_reliability_tx_replay *replay = NULL;
		if (reliability != OFI_RELIABILITY_KIND_NONE) {
			replay = fi_opx_reliability_client_replay_allocate(&opx_ep->reliability->state,
				true);
		}

		union fi_opx_reliability_tx_psn *psn_ptr = NULL;
		const int64_t psn =
			(reliability != OFI_RELIABILITY_KIND_NONE) ?
				fi_opx_reliability_tx_next_psn(&opx_ep->reliability->state,
							       opx_target_addr.uid.lid, dest_rx, &psn_ptr) :
				0;

		if(OFI_UNLIKELY(psn == -1)) {
			fi_opx_reliability_client_replay_deallocate(&opx_ep->reliability->state, replay);
			// TODO:  NEED TO HANDLE EAGAIN
			abort();
		}

		union fi_opx_hfi1_pio_state pio_state = *opx_ep->tx->pio_state;
		uint16_t total_credits_available = FI_OPX_HFI1_AVAILABLE_CREDITS(pio_state, &opx_ep->tx->force_credit_return, 2);
		if (OFI_UNLIKELY(total_credits_available < 2)) {
			do {
				fi_opx_compiler_msync_writes(); // credit return
				FI_OPX_HFI1_UPDATE_CREDITS(pio_state, opx_ep->tx->pio_credits_addr);
				total_credits_available = FI_OPX_HFI1_AVAILABLE_CREDITS(pio_state, &opx_ep->tx->force_credit_return, 2);
			} while (total_credits_available < 2);
		}
		volatile uint64_t * const scb =
			FI_OPX_HFI1_PIO_SCB_HEAD(opx_ep->tx->pio_scb_sop_first, pio_state);

		uint64_t tmp[8];
		uint64_t op64 = (op == FI_NOOP) ? FI_NOOP-1 : op;
		uint64_t dt64 = (dt == FI_VOID) ? FI_VOID-1 : dt;
		assert(FI_OPX_HFI_DPUT_OPCODE_GET == opcode); // double check packet type
		fi_opx_set_scb(scb, tmp, opx_ep->rx->tx.cts.qw0 | pbc_dws | ((opx_ep->tx->force_credit_return & FI_OPX_HFI1_PBC_CR_MASK) << FI_OPX_HFI1_PBC_CR_SHIFT),
			       opx_ep->rx->tx.cts.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32),
			       opx_ep->rx->tx.cts.hdr.qw[1] | bth_rx,
			       opx_ep->rx->tx.cts.hdr.qw[2] | psn,
				   opx_ep->rx->tx.cts.hdr.qw[3],
				   opx_ep->rx->tx.cts.hdr.qw[4] | opcode | (dt64 << 32) | (op64 << 40) | (niov << 48),
			       (uintptr_t)cc, // target_completion_counter_vaddr
			       (key == NULL) ? -1 : *key); // key

		/* consume one credit for the packet header */
		FI_OPX_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

		FI_OPX_HFI1_CLEAR_CREDIT_RETURN(opx_ep);

		if (reliability !=
		    OFI_RELIABILITY_KIND_NONE) { /* compile-time constant expression */
			replay->scb.qw0 = tmp[0];
			replay->scb.hdr.qw[0] = tmp[1];
			replay->scb.hdr.qw[1] = tmp[2];
			replay->scb.hdr.qw[2] = tmp[3];
			replay->scb.hdr.qw[3] = tmp[4];
			replay->scb.hdr.qw[4] = tmp[5];
			replay->scb.hdr.qw[5] = tmp[6];
			replay->scb.hdr.qw[6] = tmp[7];
		}

		/* write the CTS payload "send control block"  */
		volatile uint64_t * scb_payload =
			FI_OPX_HFI1_PIO_SCB_HEAD(opx_ep->tx->pio_scb_first, pio_state);

		fi_opx_set_scb(scb_payload, tmp,
			       (uintptr_t)iov[0].iov_base, /* receive buffer virtual address */
			       addr_offset[0], /* send buffer virtual address */
			       iov[0].iov_len, /* number of bytes to transfer */
			       0, 0, 0, 0, 0);

		FI_OPX_HFI1_CONSUME_SINGLE_CREDIT(pio_state);
		if (reliability !=
		    OFI_RELIABILITY_KIND_NONE) { /* compile-time constant expression */
			replay->payload[0] = tmp[0];
			replay->payload[1] = tmp[1];
			replay->payload[2] = tmp[2];
			replay->payload[3] = tmp[3];
			replay->payload[4] = tmp[4];
			replay->payload[5] = tmp[5];
			replay->payload[6] = tmp[6];
			replay->payload[7] = tmp[7];

			fi_opx_reliability_client_replay_register_no_update(
				&opx_ep->reliability->state, opx_target_addr.uid.lid,
				opx_target_addr.reliability_rx, dest_rx, psn_ptr, replay, reliability);
		}
		FI_OPX_HFI1_CHECK_CREDITS_FOR_ERROR(opx_ep->tx->pio_credits_addr);
		opx_ep->tx->pio_state->qw0 = pio_state.qw0;
	}
}


void fi_opx_write_fence(struct fi_opx_ep *opx_ep, const uint64_t tx_op_flags,
			const union fi_opx_addr *opx_dst_addr, union fi_opx_context *opx_context,
			const int lock_required);

static inline void fi_opx_shm_write_fence(struct fi_opx_ep *opx_ep, const uint64_t dest_rx,
					  const uint64_t lrh_dlid,
					  struct fi_opx_completion_counter *cc,
					  const uint64_t bytes_to_sync)
{
	const uint64_t pbc_dws = 2 + /* pbc */
				 2 + /* lrh */
				 3 + /* bth */
				 9 + /* kdeth; from "RcvHdrSize[i].HdrSize" CSR */
				 (0 << 4);
	const uint16_t lrh_dws = htons(pbc_dws - 1);
	const uint64_t bth_rx = dest_rx << 56;
	uint64_t pos;
	union fi_opx_hfi1_packet_hdr * tx_hdr = opx_shm_tx_next(
		&opx_ep->tx->shm, dest_rx, &pos);
	while(OFI_UNLIKELY(tx_hdr == NULL)) {
		fi_opx_shm_poll_once(&opx_ep->ep_fid, 0);
		tx_hdr = opx_shm_tx_next(
			&opx_ep->tx->shm, dest_rx, &pos);
	}

	tx_hdr->qw[0] = opx_ep->rx->tx.cts.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);
	tx_hdr->qw[1] = opx_ep->rx->tx.cts.hdr.qw[1] | bth_rx;
	tx_hdr->qw[2] = opx_ep->rx->tx.cts.hdr.qw[2];
	tx_hdr->qw[3] = opx_ep->rx->tx.cts.hdr.qw[3];
	tx_hdr->qw[4] = opx_ep->rx->tx.cts.hdr.qw[4] | FI_OPX_HFI_DPUT_OPCODE_FENCE | (0ULL << 32);
	tx_hdr->qw[5] = (uintptr_t)cc;
	tx_hdr->qw[6] = bytes_to_sync;

	opx_shm_tx_advance(&opx_ep->tx->shm, (void *)tx_hdr, pos);
}


static inline void fi_opx_write_internal(struct fi_opx_ep *opx_ep, const void *buf, size_t len,
				  const union fi_opx_addr opx_dst_addr, uint64_t addr_offset,
				  const uint64_t key, union fi_opx_context *opx_context,
										 struct fi_opx_completion_counter *cc, enum fi_datatype dt, enum fi_op op,
										 const uint64_t tx_op_flags,
				  const int lock_required, const uint64_t caps,
				  const enum ofi_reliability_kind reliability)
{
	fi_opx_ep_rx_poll(&opx_ep->ep_fid, 0, OPX_RELIABILITY, FI_OPX_HDRQ_MASK_RUNTIME);
	const unsigned is_intranode = fi_opx_rma_dput_is_intranode(caps, opx_dst_addr, opx_ep);
	const uint64_t dest_rx = opx_dst_addr.hfi1_rx;
	const uint64_t lrh_dlid = FI_OPX_ADDR_TO_HFI1_LRH_DLID(opx_dst_addr.fi);
	const uint64_t bth_rx = dest_rx << 56;

	uint8_t *sbuf = (uint8_t *)buf;
	uintptr_t rbuf = addr_offset;
	uint64_t bytes_to_send = len;

	if (tx_op_flags & FI_INJECT) {
		assert((tx_op_flags & (FI_COMPLETION | FI_TRANSMIT_COMPLETE)) !=
		       (FI_COMPLETION | FI_TRANSMIT_COMPLETE));
		assert((tx_op_flags & (FI_COMPLETION | FI_DELIVERY_COMPLETE)) !=
		       (FI_COMPLETION | FI_DELIVERY_COMPLETE));
		fprintf(stderr, "FI_INJECT flag unimplemented with rma_write internal\n");
		abort();
	}

	assert((opx_ep->tx->pio_max_eager_tx_bytes & 0x3f) == 0);
	while (bytes_to_send > 0) {
		uint64_t       payload_bytes = (bytes_to_send < opx_ep->tx->pio_max_eager_tx_bytes) ? bytes_to_send : opx_ep->tx->pio_max_eager_tx_bytes;
		assert(payload_bytes <= opx_ep->tx->pio_max_eager_tx_bytes);

		const size_t   xfer_bytes_tail   = payload_bytes & 0x07ul;
		const uint64_t payload_qws_tail  = (payload_bytes >> 3) &0x7ul;
		uint16_t full_block_credits_needed = (payload_bytes >> 6);
		if(payload_qws_tail || xfer_bytes_tail) {
			full_block_credits_needed += 1;
		}

		uint16_t total_credits_needed = 1 +  /* packet header */
			full_block_credits_needed;      /* full blocks */

		const uint64_t pbc_dws = 2 + /* pbc */
					 2 + /* lrh */
					 3 + /* bth */
					 9 + /* kdeth; from "RcvHdrSize[i].HdrSize" CSR */
			         ((total_credits_needed-1) << 4);

		const uint16_t lrh_dws = htons(pbc_dws - 1);

		if (is_intranode) { /* compile-time constant expression */

			fi_opx_shm_dynamic_tx_connect(is_intranode, opx_ep, dest_rx);

			uint64_t pos;
			union fi_opx_hfi1_packet_hdr *tx_hdr =
				opx_shm_tx_next(&opx_ep->tx->shm, dest_rx, &pos);
			while(OFI_UNLIKELY(tx_hdr == NULL)) {
				fi_opx_shm_poll_once(&opx_ep->ep_fid, 0);
				tx_hdr = opx_shm_tx_next(
					&opx_ep->tx->shm, dest_rx, &pos);
			}
			uint64_t op64 = (op == FI_NOOP) ? FI_NOOP-1 : op;
			uint64_t dt64 = (dt == FI_VOID) ? FI_VOID-1 : dt;

			tx_hdr->qw[0] = opx_ep->rx->tx.dput.hdr.qw[0] | lrh_dlid |
					((uint64_t)lrh_dws << 32);
			tx_hdr->qw[1] = opx_ep->rx->tx.dput.hdr.qw[1] | bth_rx;
			tx_hdr->qw[2] = opx_ep->rx->tx.dput.hdr.qw[2];
			tx_hdr->qw[3] = opx_ep->rx->tx.dput.hdr.qw[3];

			tx_hdr->qw[4] = opx_ep->rx->tx.dput.hdr.qw[4] | FI_OPX_HFI_DPUT_OPCODE_PUT | (dt64 << 32) | (op64 << 40) | (payload_bytes << 48);
			tx_hdr->qw[5] = rbuf;
			tx_hdr->qw[6] = key;

			union fi_opx_hfi1_packet_payload *const tx_payload =
				(union fi_opx_hfi1_packet_payload *)(tx_hdr + 1);

			memcpy((void *)tx_payload->byte, (const void *)sbuf,
			       payload_bytes);

			opx_shm_tx_advance(&opx_ep->tx->shm, (void *)tx_hdr, pos);

		} else {
			/* compile-time constant expression */
			struct fi_opx_reliability_tx_replay *replay = NULL;
			if (reliability != OFI_RELIABILITY_KIND_NONE) {
				replay = fi_opx_reliability_client_replay_allocate(&opx_ep->reliability->state,
					true);
			}

			uint64_t op64 = op == FI_NOOP ? FI_NOOP-1 : op;
			uint64_t dt64 = dt == FI_VOID ? FI_VOID-1 : dt;

			union fi_opx_reliability_tx_psn *psn_ptr = NULL;
			const int64_t psn = (reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
				fi_opx_reliability_tx_next_psn(&opx_ep->reliability->state, opx_dst_addr.uid.lid,
											   dest_rx, &psn_ptr) : 0;
			if(OFI_UNLIKELY(psn == -1)) {
				fi_opx_reliability_client_replay_deallocate(&opx_ep->reliability->state, replay);
				// Need to handle eagain
				abort();
			}


			replay->scb.qw0       = opx_ep->rx->tx.dput.qw0 | pbc_dws;
			replay->scb.hdr.qw[0] = opx_ep->rx->tx.dput.hdr.qw[0] | lrh_dlid |((uint64_t)lrh_dws << 32);
			replay->scb.hdr.qw[1] = opx_ep->rx->tx.dput.hdr.qw[1] | bth_rx;
			replay->scb.hdr.qw[2] = opx_ep->rx->tx.dput.hdr.qw[2] | psn;
			replay->scb.hdr.qw[3] = opx_ep->rx->tx.dput.hdr.qw[3];
			replay->scb.hdr.qw[4] = opx_ep->rx->tx.dput.hdr.qw[4] |FI_OPX_HFI_DPUT_OPCODE_PUT | (dt64 << 32) | (op64 << 40) | (payload_bytes << 48);
			replay->scb.hdr.qw[5] = rbuf;
			replay->scb.hdr.qw[6] = key;


			struct iovec iov = {sbuf, payload_bytes };
			ssize_t remain = payload_bytes, iov_idx = 0, iov_base_offset = 0;
			uint64_t *payload = replay->payload;
			while (false ==
				   fi_opx_hfi1_fill_from_iov8(
					   &iov, /* In:  iovec array */
					   1, /* In:  total iovecs */
					   payload, /* In:  target buffer to fill */
					   &remain, /* In/Out:  buffer length to fill */
					   &iov_idx, /* In/Out:  start index, returns end */
					   &iov_base_offset)) { /* In/Out:  start offset, returns offset */
				// copy until done;
			}
			assert(remain==0);
			fi_opx_reliability_client_replay_register_with_update(
				&opx_ep->reliability->state, opx_dst_addr.uid.lid,
				opx_dst_addr.reliability_rx, dest_rx, psn_ptr, replay, cc,
				payload_bytes, reliability);
			fi_opx_reliability_service_do_replay(&opx_ep->reliability->service, replay);



		} /* if !is_intranode */

		rbuf += payload_bytes;
		sbuf += payload_bytes;
		bytes_to_send -= payload_bytes;
	} /* while bytes_to_send */
	if (is_intranode) {
		fi_opx_shm_write_fence(opx_ep, dest_rx, lrh_dlid, cc, len);
	} else {
		fi_reliability_service_ping_remote(&opx_ep->ep_fid, opx_ep->reliability->state.service);
	}

	return;
}



ssize_t fi_opx_inject_write_generic(struct fid_ep *ep, const void *buf, size_t len,
				    fi_addr_t dst_addr, uint64_t addr_offset, uint64_t key,
				    int lock_required, const enum fi_av_type av_type,
				    const uint64_t caps,
				    const enum ofi_reliability_kind reliability);

ssize_t fi_opx_write_generic(struct fid_ep *ep, const void *buf, size_t len, void *desc,
			     fi_addr_t dst_addr, uint64_t addr_offset, uint64_t key, void *context,
			     int lock_required, const enum fi_av_type av_type, const uint64_t caps,
			     const enum ofi_reliability_kind reliability);

ssize_t fi_opx_writev_generic(struct fid_ep *ep, const struct iovec *iov, void **desc, size_t count,
			      fi_addr_t dst_addr, uint64_t addr_offset, uint64_t key, void *context,
			      int lock_required, const enum fi_av_type av_type, const uint64_t caps,
			      const enum ofi_reliability_kind reliability);

ssize_t fi_opx_writemsg_generic(struct fid_ep *ep, const struct fi_msg_rma *msg, uint64_t flags,
				int lock_required, const enum fi_av_type av_type,
				const uint64_t caps, const enum ofi_reliability_kind reliability);

ssize_t fi_opx_read_generic(struct fid_ep *ep, void *buf, size_t len, void *desc,
			    fi_addr_t src_addr, uint64_t addr_offset, uint64_t key, void *context,
			    int lock_required, const enum fi_av_type av_type, const uint64_t caps,

			    const enum ofi_reliability_kind reliability);

ssize_t fi_opx_readv_generic(struct fid_ep *ep, const struct iovec *iov, void **desc, size_t count,
			     fi_addr_t src_addr, uint64_t addr_offset, uint64_t key, void *context,
			     int lock_required, const enum fi_av_type av_type, const uint64_t caps,

			     const enum ofi_reliability_kind reliability);

ssize_t fi_opx_readmsg_generic(struct fid_ep *ep, const struct fi_msg_rma *msg, uint64_t flags,
			       int lock_required, const enum fi_av_type av_type,
			       const uint64_t caps, const enum ofi_reliability_kind reliability);

#ifdef __cplusplus
}
#endif

#endif /* _FI_PROV_OPX_RMA_H_ */
