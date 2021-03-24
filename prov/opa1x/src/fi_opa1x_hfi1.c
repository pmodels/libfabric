
#include <assert.h>
#include <stdlib.h>

#include "rdma/fabric.h" // only for 'fi_addr_t' ... which is a typedef to uint64_t
#include "rdma/opa1x/fi_opa1x_hfi1.h"
#include "opa_user.h"

#define BYTE2DWORD_SHIFT	(2)

#define ESSP_SL_DEFAULT		(0)	/* PSMI_SL_DEFAULT */
#define ESSP_SC_DEFAULT		(0)	/* PSMI_SC_DEFAULT */
#define ESSP_VL_DEFAULT		(0)	/* PSMI_VL_DEFAULT */
#define ESSP_SC_ADMIN		(15)	/* PSMI_SC_ADMIN */
#define ESSP_VL_ADMIN		(15)	/* PSMI_VL_ADMIN */



struct fi_opa1x_hfi1_context_internal {
	struct fi_opa1x_hfi1_context	context;

	struct hfi1_user_info_dep	user_info;
	struct _hfi_ctrl *		ctrl;

};




struct fi_opa1x_hfi1_context * fi_opa1x_hfi1_context_open (uuid_t unique_job_key)
{

	struct fi_opa1x_hfi1_context_internal * internal =
		calloc(1, sizeof(struct fi_opa1x_hfi1_context_internal));

	struct fi_opa1x_hfi1_context * context = &internal->context;


//int open_hfi1_context (uuid_t unique_job_key,
//		struct fi_opa1x_hfi1_context * context)
//{
//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);

	/*
	 * open the hfi1 context
	 */
	context->fd = -1;
	internal->ctrl = NULL;

	/* verify that at least one hfi unit exists */
	const int num_units = hfi_get_num_units();
	if (0 == num_units) { assert(0); return NULL; }

	int unit, fd = -1;
	struct _hfi_ctrl * ctrl = NULL;
	for (unit = 0; unit < num_units && ctrl == NULL; ++unit) {

		if (!hfi_get_unit_active(unit)) continue;

		fd = hfi_context_open(unit, 0, 0);	/* TODO - port (0 == autodetect, speedoflight uses '5') ?, timeout? */
		if (fd == -1) continue;

		memset(&internal->user_info, 0, sizeof(internal->user_info));
		internal->user_info.userversion = HFI1_USER_SWMINOR|(hfi_get_user_major_version()<<HFI1_SWMAJOR_SHIFT);

		internal->user_info.hfi1_alg = HFI1_ALG_ACROSS;

		/* do not share hfi contexts */
		internal->user_info.subctxt_id = 0;
		internal->user_info.subctxt_cnt = 0;

		memcpy(internal->user_info.uuid, unique_job_key, sizeof(internal->user_info.uuid));

		ctrl = hfi_userinit(fd, &internal->user_info);
		if (!ctrl) hfi_context_close(fd);
	}

	if (ctrl == NULL || fd == -1) { assert(0); return NULL; }

	context->fd = fd;
	internal->ctrl = ctrl;	/* memory was allocated during 'hfi_userinit()' */

	int lid = 0;
	lid = hfi_get_port_lid(ctrl->__hfi_unit, ctrl->__hfi_port);
	assert(lid > 0);

	uint64_t gid_hi, gid_lo;
	int rc __attribute__ ((unused)) = -1;
	rc = hfi_get_port_gid(ctrl->__hfi_unit, ctrl->__hfi_port, &gid_hi, &gid_lo);
	assert(rc != -1);

	/* these don't change - move to domain ? */
	context->hfi_unit = ctrl->__hfi_unit;
	context->hfi_port = ctrl->__hfi_port;
	context->lid = (uint16_t)lid;
	context->gid_hi = gid_hi;
	context->gid_lo = gid_lo;

	context->sl = ESSP_SL_DEFAULT;

	context->sc = hfi_get_port_sl2sc(ctrl->__hfi_unit, ctrl->__hfi_port, ESSP_SL_DEFAULT);
	if (context->sc < 0) context->sc = ESSP_SC_DEFAULT;

	context->vl = hfi_get_port_sc2vl(ctrl->__hfi_unit, ctrl->__hfi_port, context->sc);
	if (context->vl < 0) context->vl = ESSP_VL_DEFAULT;

	assert(context->sc != ESSP_SC_ADMIN);
	assert(context->vl != ESSP_VL_ADMIN);
	assert((context->vl == 15) || (context->vl <= 7));

	context->mtu = hfi_get_port_vl2mtu(ctrl->__hfi_unit, ctrl->__hfi_port, context->vl);
	assert(context->mtu >= 0);

	rc = hfi_set_pkey(ctrl, HFI_DEFAULT_P_KEY);


	const struct hfi1_base_info *base_info = &ctrl->base_info;
	const struct hfi1_ctxt_info *ctxt_info = &ctrl->ctxt_info;

	/*
	 * initialize the hfi tx context
	 */


	context->bthqp = (uint8_t)base_info->bthqp;
	context->jkey = base_info->jkey;
	context->send_ctxt = ctxt_info->send_ctxt;


	context->info.pio.scb_sop_first = (volatile uint64_t *) (ptrdiff_t) base_info->pio_bufbase_sop;	// tx->pio_bufbase_sop
	context->info.pio.scb_first = (volatile uint64_t *) (ptrdiff_t) base_info->pio_bufbase;	// tx->pio_bufbase
	context->info.pio.credits_addr = (volatile uint64_t *) (ptrdiff_t) base_info->sc_credits_addr;

	const uint64_t credit_return = *(context->info.pio.credits_addr);
	context->state.pio.free_counter_shadow = (uint16_t)(credit_return & 0x00000000000007FFul);
	context->state.pio.fill_counter = 0;
	context->state.pio.scb_head_index = 0;
	context->state.pio.credits_total = ctxt_info->credits;	/* yeah, yeah .. THIS field is static, but there was an unused halfword at this spot, so .... */

	/* move to domain ? */
	uint8_t i;
	for (i=0; i<32; ++i) {
		context->sl2sc[i] = hfi_get_port_sl2sc(ctrl->__hfi_unit, ctrl->__hfi_port, i);
		if (context->sl2sc[i] < 0) context->sl2sc[i] = ESSP_SC_DEFAULT;

		context->sc2vl[i] = hfi_get_port_sc2vl(ctrl->__hfi_unit, ctrl->__hfi_port, i);
		if (context->sc2vl[i] < 0) context->sc2vl[i] = ESSP_VL_DEFAULT;
	}

#if 0
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(ctxt_info->rec_cpu, &cpuset);	/* TODO - what is this 'rec_cpu' field mean? */
	if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
		abort();
	}
#endif

	context->info.sdma.queue_size = ctxt_info->sdma_ring_size - 1;
	context->info.sdma.available_counter = context->info.sdma.queue_size;
	context->info.sdma.fill_index = 0;
	context->info.sdma.done_index = 0;
	context->info.sdma.completion_queue = (struct hfi1_sdma_comp_entry *) base_info->sdma_comp_bufbase;


	/*
	 * initialize the hfi rx context
	 */

	context->info.rxe.id = ctrl->ctxt_info.ctxt;
	context->info.rxe.hdrq.rhf_off = (ctxt_info->rcvhdrq_entsize - 8) >> BYTE2DWORD_SHIFT;

	/* hardware registers */
	volatile uint64_t *uregbase = (volatile uint64_t *)(uintptr_t) base_info->user_regbase;
	context->info.rxe.hdrq.head_register = (volatile uint64_t *)&uregbase[ur_rcvhdrhead];
	context->info.rxe.hdrq.tail_register = (volatile uint64_t *)&uregbase[ur_rcvhdrtail];
	context->info.rxe.egrq.head_register = (volatile uint64_t *)&uregbase[ur_rcvegrindexhead];
	context->info.rxe.egrq.tail_register = (volatile uint64_t *)&uregbase[ur_rcvegrindextail];
	context->info.rxe.uregbase = uregbase;


	context->runtime_flags = ctxt_info->runtime_flags;

	if (context->runtime_flags & HFI1_CAP_DMA_RTAIL) {
		context->info.rxe.hdrq.rhf_notail = 0;
	} else {
		context->info.rxe.hdrq.rhf_notail = 1;
	}

	context->info.rxe.hdrq.elemsz = ctxt_info->rcvhdrq_entsize >> BYTE2DWORD_SHIFT;
	context->info.rxe.hdrq.elemcnt = ctxt_info->rcvhdrq_cnt;
	context->info.rxe.hdrq.elemlast = ((context->info.rxe.hdrq.elemcnt - 1) * context->info.rxe.hdrq.elemsz);
	context->info.rxe.hdrq.base_addr = (uint32_t *) (uintptr_t) base_info->rcvhdr_bufbase;
	context->info.rxe.hdrq.rhf_base = context->info.rxe.hdrq.base_addr + context->info.rxe.hdrq.rhf_off;

	context->info.rxe.egrq.base_addr = (uint32_t *) (uintptr_t) base_info->rcvegr_bufbase;
	context->info.rxe.egrq.elemsz = ctxt_info->rcvegr_size;

//fprintf(stderr, "%s:%s():%d\n", __FILE__, __func__, __LINE__);
	return context;
}



int init_hfi1_rxe_state (struct fi_opa1x_hfi1_context * context,
		struct fi_opa1x_hfi1_rxe_state * rxe_state)
{
	rxe_state->hdrq.head = 0;

	if (context->runtime_flags & HFI1_CAP_DMA_RTAIL) {
		rxe_state->hdrq.rhf_seq = 0;		/* will be ignored */
	} else {
		rxe_state->hdrq.rhf_seq = 0x10000000u;
	}

	rxe_state->egrq.countdown = 8;

	return 0;
}







#include "rdma/opa1x/fi_opa1x.h"
#include "rdma/opa1x/fi_opa1x_endpoint.h"
#include "rdma/opa1x/fi_opa1x_reliability.h"

void fi_opa1x_hfi1_tx_connect (struct fi_opa1x_ep *opa1x_ep, fi_addr_t peer)
{

	if ((opa1x_ep->tx.caps & FI_LOCAL_COMM) || ((opa1x_ep->tx.caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == 0)) {

		const uint64_t lrh_dlid = FI_OPA1X_ADDR_TO_HFI1_LRH_DLID(peer);
		const uint16_t dlid_be16 = (uint16_t)(FI_OPA1X_HFI1_LRH_DLID_TO_LID(lrh_dlid));
		const uint16_t slid_be16 = htons(opa1x_ep->hfi->lid);

		if (slid_be16 == dlid_be16) {
			union fi_opa1x_addr addr;
			addr.raw64b = (uint64_t)peer;

			ofi_shm2_tx_connect(&opa1x_ep->tx.shm,
				(const char * const)opa1x_ep->domain->unique_job_key_str,
				addr.hfi1_rx,
				FI_OPA1X_SHM_FIFO_SIZE,
				FI_OPA1X_SHM_PACKET_SIZE);
		}
	}

	return;
}


void fi_opa1x_hfi1_rx_rzv_rts (struct fid_ep *ep,
		const void * const hdr, const void * const payload,
		const uint8_t u8_rx, const uint64_t niov,
		uintptr_t origin_byte_counter_vaddr,
		uintptr_t target_byte_counter_vaddr,
		const uintptr_t dst_vaddr,
		const uintptr_t src_vaddr,
		const uint64_t nbytes_to_transfer,
		const unsigned is_intranode,
		const enum ofi_reliability_kind reliability)
{

	struct fi_opa1x_ep * opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);

	const union fi_opa1x_hfi1_packet_hdr * const hfi1_hdr =
		(const union fi_opa1x_hfi1_packet_hdr * const) hdr;

	/* use the slid from the lrh header of the incoming packet
	 * as the dlid for the lrh header of the outgoing packet */
	const uint64_t lrh_dlid = (hfi1_hdr->stl.lrh.qw[0] & 0xFFFF000000000000ul) >> 32;

	const uint64_t bth_rx = ((uint64_t)u8_rx) << 56;

	const uint64_t pbc_dws =
		2 +			/* pbc */
		2 +			/* lrh */
		3 +			/* bth */
		9 +			/* kdeth; from "RcvHdrSize[i].HdrSize" CSR */
		6;			/* one "struct fi_opa1x_hfi1_dput_iov" */

	const uint16_t lrh_dws = htons(pbc_dws-1);

	if (is_intranode) {	/* compile-time constant expression */

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV, SHM -- RENDEZVOUS RTS (begin)\n");

		union fi_opa1x_hfi1_packet_hdr * const tx_hdr =
			ofi_shm2_tx_next(&opa1x_ep->tx.shm, u8_rx,
				FI_OPA1X_SHM_FIFO_SIZE,
				FI_OPA1X_SHM_PACKET_SIZE);

		tx_hdr->qw[0] = opa1x_ep->rx.tx.cts.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);
		tx_hdr->qw[1] = opa1x_ep->rx.tx.cts.hdr.qw[1] | bth_rx;
		tx_hdr->qw[2] = opa1x_ep->rx.tx.cts.hdr.qw[2];
		tx_hdr->qw[3] = opa1x_ep->rx.tx.cts.hdr.qw[3];
		tx_hdr->qw[4] = opa1x_ep->rx.tx.cts.hdr.qw[4] | (0x01ul << 32);   /* 1 iov; TODO: psn and tx */
		tx_hdr->qw[5] = origin_byte_counter_vaddr;
		tx_hdr->qw[6] = target_byte_counter_vaddr;


		union fi_opa1x_hfi1_packet_payload * const tx_payload =
			(union fi_opa1x_hfi1_packet_payload *)(tx_hdr+1);

		tx_payload->cts.iov[0].rbuf = dst_vaddr;		/* receive buffer virtual address */
		tx_payload->cts.iov[0].sbuf = src_vaddr;		/* send buffer virtual address */
		tx_payload->cts.iov[0].bytes = nbytes_to_transfer;	/* number of bytes to transfer */

		ofi_shm2_tx_advance(&opa1x_ep->tx.shm, (void*)tx_hdr);

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV, SHM -- RENDEZVOUS RTS (end)\n");

	} else 	{

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV, HFI -- RENDEZVOUS RTS (begin)\n");

		/* use the slid from the lrh header of the incoming packet
		 * as the dlid for the lrh header of the outgoing packet */

		const uint64_t psn = (reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
			fi_opa1x_reliability_tx_next_psn(&opa1x_ep->reliability_state, hfi1_hdr->stl.lrh.slid, u8_rx) :
			0;

		/*
		 * send the rendezvous CTS packet
		 */

		union fi_opa1x_hfi1_pio_state pio_state = opa1x_ep->tx.pio_state;

		volatile uint64_t * const pio_scb_sop_first = opa1x_ep->tx.pio_scb_sop_first;
		volatile uint64_t * const pio_scb_first = opa1x_ep->tx.pio_scb_first;
		volatile uint64_t * const pio_credits_addr = opa1x_ep->tx.pio_credits_addr;

		/*
		 * BLOCK until enough credits become available
		 */
		uint16_t total_credits_available = FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state);
		if (unlikely(total_credits_available < 2)) {
			do {
				FI_OPA1X_HFI1_UPDATE_CREDITS(pio_state, pio_credits_addr);
				total_credits_available = FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state);
			} while (total_credits_available < 2);
		}

		volatile uint64_t * const scb =
			FI_OPA1X_HFI1_PIO_SCB_HEAD(pio_scb_sop_first, pio_state);

		uint64_t tmp[8];

		tmp[0] = scb[0] = opa1x_ep->rx.tx.cts.qw0 | pbc_dws;
		tmp[1] = scb[1] = opa1x_ep->rx.tx.cts.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);
		tmp[2] = scb[2] = opa1x_ep->rx.tx.cts.hdr.qw[1] | bth_rx;
		tmp[3] = scb[3] = opa1x_ep->rx.tx.cts.hdr.qw[2] | psn;
		tmp[4] = scb[4] = opa1x_ep->rx.tx.cts.hdr.qw[3];
		tmp[5] = scb[5] = opa1x_ep->rx.tx.cts.hdr.qw[4] | (0x01ul << 32);   /* 1 iov; TODO: psn and tx */
		tmp[6] = scb[6] = origin_byte_counter_vaddr;
		tmp[7] = scb[7] = target_byte_counter_vaddr;

		/* consume one credit for the packet header */
		FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

		struct fi_opa1x_reliability_tx_replay * replay =
			(reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
				fi_opa1x_reliability_client_replay_allocate(&opa1x_ep->reliability_state) :
				NULL;

		if (reliability != OFI_RELIABILITY_KIND_NONE) {		/* compile-time constant expression */
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

		uint64_t * scb_payload = (uint64_t *)FI_OPA1X_HFI1_PIO_SCB_HEAD(pio_scb_first, pio_state);

		tmp[0] = scb_payload[0] = dst_vaddr;		/* receive buffer virtual address */
		tmp[1] = scb_payload[1] = src_vaddr;		/* send buffer virtual address */
		tmp[2] = scb_payload[2] = nbytes_to_transfer;	/* number of bytes to transfer */
		tmp[3] = scb_payload[3] = 0;
		tmp[4] = scb_payload[4] = 0;
		tmp[5] = scb_payload[5] = 0;
		tmp[6] = scb_payload[6] = 0;
		tmp[7] = scb_payload[7] = 0;

		FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

		fi_opa1x_compiler_msync_writes(); /* TODO: not needed if using avx512 */

		if (reliability != OFI_RELIABILITY_KIND_NONE) {		/* compile-time constant expression */
			replay->payload[0] = tmp[0];
			replay->payload[1] = tmp[1];
			replay->payload[2] = tmp[2];
			replay->payload[3] = tmp[3];
			replay->payload[4] = tmp[4];
			replay->payload[5] = tmp[5];
			replay->payload[6] = tmp[6];
			replay->payload[7] = tmp[7];

			fi_opa1x_reliability_client_replay_register_no_update(&opa1x_ep->reliability_state,
				hfi1_hdr->stl.lrh.slid, hfi1_hdr->rendezvous.origin_rs,
				hfi1_hdr->rendezvous.origin_rx, psn, replay,
				reliability);
		}

		/* update the hfi txe state */
		opa1x_ep->tx.pio_state.qw0 = pio_state.qw0;

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== RECV, HFI -- RENDEZVOUS RTS (end)\n");

	} /* end hfi1 */
}


void fi_opa1x_hfi1_rx_rzv_cts (struct fid_ep *ep,
	const void * const hdr, const void * const payload,
	const uint8_t u8_rx, const uint32_t niov,
	const struct fi_opa1x_hfi1_dput_iov * const dput_iov,
	const uintptr_t target_byte_counter_vaddr,
	uint64_t * origin_byte_counter,
	const unsigned is_intranode,
	const enum ofi_reliability_kind reliability)
{

	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"===================================== RECV, %s -- RENDEZVOUS CTS (begin)\n", is_intranode ? "SHM" : "HFI");

	struct fi_opa1x_ep * opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);

	union fi_opa1x_hfi1_pio_state pio_state = opa1x_ep->tx.pio_state;

	volatile uint64_t * const pio_scb_sop_first = opa1x_ep->tx.pio_scb_sop_first;
	volatile uint64_t * const pio_scb_first = opa1x_ep->tx.pio_scb_first;
	volatile uint64_t * const pio_credits_addr = opa1x_ep->tx.pio_credits_addr;

	const union fi_opa1x_hfi1_packet_hdr * const hfi1_hdr =
		(const union fi_opa1x_hfi1_packet_hdr * const) hdr;

	/* use the slid from the lrh header of the incoming packet
	 * as the dlid for the lrh header of the outgoing packet */
	const uint64_t lrh_dlid = (hfi1_hdr->stl.lrh.qw[0] & 0xFFFF000000000000ul) >> 32;

	const uint64_t bth_rx = (uint64_t)u8_rx << 56;

	unsigned i;
	for (i=0; i<niov; ++i) {

		uint8_t * sbuf = (uint8_t *)dput_iov[i].sbuf;
		uintptr_t rbuf = dput_iov[i].rbuf;
		uint64_t bytes_to_send = dput_iov[i].bytes;

		assert((bytes_to_send & 0x03Fu) == 0);	/* only full blocks */
		while (bytes_to_send > 0) {

			FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
				"inject rendezvous data packet\n");

			uint64_t blocks_to_send_in_this_packet =
				bytes_to_send < 8192 ? bytes_to_send >> 6 : 128;

			uint64_t bytes_to_send_in_this_packet =
				blocks_to_send_in_this_packet << 6;

			const uint64_t pbc_dws =
				2 +			/* pbc */
				2 +			/* lrh */
				3 +			/* bth */
				9 +			/* kdeth; from "RcvHdrSize[i].HdrSize" CSR */
				(blocks_to_send_in_this_packet << 4);

			const uint16_t lrh_dws = htons(pbc_dws-1);

			if (is_intranode) {					/* compile-time constant expression */

				FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
					"===================================== SEND, SHM -- RENDEZVOUS DATA (begin)\n");

				union fi_opa1x_hfi1_packet_hdr * const tx_hdr =
					ofi_shm2_tx_next(&opa1x_ep->tx.shm, u8_rx,
						FI_OPA1X_SHM_FIFO_SIZE,
						FI_OPA1X_SHM_PACKET_SIZE);

				tx_hdr->qw[0] = opa1x_ep->rx.tx.dput.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);
				tx_hdr->qw[1] = opa1x_ep->rx.tx.dput.hdr.qw[1] | bth_rx;
				tx_hdr->qw[2] = opa1x_ep->rx.tx.dput.hdr.qw[2];
				tx_hdr->qw[3] = opa1x_ep->rx.tx.dput.hdr.qw[3];
				tx_hdr->qw[4] = opa1x_ep->rx.tx.dput.hdr.qw[4] | (bytes_to_send_in_this_packet << 32);
				tx_hdr->qw[5] = rbuf;
				tx_hdr->qw[6] = target_byte_counter_vaddr;


				union fi_opa1x_hfi1_packet_payload * const tx_payload =
					(union fi_opa1x_hfi1_packet_payload *)(tx_hdr+1);


				memcpy((void *)tx_payload->byte,
					(const void *)sbuf,
					bytes_to_send_in_this_packet);

				ofi_shm2_tx_advance(&opa1x_ep->tx.shm, (void*)tx_hdr);

				FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
					"===================================== SEND, SHM -- RENDEZVOUS DATA (end)\n");

			} else {

				FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
					"===================================== SEND, HFI -- RENDEZVOUS DATA (begin)\n");

				const uint64_t psn = (reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
					fi_opa1x_reliability_tx_next_psn(&opa1x_ep->reliability_state, hfi1_hdr->stl.lrh.slid, u8_rx) :
					0;

				/*
				 * BLOCK until enough credits become available
				 */
				uint16_t total_credits_needed = blocks_to_send_in_this_packet + 1;
				uint16_t total_credits_available = FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state);
				if (unlikely(total_credits_available < total_credits_needed)) {
					do {
						FI_OPA1X_HFI1_UPDATE_CREDITS(pio_state, pio_credits_addr);
						total_credits_available = FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state);
					} while (total_credits_available < total_credits_needed);
				}

				volatile uint64_t * const scb = FI_OPA1X_HFI1_PIO_SCB_HEAD(pio_scb_sop_first, pio_state);

				uint64_t tmp[8];
				tmp[0] = scb[0] = opa1x_ep->rx.tx.dput.qw0 | pbc_dws;
				tmp[1] = scb[1] = opa1x_ep->rx.tx.dput.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);
				tmp[2] = scb[2] = opa1x_ep->rx.tx.dput.hdr.qw[1] | bth_rx;
				tmp[3] = scb[3] = opa1x_ep->rx.tx.dput.hdr.qw[2] | psn;
				tmp[4] = scb[4] = opa1x_ep->rx.tx.dput.hdr.qw[3];
				tmp[5] = scb[5] = opa1x_ep->rx.tx.dput.hdr.qw[4] | (bytes_to_send_in_this_packet << 32);
				tmp[6] = scb[6] = rbuf;
				tmp[7] = scb[7] = target_byte_counter_vaddr;

				/* consume one credit for the packet header */
				--total_credits_available;
				FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);


				struct fi_opa1x_reliability_tx_replay * replay =
					(reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
						fi_opa1x_reliability_client_replay_allocate(&opa1x_ep->reliability_state) :
						NULL;

				if (reliability != OFI_RELIABILITY_KIND_NONE) {		/* compile-time constant expression */
					replay->scb.qw0 = tmp[0];
					replay->scb.hdr.qw[0] = tmp[1];
					replay->scb.hdr.qw[1] = tmp[2];
					replay->scb.hdr.qw[2] = tmp[3];
					replay->scb.hdr.qw[3] = tmp[4];
					replay->scb.hdr.qw[4] = tmp[5];
					replay->scb.hdr.qw[5] = tmp[6];
					replay->scb.hdr.qw[6] = tmp[7];
				}

				uint64_t * replay_payload =
					(reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
						replay->payload : NULL;

				uint64_t * buf_qws = (uint64_t*)((uintptr_t)sbuf);
				while (blocks_to_send_in_this_packet > 0) {

					volatile uint64_t * scb_payload =
						FI_OPA1X_HFI1_PIO_SCB_HEAD(pio_scb_first, pio_state);

					const uint16_t contiguous_credits_until_wrap =
						(uint16_t)(pio_state.credits_total - pio_state.scb_head_index);

					const uint16_t contiguous_credits_available =
						MIN(total_credits_available, contiguous_credits_until_wrap);

					const uint16_t contiguous_blocks_to_write =
						MIN(blocks_to_send_in_this_packet, contiguous_credits_available);

					unsigned n;
					for (n=0; n<contiguous_blocks_to_write; ++n) {
						scb_payload[0] = buf_qws[0];
						scb_payload[1] = buf_qws[1];
						scb_payload[2] = buf_qws[2];
						scb_payload[3] = buf_qws[3];
						scb_payload[4] = buf_qws[4];
						scb_payload[5] = buf_qws[5];
						scb_payload[6] = buf_qws[6];
						scb_payload[7] = buf_qws[7];
						scb_payload += 8;

						if (reliability != OFI_RELIABILITY_KIND_NONE) {	/* compile-time constant expression */
							replay_payload[0] = buf_qws[0];
							replay_payload[1] = buf_qws[1];
							replay_payload[2] = buf_qws[2];
							replay_payload[3] = buf_qws[3];
							replay_payload[4] = buf_qws[4];
							replay_payload[5] = buf_qws[5];
							replay_payload[6] = buf_qws[6];
							replay_payload[7] = buf_qws[7];
							replay_payload += 8;
						}

						buf_qws += 8;
					}

					blocks_to_send_in_this_packet -= contiguous_blocks_to_write;
					total_credits_available -= contiguous_blocks_to_write;

					FI_OPA1X_HFI1_CONSUME_CREDITS(pio_state, contiguous_blocks_to_write);
				}

				if (reliability != OFI_RELIABILITY_KIND_NONE) {		/* compile-time constant expression */
					fi_opa1x_reliability_client_replay_register_no_update(&opa1x_ep->reliability_state,
						hfi1_hdr->stl.lrh.slid, hfi1_hdr->cts.origin_rs, u8_rx, psn, replay,
						reliability);
				}

				/* update the shared hfi txe state */
				opa1x_ep->tx.pio_state.qw0 = pio_state.qw0;

				fi_opa1x_compiler_msync_writes();


				FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
					"===================================== SEND, HFI -- RENDEZVOUS DATA (end)\n");
			} /* if !is_intranode */

			rbuf += bytes_to_send_in_this_packet;
			sbuf += bytes_to_send_in_this_packet;
			bytes_to_send -= bytes_to_send_in_this_packet;

			*origin_byte_counter -= bytes_to_send_in_this_packet;

		} /* while bytes_to_send */

	} /* for niov */

	return;
}




ssize_t fi_opa1x_hfi1_tx_send_rzv (struct fid_ep *ep,
		const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, uint64_t tag, void* context,
		const uint32_t data, int lock_required,
		const unsigned is_contiguous,
		const unsigned override_flags, uint64_t tx_op_flags,
		const uint64_t dest_rx,
		const uintptr_t origin_byte_counter_vaddr,
		uint64_t *origin_byte_counter_value,
		const uint64_t caps,
		const enum ofi_reliability_kind reliability)
{
	struct fi_opa1x_ep * opa1x_ep = container_of(ep, struct fi_opa1x_ep, ep_fid);
	const union fi_opa1x_addr addr = { .fi = dest_addr };

	size_t niov = is_contiguous ? 1 : len;

#ifndef NDEBUG
	if (niov > 1) {
		fprintf(stderr, "%s:%s():%d TODO noncontiguous rendezvous send\n", __FILE__, __func__, __LINE__);
		abort();
	}
#endif

#ifdef RZV_IMMEDIATE_BLOCK_ENABLED
	const uint64_t max_immediate_block_count = 2; /* alternatively: (FI_OPA1X_HFI1_PACKET_MTU >> 6)-2) */
	const uint64_t immediate_block_count = MIN((len >> 6), max_immediate_block_count);
#else
	const uint64_t immediate_block_count = 0;
#endif
	const uint64_t payload_blocks_total =
		1 +				/* rzv metadata */
		1 +				/* immediate data tail */
		immediate_block_count;


	const uint64_t bth_rx = ((uint64_t)dest_rx) << 56;
	const uint64_t lrh_dlid = FI_OPA1X_ADDR_TO_HFI1_LRH_DLID(dest_addr);

	const uint64_t immediate_byte_count = len & 0x0007ul;
	const uint64_t immediate_qw_count = (len >> 3) & 0x0007ul;
	const uint64_t immediate_total = immediate_byte_count +
		immediate_qw_count * sizeof(uint64_t) +
		immediate_block_count * sizeof(union cacheline);

	assert(((len - immediate_total) & 0x003Fu) == 0);

	*origin_byte_counter_value = len - immediate_total;

	const uint64_t pbc_dws =
		2 +			/* pbc */
		2 +			/* lhr */
		3 +			/* bth */
		9 +			/* kdeth; from "RcvHdrSize[i].HdrSize" CSR */
		(payload_blocks_total << 4);

	const uint16_t lrh_dws = htons(pbc_dws-1);

#if 0
	if ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == FI_LOCAL_COMM) {	/* compile-time constant expression */
		fprintf(stderr, "%s:%s():%d only intranode\n", __FILE__, __func__, __LINE__);
	}
	if ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == FI_REMOTE_COMM) {	/* compile-time constant expression */
		fprintf(stderr, "%s:%s():%d only fabric\n", __FILE__, __func__, __LINE__);
	}
	if ((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == (FI_LOCAL_COMM | FI_REMOTE_COMM)) {	/* compile-time constant expression */
		fprintf(stderr, "%s:%s():%d check intranode, then fabric\n", __FILE__, __func__, __LINE__);
	}
#endif

	if (((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == FI_LOCAL_COMM) ||	/* compile-time constant expression */
		(((caps & (FI_LOCAL_COMM | FI_REMOTE_COMM)) == (FI_LOCAL_COMM | FI_REMOTE_COMM)) &&
			(opa1x_ep->tx.send.hdr.stl.lrh.slid == addr.uid.lid))) {

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== SEND, SHM -- RENDEZVOUS RTS (begin)\n");

		union fi_opa1x_hfi1_packet_hdr * const hdr =
			ofi_shm2_tx_next(&opa1x_ep->tx.shm, dest_rx,
				FI_OPA1X_SHM_FIFO_SIZE,
				FI_OPA1X_SHM_PACKET_SIZE);

		hdr->qw[0] = opa1x_ep->tx.rzv.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);

		hdr->qw[1] = opa1x_ep->tx.rzv.hdr.qw[1] | bth_rx |
			((caps & FI_MSG) ?
				(uint64_t)FI_OPA1X_HFI_BTH_OPCODE_MSG_RZV_RTS :
				(uint64_t)FI_OPA1X_HFI_BTH_OPCODE_TAG_RZV_RTS);

		hdr->qw[2] = opa1x_ep->tx.rzv.hdr.qw[2];
		hdr->qw[3] = opa1x_ep->tx.rzv.hdr.qw[3] | (((uint64_t)data) << 32);
		hdr->qw[4] = opa1x_ep->tx.rzv.hdr.qw[4] | (niov << 48);
		hdr->qw[5] = len;
		hdr->qw[6] = tag;


		union fi_opa1x_hfi1_packet_payload * const payload =
			(union fi_opa1x_hfi1_packet_payload *)(hdr+1);

		payload->rendezvous.contiguous.src_vaddr = (uintptr_t)buf + immediate_total;
		payload->rendezvous.contiguous.src_blocks = (len - immediate_total) >> 6;
		payload->rendezvous.contiguous.immediate_byte_count = immediate_byte_count;
		payload->rendezvous.contiguous.immediate_qw_count = immediate_qw_count;
		payload->rendezvous.contiguous.immediate_block_count = immediate_block_count;
		payload->rendezvous.contiguous.origin_byte_counter_vaddr = origin_byte_counter_vaddr;
		payload->rendezvous.contiguous.unused[0] = 0;
		payload->rendezvous.contiguous.unused[1] = 0;


		uint8_t *sbuf = (uint8_t *)buf;

		if (immediate_byte_count > 0) {
			memcpy((void*)&payload->rendezvous.contiguous.immediate_byte, (const void*)sbuf, immediate_byte_count);
			sbuf += immediate_byte_count;
		}

		uint64_t * sbuf_qw = (uint64_t *)sbuf;
		unsigned i=0;
		for (i=0; i<immediate_qw_count; ++i) {
			payload->rendezvous.contiguous.immediate_qw[i] = sbuf_qw[i];
		}

#ifdef RZV_IMMEDIATE_BLOCK_ENABLED
		sbuf_qw += immediate_qw_count;

		memcpy((void*)payload->rendezvous.contiguous.immediate_block,
			(const void *)sbuf_qw, immediate_block_count * 64);
#endif

		ofi_shm2_tx_advance(&opa1x_ep->tx.shm, (void*)hdr);

		FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
			"===================================== SEND, SHM -- RENDEZVOUS RTS (end)\n");

		return FI_SUCCESS;
	}

	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"===================================== SEND, HFI -- RENDEZVOUS RTS (begin)\n");

	/*
	 * For now this is implemented as PIO-only protocol, no SDMA
	 * engines are used and no TIDs are allocated for expected
	 * receives.
	 *
	 * This will have lower performance because software on the
	 * initiator must copy the data into the injection buffer,
	 * rather than the hardware via SDMA engines, and the
	 * target must copy the data into the receive buffer, rather
	 * than the hardware.
	 */

	union fi_opa1x_hfi1_pio_state pio_state = opa1x_ep->tx.pio_state;

	const uint16_t total_credits_needed =
		1 +				/* packet header */
		payload_blocks_total;		/* packet payload */

	uint64_t total_credits_available = FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state);
	unsigned loop = 0;
	while (unlikely(total_credits_available < total_credits_needed)) {
		FI_OPA1X_HFI1_UPDATE_CREDITS(pio_state, opa1x_ep->tx.pio_credits_addr);
		total_credits_available = FI_OPA1X_HFI1_AVAILABLE_CREDITS(pio_state);
		if (total_credits_available < total_credits_needed && loop > 10000) {
			return -FI_EAGAIN;
		}
		loop++;
	}

	const uint64_t psn = (reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
		fi_opa1x_reliability_tx_next_psn(&opa1x_ep->reliability_state, addr.uid.lid, dest_rx) :
		0;

	if (is_contiguous || niov == 1) {

		struct fi_opa1x_reliability_tx_replay * replay =
			(reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
				fi_opa1x_reliability_client_replay_allocate(&opa1x_ep->reliability_state) :
				NULL;
		/*
		 * Write the 'start of packet' (hw+sw header) 'send control block'
		 * which will consume a single pio credit.
		 */

		volatile uint64_t * const scb =
			FI_OPA1X_HFI1_PIO_SCB_HEAD(opa1x_ep->tx.pio_scb_sop_first, pio_state);

		uint64_t tmp[8];

		tmp[0] = scb[0] = opa1x_ep->tx.rzv.qw0 | pbc_dws;
		tmp[1] = scb[1] = opa1x_ep->tx.rzv.hdr.qw[0] | lrh_dlid | ((uint64_t)lrh_dws << 32);

		tmp[2] = scb[2] = opa1x_ep->tx.rzv.hdr.qw[1] | bth_rx |
			((caps & FI_MSG) ?
				(uint64_t)FI_OPA1X_HFI_BTH_OPCODE_MSG_RZV_RTS :
				(uint64_t)FI_OPA1X_HFI_BTH_OPCODE_TAG_RZV_RTS);

		tmp[3] = scb[3] = opa1x_ep->tx.rzv.hdr.qw[2] | psn;
		tmp[4] = scb[4] = opa1x_ep->tx.rzv.hdr.qw[3] | (((uint64_t)data) << 32);
		tmp[5] = scb[5] = opa1x_ep->tx.rzv.hdr.qw[4] | (niov << 48);
		tmp[6] = scb[6] = len;
		tmp[7] = scb[7] = tag;

		if (reliability != OFI_RELIABILITY_KIND_NONE) {	/* compile-time constant expression */
			replay->scb.qw0 = tmp[0];
			replay->scb.hdr.qw[0] = tmp[1];
			replay->scb.hdr.qw[1] = tmp[2];
			replay->scb.hdr.qw[2] = tmp[3];
			replay->scb.hdr.qw[3] = tmp[4];
			replay->scb.hdr.qw[4] = tmp[5];
			replay->scb.hdr.qw[5] = tmp[6];
			replay->scb.hdr.qw[6] = tmp[7];
		}

		/* consume one credit for the packet header */
		FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

		/*
		 * write the rendezvous payload "send control blocks"
		 */

		uint64_t * scb_payload = (uint64_t *)FI_OPA1X_HFI1_PIO_SCB_HEAD(opa1x_ep->tx.pio_scb_first, pio_state);

		tmp[0] = scb_payload[0] = (uintptr_t)buf + immediate_total;	/* src_vaddr */
		tmp[1] = scb_payload[1] = (len - immediate_total) >> 6;		/* src_blocks */
		tmp[2] = scb_payload[2] = immediate_byte_count;
		tmp[3] = scb_payload[3] = immediate_qw_count;
		tmp[4] = scb_payload[4] = immediate_block_count;
		tmp[5] = scb_payload[5] = origin_byte_counter_vaddr;
		tmp[6] = scb_payload[6] = 0; /* unused */
		tmp[7] = scb_payload[7] = 0; /* unused */


		uint64_t * replay_payload =
			(reliability != OFI_RELIABILITY_KIND_NONE) ?	/* compile-time constant expression */
				replay->payload : NULL;

		if (reliability != OFI_RELIABILITY_KIND_NONE) {	/* compile-time constant expression */
			replay_payload[0] = tmp[0];
			replay_payload[1] = tmp[1];
			replay_payload[2] = tmp[2];
			replay_payload[3] = tmp[3];
			replay_payload[4] = tmp[4];
			replay_payload[5] = tmp[5];
			replay_payload[6] = tmp[6];
			replay_payload[7] = tmp[7];
			replay_payload += 8;
		}

		/* consume one credit for the rendezvous payload metadata */
		FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

		scb_payload = (uint64_t *)FI_OPA1X_HFI1_PIO_SCB_HEAD(opa1x_ep->tx.pio_scb_first, pio_state);


		uint8_t *sbuf = (uint8_t *)buf;

		if (immediate_byte_count > 0) {
			memset(tmp, 0, sizeof(tmp));
			memcpy((void*)&tmp[0], (const void*)sbuf, immediate_byte_count);
			scb_payload[0] = tmp[0];
			scb_payload[1] = tmp[1];
			scb_payload[2] = tmp[2];
			scb_payload[3] = tmp[3];
			scb_payload[4] = tmp[4];
			scb_payload[5] = tmp[5];
			scb_payload[6] = tmp[6];
			scb_payload[7] = tmp[7];
			sbuf += immediate_byte_count;
		} else {
			tmp[0] = scb_payload[0] = 0;
			tmp[1] = scb_payload[1] = 0;
			tmp[2] = scb_payload[2] = 0;
			tmp[3] = scb_payload[3] = 0;
			tmp[4] = scb_payload[4] = 0;
			tmp[5] = scb_payload[5] = 0;
			tmp[6] = scb_payload[6] = 0;
			tmp[7] = scb_payload[7] = 0;
		}
		scb_payload += 1;

		uint64_t * sbuf_qw = (uint64_t *)sbuf;
		sbuf_qw += immediate_qw_count;

		if (reliability != OFI_RELIABILITY_KIND_NONE) {	/* compile-time constant expression */
			replay_payload[0] = tmp[0];
			replay_payload[1] = tmp[1];
			replay_payload[2] = tmp[2];
			replay_payload[3] = tmp[3];
			replay_payload[4] = tmp[4];
			replay_payload[5] = tmp[5];
			replay_payload[6] = tmp[6];
			replay_payload[7] = tmp[7];
			replay_payload += 8;
		}

		/* consume one credit for the rendezvous payload immediate data */
		FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

#ifdef RZV_IMMEDIATE_BLOCK_ENABLED
		switch (immediate_block_count) {

			case 2:
				scb_payload = (uint64_t *)FI_OPA1X_HFI1_PIO_SCB_HEAD(opa1x_ep->tx.pio_scb_first, pio_state);

				scb_payload[0] = sbuf_qw[0];
				scb_payload[1] = sbuf_qw[1];
				scb_payload[2] = sbuf_qw[2];
				scb_payload[3] = sbuf_qw[3];
				scb_payload[4] = sbuf_qw[4];
				scb_payload[5] = sbuf_qw[5];
				scb_payload[6] = sbuf_qw[6];
				scb_payload[7] = sbuf_qw[7];
				scb_payload += 8;

				if (reliability != OFI_RELIABILITY_KIND_NONE) {	/* compile-time constant expression */
					replay_payload[0] = sbuf_qw[0];
					replay_payload[1] = sbuf_qw[1];
					replay_payload[2] = sbuf_qw[2];
					replay_payload[3] = sbuf_qw[3];
					replay_payload[4] = sbuf_qw[4];
					replay_payload[5] = sbuf_qw[5];
					replay_payload[6] = sbuf_qw[6];
					replay_payload[7] = sbuf_qw[7];
					replay_payload += 8;
				}

				sbuf_qw += 8;

				FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

				/* break; is purposefully omitted */

			case 1:
				scb_payload = (uint64_t *)FI_OPA1X_HFI1_PIO_SCB_HEAD(opa1x_ep->tx.>pio_scb_first, pio_state);

				scb_payload[0] = sbuf_qw[0];
				scb_payload[1] = sbuf_qw[1];
				scb_payload[2] = sbuf_qw[2];
				scb_payload[3] = sbuf_qw[3];
				scb_payload[4] = sbuf_qw[4];
				scb_payload[5] = sbuf_qw[5];
				scb_payload[6] = sbuf_qw[6];
				scb_payload[7] = sbuf_qw[7];
				scb_payload += 8;

				if (reliability != OFI_RELIABILITY_KIND_NONE) {	/* compile-time constant expression */
					replay_payload[0] = sbuf_qw[0];
					replay_payload[1] = sbuf_qw[1];
					replay_payload[2] = sbuf_qw[2];
					replay_payload[3] = sbuf_qw[3];
					replay_payload[4] = sbuf_qw[4];
					replay_payload[5] = sbuf_qw[5];
					replay_payload[6] = sbuf_qw[6];
					replay_payload[7] = sbuf_qw[7];
					replay_payload += 8;
				}

				sbuf_qw += 8;

				FI_OPA1X_HFI1_CONSUME_SINGLE_CREDIT(pio_state);

				break;

			default:
				break;

		}
#endif /* RZV_IMMEDIATE_BLOCK_ENABLED */

		fi_opa1x_compiler_msync_writes();	/* TODO: not needed if using avx512 */

		if (reliability != OFI_RELIABILITY_KIND_NONE) {	/* compile-time constant expression */
			fi_opa1x_reliability_client_replay_register_no_update(&opa1x_ep->reliability_state,
				addr.uid.lid, addr.reliability_rx, dest_rx, psn, replay,
				reliability);
		}
	} else {
		/* !is_contiguous || niov > 1 */
		fprintf(stderr, "%s:%s():%d TODO noncontiguous rendezvous send\n", __FILE__, __func__, __LINE__);
		abort();
	}

	/* update the hfi txe state */
	opa1x_ep->tx.pio_state.qw0 = pio_state.qw0;

	FI_DBG_TRACE(fi_opa1x_global.prov, FI_LOG_EP_DATA,
		"===================================== SEND, HFI -- RENDEZVOUS RTS (end)\n");

	return FI_SUCCESS;
}
