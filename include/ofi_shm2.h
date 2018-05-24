/*
 * Copyright (c) 2016-2018 Intel Corporation. All rights reserved.
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
#ifndef _OFI_SHM2_H_
#define _OFI_SHM2_H_

#include <fcntl.h>

#define ofi_shm2_compiler_barrier() __asm__ __volatile__ ( "" ::: "memory" )

#define ofi_shm2_x86_mfence() __asm__ __volatile__ ( "mfence" )
#define ofi_shm2_x86_sfence() __asm__ __volatile__ ( "sfence" )
#define ofi_shm2_x86_lfence() __asm__ __volatile__ ( "lfence" )
#define ofi_shm2_x86_pause()  __asm__ __volatile__ ( "pause"  )

static inline void
ofi_shm2_x86_atomic_int_inc(int * var) {
	__asm__ __volatile__ ("lock ; incl %0" :"=m" (*var) :"m" (*var));
	return;
}

static inline int
ofi_shm2_x86_atomic_fetch_and_add_int(volatile int * var, int val) {
	__asm__ __volatile__ ("lock ; xadd %0,%1"
			      : "=r" (val), "=m" (*var)
			      :  "0" (val),  "m" (*var));
	return val;
}

static inline int
ofi_shm2_x86_atomic_int_cas(int * var, int old_value, int new_value) {
	int prev_value;

	__asm__ __volatile__ ("lock ; cmpxchg %3,%4" : "=a" (prev_value), "=m" (*var) : "0" (old_value), "q" (new_value), "m" (*var));

	return prev_value;
}

#define OFI_SHM2_MAX_CONN_NUM (UINT8_MAX)

#define OFI_SHM2_SEGMENT_NAME_MAX_LENGTH (512)
#define OFI_SHM2_SEGMENT_NAME_PREFIX "/ofi.shm."

struct ofi_shm2_connection {
	void 				*segment_ptr;
	size_t				segment_size;
};

struct ofi_shm2_tx {
	struct ofi_shm2_fifo		*fifo[OFI_SHM2_MAX_CONN_NUM];
	struct ofi_shm2_connection	connection[OFI_SHM2_MAX_CONN_NUM];
	struct fi_provider		*prov;
};

struct ofi_shm2_rx {
	struct ofi_shm2_fifo		*fifo;
	int				local_ticket;
	void				*segment_ptr;
	size_t				segment_size;
	char				segment_key[OFI_SHM2_SEGMENT_NAME_MAX_LENGTH];
	struct fi_provider		*prov;
};

struct ofi_shm2_packet_metadata {
	volatile uint64_t		is_busy;
} __attribute__((__aligned__(8)));


struct ofi_shm2_packet {
	struct ofi_shm2_packet_metadata	metadata;
	uint8_t				data[0];
} __attribute__((__aligned__(8)));



struct ofi_shm2_poll_state {
	void				*next_packet_ptr;
};

struct of_shm2_fifo_metadata {
	volatile int			ticket;		/* shared rw with all fifo producers; consumer does not access */
	uint64_t			fifo_size;	/* debug only */
	uint64_t			packet_size;	/* debug only */
	uint64_t			pad[5];
} __attribute__((__aligned__(64)));

struct ofi_shm2_fifo {
	struct of_shm2_fifo_metadata	metadata;
	struct ofi_shm2_packet		packet[0];
} __attribute__((__aligned__(8)));

static inline void
ofi_shm2_memcpy(void * dst, const void * src, size_t len) {
	size_t nl = len >> 2;
	__asm__ __volatile__ ("\
	cld;\
	rep; movsl;\
	mov %3,%0;\
	rep; movsb"\
	: "+c" (nl), "+S" (src), "+D" (dst)	\
	: "r" (len & 3));
}


static inline
ssize_t ofi_shm2_rx_init (struct ofi_shm2_rx *rx,
		struct fi_provider *prov,
		const char * const unique_job_key,
		const unsigned rx_id,
		const unsigned fifo_size,
		const unsigned packet_size)
{
	__attribute__((__unused__)) int err = 0;
	int segment_fd = 0;
	void *segment_ptr = 0;

	rx->segment_ptr = NULL;
	rx->segment_size = 0;
	rx->local_ticket = 0;
	rx->prov = prov;

	memset(rx->segment_key, 0, OFI_SHM2_SEGMENT_NAME_MAX_LENGTH);

	snprintf(rx->segment_key, OFI_SHM2_SEGMENT_NAME_MAX_LENGTH,
		OFI_SHM2_SEGMENT_NAME_PREFIX "%s.%02x",
		unique_job_key, rx_id);

	const size_t shm2_packet_size = sizeof(struct ofi_shm2_packet_metadata) + packet_size;
	size_t segment_size = sizeof(struct of_shm2_fifo_metadata) +
		shm2_packet_size * fifo_size +
		64;	/* to ensure 64-byte alignment of fifo */

	segment_fd = shm_open(rx->segment_key, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (segment_fd == -1) {
		FI_LOG(prov, FI_LOG_WARN, FI_LOG_FABRIC,
			"Unable to create shm object '%s'; errno = '%s'\n",
			rx->segment_key, strerror(errno));
		err = errno;
		goto error_return;
	}

	errno = 0;
	if (ftruncate(segment_fd, segment_size) == -1) {
		FI_LOG(prov, FI_LOG_WARN, FI_LOG_FABRIC,
			"Unable to set size of shm object '%s' to %zu; errno = '%s'\n",
			rx->segment_key, segment_size, strerror(errno));
		err = errno;
		goto error_return;
	}

	errno = 0;
	segment_ptr = mmap(NULL, segment_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, segment_fd, 0);
	if (segment_ptr == MAP_FAILED) {
		FI_LOG(prov, FI_LOG_WARN, FI_LOG_FABRIC,
			"mmap failed: '%s'\n", strerror(errno));
		err = errno;
		goto error_return;
	}

	close(segment_fd);	/* safe to close now */

	memset(segment_ptr, 0, segment_size);

	rx->fifo = (struct ofi_shm2_fifo *)(((uintptr_t)segment_ptr + 64) & (~0x03Full));

	rx->fifo->metadata.ticket = 0;
	rx->fifo->metadata.fifo_size = fifo_size;
	rx->fifo->metadata.packet_size = packet_size;

	ofi_shm2_compiler_barrier();

	rx->segment_ptr = segment_ptr;
	rx->segment_size = segment_size;

	return FI_SUCCESS;

error_return:

	return -FI_EINVAL;
}

static inline
ssize_t ofi_shm2_rx_fini (struct ofi_shm2_rx *rx)
{
	if (rx->segment_ptr != NULL) {
		munmap(rx->segment_ptr, rx->segment_size);
		shm_unlink(rx->segment_key);

		return FI_SUCCESS;
	}

	return -FI_EINVAL;
}



static inline
ssize_t ofi_shm2_tx_init (struct ofi_shm2_tx *tx,
		struct fi_provider *prov)
{
	int i = 0;
	for (i = 0; i < OFI_SHM2_MAX_CONN_NUM; ++i) {
		tx->connection[i].segment_ptr = NULL;
		tx->connection[i].segment_size = 0;
		tx->fifo[i] = NULL;
	}

	tx->prov = prov;

	return FI_SUCCESS;
}

static inline
ssize_t ofi_shm2_tx_connect (struct ofi_shm2_tx *tx,
		const char * const unique_job_key,
		const unsigned rx_id,
		const unsigned fifo_size,
		const unsigned packet_size)
{
	int err = 0;

	char segment_key[OFI_SHM2_SEGMENT_NAME_MAX_LENGTH];
	memset(segment_key, 0, OFI_SHM2_SEGMENT_NAME_MAX_LENGTH);

	snprintf(segment_key, OFI_SHM2_SEGMENT_NAME_MAX_LENGTH,
		OFI_SHM2_SEGMENT_NAME_PREFIX "%s.%02x",
		unique_job_key, rx_id);

	int segment_fd = shm_open(segment_key, O_RDWR, 0600);
	if (segment_fd == -1) {
		FI_LOG(tx->prov, FI_LOG_WARN, FI_LOG_FABRIC,
			"Unable to create shm object '%s'; errno = '%s'\n",
			segment_key, strerror(errno));
		err = errno;
		goto error_return;
	}

	const size_t shm2_packet_size = sizeof(struct ofi_shm2_packet_metadata) + packet_size;
	size_t segment_size = sizeof(struct of_shm2_fifo_metadata) +
		shm2_packet_size * fifo_size +
		64;	/* to ensure 64-byte alignment of fifo */


	void *segment_ptr = mmap(NULL, segment_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, segment_fd, 0);
	if (segment_ptr == MAP_FAILED) {
		FI_LOG(tx->prov, FI_LOG_WARN, FI_LOG_FABRIC,
			"mmap failed: '%s'\n", strerror(errno));
		err = errno;
		goto error_return;
	}

	close(segment_fd);	/* safe to close now */

	tx->connection[rx_id].segment_ptr = segment_ptr;
	tx->connection[rx_id].segment_size = segment_size;
	tx->fifo[rx_id] = (struct ofi_shm2_fifo *)(((uintptr_t)segment_ptr + 64) & (~0x03Full));

	FI_LOG(tx->prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
		"SHM connection to %u context passed. Segment (%s), %d, (%p)\n",
		rx_id, segment_key, segment_fd, segment_ptr);

	return FI_SUCCESS;

error_return:

	FI_LOG(tx->prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
		"Connection failed: %s\n", strerror(err));

	return -FI_EINVAL;
}

static inline
ssize_t ofi_shm2_tx_fini (struct ofi_shm2_tx *tx)
{
	unsigned i = 0;

	for (i = 0; i < OFI_SHM2_MAX_CONN_NUM; ++i) {
		if (tx->connection[i].segment_ptr != NULL) {
			munmap(tx->connection[i].segment_ptr,
				tx->connection[i].segment_size);
			tx->connection[i].segment_ptr = NULL;
			tx->connection[i].segment_size = 0;
			tx->fifo[i] = NULL;
		}
	}

	return FI_SUCCESS;
}



static inline
void * ofi_shm2_tx_next (struct ofi_shm2_tx *tx, unsigned peer,
		const unsigned fifo_size, const unsigned packet_size)
{
	struct ofi_shm2_fifo *tx_fifo = tx->fifo[peer];

#ifndef NDEBUG
	if (unlikely(fifo_size != tx_fifo->metadata.fifo_size)) {
		FI_WARN(tx->prov, FI_LOG_EP_DATA, "shm fifo size mismatch (%u != %lu)\n", fifo_size, tx_fifo->metadata.fifo_size); abort();
	}
	if (unlikely(packet_size != tx_fifo->metadata.packet_size)) {
		FI_WARN(tx->prov, FI_LOG_EP_DATA, "shm packet size mismatch (%u != %lu)\n", packet_size, tx_fifo->metadata.packet_size); abort();
	}
#endif

	const int global_ticket = ofi_shm2_x86_atomic_fetch_and_add_int(&(tx_fifo->metadata.ticket), 1);

	const int packet_index = global_ticket % fifo_size;

	struct ofi_shm2_packet *packet =
		(struct ofi_shm2_packet *)((uintptr_t)tx_fifo->packet +
			packet_index * (packet_size + sizeof(struct ofi_shm2_packet_metadata)));

	unsigned spin_count = 0;
	while (packet->metadata.is_busy) {
		/* Spin wait */
		if (spin_count++ > 1000) {
			FI_WARN(tx->prov, FI_LOG_EP_DATA, "shm fifo stuck!!!!!!!!!!!!\n"); abort();
		}
		ofi_shm2_x86_pause();
	}

	return (void*)packet->data;
}

static inline
void ofi_shm2_tx_advance (struct ofi_shm2_tx *tx, void *packet_data)
{
	struct ofi_shm2_packet *packet = container_of(packet_data, struct ofi_shm2_packet, data);
	ofi_shm2_compiler_barrier();
	packet->metadata.is_busy = 1;

	return;
}


static inline
void * ofi_shm2_rx_next (struct ofi_shm2_rx *rx,
		const unsigned fifo_size, const unsigned packet_size)
{
	struct ofi_shm2_fifo *rx_fifo = rx->fifo;

#ifndef NDEBUG
	if (unlikely(fifo_size != rx_fifo->metadata.fifo_size)) {
		FI_WARN(rx->prov, FI_LOG_EP_DATA, "shm fifo size mismatch (%u != %lu)\n", fifo_size, rx_fifo->metadata.fifo_size); abort();
	}
	if (unlikely(packet_size != rx_fifo->metadata.packet_size)) {
		FI_WARN(rx->prov, FI_LOG_EP_DATA, "shm packet size mismatch (%u != %lu)\n", packet_size, rx_fifo->metadata.packet_size); abort();
	}
#endif

	const int local_ticket = rx->local_ticket;
	const int packet_index = local_ticket % fifo_size;

	struct ofi_shm2_packet *packet =
		(struct ofi_shm2_packet *)((uintptr_t)rx_fifo->packet +
			packet_index * (packet_size + sizeof(struct ofi_shm2_packet_metadata)));

	return packet->metadata.is_busy ? (void *)packet->data : NULL;
}

static inline
void ofi_shm2_rx_advance (struct ofi_shm2_rx *rx, void *packet_data)
{
	rx->local_ticket++;
	ofi_shm2_compiler_barrier();

	struct ofi_shm2_packet *packet = container_of(packet_data, struct ofi_shm2_packet, data);
	packet->metadata.is_busy = 0;

	return;
}

#endif /* _OFI_SHM2_H_ */
