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
#include <ofi.h>

#include "rdma/opx/fi_opx.h"
#include "rdma/opx/fi_opx_internal.h"
#include "rdma/opx/fi_opx_hfi1.h"
#include "rdma/opx/fi_opx_domain.h"
#include "ofi_prov.h"

#include "rdma/opx/fi_opx_addr.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int fi_opx_init;
static int fi_opx_count;

int fi_opx_check_info(const struct fi_info *info)
{
FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	int ret;
	/* TODO: check caps, mode */

	if ((info->tx_attr) && ((info->tx_attr->caps | info->caps) != info->caps)) {
FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "info->tx_attr->caps = 0x%016lx, info->caps = 0x%016lx\n", info->tx_attr->caps, info->caps);
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
				"The tx_attr capabilities (0x%016lx) must be a subset of those requested of the associated endpoint (0x%016lx)",
				info->tx_attr->caps, info->caps);
		goto err;
	}

FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	if ((info->rx_attr) && ((info->rx_attr->caps | info->caps) != info->caps)) {
FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "info->rx_attr->caps = 0x%016lx, info->caps = 0x%016lx, (info->rx_attr->caps | info->caps) = 0x%016lx, ((info->rx_attr->caps | info->caps) ^ info->caps) = 0x%016lx\n", info->rx_attr->caps, info->caps, (info->rx_attr->caps | info->caps), ((info->rx_attr->caps | info->caps) ^ info->caps));
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
				"The rx_attr capabilities (0x%016lx) must be a subset of those requested of the associated endpoint (0x%016lx)",
				info->rx_attr->caps, info->caps);
		goto err;
	}

FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");


	switch (info->addr_format) {
	case FI_ADDR_OPX:
	case FI_FORMAT_UNSPEC:
		break;
	default:
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
				"unavailable [bad info->addr_format (%u)]",
				info->addr_format);
		goto err;
	}

FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	if (info->tx_attr) {
		ret = fi_opx_check_tx_attr(info->tx_attr);
		if (ret)
			return ret;
	}

FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	if (info->rx_attr) {
		ret = fi_opx_check_rx_attr(info->rx_attr);
		if (ret)
			return ret;
	}

FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	if (info->ep_attr) {
		ret = fi_opx_check_ep_attr(info->ep_attr);
		if (ret)
			return ret;
	}

FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	if (info->domain_attr) {
		ret = fi_opx_check_domain_attr(info->domain_attr);
		if (ret)
			return ret;
	}
FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	if (info->fabric_attr) {
		ret = fi_opx_check_fabric_attr(info->fabric_attr);
		if (ret)
			return ret;
	}

FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	return 0;

err:
FI_DBG_TRACE(fi_opx_global.prov, FI_LOG_EP_DATA, "\n");

	errno = FI_ENODATA;
	return -errno;
}

static int fi_opx_fillinfo(struct fi_info *fi, const char *node,
		const char* service, const struct fi_info *hints,
	        uint64_t flags)
{
	int ret;
	uint64_t caps;

	if (!fi)
		goto err;

	if (!hints && !node && !service)
		goto err;

	if (hints && (((hints->mode & FI_CONTEXT) != 0) && ((hints->mode & FI_CONTEXT2) == 0))) {
		FI_WARN(fi_opx_global.prov, FI_LOG_FABRIC,
			"FI_CONTEXT mode is not supported. Use FI_CONTEXT2 mode instead.\n");
		errno = FI_ENODATA;
		return -errno;
	}

	fi->next = NULL;
	fi->caps = FI_OPX_DEFAULT_CAPS;

	/* set the mode that we require */
	fi->mode = FI_ASYNC_IOV;
	fi->mode |= (FI_CONTEXT2);

	/* clear modes that we do not require */
	fi->mode &= (~FI_LOCAL_MR);
	fi->mode &= (~FI_MSG_PREFIX);
	fi->mode &= (~FI_CONTEXT);

	fi->addr_format = FI_ADDR_OPX;
	fi->src_addrlen = sizeof(union fi_opx_addr);
	fi->dest_addrlen = sizeof(union fi_opx_addr);

	if (flags & FI_SOURCE) {
		if ((hints != NULL) && (hints->dest_addr)) {
			FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
				"cannot support dest_addr lookups now\n");
			errno = FI_ENOSYS;
			return -errno;
		}

		fi->src_addr = strdup(service);
		if (!fi->src_addr) {
			goto err;
		}
	}

	if ((hints != NULL) && (hints->dest_addr != NULL) && (((node == NULL) && (service == NULL)) || (flags & FI_SOURCE))) {

		/*
		 * man/fi_getinfo.3
		 *
		 * dest_addr - destination address
		 * If specified, indicates the destination address. This field
		 * will be ignored in hints unless the node and service
		 * parameters are NULL or FI_SOURCE flag is set. If FI_SOURCE
		 * is not specified, on output a provider shall return an
		 * address the corresponds to the indicated node and/or service
		 * fields, relative to the fabric and domain. Note that any
		 * returned address is only usable locally.
		 */

		if ((flags & FI_SOURCE) == 0) {
			if ((hints->addr_format != FI_FORMAT_UNSPEC) &&
				(hints->addr_format != FI_ADDR_OPX)) {

				FI_WARN(fi_opx_global.prov, FI_LOG_FABRIC,
					"invalid addr_format hint (%d)\n", hints->addr_format);
				errno = FI_EINVAL;
				return -errno;
			}
		}
	}

	fi->dest_addr = NULL;

	/*
	 * man/fi_fabric.3
	 *
	 * On input to fi_getinfo, a user may set this (fi_fabric_attr::fabric)
	 * to an opened fabric instance to restrict output to the given fabric.
	 * On output from fi_getinfo, if no fabric was specified, but the user
	 * has an opened instance of the named fabric, this (fi_fabric_attr::fabric)
	 * will reference the first opened instance. If no instance has been
	 * opened, this field will be NULL.
	 */

	fi->fabric_attr->name = strdup(FI_OPX_FABRIC_NAME);
	if (!fi->fabric_attr->name) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
				"memory allocation failed");
		goto err;
	}

	fi->fabric_attr->prov_version = FI_OPX_PROVIDER_VERSION;

	memcpy(fi->tx_attr, fi_opx_global.default_tx_attr, sizeof(*fi->tx_attr));
	if (hints->tx_attr) {

		/*
		 * man/fi_endpoint.3
		 *
		 *   fi_tx_attr::caps
		 *
		 *   "... If the caps field is 0 on input to fi_getinfo(3), the
		 *   caps value from the fi_info structure will be used."
		 */
		if (hints->tx_attr->caps) {
			fi->tx_attr->caps = hints->tx_attr->caps;
		}

		/* adjust parameters down from what requested if required */
		fi->tx_attr->op_flags = hints->tx_attr->op_flags;
	} else if (hints->caps) {
		fi->tx_attr->caps = hints->caps;
	}

	memcpy(fi->rx_attr, fi_opx_global.default_rx_attr, sizeof(*fi->rx_attr));
	if (hints->rx_attr) {

		/*
		 * man/fi_endpoint.3
		 *
		 *   fi_rx_attr::caps
		 *
		 *   "... If the caps field is 0 on input to fi_getinfo(3), the
		 *   caps value from the fi_info structure will be used."
		 */
		if (hints->rx_attr->caps) {
			fi->rx_attr->caps = hints->rx_attr->caps;
		}

		/* adjust parameters down from what requested if required */
		fi->rx_attr->op_flags = hints->rx_attr->op_flags;
		if (hints->rx_attr->total_buffered_recv > 0 &&
			hints->rx_attr->total_buffered_recv < fi_opx_global.default_rx_attr->total_buffered_recv)
				fi->rx_attr->total_buffered_recv = hints->rx_attr->total_buffered_recv;
	} else if (hints->caps) {
		fi->rx_attr->caps = hints->caps;
	}

	caps = fi->caps | fi->tx_attr->caps | fi->rx_attr->caps;

	/*
	 * man/fi_domain.3
	 *
	 * On input to fi_getinfo, a user may set this (fi_domain_attr::domain)
	 * to an opened domain instance to restrict output to the given domain.
	 * On output from fi_getinfo, if no domain was specified, but the user
	 * has an opened instance of the named domain, this (fi_domain_attr::domain)
	 * will reference the first opened instance. If no instance has been
	 * opened, this field will be NULL.
	 */

	ret = fi_opx_choose_domain(caps, fi->domain_attr, hints->domain_attr);
	if (ret) {
		FI_LOG(fi_opx_global.prov, FI_LOG_DEBUG, FI_LOG_FABRIC,
				"cannot find appropriate domain\n");
		goto err;
	}

	memcpy(fi->ep_attr, fi_opx_global.default_ep_attr, sizeof(*fi->ep_attr));
	if (hints->ep_attr) {
		/* adjust parameters down from what requested if required */
		fi->ep_attr->type	= hints->ep_attr->type;
		if (hints->ep_attr->max_msg_size > 0 &&
			hints->ep_attr->max_msg_size <= fi_opx_global.default_ep_attr->max_msg_size)
				fi->ep_attr->max_msg_size = hints->ep_attr->max_msg_size;

		if (0 != hints->ep_attr->tx_ctx_cnt && hints->ep_attr->tx_ctx_cnt <= fi->ep_attr->tx_ctx_cnt)
			fi->ep_attr->tx_ctx_cnt = hints->ep_attr->tx_ctx_cnt;	/* TODO - check */

		if (0 != hints->ep_attr->rx_ctx_cnt && hints->ep_attr->rx_ctx_cnt <= fi->ep_attr->rx_ctx_cnt)
			fi->ep_attr->rx_ctx_cnt = hints->ep_attr->rx_ctx_cnt;	/* TODO - check */
	}

	return 0;
err:
	if (fi->domain_attr->name) free(fi->domain_attr->name);
	if (fi->fabric_attr->name) free(fi->fabric_attr->name);
	if (fi->fabric_attr->prov_name) free(fi->fabric_attr->prov_name);
	errno = FI_ENODATA;
	return -errno;
}

struct fi_opx_global_data fi_opx_global;

static int fi_opx_getinfo(uint32_t version, const char *node,
		const char *service, uint64_t flags,
		const struct fi_info *hints, struct fi_info **info)
{
	int ret;
	struct fi_info *fi;

	if (!fi_opx_count) {
		errno = FI_ENODATA;
		return -errno;
	}

	if (hints) {
		ret = fi_opx_check_info(hints);
		if (ret) {
			return ret;
		}
		if (!(fi = fi_allocinfo())) {
			return -FI_ENOMEM;
		}
		if (fi_opx_fillinfo(fi, node, service,
					hints, flags)) {
			return -errno;
		}
		*info = fi;
	} else {
		if(node || service) {
			errno = FI_ENODATA;
			return -errno;
		} else {
			if (!(fi = fi_dupinfo(fi_opx_global.info))) {
				return -FI_ENOMEM;
			}
			*info = fi;
		}
	}
	return 0;
}

static void fi_opx_fini()
{
	always_assert(fi_opx_init == 1,
		"OPX provider finalize called before initialize\n");
	fi_freeinfo(fi_opx_global.info);
}

struct fi_provider fi_opx_provider = {
	.name 		= FI_OPX_PROVIDER_NAME,
	.version	= FI_OPX_PROVIDER_VERSION,
	.fi_version 	= OFI_VERSION_LATEST,
	.getinfo	= fi_opx_getinfo,
	.fabric		= fi_opx_fabric,
	.cleanup	= fi_opx_fini
};

#pragma GCC diagnostic ignored "=Wunused-function"
/*
 * Use this dummy function to do any compile-time validation of data
 * structure sizes needed to ensure performance.
 */
static void do_static_assert_tests()
{
	// Verify that pio_state is exactly one cache-line long. */
	OPX_COMPILE_TIME_ASSERT((sizeof(union fi_opx_hfi1_pio_state) == 8),
		"fi_opx_hfi1_pio_state size error.");
	// Verify that pointers are exactly one cache-line long. */
	OPX_COMPILE_TIME_ASSERT((sizeof(union fi_opx_hfi1_pio_state*) == 8),
		"fi_opx_hfi1_pio_state pointer size error.");

	OPX_COMPILE_TIME_ASSERT(sizeof(struct fi_opx_mr_atomic) == 24,
							"Memory region Packet size error");

	OPX_COMPILE_TIME_ASSERT(sizeof(struct fi_opx_mr_atomic) == sizeof(union fi_opx_mr_atomic_qw),
							"Memory region Packet QW size error");

	union fi_opx_hfi1_packet_payload *payload = NULL;
	OPX_COMPILE_TIME_ASSERT(sizeof(*payload) == sizeof(payload->rendezvous.contiguous),
							"Contiguous rendezvous payload size error");

	OPX_COMPILE_TIME_ASSERT(sizeof(*payload) == sizeof(payload->rendezvous.noncontiguous),
							"Non-contiguous rendezvous payload size error");
}
#pragma GCC diagnostic pop

OPX_INI
{
	fi_opx_count = 1;
	fi_opx_set_default_info(); // TODO: fold into fi_opx_set_defaults

	if (fi_opx_alloc_default_domain_attr(&fi_opx_global.default_domain_attr)) {
		return NULL;
	}

	if (fi_opx_alloc_default_ep_attr(&fi_opx_global.default_ep_attr)) {
		return NULL;
	}

	if (fi_opx_alloc_default_tx_attr(&fi_opx_global.default_tx_attr)) {
		return NULL;
	}
	if (fi_opx_alloc_default_rx_attr(&fi_opx_global.default_rx_attr)) {
		return NULL;
	}

	fi_opx_global.prov = &fi_opx_provider;

	fi_opx_init = 1;

	fi_param_define(&fi_opx_provider, "uuid", FI_PARAM_STRING, "Globally unique ID for preventing OPX jobs from conflicting either in shared memory or over the OPX fabric. Defaults to \"%s\"",
		OPX_DEFAULT_JOB_KEY_STR);
	fi_param_define(&fi_opx_provider, "force_cpuaffinity", FI_PARAM_BOOL, "Causes the thread to bind itself to the cpu core it is running on. Defaults to \"No\"");
	fi_param_define(&fi_opx_provider, "reliability_service_usec_max", FI_PARAM_INT, "The number of microseconds between pings for un-acknowledged packets. Defaults to 100 usec.");
	fi_param_define(&fi_opx_provider, "selinux", FI_PARAM_BOOL, "Set to true if you're running a security-enhanced Linux. This enables updating the Jkey used based on system settings. Defaults to \"No\"");
	fi_param_define(&fi_opx_provider, "hfi_select", FI_PARAM_STRING, "Overrides the normal algorithm used to choose which HFI a process will use. See the documentation for more information.");
	// fi_param_define(&fi_opx_provider, "varname", FI_PARAM_*, "help");
	// fi_param_define(&fi_opx_provider, "varname", FI_PARAM_*, "help");
	// fi_param_define(&fi_opx_provider, "varname", FI_PARAM_*, "help");
	return (&fi_opx_provider);
}
