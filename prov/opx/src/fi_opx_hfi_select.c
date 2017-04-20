/*
 * Copyright (C) 2021 by Cornelis Networks.
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
#include "fi_opx_hfi_select.h"
#include "rdma/opx/fi_opx.h"
#include <ctype.h>
#include <limits.h>
#include <stdio.h>

/**
 * @param end pointer to end of string (exclusive) or NULL, in which case function parses until @c '\0' is reached.
 * @return 0 on success, non-zero on failure.
 */
static int parse_int_range(const char *lbl, const char *start, const char *end,
	int min, int max, int *out)
{
	if (!out)
		return 1;

	if (end && start >= end)
		return 1;

	char *v;
	long val = strtol(start, &v, 10);
	if ((end && v != end) || (!end && *v != '\0')) {
		long prchrs = ((end? end: v) - start);
		prchrs = (prchrs <= INT_MAX? prchrs: INT_MAX);
		FI_WARN(&fi_opx_provider, FI_LOG_FABRIC,
			"Error parsing \"%.*s\" as long integer for %s\n", (int)prchrs, start, lbl);
		return 1;
	}

	if (val < min || val > max) {
		FI_WARN(&fi_opx_provider, FI_LOG_FABRIC,
			"Error: value %ld outside valid range [%d,%d] for %s\n",
			val, min, max, lbl);
		return 1;
	}

	*out = (int)val;
	return 0;
}

/**
 * Parse MapBy HFI selector data from characters in range @c [start,end).
 *
 * Mapby specifier consists of three parts:
 *     <selector_type>:<hfi_unit>:<selector_type_data>
 *
 * @return 0 on success, non-zero on failure.
 */
static int hfi_select_parse_mapby(const char *start, const char *end, struct hfi_selector *out)
{
	const char *orig_start = start; // for error messages
	out->type = HFI_SELECTOR_MAPBY;

	if (strncmp(start, "numa:", 5)) {
		// map-by NUMA only supported selector type for now
		FI_WARN(&fi_opx_provider, FI_LOG_FABRIC,
			"Error: invalid mapby specifier \"%s\"\n", start);
		return 1;
	}

	out->mapby.type = HFI_SELECTOR_MAPBY_NUMA;
	start += 5; // skip to 1-after ':'
	const char *c;
	for (c = start; c != end && *c != ':'; c++) { }

	if (*c != ':') {
		FI_WARN(&fi_opx_provider, FI_LOG_FABRIC,
			"Error: did not find \":\" in \"%s\" when scanning for end of unit number\n",
			orig_start);
		return 1;
	}

	if (parse_int_range("unit", start, c, 0, HFI_SELECTOR_UNIT_MAX, &out->unit))
		return 1;

	start = c + 1; // 1-after ':'

	if (parse_int_range("numa", start, end, 0, HFI_SELECTOR_NUMA_MAX, &out->mapby.numa))
		return 1;

	return 0;
}

const char *hfi_selector_next(const char *start, struct hfi_selector *selector)
{
	const char *c;
	int digit_count = 0;
	int colon_count = 0;
	memset(selector, 0, sizeof(struct hfi_selector));

	for (c = start; *c != ',' && *c != '\0'; c++) {
		if ((c - start) > HFI_SELECTOR_SUBSTRING_MAX) {
			FI_WARN(&fi_opx_provider, FI_LOG_FABRIC,
				"Error: HFI selection substring must be <= %d characters long\n",
				HFI_SELECTOR_SUBSTRING_MAX);
			return NULL;
		}

		// Only accept strings containing accepted characters
		if (!isalnum(*c) && *c != ':') {
			FI_WARN(&fi_opx_provider, FI_LOG_FABRIC,
				"Error: HFI selection substring can only contain alpha-numeric characters, ':', and ','\n");
			return NULL;
		}

		if (isdigit(*c)) {
			digit_count++;
		} else if (*c == ':') {
			colon_count++;
		}
	}

	// End of HFI selection (sub)string; process what we scanned
	if (digit_count && (c - start) == digit_count && *c == '\0') {
		// All chars are digits => fixed HFI assignment
		int unit;
		if (parse_int_range("unit", start, c, 0, HFI_SELECTOR_UNIT_MAX, &unit))
			return NULL;

		selector->type = HFI_SELECTOR_FIXED;
		selector->unit = unit;
	} else if (colon_count) {
		// mapby specifier
		if (hfi_select_parse_mapby(start, c, selector))
			return NULL;
	} else {
		FI_WARN(&fi_opx_provider, FI_LOG_FABRIC,
			"Error: unsupported parse case on string \"%.*s\"\n",
			(int)(c - start), start);
		return NULL;
	}

	return (*c == '\0'? c: (c + 1));
}
