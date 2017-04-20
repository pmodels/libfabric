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
#include <stdio.h>
#include <stdarg.h>
#include <check.h>

#include "fi_opx_hfi_select.h"
#include "rdma/providers/fi_log.h"

// dummy definitions
struct fi_provider *fi_opx_provider = NULL;

void fi_log(const struct fi_provider *prov, enum fi_log_level level,
	    enum fi_log_subsys subsys, const char *func, int line,
	    const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int fi_log_enabled(const struct fi_provider *prov, enum fi_log_level level,
		   enum fi_log_subsys subsys)
{
	return 1;
}

START_TEST (test_empty)
{
	struct hfi_selector s;
	ck_assert_ptr_null(hfi_selector_next("", &s));
	ck_assert_ptr_null(hfi_selector_next("     ", &s));
}
END_TEST

START_TEST (test_hfi_select_bad)
{
	struct hfi_selector s;
	ck_assert_ptr_null(hfi_selector_next("notavalidselector", &s));
	ck_assert_ptr_null(hfi_selector_next("0,numa:0:0", &s));
}
END_TEST

START_TEST (test_hfi_unit)
{
	struct hfi_selector s;
	ck_assert_ptr_nonnull(hfi_selector_next("0", &s));
	ck_assert_int_eq(s.type, HFI_SELECTOR_FIXED);
	ck_assert_int_eq(s.unit, 0);

	ck_assert_ptr_nonnull(hfi_selector_next("4", &s));
	ck_assert_int_eq(s.type, HFI_SELECTOR_FIXED);
	ck_assert_int_eq(s.unit, 4);
}
END_TEST

START_TEST (test_hfi_unit_bad)
{
	struct hfi_selector s;
	ck_assert_ptr_null(hfi_selector_next("  0  ", &s));
	ck_assert_ptr_null(hfi_selector_next("0,", &s));
	ck_assert_ptr_null(hfi_selector_next("-1", &s));
}
END_TEST

START_TEST (test_mapby_numa)
{
	struct hfi_selector s;
	ck_assert_ptr_nonnull(hfi_selector_next("numa:0:0", &s));
	ck_assert_int_eq(s.type, HFI_SELECTOR_MAPBY);
	ck_assert_int_eq(s.unit, 0);
	ck_assert_int_eq(s.mapby.type, HFI_SELECTOR_MAPBY_NUMA);
	ck_assert_int_eq(s.mapby.numa, 0);

	ck_assert_ptr_nonnull(hfi_selector_next("numa:1:4", &s));
	ck_assert_int_eq(s.unit, 1);
	ck_assert_int_eq(s.mapby.numa, 4);
}
END_TEST

START_TEST (test_mapby_numa_many)
{
	struct hfi_selector s;
	const char *c = "numa:1:1,numa:0:3,numa:0:0,numa:0:2";
	int exp_unit_numa[] = { 1, 1, 0, 3, 0, 0, 0, 2 };
	int i = 0;
	for (i = 0; i < 8; i += 2) {
		c = hfi_selector_next(c, &s);
		ck_assert_ptr_nonnull(c);
		ck_assert_int_eq(s.type, HFI_SELECTOR_MAPBY);
		ck_assert_int_eq(s.unit, exp_unit_numa[i]);
		ck_assert_int_eq(s.mapby.type, HFI_SELECTOR_MAPBY_NUMA);
		ck_assert_int_eq(s.mapby.numa, exp_unit_numa[i + 1]);
	}
	ck_assert_int_eq(i, 8);
}
END_TEST

START_TEST (test_mapby_bad)
{
	struct hfi_selector s;
	ck_assert_ptr_null(hfi_selector_next("notnuma:0:0", &s));
}
END_TEST

START_TEST (test_mapby_numa_bad)
{
	struct hfi_selector s;
	ck_assert_ptr_null(hfi_selector_next("numa:-1:0", &s));
	ck_assert_ptr_null(hfi_selector_next("numa:0:-1", &s));
	ck_assert_ptr_null(hfi_selector_next("numa:0", &s));
	ck_assert_ptr_null(hfi_selector_next("numa::0", &s));
	ck_assert_ptr_null(hfi_selector_next("numa:   :0", &s));
	ck_assert_ptr_null(hfi_selector_next("numa0:0:", &s));
	ck_assert_ptr_null(hfi_selector_next("numa:0:0:", &s));
}
END_TEST

Suite *hfi_select_suite(void)
{
	Suite *s = suite_create("hfi_select");
	TCase *tc = tcase_create("envvar_parsing");

	tcase_add_test(tc, test_empty);
	tcase_add_test(tc, test_hfi_select_bad);
	tcase_add_test(tc, test_hfi_unit);
	tcase_add_test(tc, test_hfi_unit_bad);
	tcase_add_test(tc, test_mapby_bad);
	tcase_add_test(tc, test_mapby_numa);
	tcase_add_test(tc, test_mapby_numa_many);
	tcase_add_test(tc, test_mapby_numa_bad);

	suite_add_tcase(s, tc);
	return s;
}

int main(void)
{
	Suite *s = hfi_select_suite();
	SRunner *sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	int fail_count = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (fail_count == 0);
}
