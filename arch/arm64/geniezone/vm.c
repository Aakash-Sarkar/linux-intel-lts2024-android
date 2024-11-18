// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 MediaTek Inc.
 */

#include <linux/arm-smccc.h>
#include <linux/err.h>
#include <linux/uaccess.h>

#include <linux/gzvm.h>
#include <linux/soc/mediatek/gzvm_drv.h>
#include "gzvm_arch_common.h"

/**
 * gzvm_hypcall_wrapper() - the wrapper for hvc calls
 * @a0: arguments passed in registers 0
 * @a1: arguments passed in registers 1
 * @a2: arguments passed in registers 2
 * @a3: arguments passed in registers 3
 * @a4: arguments passed in registers 4
 * @a5: arguments passed in registers 5
 * @a6: arguments passed in registers 6
 * @a7: arguments passed in registers 7
 * @res: result values from registers 0 to 3
 *
 * Return: The wrapper helps caller to convert geniezone errno to Linux errno.
 */
int gzvm_hypcall_wrapper(unsigned long a0, unsigned long a1,
			 unsigned long a2, unsigned long a3,
			 unsigned long a4, unsigned long a5,
			 unsigned long a6, unsigned long a7,
			 struct arm_smccc_res *res)
{
	struct arm_smccc_1_2_regs res_1_2;
	struct arm_smccc_1_2_regs args = {
		.a0 = a0,
		.a1 = a1,
		.a2 = a2,
		.a3 = a3,
		.a4 = a4,
		.a5 = a5,
		.a6 = a6,
		.a7 = a7,
	};
	arm_smccc_1_2_hvc(&args, &res_1_2);
	res->a0 = res_1_2.a0;
	res->a1 = res_1_2.a1;
	res->a2 = res_1_2.a2;
	res->a3 = res_1_2.a3;

	return gzvm_err_to_errno(res->a0);
}

int gzvm_arch_probe(struct gzvm_version drv_version,
		    struct gzvm_version *hyp_version)
{
	struct arm_smccc_res res;
	int ret;

	ret = gzvm_hypcall_wrapper(MT_HVC_GZVM_PROBE,
				   drv_version.major,
				   drv_version.minor,
				   drv_version.sub,
				   0, 0, 0, 0, &res);
	if (ret)
		return -ENXIO;

	hyp_version->major = (u32)res.a1;
	hyp_version->minor = (u32)res.a2;
	hyp_version->sub = res.a3;

	return 0;
}

int gzvm_arch_set_memregion(u16 vm_id, size_t buf_size,
			    phys_addr_t region)
{
	struct arm_smccc_res res;

	return gzvm_hypcall_wrapper(MT_HVC_GZVM_SET_MEMREGION, vm_id,
				    buf_size, region, 0, 0, 0, 0, &res);
}

/**
 * gzvm_arch_create_vm() - create vm
 * @vm_type: VM type. Only supports Linux VM now.
 *
 * Return:
 * * positive value	- VM ID
 * * -ENOMEM		- Memory not enough for storing VM data
 */
int gzvm_arch_create_vm(unsigned long vm_type)
{
	struct arm_smccc_res res;
	int ret;

	ret = gzvm_hypcall_wrapper(MT_HVC_GZVM_CREATE_VM, vm_type, 0, 0, 0, 0,
				   0, 0, &res);
	return ret ? ret : res.a1;
}

int gzvm_arch_destroy_vm(u16 vm_id)
{
	struct arm_smccc_res res;

	return gzvm_hypcall_wrapper(MT_HVC_GZVM_DESTROY_VM, vm_id, 0, 0, 0, 0,
				    0, 0, &res);
}
