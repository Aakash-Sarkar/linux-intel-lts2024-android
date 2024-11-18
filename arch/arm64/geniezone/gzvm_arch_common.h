/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 MediaTek Inc.
 */

#ifndef __GZVM_ARCH_COMMON_H__
#define __GZVM_ARCH_COMMON_H__

#include <linux/arm-smccc.h>

enum {
	GZVM_FUNC_CREATE_VM = 0,
	GZVM_FUNC_DESTROY_VM = 1,
	GZVM_FUNC_CREATE_VCPU = 2,
	GZVM_FUNC_DESTROY_VCPU = 3,
	GZVM_FUNC_SET_MEMREGION = 4,
	GZVM_FUNC_RUN = 5,
	GZVM_FUNC_GET_ONE_REG = 8,
	GZVM_FUNC_SET_ONE_REG = 9,
	GZVM_FUNC_PROBE = 12,
	GZVM_FUNC_ENABLE_CAP = 13,
	GZVM_FUNC_INFORM_EXIT = 14,
	NR_GZVM_FUNC,
};

#define SMC_ENTITY_MTK			59
#define GZVM_FUNCID_START		(0x1000)
#define GZVM_HCALL_ID(func)						\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_64,	\
			   SMC_ENTITY_MTK, (GZVM_FUNCID_START + (func)))

#define MT_HVC_GZVM_CREATE_VM		GZVM_HCALL_ID(GZVM_FUNC_CREATE_VM)
#define MT_HVC_GZVM_DESTROY_VM		GZVM_HCALL_ID(GZVM_FUNC_DESTROY_VM)
#define MT_HVC_GZVM_CREATE_VCPU		GZVM_HCALL_ID(GZVM_FUNC_CREATE_VCPU)
#define MT_HVC_GZVM_DESTROY_VCPU	GZVM_HCALL_ID(GZVM_FUNC_DESTROY_VCPU)
#define MT_HVC_GZVM_SET_MEMREGION	GZVM_HCALL_ID(GZVM_FUNC_SET_MEMREGION)
#define MT_HVC_GZVM_RUN			GZVM_HCALL_ID(GZVM_FUNC_RUN)
#define MT_HVC_GZVM_GET_ONE_REG		GZVM_HCALL_ID(GZVM_FUNC_GET_ONE_REG)
#define MT_HVC_GZVM_SET_ONE_REG		GZVM_HCALL_ID(GZVM_FUNC_SET_ONE_REG)
#define MT_HVC_GZVM_PROBE		GZVM_HCALL_ID(GZVM_FUNC_PROBE)
#define MT_HVC_GZVM_ENABLE_CAP		GZVM_HCALL_ID(GZVM_FUNC_ENABLE_CAP)
#define MT_HVC_GZVM_INFORM_EXIT		GZVM_HCALL_ID(GZVM_FUNC_INFORM_EXIT)

/**
 * gzvm_hypcall_wrapper() - the wrapper for hvc calls
 * @a0: argument passed in registers 0
 * @a1: argument passed in registers 1
 * @a2: argument passed in registers 2
 * @a3: argument passed in registers 3
 * @a4: argument passed in registers 4
 * @a5: argument passed in registers 5
 * @a6: argument passed in registers 6
 * @a7: argument passed in registers 7
 * @res: result values from registers 0 to 3
 *
 * Return: The wrapper helps caller to convert geniezone errno to Linux errno.
 */
int gzvm_hypcall_wrapper(unsigned long a0, unsigned long a1,
			 unsigned long a2, unsigned long a3,
			 unsigned long a4, unsigned long a5,
			 unsigned long a6, unsigned long a7,
			 struct arm_smccc_res *res);

static inline unsigned int
assemble_vm_vcpu_tuple(u16 vmid, u16 vcpuid)
{
	return ((unsigned int)vmid << 16 | vcpuid);
}

#endif /* __GZVM_ARCH_COMMON_H__ */
