/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ALTERNATIVE_MACROS_H
#define __ASM_ALTERNATIVE_MACROS_H

#include <linux/const.h>
#include <vdso/bits.h>

#include <asm/cpucaps.h>
#include <asm/insn-def.h>

/*
 * Binutils 2.27.0 can't handle a 'UL' suffix on constants, so for the assembly
 * macros below we must use we must use `(1 << ARM64_CB_SHIFT)`.
 */
#define ARM64_CB_SHIFT	15
#define ARM64_CB_BIT	BIT(ARM64_CB_SHIFT)

#if ARM64_NCAPS >= ARM64_CB_BIT
#error "cpucaps have overflown ARM64_CB_BIT"
#endif

#ifndef BUILD_FIPS140_KO
#ifndef __ASSEMBLY__

#include <linux/stringify.h>

#define ALTINSTR_ENTRY(cpucap)					              \
	" .word 661b - .\n"				/* label           */ \
	" .word 663f - .\n"				/* new instruction */ \
	" .hword " __stringify(cpucap) "\n"		/* cpucap          */ \
	" .byte 662b-661b\n"				/* source len      */ \
	" .byte 664f-663f\n"				/* replacement len */

#define ALTINSTR_ENTRY_CB(cpucap, cb)					      \
	" .word 661b - .\n"				/* label           */ \
	" .word " __stringify(cb) "- .\n"		/* callback        */ \
	" .hword " __stringify(cpucap) "\n"		/* cpucap          */ \
	" .byte 662b-661b\n"				/* source len      */ \
	" .byte 664f-663f\n"				/* replacement len */

/*
 * alternative assembly primitive:
 *
 * If any of these .org directive fail, it means that insn1 and insn2
 * don't have the same length. This used to be written as
 *
 * .if ((664b-663b) != (662b-661b))
 * 	.error "Alternatives instruction length mismatch"
 * .endif
 *
 * but most assemblers die if insn1 or insn2 have a .inst. This should
 * be fixed in a binutils release posterior to 2.25.51.0.2 (anything
 * containing commit 4e4d08cf7399b606 or c1baaddf8861).
 *
 * Alternatives with callbacks do not generate replacement instructions.
 */
#define __ALTERNATIVE_CFG(oldinstr, newinstr, cpucap, cfg_enabled)	\
	".if "__stringify(cfg_enabled)" == 1\n"				\
	"661:\n\t"							\
	oldinstr "\n"							\
	"662:\n"							\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY(cpucap)						\
	".popsection\n"							\
	".subsection 1\n"						\
	"663:\n\t"							\
	newinstr "\n"							\
	"664:\n\t"							\
	".org	. - (664b-663b) + (662b-661b)\n\t"			\
	".org	. - (662b-661b) + (664b-663b)\n\t"			\
	".previous\n"							\
	".endif\n"

#define __ALTERNATIVE_CFG_CB(oldinstr, cpucap, cfg_enabled, cb)	\
	".if "__stringify(cfg_enabled)" == 1\n"				\
	"661:\n\t"							\
	oldinstr "\n"							\
	"662:\n"							\
	".pushsection .altinstructions,\"a\"\n"				\
	ALTINSTR_ENTRY_CB(cpucap, cb)					\
	".popsection\n"							\
	"663:\n\t"							\
	"664:\n\t"							\
	".endif\n"

#define _ALTERNATIVE_CFG(oldinstr, newinstr, cpucap, cfg, ...)	\
	__ALTERNATIVE_CFG(oldinstr, newinstr, cpucap, IS_ENABLED(cfg))

#define ALTERNATIVE_CB(oldinstr, cpucap, cb) \
	__ALTERNATIVE_CFG_CB(oldinstr, (1 << ARM64_CB_SHIFT) | (cpucap), 1, cb)
#else

#include <asm/assembler.h>

.macro altinstruction_entry orig_offset alt_offset cpucap orig_len alt_len
	.word \orig_offset - .
	.word \alt_offset - .
	.hword (\cpucap)
	.byte \orig_len
	.byte \alt_len
.endm

.macro alternative_insn insn1, insn2, cap, enable = 1
	.if \enable
661:	\insn1
662:	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663f, \cap, 662b-661b, 664f-663f
	.popsection
	.subsection 1
663:	\insn2
664:	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
	.previous
	.endif
.endm

/*
 * Alternative sequences
 *
 * The code for the case where the capability is not present will be
 * assembled and linked as normal. There are no restrictions on this
 * code.
 *
 * The code for the case where the capability is present will be
 * assembled into a special section to be used for dynamic patching.
 * Code for that case must:
 *
 * 1. Be exactly the same length (in bytes) as the default code
 *    sequence.
 *
 * 2. Not contain a branch target that is used outside of the
 *    alternative sequence it is defined in (branches into an
 *    alternative sequence are not fixed up).
 */

/*
 * Begin an alternative code sequence.
 */
.macro alternative_if_not cap
	.set .Lasm_alt_mode, 0
	.pushsection .altinstructions, "a"
	altinstruction_entry 661f, 663f, \cap, 662f-661f, 664f-663f
	.popsection
661:
.endm

.macro alternative_if cap
	.set .Lasm_alt_mode, 1
	.pushsection .altinstructions, "a"
	altinstruction_entry 663f, 661f, \cap, 664f-663f, 662f-661f
	.popsection
	.subsection 1
	.align 2	/* So GAS knows label 661 is suitably aligned */
661:
.endm

.macro alternative_cb cap, cb
	.set .Lasm_alt_mode, 0
	.pushsection .altinstructions, "a"
	altinstruction_entry 661f, \cb, (1 << ARM64_CB_SHIFT) | \cap, 662f-661f, 0
	.popsection
661:
.endm

/*
 * Provide the other half of the alternative code sequence.
 */
.macro alternative_else
662:
	.if .Lasm_alt_mode==0
	.subsection 1
	.else
	.previous
	.endif
663:
.endm

/*
 * Complete an alternative code sequence.
 */
.macro alternative_endif
664:
	.org	. - (664b-663b) + (662b-661b)
	.org	. - (662b-661b) + (664b-663b)
	.if .Lasm_alt_mode==0
	.previous
	.endif
.endm

/*
 * Callback-based alternative epilogue
 */
.macro alternative_cb_end
662:
.endm

/*
 * Provides a trivial alternative or default sequence consisting solely
 * of NOPs. The number of NOPs is chosen automatically to match the
 * previous case.
 */
.macro alternative_else_nop_endif
alternative_else
	nops	(662b-661b) / AARCH64_INSN_SIZE
alternative_endif
.endm

#define _ALTERNATIVE_CFG(insn1, insn2, cap, cfg, ...)	\
	alternative_insn insn1, insn2, cap, IS_ENABLED(cfg)

#endif  /*  __ASSEMBLY__  */

/*
 * Usage: asm(ALTERNATIVE(oldinstr, newinstr, cpucap));
 *
 * Usage: asm(ALTERNATIVE(oldinstr, newinstr, cpucap, CONFIG_FOO));
 * N.B. If CONFIG_FOO is specified, but not selected, the whole block
 *      will be omitted, including oldinstr.
 */
#define ALTERNATIVE(oldinstr, newinstr, ...)   \
	_ALTERNATIVE_CFG(oldinstr, newinstr, __VA_ARGS__, 1)

#ifndef __ASSEMBLY__

#include <linux/types.h>

static __always_inline bool
alternative_has_cap_likely(const unsigned long cpucap)
{
	if (!cpucap_is_possible(cpucap))
		return false;

	asm goto(
#ifdef BUILD_VDSO
	ALTERNATIVE("b	%l[l_no]", "nop", %[cpucap])
#else
	ALTERNATIVE_CB("b	%l[l_no]", %[cpucap], alt_cb_patch_nops)
#endif
	:
	: [cpucap] "i" (cpucap)
	:
	: l_no);

	return true;
l_no:
	return false;
}

static __always_inline bool
alternative_has_cap_unlikely(const unsigned long cpucap)
{
	if (!cpucap_is_possible(cpucap))
		return false;

	asm goto(
	ALTERNATIVE("nop", "b	%l[l_yes]", %[cpucap])
	:
	: [cpucap] "i" (cpucap)
	:
	: l_yes);

	return false;
l_yes:
	return true;
}

#endif /* __ASSEMBLY__ */

#else

/*
 * The FIPS140 module does not support alternatives patching, as this
 * invalidates the HMAC digest of the .text section. However, some alternatives
 * are known to be irrelevant so we can tolerate them in the FIPS140 module, as
 * they will never be applied in the first place in the use cases that the
 * FIPS140 module targets (Android running on a production phone). Any other
 * uses of alternatives should be avoided, as it is not safe in the general
 * case to simply use the default sequence in one place (the fips module) and
 * the alternative sequence everywhere else.
 *
 * Below is an allowlist of cpucaps that we can ignore, by simply taking the
 * safe default instruction sequence. Note that this implies that the FIPS140
 * module is not compatible with VHE, or with pseudo-NMI support.
 */

#define __ALT_ARM64_HAS_LDAPR			0,
#define __ALT_ARM64_HAS_VIRT_HOST_EXTN		0,
#define __ALT_ARM64_HAS_GIC_PRIO_MASKING	0,
#define __ALT_ARM64_HAS_GIC_PRIO_RELAXED_SYNC	0,

#define ALTERNATIVE(oldinstr, newinstr, cpucap, ...)   \
	_ALTERNATIVE(oldinstr, __ALT_ ## cpucap, #cpucap)

#define ALTERNATIVE_CB(oldinstr, cpucap, cb)	\
	_ALTERNATIVE(oldinstr, __ALT_ ## cpucap, #cpucap)

#define _ALTERNATIVE(oldinstr, cpucap, cpucap_str)   \
	__take_second_arg(cpucap oldinstr, \
		".err CPU capability " cpucap_str " not supported in fips140 module")

#ifndef __ASSEMBLY__

#include <linux/types.h>

static bool __maybe_unused cpus_have_cap(unsigned int num);

/*
 * Return 'false' for all capabilities listed above, and use the slow path for
 * the remaining ones. This ensures that the FIPS140 module is consistent with
 * itself for all capabilities, and with the rest of the kernel at least for the
 * ones not listed.
 */
#define __alternative_has_cap(cpucap, altcap) \
	__take_second_arg(altcap false, cpus_have_cap(cpucap))

#define alternative_has_cap_likely(cpucap) \
	__alternative_has_cap(cpucap, __ALT_ ## cpucap)

#define alternative_has_cap_unlikely alternative_has_cap_likely

#endif /* !__ASSEMBLY__ */

#endif /* BUILD_FIPS140_KO */

#endif /* __ASM_ALTERNATIVE_MACROS_H */
