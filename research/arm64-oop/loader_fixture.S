/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Controlled code only. The ELF packer places this section at guest VA 0x1000
 * and its data at 0x4000. No Android/game code or security checks are patched. */
.text
.p2align 2
.global fixture_entry
.type fixture_entry,%function
fixture_entry:
    stp x29, x30, [sp, #-16]!
    adr x12, .Lmarker
    .inst 0xf0000009          /* adrp x9, guest 0x4000 from page 0x1000 */
    ldr x10, [x9]
    ldr x0, [x10]
    bl .Lmiddle
    ldr x11, [x9, #8]
    blr x11
.global fixture_host_return
fixture_host_return:
    str x0, [x9, #32]
    ldp x29, x30, [sp], #16
    ret
.global fixture_middle
fixture_middle:
.Lmiddle:
    stp x29, x30, [sp, #-16]!
    ldr x13, [x9, #16]
    blr x13
.global fixture_nested_return
fixture_nested_return:
    ldp x29, x30, [sp], #16
    ret
.global fixture_nested
.type fixture_nested,%function
fixture_nested:
    add x0, x0, #5
    ret
.global fixture_marker
fixture_marker:
.Lmarker:
    nop
