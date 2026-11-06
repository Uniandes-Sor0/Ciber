#!/bin/sh
# Lab 7 - Fase 3 - Paso 2 de WazuhAlpine.pdf: cabeceras de compatibilidad musl/BPF.
#
# Se ejecuta COMO ROOT dentro del servidor web Alpine (192.123.10.10), DESPUES del
# Paso 1 (apk add ...) y del git clone de wazuh.
#
# Por que es un script y no copy-paste: el PDF trae comillas tipograficas en los
# heredocs (EOF con comillas curvas) y espacios perdidos; pegarlo desde el PDF rompe
# los archivos .h en silencio. La guia misma lo advierte al final (seccion 7).
set -e
[ "$(id -u)" = "0" ] || { echo "ERROR: hay que ejecutarlo como root"; exit 1; }

mkdir -p /usr/include/linux /usr/include/bpf

# --- 1/5 /usr/include/linux/compiler.h -------------------------------------
cat << 'EOF_COMPILER' > /usr/include/linux/compiler.h
#ifndef _LINUX_COMPILER_H
#define _LINUX_COMPILER_H
#include <linux/bpf.h>
#ifndef __user
#define __user
#endif
#ifndef __force
#define __force
#endif
#ifndef __must_check
#define __must_check
#endif
#ifndef __always_inline
#define __always_inline inline
#endif
#ifndef __noreturn
#define __noreturn __attribute__((noreturn))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif
#ifndef __printf
#define __printf(a, b) __attribute__((format(printf, a, b)))
#endif
#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif
#ifndef __always_unused
#define __always_unused __attribute__((unused))
#endif
#ifndef fallthrough
#define fallthrough __attribute__((fallthrough))
#endif
#ifndef BPF_REG_0
#define BPF_REG_0 0
#endif
#ifndef BPF_MOV64_IMM
#define BPF_MOV64_IMM(DST, IMM) \
((struct bpf_insn) { \
.code = 0xb7, \
.dst_reg = DST, \
.src_reg = 0, \
.off = 0, \
.imm = IMM })
#endif
#ifndef BPF_EXIT_INSN
#define BPF_EXIT_INSN() \
((struct bpf_insn) { \
.code = 0x95, \
.dst_reg = 0, \
.src_reg = 0, \
.off = 0, \
.imm = 0 })
#endif
#endif
EOF_COMPILER

# --- 2/5 /usr/include/linux/kernel.h ---------------------------------------
cat << 'EOF_KERNEL' > /usr/include/linux/kernel.h
#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H
#include <sys/param.h>
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#ifndef roundup
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#endif
#endif
EOF_KERNEL

# --- 3/5 /usr/include/linux/err.h ------------------------------------------
cat << 'EOF_ERR' > /usr/include/linux/err.h
#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H
#include <linux/compiler.h>
#include <errno.h>
#include <stdbool.h>
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
static inline void *ERR_PTR(long error) { return (void *) error; }
static inline long PTR_ERR(const void *ptr) { return (long) ptr; }
static inline bool IS_ERR(const void *ptr) { return IS_ERR_VALUE((unsigned long)ptr); }
static inline bool IS_ERR_OR_NULL(const void *ptr) { return !ptr || IS_ERR_VALUE((unsigned long)ptr); }
static inline void *ERR_CAST(const void *ptr) { return (void *) ptr; }
static inline int PTR_ERR_OR_ZERO(const void *ptr) { return IS_ERR(ptr) ? PTR_ERR(ptr) : 0; }
#endif
EOF_ERR

# --- 4/5 /usr/include/linux/bpf_insn.h  (+ copia en /usr/include/bpf/) -----
cat << 'EOF_INSN' > /usr/include/linux/bpf_insn.h
#ifndef _LINUX_BPF_INSN_H
#define _LINUX_BPF_INSN_H
#include <linux/bpf.h>
#ifndef BPF_REG_0
#define BPF_REG_0 0
#endif
#ifndef BPF_MOV64_IMM
#define BPF_MOV64_IMM(DST, IMM) \
((struct bpf_insn) { \
.code = 0xb7, \
.dst_reg = DST, \
.src_reg = 0, \
.off = 0, \
.imm = IMM })
#endif
#ifndef BPF_EXIT_INSN
#define BPF_EXIT_INSN() \
((struct bpf_insn) { \
.code = 0x95, \
.dst_reg = 0, \
.src_reg = 0, \
.off = 0, \
.imm = 0 })
#endif
#endif
EOF_INSN
cp /usr/include/linux/bpf_insn.h /usr/include/bpf/bpf_insn.h

# --- 5/5 parche BPF_MAP_TYPE_ARENA en linux/bpf.h -------------------------
if ! grep -q "BPF_MAP_TYPE_ARENA" /usr/include/linux/bpf.h 2>/dev/null; then
cat << 'EOF_ARENA' >> /usr/include/linux/bpf.h
#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA 31
#endif
EOF_ARENA
  echo "  parche BPF_MAP_TYPE_ARENA aplicado"
else
  echo "  BPF_MAP_TYPE_ARENA ya existia, no se parchea"
fi

echo
echo "OK - cabeceras creadas:"
ls -l /usr/include/linux/compiler.h /usr/include/linux/kernel.h \
      /usr/include/linux/err.h /usr/include/linux/bpf_insn.h \
      /usr/include/bpf/bpf_insn.h
echo
echo "Comprobacion rapida de sintaxis (no debe imprimir errores):"
printf '#include <linux/err.h>\n#include <linux/kernel.h>\nint main(void){return 0;}\n' > /tmp/_hdr_test.c
gcc -D_GNU_SOURCE -fsyntax-only /tmp/_hdr_test.c && echo "  cabeceras compilan OK"
rm -f /tmp/_hdr_test.c
