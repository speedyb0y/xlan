savedcmd_/build/xlan/xnic.mod.o := gcc -Wp,-MMD,/build/xlan/.xnic.mod.o.d -nostdinc -I/build/linux/arch/x86/include -I./arch/x86/include/generated -I/build/linux/include -I./include -I/build/linux/arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I/build/linux/include/uapi -I./include/generated/uapi -include /build/linux/include/linux/compiler-version.h -include /build/linux/include/linux/kconfig.h -include /build/linux/include/linux/compiler_types.h -D__KERNEL__ -fmacro-prefix-map=/build/linux/= -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -funsigned-char -std=gnu11 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -march=core2 -mno-red-zone -mcmodel=kernel -Wno-sign-compare -fno-asynchronous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 -fno-allow-store-data-races -Wframe-larger-than=2048 -fno-stack-protector -Wno-main -Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-dangling-pointer -fomit-frame-pointer -fno-stack-clash-protection -falign-functions=16 -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wcast-function-type -Wno-stringop-truncation -Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized -Wno-array-bounds -Wno-alloc-size-larger-than -Wimplicit-fallthrough=5 -fno-strict-overflow -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wno-packed-not-aligned -DMODULE -DKBUILD_BASENAME='"xnic.mod"' -DKBUILD_MODNAME='"xnic"' -D__KBUILD_MODNAME=kmod_xnic -c -o /build/xlan/xnic.mod.o /build/xlan/xnic.mod.c

source_/build/xlan/xnic.mod.o := /build/xlan/xnic.mod.c

deps_/build/xlan/xnic.mod.o := \
    $(wildcard include/config/MODULE_UNLOAD) \
    $(wildcard include/config/RETPOLINE) \
  /build/linux/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /build/linux/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \
  /build/linux/include/linux/compiler_types.h \
    $(wildcard include/config/DEBUG_INFO_BTF) \
    $(wildcard include/config/PAHOLE_HAS_BTF_TAG) \
    $(wildcard include/config/FUNCTION_ALIGNMENT) \
    $(wildcard include/config/CC_IS_GCC) \
    $(wildcard include/config/HAVE_ARCH_COMPILER_H) \
    $(wildcard include/config/CC_HAS_ASM_INLINE) \
  /build/linux/include/linux/compiler_attributes.h \
  /build/linux/include/linux/compiler-gcc.h \
    $(wildcard include/config/ARCH_USE_BUILTIN_BSWAP) \
    $(wildcard include/config/SHADOW_CALL_STACK) \
    $(wildcard include/config/KCOV) \
  /build/linux/include/linux/module.h \
    $(wildcard include/config/MODULES) \
    $(wildcard include/config/SYSFS) \
    $(wildcard include/config/MODULES_TREE_LOOKUP) \
    $(wildcard include/config/LIVEPATCH) \
    $(wildcard include/config/STACKTRACE_BUILD_ID) \
    $(wildcard include/config/ARCH_USES_CFI_TRAPS) \
    $(wildcard include/config/MODULE_SIG) \
    $(wildcard include/config/ARCH_WANTS_MODULES_DATA_IN_VMALLOC) \
    $(wildcard include/config/GENERIC_BUG) \
    $(wildcard include/config/KALLSYMS) \
    $(wildcard include/config/SMP) \
    $(wildcard include/config/TRACEPOINTS) \
    $(wildcard include/config/TREE_SRCU) \
    $(wildcard include/config/BPF_EVENTS) \
    $(wildcard include/config/DEBUG_INFO_BTF_MODULES) \
    $(wildcard include/config/JUMP_LABEL) \
    $(wildcard include/config/TRACING) \
    $(wildcard include/config/EVENT_TRACING) \
    $(wildcard include/config/FTRACE_MCOUNT_RECORD) \
    $(wildcard include/config/KPROBES) \
    $(wildcard include/config/HAVE_STATIC_CALL_INLINE) \
    $(wildcard include/config/KUNIT) \
    $(wildcard include/config/PRINTK_INDEX) \
    $(wildcard include/config/CONSTRUCTORS) \
    $(wildcard include/config/FUNCTION_ERROR_INJECTION) \
  /build/linux/include/linux/list.h \
    $(wildcard include/config/DEBUG_LIST) \
  /build/linux/include/linux/container_of.h \
  /build/linux/include/linux/build_bug.h \
  /build/linux/include/linux/compiler.h \
    $(wildcard include/config/TRACE_BRANCH_PROFILING) \
    $(wildcard include/config/PROFILE_ALL_BRANCHES) \
    $(wildcard include/config/OBJTOOL) \
  arch/x86/include/generated/asm/rwonce.h \
  /build/linux/include/asm-generic/rwonce.h \
  /build/linux/include/linux/kasan-checks.h \
    $(wildcard include/config/KASAN_GENERIC) \
    $(wildcard include/config/KASAN_SW_TAGS) \
  /build/linux/include/linux/types.h \
    $(wildcard include/config/HAVE_UID16) \
    $(wildcard include/config/UID16) \
    $(wildcard include/config/ARCH_DMA_ADDR_T_64BIT) \
    $(wildcard include/config/PHYS_ADDR_T_64BIT) \
    $(wildcard include/config/64BIT) \
    $(wildcard include/config/ARCH_32BIT_USTAT_F_TINODE) \
  /build/linux/include/uapi/linux/types.h \
  arch/x86/include/generated/uapi/asm/types.h \
  /build/linux/include/uapi/asm-generic/types.h \
  /build/linux/include/asm-generic/int-ll64.h \
  /build/linux/include/uapi/asm-generic/int-ll64.h \
  /build/linux/arch/x86/include/uapi/asm/bitsperlong.h \
  /build/linux/include/asm-generic/bitsperlong.h \
  /build/linux/include/uapi/asm-generic/bitsperlong.h \
  /build/linux/include/uapi/linux/posix_types.h \
  /build/linux/include/linux/stddef.h \
  /build/linux/include/uapi/linux/stddef.h \
  /build/linux/arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/X86_32) \
  /build/linux/arch/x86/include/uapi/asm/posix_types_64.h \
  /build/linux/include/uapi/asm-generic/posix_types.h \
  /build/linux/include/linux/kcsan-checks.h \
    $(wildcard include/config/KCSAN) \
    $(wildcard include/config/KCSAN_WEAK_MEMORY) \
    $(wildcard include/config/KCSAN_IGNORE_ATOMICS) \
  /build/linux/include/linux/poison.h \
    $(wildcard include/config/ILLEGAL_POINTER_VALUE) \
  /build/linux/include/linux/const.h \
  /build/linux/include/vdso/const.h \
  /build/linux/include/uapi/linux/const.h \
  /build/linux/arch/x86/include/asm/barrier.h \
  /build/linux/arch/x86/include/asm/alternative.h \
    $(wildcard include/config/CALL_THUNKS) \
  /build/linux/include/linux/stringify.h \
  /build/linux/arch/x86/include/asm/asm.h \
  /build/linux/arch/x86/include/asm/extable_fixup_types.h \
  /build/linux/arch/x86/include/asm/nops.h \
  /build/linux/include/asm-generic/barrier.h \
  /build/linux/include/linux/stat.h \
  /build/linux/arch/x86/include/uapi/asm/stat.h \
  /build/linux/include/uapi/linux/stat.h \
  /build/linux/include/linux/time.h \
    $(wildcard include/config/POSIX_TIMERS) \
  /build/linux/include/linux/cache.h \
    $(wildcard include/config/ARCH_HAS_CACHE_LINE_SIZE) \
  /build/linux/include/uapi/linux/kernel.h \
  /build/linux/include/uapi/linux/sysinfo.h \
  /build/linux/arch/x86/include/asm/cache.h \
    $(wildcard include/config/X86_L1_CACHE_SHIFT) \
    $(wildcard include/config/X86_INTERNODE_CACHE_SHIFT) \
    $(wildcard include/config/X86_VSMP) \
  /build/linux/include/linux/linkage.h \
    $(wildcard include/config/ARCH_USE_SYM_ANNOTATIONS) \
  /build/linux/include/linux/export.h \
    $(wildcard include/config/MODVERSIONS) \
    $(wildcard include/config/HAVE_ARCH_PREL32_RELOCATIONS) \
    $(wildcard include/config/TRIM_UNUSED_KSYMS) \
  /build/linux/arch/x86/include/asm/linkage.h \
    $(wildcard include/config/CALL_PADDING) \
    $(wildcard include/config/RETHUNK) \
    $(wildcard include/config/SLS) \
    $(wildcard include/config/FUNCTION_PADDING_BYTES) \
  /build/linux/arch/x86/include/asm/ibt.h \
    $(wildcard include/config/X86_KERNEL_IBT) \
    $(wildcard include/config/X86_64) \
  /build/linux/include/linux/math64.h \
    $(wildcard include/config/ARCH_SUPPORTS_INT128) \
  /build/linux/include/linux/math.h \
  /build/linux/arch/x86/include/asm/div64.h \
  /build/linux/include/asm-generic/div64.h \
  /build/linux/include/vdso/math64.h \
  /build/linux/include/linux/time64.h \
  /build/linux/include/vdso/time64.h \
  /build/linux/include/uapi/linux/time.h \
  /build/linux/include/uapi/linux/time_types.h \
  /build/linux/include/linux/time32.h \
  /build/linux/include/linux/timex.h \
  /build/linux/include/uapi/linux/timex.h \
  /build/linux/include/uapi/linux/param.h \
  arch/x86/include/generated/uapi/asm/param.h \
  /build/linux/include/asm-generic/param.h \
    $(wildcard include/config/HZ) \
  /build/linux/include/uapi/asm-generic/param.h \
  /build/linux/arch/x86/include/asm/timex.h \
    $(wildcard include/config/X86_TSC) \
  /build/linux/arch/x86/include/asm/processor.h \
    $(wildcard include/config/X86_VMX_FEATURE_NAMES) \
    $(wildcard include/config/X86_IOPL_IOPERM) \
    $(wildcard include/config/STACKPROTECTOR) \
    $(wildcard include/config/VM86) \
    $(wildcard include/config/PARAVIRT_XXL) \
    $(wildcard include/config/X86_DEBUGCTLMSR) \
    $(wildcard include/config/CPU_SUP_AMD) \
    $(wildcard include/config/XEN) \
    $(wildcard include/config/X86_SGX) \
  /build/linux/arch/x86/include/asm/processor-flags.h \
    $(wildcard include/config/PAGE_TABLE_ISOLATION) \
  /build/linux/arch/x86/include/uapi/asm/processor-flags.h \
  /build/linux/include/linux/mem_encrypt.h \
    $(wildcard include/config/ARCH_HAS_MEM_ENCRYPT) \
    $(wildcard include/config/AMD_MEM_ENCRYPT) \
  /build/linux/arch/x86/include/asm/mem_encrypt.h \
  /build/linux/include/linux/init.h \
    $(wildcard include/config/STRICT_KERNEL_RWX) \
    $(wildcard include/config/STRICT_MODULE_RWX) \
    $(wildcard include/config/LTO_CLANG) \
  /build/linux/include/linux/cc_platform.h \
    $(wildcard include/config/ARCH_HAS_CC_PLATFORM) \
  /build/linux/arch/x86/include/uapi/asm/bootparam.h \
  /build/linux/include/linux/screen_info.h \
  /build/linux/include/uapi/linux/screen_info.h \
  /build/linux/include/linux/apm_bios.h \
  /build/linux/include/uapi/linux/apm_bios.h \
  /build/linux/include/uapi/linux/ioctl.h \
  arch/x86/include/generated/uapi/asm/ioctl.h \
  /build/linux/include/asm-generic/ioctl.h \
  /build/linux/include/uapi/asm-generic/ioctl.h \
  /build/linux/include/linux/edd.h \
  /build/linux/include/uapi/linux/edd.h \
  /build/linux/arch/x86/include/asm/ist.h \
  /build/linux/arch/x86/include/uapi/asm/ist.h \
  /build/linux/include/video/edid.h \
    $(wildcard include/config/X86) \
  /build/linux/include/uapi/video/edid.h \
  /build/linux/arch/x86/include/asm/math_emu.h \
  /build/linux/arch/x86/include/asm/ptrace.h \
    $(wildcard include/config/PARAVIRT) \
    $(wildcard include/config/IA32_EMULATION) \
  /build/linux/arch/x86/include/asm/segment.h \
    $(wildcard include/config/XEN_PV) \
  /build/linux/arch/x86/include/asm/page_types.h \
    $(wildcard include/config/PHYSICAL_START) \
    $(wildcard include/config/PHYSICAL_ALIGN) \
    $(wildcard include/config/DYNAMIC_PHYSICAL_MASK) \
  /build/linux/arch/x86/include/asm/page_64_types.h \
    $(wildcard include/config/KASAN) \
    $(wildcard include/config/DYNAMIC_MEMORY_LAYOUT) \
    $(wildcard include/config/X86_5LEVEL) \
    $(wildcard include/config/RANDOMIZE_BASE) \
  /build/linux/arch/x86/include/asm/kaslr.h \
    $(wildcard include/config/RANDOMIZE_MEMORY) \
  /build/linux/arch/x86/include/uapi/asm/ptrace.h \
  /build/linux/arch/x86/include/uapi/asm/ptrace-abi.h \
  /build/linux/arch/x86/include/asm/proto.h \
  /build/linux/arch/x86/include/uapi/asm/ldt.h \
  /build/linux/arch/x86/include/uapi/asm/sigcontext.h \
  /build/linux/arch/x86/include/asm/current.h \
    $(wildcard include/config/CALL_DEPTH_TRACKING) \
  /build/linux/arch/x86/include/asm/percpu.h \
    $(wildcard include/config/X86_64_SMP) \
    $(wildcard include/config/X86_CMPXCHG64) \
  /build/linux/include/linux/kernel.h \
    $(wildcard include/config/PREEMPT_VOLUNTARY_BUILD) \
    $(wildcard include/config/PREEMPT_DYNAMIC) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_CALL) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_KEY) \
    $(wildcard include/config/PREEMPT_) \
    $(wildcard include/config/DEBUG_ATOMIC_SLEEP) \
    $(wildcard include/config/MMU) \
    $(wildcard include/config/PROVE_LOCKING) \
  /build/linux/include/linux/stdarg.h \
  /build/linux/include/linux/align.h \
  /build/linux/include/linux/limits.h \
  /build/linux/include/uapi/linux/limits.h \
  /build/linux/include/vdso/limits.h \
  /build/linux/include/linux/bitops.h \
  /build/linux/include/linux/bits.h \
  /build/linux/include/vdso/bits.h \
  /build/linux/include/linux/typecheck.h \
  /build/linux/include/asm-generic/bitops/generic-non-atomic.h \
  /build/linux/arch/x86/include/asm/bitops.h \
    $(wildcard include/config/X86_CMOV) \
  /build/linux/arch/x86/include/asm/rmwcc.h \
  /build/linux/include/asm-generic/bitops/sched.h \
  /build/linux/arch/x86/include/asm/arch_hweight.h \
  /build/linux/arch/x86/include/asm/cpufeatures.h \
  /build/linux/arch/x86/include/asm/required-features.h \
    $(wildcard include/config/X86_MINIMUM_CPU_FAMILY) \
    $(wildcard include/config/MATH_EMULATION) \
    $(wildcard include/config/X86_PAE) \
    $(wildcard include/config/X86_P6_NOP) \
    $(wildcard include/config/MATOM) \
  /build/linux/arch/x86/include/asm/disabled-features.h \
    $(wildcard include/config/X86_UMIP) \
    $(wildcard include/config/X86_INTEL_MEMORY_PROTECTION_KEYS) \
    $(wildcard include/config/CPU_UNRET_ENTRY) \
    $(wildcard include/config/INTEL_IOMMU_SVM) \
    $(wildcard include/config/INTEL_TDX_GUEST) \
  /build/linux/include/asm-generic/bitops/const_hweight.h \
  /build/linux/include/asm-generic/bitops/instrumented-atomic.h \
  /build/linux/include/linux/instrumented.h \
  /build/linux/include/linux/kmsan-checks.h \
    $(wildcard include/config/KMSAN) \
  /build/linux/include/asm-generic/bitops/instrumented-non-atomic.h \
    $(wildcard include/config/KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) \
  /build/linux/include/asm-generic/bitops/instrumented-lock.h \
  /build/linux/include/asm-generic/bitops/le.h \
  /build/linux/arch/x86/include/uapi/asm/byteorder.h \
  /build/linux/include/linux/byteorder/little_endian.h \
  /build/linux/include/uapi/linux/byteorder/little_endian.h \
  /build/linux/include/linux/swab.h \
  /build/linux/include/uapi/linux/swab.h \
  /build/linux/arch/x86/include/uapi/asm/swab.h \
  /build/linux/include/linux/byteorder/generic.h \
  /build/linux/include/asm-generic/bitops/ext2-atomic-setbit.h \
  /build/linux/include/linux/kstrtox.h \
  /build/linux/include/linux/log2.h \
    $(wildcard include/config/ARCH_HAS_ILOG2_U32) \
    $(wildcard include/config/ARCH_HAS_ILOG2_U64) \
  /build/linux/include/linux/minmax.h \
  /build/linux/include/linux/panic.h \
    $(wildcard include/config/PANIC_TIMEOUT) \
  /build/linux/include/linux/printk.h \
    $(wildcard include/config/MESSAGE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_QUIET) \
    $(wildcard include/config/EARLY_PRINTK) \
    $(wildcard include/config/PRINTK) \
    $(wildcard include/config/DYNAMIC_DEBUG) \
    $(wildcard include/config/DYNAMIC_DEBUG_CORE) \
  /build/linux/include/linux/kern_levels.h \
  /build/linux/include/linux/ratelimit_types.h \
  /build/linux/include/linux/spinlock_types_raw.h \
    $(wildcard include/config/DEBUG_SPINLOCK) \
    $(wildcard include/config/DEBUG_LOCK_ALLOC) \
  /build/linux/arch/x86/include/asm/spinlock_types.h \
  /build/linux/include/asm-generic/qspinlock_types.h \
    $(wildcard include/config/NR_CPUS) \
  /build/linux/include/asm-generic/qrwlock_types.h \
  /build/linux/include/linux/lockdep_types.h \
    $(wildcard include/config/PROVE_RAW_LOCK_NESTING) \
    $(wildcard include/config/LOCKDEP) \
    $(wildcard include/config/LOCK_STAT) \
  /build/linux/include/linux/once_lite.h \
  /build/linux/include/linux/static_call_types.h \
    $(wildcard include/config/HAVE_STATIC_CALL) \
  /build/linux/include/linux/instruction_pointer.h \
  /build/linux/include/asm-generic/percpu.h \
    $(wildcard include/config/DEBUG_PREEMPT) \
    $(wildcard include/config/HAVE_SETUP_PER_CPU_AREA) \
  /build/linux/include/linux/threads.h \
    $(wildcard include/config/BASE_SMALL) \
  /build/linux/include/linux/percpu-defs.h \
    $(wildcard include/config/DEBUG_FORCE_WEAK_PER_CPU) \
  /build/linux/arch/x86/include/asm/cpuid.h \
  /build/linux/arch/x86/include/asm/string.h \
  /build/linux/arch/x86/include/asm/string_64.h \
    $(wildcard include/config/ARCH_HAS_UACCESS_FLUSHCACHE) \
  /build/linux/include/linux/jump_label.h \
    $(wildcard include/config/HAVE_ARCH_JUMP_LABEL_RELATIVE) \
  /build/linux/arch/x86/include/asm/jump_label.h \
    $(wildcard include/config/HAVE_JUMP_LABEL_HACK) \
  /build/linux/arch/x86/include/asm/page.h \
  /build/linux/arch/x86/include/asm/page_64.h \
    $(wildcard include/config/DEBUG_VIRTUAL) \
    $(wildcard include/config/X86_VSYSCALL_EMULATION) \
  /build/linux/include/linux/range.h \
  /build/linux/include/asm-generic/memory_model.h \
    $(wildcard include/config/FLATMEM) \
    $(wildcard include/config/SPARSEMEM_VMEMMAP) \
    $(wildcard include/config/SPARSEMEM) \
  /build/linux/include/linux/pfn.h \
  /build/linux/include/asm-generic/getorder.h \
  /build/linux/arch/x86/include/asm/pgtable_types.h \
    $(wildcard include/config/MEM_SOFT_DIRTY) \
    $(wildcard include/config/HAVE_ARCH_USERFAULTFD_WP) \
    $(wildcard include/config/PGTABLE_LEVELS) \
    $(wildcard include/config/PROC_FS) \
  /build/linux/arch/x86/include/asm/pgtable_64_types.h \
    $(wildcard include/config/DEBUG_KMAP_LOCAL_FORCE_MAP) \
  /build/linux/arch/x86/include/asm/sparsemem.h \
    $(wildcard include/config/NUMA_KEEP_MEMINFO) \
  /build/linux/include/asm-generic/pgtable-nop4d.h \
  /build/linux/arch/x86/include/asm/msr.h \
  /build/linux/arch/x86/include/asm/msr-index.h \
  arch/x86/include/generated/uapi/asm/errno.h \
  /build/linux/include/uapi/asm-generic/errno.h \
  /build/linux/include/uapi/asm-generic/errno-base.h \
  /build/linux/arch/x86/include/asm/cpumask.h \
  /build/linux/include/linux/cpumask.h \
    $(wildcard include/config/FORCE_NR_CPUS) \
    $(wildcard include/config/HOTPLUG_CPU) \
    $(wildcard include/config/DEBUG_PER_CPU_MAPS) \
    $(wildcard include/config/CPUMASK_OFFSTACK) \
  /build/linux/include/linux/bitmap.h \
  /build/linux/include/linux/find.h \
  /build/linux/include/linux/string.h \
    $(wildcard include/config/BINARY_PRINTF) \
    $(wildcard include/config/FORTIFY_SOURCE) \
  /build/linux/include/linux/errno.h \
  /build/linux/include/uapi/linux/errno.h \
  /build/linux/include/uapi/linux/string.h \
  /build/linux/include/linux/atomic.h \
  /build/linux/arch/x86/include/asm/atomic.h \
  /build/linux/arch/x86/include/asm/cmpxchg.h \
  /build/linux/arch/x86/include/asm/cmpxchg_64.h \
  /build/linux/arch/x86/include/asm/atomic64_64.h \
  /build/linux/include/linux/atomic/atomic-arch-fallback.h \
    $(wildcard include/config/GENERIC_ATOMIC64) \
  /build/linux/include/linux/atomic/atomic-long.h \
  /build/linux/include/linux/atomic/atomic-instrumented.h \
  /build/linux/include/linux/bug.h \
    $(wildcard include/config/BUG_ON_DATA_CORRUPTION) \
  /build/linux/arch/x86/include/asm/bug.h \
    $(wildcard include/config/DEBUG_BUGVERBOSE) \
  /build/linux/include/linux/instrumentation.h \
    $(wildcard include/config/NOINSTR_VALIDATION) \
  /build/linux/include/linux/objtool.h \
    $(wildcard include/config/FRAME_POINTER) \
  /build/linux/include/asm-generic/bug.h \
    $(wildcard include/config/BUG) \
    $(wildcard include/config/GENERIC_BUG_RELATIVE_POINTERS) \
  /build/linux/include/linux/gfp_types.h \
    $(wildcard include/config/KASAN_HW_TAGS) \
  /build/linux/include/linux/numa.h \
    $(wildcard include/config/NODES_SHIFT) \
    $(wildcard include/config/NUMA) \
    $(wildcard include/config/HAVE_ARCH_NODE_DEV_GROUP) \
  /build/linux/arch/x86/include/uapi/asm/msr.h \
  /build/linux/arch/x86/include/asm/shared/msr.h \
  /build/linux/include/linux/tracepoint-defs.h \
  /build/linux/include/linux/static_key.h \
  /build/linux/arch/x86/include/asm/desc_defs.h \
  /build/linux/arch/x86/include/asm/special_insns.h \
  /build/linux/include/linux/irqflags.h \
    $(wildcard include/config/TRACE_IRQFLAGS) \
    $(wildcard include/config/PREEMPT_RT) \
    $(wildcard include/config/IRQSOFF_TRACER) \
    $(wildcard include/config/PREEMPT_TRACER) \
    $(wildcard include/config/DEBUG_IRQFLAGS) \
    $(wildcard include/config/TRACE_IRQFLAGS_SUPPORT) \
  /build/linux/arch/x86/include/asm/irqflags.h \
    $(wildcard include/config/DEBUG_ENTRY) \
  /build/linux/arch/x86/include/asm/nospec-branch.h \
    $(wildcard include/config/CALL_THUNKS_DEBUG) \
    $(wildcard include/config/CPU_IBPB_ENTRY) \
  /build/linux/arch/x86/include/asm/unwind_hints.h \
  /build/linux/arch/x86/include/asm/orc_types.h \
  /build/linux/arch/x86/include/asm/fpu/types.h \
  /build/linux/arch/x86/include/asm/vmxfeatures.h \
  /build/linux/arch/x86/include/asm/vdso/processor.h \
  /build/linux/include/linux/personality.h \
  /build/linux/include/uapi/linux/personality.h \
  /build/linux/include/linux/err.h \
  /build/linux/arch/x86/include/asm/tsc.h \
  /build/linux/arch/x86/include/asm/cpufeature.h \
    $(wildcard include/config/X86_FEATURE_NAMES) \
  /build/linux/include/vdso/time32.h \
  /build/linux/include/vdso/time.h \
  /build/linux/include/linux/uidgid.h \
    $(wildcard include/config/MULTIUSER) \
    $(wildcard include/config/USER_NS) \
  /build/linux/include/linux/highuid.h \
  /build/linux/include/linux/buildid.h \
    $(wildcard include/config/CRASH_CORE) \
  /build/linux/include/linux/mm_types.h \
    $(wildcard include/config/HAVE_ALIGNED_STRUCT_PAGE) \
    $(wildcard include/config/MEMCG) \
    $(wildcard include/config/USERFAULTFD) \
    $(wildcard include/config/ANON_VMA_NAME) \
    $(wildcard include/config/SWAP) \
    $(wildcard include/config/HAVE_ARCH_COMPAT_MMAP_BASES) \
    $(wildcard include/config/MEMBARRIER) \
    $(wildcard include/config/SCHED_MM_CID) \
    $(wildcard include/config/AIO) \
    $(wildcard include/config/MMU_NOTIFIER) \
    $(wildcard include/config/TRANSPARENT_HUGEPAGE) \
    $(wildcard include/config/NUMA_BALANCING) \
    $(wildcard include/config/ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH) \
    $(wildcard include/config/HUGETLB_PAGE) \
    $(wildcard include/config/IOMMU_SVA) \
    $(wildcard include/config/KSM) \
    $(wildcard include/config/LRU_GEN) \
  /build/linux/include/linux/mm_types_task.h \
    $(wildcard include/config/SPLIT_PTLOCK_CPUS) \
    $(wildcard include/config/ARCH_ENABLE_SPLIT_PMD_PTLOCK) \
  /build/linux/arch/x86/include/asm/tlbbatch.h \
  /build/linux/include/linux/auxvec.h \
  /build/linux/include/uapi/linux/auxvec.h \
  /build/linux/arch/x86/include/uapi/asm/auxvec.h \
  /build/linux/include/linux/kref.h \
  /build/linux/include/linux/spinlock.h \
    $(wildcard include/config/PREEMPTION) \
  /build/linux/include/linux/preempt.h \
    $(wildcard include/config/PREEMPT_COUNT) \
    $(wildcard include/config/TRACE_PREEMPT_TOGGLE) \
    $(wildcard include/config/PREEMPT_NOTIFIERS) \
  /build/linux/arch/x86/include/asm/preempt.h \
  /build/linux/include/linux/thread_info.h \
    $(wildcard include/config/THREAD_INFO_IN_TASK) \
    $(wildcard include/config/GENERIC_ENTRY) \
    $(wildcard include/config/HAVE_ARCH_WITHIN_STACK_FRAMES) \
    $(wildcard include/config/HARDENED_USERCOPY) \
  /build/linux/include/linux/restart_block.h \
  /build/linux/arch/x86/include/asm/thread_info.h \
    $(wildcard include/config/COMPAT) \
  /build/linux/include/linux/bottom_half.h \
  /build/linux/include/linux/lockdep.h \
    $(wildcard include/config/DEBUG_LOCKING_API_SELFTESTS) \
  /build/linux/include/linux/smp.h \
    $(wildcard include/config/UP_LATE_INIT) \
  /build/linux/include/linux/smp_types.h \
  /build/linux/include/linux/llist.h \
    $(wildcard include/config/ARCH_HAVE_NMI_SAFE_CMPXCHG) \
  /build/linux/arch/x86/include/asm/smp.h \
    $(wildcard include/config/X86_LOCAL_APIC) \
    $(wildcard include/config/DEBUG_NMI_SELFTEST) \
  arch/x86/include/generated/asm/mmiowb.h \
  /build/linux/include/asm-generic/mmiowb.h \
    $(wildcard include/config/MMIOWB) \
  /build/linux/include/linux/spinlock_types.h \
  /build/linux/include/linux/rwlock_types.h \
  /build/linux/arch/x86/include/asm/spinlock.h \
  /build/linux/arch/x86/include/asm/paravirt.h \
    $(wildcard include/config/PARAVIRT_SPINLOCKS) \
  /build/linux/arch/x86/include/asm/paravirt_types.h \
    $(wildcard include/config/ZERO_CALL_USED_REGS) \
    $(wildcard include/config/PARAVIRT_DEBUG) \
  /build/linux/arch/x86/include/asm/qspinlock.h \
  /build/linux/include/asm-generic/qspinlock.h \
  /build/linux/arch/x86/include/asm/qrwlock.h \
  /build/linux/include/asm-generic/qrwlock.h \
  /build/linux/include/linux/rwlock.h \
    $(wildcard include/config/PREEMPT) \
  /build/linux/include/linux/spinlock_api_smp.h \
    $(wildcard include/config/INLINE_SPIN_LOCK) \
    $(wildcard include/config/INLINE_SPIN_LOCK_BH) \
    $(wildcard include/config/INLINE_SPIN_LOCK_IRQ) \
    $(wildcard include/config/INLINE_SPIN_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_SPIN_TRYLOCK) \
    $(wildcard include/config/INLINE_SPIN_TRYLOCK_BH) \
    $(wildcard include/config/UNINLINE_SPIN_UNLOCK) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_BH) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_SPIN_UNLOCK_IRQRESTORE) \
    $(wildcard include/config/GENERIC_LOCKBREAK) \
  /build/linux/include/linux/rwlock_api_smp.h \
    $(wildcard include/config/INLINE_READ_LOCK) \
    $(wildcard include/config/INLINE_WRITE_LOCK) \
    $(wildcard include/config/INLINE_READ_LOCK_BH) \
    $(wildcard include/config/INLINE_WRITE_LOCK_BH) \
    $(wildcard include/config/INLINE_READ_LOCK_IRQ) \
    $(wildcard include/config/INLINE_WRITE_LOCK_IRQ) \
    $(wildcard include/config/INLINE_READ_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_WRITE_LOCK_IRQSAVE) \
    $(wildcard include/config/INLINE_READ_TRYLOCK) \
    $(wildcard include/config/INLINE_WRITE_TRYLOCK) \
    $(wildcard include/config/INLINE_READ_UNLOCK) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK) \
    $(wildcard include/config/INLINE_READ_UNLOCK_BH) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_BH) \
    $(wildcard include/config/INLINE_READ_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_IRQ) \
    $(wildcard include/config/INLINE_READ_UNLOCK_IRQRESTORE) \
    $(wildcard include/config/INLINE_WRITE_UNLOCK_IRQRESTORE) \
  /build/linux/include/linux/refcount.h \
  /build/linux/include/linux/rbtree.h \
  /build/linux/include/linux/rbtree_types.h \
  /build/linux/include/linux/rcupdate.h \
    $(wildcard include/config/PREEMPT_RCU) \
    $(wildcard include/config/TINY_RCU) \
    $(wildcard include/config/RCU_STRICT_GRACE_PERIOD) \
    $(wildcard include/config/RCU_LAZY) \
    $(wildcard include/config/TASKS_RCU_GENERIC) \
    $(wildcard include/config/RCU_STALL_COMMON) \
    $(wildcard include/config/NO_HZ_FULL) \
    $(wildcard include/config/KVM_XFER_TO_GUEST_WORK) \
    $(wildcard include/config/RCU_NOCB_CPU) \
    $(wildcard include/config/TASKS_RCU) \
    $(wildcard include/config/TASKS_TRACE_RCU) \
    $(wildcard include/config/TASKS_RUDE_RCU) \
    $(wildcard include/config/TREE_RCU) \
    $(wildcard include/config/DEBUG_OBJECTS_RCU_HEAD) \
    $(wildcard include/config/PROVE_RCU) \
    $(wildcard include/config/ARCH_WEAK_RELEASE_ACQUIRE) \
  /build/linux/include/linux/context_tracking_irq.h \
    $(wildcard include/config/CONTEXT_TRACKING_IDLE) \
  /build/linux/include/linux/rcutree.h \
  /build/linux/include/linux/maple_tree.h \
    $(wildcard include/config/MAPLE_RCU_DISABLED) \
    $(wildcard include/config/DEBUG_MAPLE_TREE) \
  /build/linux/include/linux/rwsem.h \
    $(wildcard include/config/RWSEM_SPIN_ON_OWNER) \
    $(wildcard include/config/DEBUG_RWSEMS) \
  /build/linux/include/linux/osq_lock.h \
  /build/linux/include/linux/completion.h \
  /build/linux/include/linux/swait.h \
  /build/linux/include/linux/wait.h \
  /build/linux/include/uapi/linux/wait.h \
  /build/linux/include/linux/uprobes.h \
    $(wildcard include/config/UPROBES) \
  /build/linux/include/linux/page-flags-layout.h \
  include/generated/bounds.h \
  /build/linux/include/linux/workqueue.h \
    $(wildcard include/config/DEBUG_OBJECTS_WORK) \
    $(wildcard include/config/FREEZER) \
    $(wildcard include/config/WQ_WATCHDOG) \
  /build/linux/include/linux/timer.h \
    $(wildcard include/config/DEBUG_OBJECTS_TIMERS) \
  /build/linux/include/linux/ktime.h \
  /build/linux/include/linux/jiffies.h \
  /build/linux/include/vdso/jiffies.h \
  include/generated/timeconst.h \
  /build/linux/include/vdso/ktime.h \
  /build/linux/include/linux/timekeeping.h \
    $(wildcard include/config/GENERIC_CMOS_UPDATE) \
  /build/linux/include/linux/clocksource_ids.h \
  /build/linux/include/linux/debugobjects.h \
    $(wildcard include/config/DEBUG_OBJECTS) \
    $(wildcard include/config/DEBUG_OBJECTS_FREE) \
  /build/linux/include/linux/seqlock.h \
  /build/linux/include/linux/mutex.h \
    $(wildcard include/config/MUTEX_SPIN_ON_OWNER) \
    $(wildcard include/config/DEBUG_MUTEXES) \
  /build/linux/include/linux/debug_locks.h \
  /build/linux/include/linux/percpu_counter.h \
  /build/linux/include/linux/percpu.h \
    $(wildcard include/config/NEED_PER_CPU_EMBED_FIRST_CHUNK) \
    $(wildcard include/config/NEED_PER_CPU_PAGE_FIRST_CHUNK) \
  /build/linux/include/linux/mmdebug.h \
    $(wildcard include/config/DEBUG_VM) \
    $(wildcard include/config/DEBUG_VM_IRQSOFF) \
    $(wildcard include/config/DEBUG_VM_PGFLAGS) \
  /build/linux/arch/x86/include/asm/mmu.h \
    $(wildcard include/config/MODIFY_LDT_SYSCALL) \
  /build/linux/include/linux/kmod.h \
  /build/linux/include/linux/umh.h \
  /build/linux/include/linux/gfp.h \
    $(wildcard include/config/HIGHMEM) \
    $(wildcard include/config/ZONE_DMA) \
    $(wildcard include/config/ZONE_DMA32) \
    $(wildcard include/config/ZONE_DEVICE) \
    $(wildcard include/config/PM_SLEEP) \
    $(wildcard include/config/CONTIG_ALLOC) \
    $(wildcard include/config/CMA) \
  /build/linux/include/linux/mmzone.h \
    $(wildcard include/config/ARCH_FORCE_MAX_ORDER) \
    $(wildcard include/config/MEMORY_ISOLATION) \
    $(wildcard include/config/ZSMALLOC) \
    $(wildcard include/config/LRU_GEN_STATS) \
    $(wildcard include/config/MEMORY_HOTPLUG) \
    $(wildcard include/config/COMPACTION) \
    $(wildcard include/config/MEMORY_FAILURE) \
    $(wildcard include/config/PAGE_EXTENSION) \
    $(wildcard include/config/DEFERRED_STRUCT_PAGE_INIT) \
    $(wildcard include/config/HAVE_MEMORYLESS_NODES) \
    $(wildcard include/config/SPARSEMEM_EXTREME) \
    $(wildcard include/config/HAVE_ARCH_PFN_VALID) \
  /build/linux/include/linux/list_nulls.h \
  /build/linux/include/linux/nodemask.h \
  /build/linux/include/linux/random.h \
    $(wildcard include/config/VMGENID) \
  /build/linux/include/uapi/linux/random.h \
  /build/linux/include/linux/irqnr.h \
  /build/linux/include/uapi/linux/irqnr.h \
  /build/linux/include/linux/prandom.h \
  /build/linux/include/linux/once.h \
  /build/linux/include/linux/pageblock-flags.h \
    $(wildcard include/config/HUGETLB_PAGE_SIZE_VARIABLE) \
  /build/linux/include/linux/page-flags.h \
    $(wildcard include/config/ARCH_USES_PG_UNCACHED) \
    $(wildcard include/config/PAGE_IDLE_FLAG) \
    $(wildcard include/config/ARCH_USES_PG_ARCH_X) \
    $(wildcard include/config/HUGETLB_PAGE_OPTIMIZE_VMEMMAP) \
  /build/linux/include/linux/local_lock.h \
  /build/linux/include/linux/local_lock_internal.h \
  /build/linux/include/linux/memory_hotplug.h \
    $(wildcard include/config/HAVE_ARCH_NODEDATA_EXTENSION) \
    $(wildcard include/config/ARCH_HAS_ADD_PAGES) \
    $(wildcard include/config/MEMORY_HOTREMOVE) \
  /build/linux/include/linux/notifier.h \
  /build/linux/include/linux/srcu.h \
    $(wildcard include/config/TINY_SRCU) \
    $(wildcard include/config/NEED_SRCU_NMI_SAFE) \
  /build/linux/include/linux/rcu_segcblist.h \
  /build/linux/include/linux/srcutree.h \
  /build/linux/include/linux/rcu_node_tree.h \
    $(wildcard include/config/RCU_FANOUT) \
    $(wildcard include/config/RCU_FANOUT_LEAF) \
  /build/linux/include/linux/topology.h \
    $(wildcard include/config/USE_PERCPU_NUMA_NODE_ID) \
    $(wildcard include/config/SCHED_SMT) \
  /build/linux/include/linux/arch_topology.h \
    $(wildcard include/config/ACPI_CPPC_LIB) \
    $(wildcard include/config/GENERIC_ARCH_TOPOLOGY) \
  /build/linux/arch/x86/include/asm/topology.h \
    $(wildcard include/config/SCHED_MC_PRIO) \
  /build/linux/include/asm-generic/topology.h \
  /build/linux/include/linux/sysctl.h \
    $(wildcard include/config/SYSCTL) \
  /build/linux/include/uapi/linux/sysctl.h \
  /build/linux/include/linux/elf.h \
    $(wildcard include/config/ARCH_USE_GNU_PROPERTY) \
    $(wildcard include/config/ARCH_HAVE_ELF_PROT) \
  /build/linux/arch/x86/include/asm/elf.h \
    $(wildcard include/config/X86_X32_ABI) \
  /build/linux/arch/x86/include/asm/user.h \
  /build/linux/arch/x86/include/asm/user_64.h \
  /build/linux/arch/x86/include/asm/fsgsbase.h \
  /build/linux/arch/x86/include/asm/vdso.h \
  /build/linux/include/uapi/linux/elf.h \
  /build/linux/include/uapi/linux/elf-em.h \
  /build/linux/include/linux/kobject.h \
    $(wildcard include/config/UEVENT_HELPER) \
    $(wildcard include/config/DEBUG_KOBJECT_RELEASE) \
  /build/linux/include/linux/sysfs.h \
  /build/linux/include/linux/kernfs.h \
    $(wildcard include/config/KERNFS) \
  /build/linux/include/linux/idr.h \
  /build/linux/include/linux/radix-tree.h \
  /build/linux/include/linux/xarray.h \
    $(wildcard include/config/XARRAY_MULTI) \
  /build/linux/include/linux/sched/mm.h \
    $(wildcard include/config/ARCH_HAS_MEMBARRIER_CALLBACKS) \
  /build/linux/include/linux/sched.h \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING_NATIVE) \
    $(wildcard include/config/SCHED_INFO) \
    $(wildcard include/config/SCHEDSTATS) \
    $(wildcard include/config/SCHED_CORE) \
    $(wildcard include/config/FAIR_GROUP_SCHED) \
    $(wildcard include/config/RT_GROUP_SCHED) \
    $(wildcard include/config/RT_MUTEXES) \
    $(wildcard include/config/UCLAMP_TASK) \
    $(wildcard include/config/UCLAMP_BUCKETS_COUNT) \
    $(wildcard include/config/KMAP_LOCAL) \
    $(wildcard include/config/CGROUP_SCHED) \
    $(wildcard include/config/BLK_DEV_IO_TRACE) \
    $(wildcard include/config/COMPAT_BRK) \
    $(wildcard include/config/CGROUPS) \
    $(wildcard include/config/BLK_CGROUP) \
    $(wildcard include/config/PSI) \
    $(wildcard include/config/PAGE_OWNER) \
    $(wildcard include/config/EVENTFD) \
    $(wildcard include/config/CPU_SUP_INTEL) \
    $(wildcard include/config/TASK_DELAY_ACCT) \
    $(wildcard include/config/ARCH_HAS_SCALED_CPUTIME) \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING_GEN) \
    $(wildcard include/config/POSIX_CPUTIMERS) \
    $(wildcard include/config/POSIX_CPU_TIMERS_TASK_WORK) \
    $(wildcard include/config/KEYS) \
    $(wildcard include/config/SYSVIPC) \
    $(wildcard include/config/DETECT_HUNG_TASK) \
    $(wildcard include/config/IO_URING) \
    $(wildcard include/config/AUDIT) \
    $(wildcard include/config/AUDITSYSCALL) \
    $(wildcard include/config/UBSAN) \
    $(wildcard include/config/UBSAN_TRAP) \
    $(wildcard include/config/TASK_XACCT) \
    $(wildcard include/config/CPUSETS) \
    $(wildcard include/config/X86_CPU_RESCTRL) \
    $(wildcard include/config/FUTEX) \
    $(wildcard include/config/PERF_EVENTS) \
    $(wildcard include/config/RSEQ) \
    $(wildcard include/config/FAULT_INJECTION) \
    $(wildcard include/config/LATENCYTOP) \
    $(wildcard include/config/FUNCTION_GRAPH_TRACER) \
    $(wildcard include/config/BCACHE) \
    $(wildcard include/config/VMAP_STACK) \
    $(wildcard include/config/SECURITY) \
    $(wildcard include/config/BPF_SYSCALL) \
    $(wildcard include/config/GCC_PLUGIN_STACKLEAK) \
    $(wildcard include/config/X86_MCE) \
    $(wildcard include/config/KRETPROBES) \
    $(wildcard include/config/RETHOOK) \
    $(wildcard include/config/ARCH_HAS_PARANOID_L1D_FLUSH) \
    $(wildcard include/config/RV) \
    $(wildcard include/config/ARCH_TASK_STRUCT_ON_STACK) \
    $(wildcard include/config/PREEMPT_NONE) \
    $(wildcard include/config/PREEMPT_VOLUNTARY) \
    $(wildcard include/config/DEBUG_RSEQ) \
  /build/linux/include/uapi/linux/sched.h \
  /build/linux/include/linux/pid.h \
  /build/linux/include/linux/rculist.h \
    $(wildcard include/config/PROVE_RCU_LIST) \
  /build/linux/include/linux/sem.h \
  /build/linux/include/uapi/linux/sem.h \
  /build/linux/include/linux/ipc.h \
  /build/linux/include/linux/rhashtable-types.h \
  /build/linux/include/uapi/linux/ipc.h \
  arch/x86/include/generated/uapi/asm/ipcbuf.h \
  /build/linux/include/uapi/asm-generic/ipcbuf.h \
  /build/linux/arch/x86/include/uapi/asm/sembuf.h \
  /build/linux/include/linux/shm.h \
  /build/linux/include/uapi/linux/shm.h \
  /build/linux/include/uapi/asm-generic/hugetlb_encode.h \
  /build/linux/arch/x86/include/uapi/asm/shmbuf.h \
  /build/linux/include/uapi/asm-generic/shmbuf.h \
  /build/linux/arch/x86/include/asm/shmparam.h \
  /build/linux/include/linux/kmsan_types.h \
  /build/linux/include/linux/plist.h \
    $(wildcard include/config/DEBUG_PLIST) \
  /build/linux/include/linux/hrtimer.h \
    $(wildcard include/config/HIGH_RES_TIMERS) \
    $(wildcard include/config/TIME_LOW_RES) \
    $(wildcard include/config/TIMERFD) \
  /build/linux/include/linux/hrtimer_defs.h \
  /build/linux/include/linux/timerqueue.h \
  /build/linux/include/linux/seccomp.h \
    $(wildcard include/config/SECCOMP) \
    $(wildcard include/config/HAVE_ARCH_SECCOMP_FILTER) \
    $(wildcard include/config/SECCOMP_FILTER) \
    $(wildcard include/config/CHECKPOINT_RESTORE) \
    $(wildcard include/config/SECCOMP_CACHE_DEBUG) \
  /build/linux/include/uapi/linux/seccomp.h \
  /build/linux/arch/x86/include/asm/seccomp.h \
  /build/linux/arch/x86/include/asm/unistd.h \
  /build/linux/arch/x86/include/uapi/asm/unistd.h \
  arch/x86/include/generated/uapi/asm/unistd_64.h \
  arch/x86/include/generated/asm/unistd_64_x32.h \
  arch/x86/include/generated/asm/unistd_32_ia32.h \
  /build/linux/include/asm-generic/seccomp.h \
  /build/linux/include/uapi/linux/unistd.h \
  /build/linux/include/linux/resource.h \
  /build/linux/include/uapi/linux/resource.h \
  arch/x86/include/generated/uapi/asm/resource.h \
  /build/linux/include/asm-generic/resource.h \
  /build/linux/include/uapi/asm-generic/resource.h \
  /build/linux/include/linux/latencytop.h \
  /build/linux/include/linux/sched/prio.h \
  /build/linux/include/linux/sched/types.h \
  /build/linux/include/linux/signal_types.h \
    $(wildcard include/config/OLD_SIGACTION) \
  /build/linux/include/uapi/linux/signal.h \
  /build/linux/arch/x86/include/asm/signal.h \
  /build/linux/arch/x86/include/uapi/asm/signal.h \
  /build/linux/include/uapi/asm-generic/signal-defs.h \
  /build/linux/arch/x86/include/uapi/asm/siginfo.h \
  /build/linux/include/uapi/asm-generic/siginfo.h \
  /build/linux/include/linux/syscall_user_dispatch.h \
  /build/linux/include/linux/task_io_accounting.h \
    $(wildcard include/config/TASK_IO_ACCOUNTING) \
  /build/linux/include/linux/posix-timers.h \
  /build/linux/include/linux/alarmtimer.h \
    $(wildcard include/config/RTC_CLASS) \
  /build/linux/include/uapi/linux/rseq.h \
  /build/linux/include/linux/kcsan.h \
  /build/linux/include/linux/rv.h \
    $(wildcard include/config/RV_REACTORS) \
  arch/x86/include/generated/asm/kmap_size.h \
  /build/linux/include/asm-generic/kmap_size.h \
    $(wildcard include/config/DEBUG_KMAP_LOCAL) \
  /build/linux/include/linux/sync_core.h \
    $(wildcard include/config/ARCH_HAS_SYNC_CORE_BEFORE_USERMODE) \
  /build/linux/arch/x86/include/asm/sync_core.h \
  /build/linux/include/linux/ioasid.h \
    $(wildcard include/config/IOASID) \
  /build/linux/include/linux/kobject_ns.h \
  /build/linux/include/linux/moduleparam.h \
    $(wildcard include/config/ALPHA) \
    $(wildcard include/config/IA64) \
    $(wildcard include/config/PPC64) \
  /build/linux/include/linux/rbtree_latch.h \
  /build/linux/include/linux/error-injection.h \
  /build/linux/include/asm-generic/error-injection.h \
  /build/linux/arch/x86/include/asm/module.h \
    $(wildcard include/config/UNWINDER_ORC) \
  /build/linux/include/asm-generic/module.h \
    $(wildcard include/config/HAVE_MOD_ARCH_SPECIFIC) \
    $(wildcard include/config/MODULES_USE_ELF_REL) \
    $(wildcard include/config/MODULES_USE_ELF_RELA) \
  /build/linux/include/linux/build-salt.h \
    $(wildcard include/config/BUILD_SALT) \
  /build/linux/include/linux/elfnote.h \
  /build/linux/include/linux/elfnote-lto.h \
    $(wildcard include/config/LTO) \
  /build/linux/include/linux/export-internal.h \
  /build/linux/include/linux/vermagic.h \
    $(wildcard include/config/PREEMPT_BUILD) \
  include/generated/utsrelease.h \
  /build/linux/arch/x86/include/asm/vermagic.h \
    $(wildcard include/config/M486SX) \
    $(wildcard include/config/M486) \
    $(wildcard include/config/M586) \
    $(wildcard include/config/M586TSC) \
    $(wildcard include/config/M586MMX) \
    $(wildcard include/config/MCORE2) \
    $(wildcard include/config/M686) \
    $(wildcard include/config/MPENTIUMII) \
    $(wildcard include/config/MPENTIUMIII) \
    $(wildcard include/config/MPENTIUMM) \
    $(wildcard include/config/MPENTIUM4) \
    $(wildcard include/config/MK6) \
    $(wildcard include/config/MK7) \
    $(wildcard include/config/MK8) \
    $(wildcard include/config/MELAN) \
    $(wildcard include/config/MCRUSOE) \
    $(wildcard include/config/MEFFICEON) \
    $(wildcard include/config/MWINCHIPC6) \
    $(wildcard include/config/MWINCHIP3D) \
    $(wildcard include/config/MCYRIXIII) \
    $(wildcard include/config/MVIAC3_2) \
    $(wildcard include/config/MVIAC7) \
    $(wildcard include/config/MGEODEGX1) \
    $(wildcard include/config/MGEODE_LX) \

/build/xlan/xnic.mod.o: $(deps_/build/xlan/xnic.mod.o)

$(deps_/build/xlan/xnic.mod.o):
