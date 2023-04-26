savedcmd_/build/xlan/xnic.o := gcc -Wp,-MMD,/build/xlan/.xnic.o.d -nostdinc -I/build/linux/arch/x86/include -I./arch/x86/include/generated -I/build/linux/include -I./include -I/build/linux/arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I/build/linux/include/uapi -I./include/generated/uapi -include /build/linux/include/linux/compiler-version.h -include /build/linux/include/linux/kconfig.h -include /build/linux/include/linux/compiler_types.h -D__KERNEL__ -fmacro-prefix-map=/build/linux/= -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -funsigned-char -std=gnu11 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -march=core2 -mno-red-zone -mcmodel=kernel -Wno-sign-compare -fno-asynchronous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-address -Wno-format-truncation -Wno-format-overflow -Wno-address-of-packed-member -O2 -fno-allow-store-data-races -Wframe-larger-than=2048 -fno-stack-protector -Wno-main -Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-dangling-pointer -fomit-frame-pointer -fno-stack-clash-protection -falign-functions=16 -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wcast-function-type -Wno-stringop-truncation -Wno-stringop-overflow -Wno-restrict -Wno-maybe-uninitialized -Wno-array-bounds -Wno-alloc-size-larger-than -Wimplicit-fallthrough=5 -fno-strict-overflow -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wno-packed-not-aligned -Wfatal-errors -Werror -Wall -Wextra -Wno-declaration-after-statement -Wno-error=unused-parameter -Wno-error=unused-function -Wno-error=unused-label -Wno-type-limits -Wno-unused-parameter -Wno-sign-compare -Wno-implicit-fallthrough -mpopcnt  -DMODULE  -DKBUILD_BASENAME='"xnic"' -DKBUILD_MODNAME='"xnic"' -D__KBUILD_MODNAME=kmod_xnic -c -o /build/xlan/xnic.o /build/xlan/xnic.c   ; ./tools/objtool/objtool --hacks=jump_label --hacks=noinstr --static-call --uaccess   --module /build/xlan/xnic.o

source_/build/xlan/xnic.o := /build/xlan/xnic.c

deps_/build/xlan/xnic.o := \
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
    $(wildcard include/config/RETPOLINE) \
    $(wildcard include/config/ARCH_USE_BUILTIN_BSWAP) \
    $(wildcard include/config/SHADOW_CALL_STACK) \
    $(wildcard include/config/KCOV) \
  /build/linux/include/linux/init.h \
    $(wildcard include/config/HAVE_ARCH_PREL32_RELOCATIONS) \
    $(wildcard include/config/STRICT_KERNEL_RWX) \
    $(wildcard include/config/STRICT_MODULE_RWX) \
    $(wildcard include/config/LTO_CLANG) \
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
  /build/linux/include/linux/stringify.h \
  /build/linux/include/linux/kernel.h \
    $(wildcard include/config/PREEMPT_VOLUNTARY_BUILD) \
    $(wildcard include/config/PREEMPT_DYNAMIC) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_CALL) \
    $(wildcard include/config/HAVE_PREEMPT_DYNAMIC_KEY) \
    $(wildcard include/config/PREEMPT_) \
    $(wildcard include/config/DEBUG_ATOMIC_SLEEP) \
    $(wildcard include/config/SMP) \
    $(wildcard include/config/MMU) \
    $(wildcard include/config/PROVE_LOCKING) \
    $(wildcard include/config/TRACING) \
    $(wildcard include/config/FTRACE_MCOUNT_RECORD) \
  /build/linux/include/linux/stdarg.h \
  /build/linux/include/linux/align.h \
  /build/linux/include/linux/const.h \
  /build/linux/include/vdso/const.h \
  /build/linux/include/uapi/linux/const.h \
  /build/linux/include/linux/limits.h \
  /build/linux/include/uapi/linux/limits.h \
  /build/linux/include/vdso/limits.h \
  /build/linux/include/linux/linkage.h \
    $(wildcard include/config/ARCH_USE_SYM_ANNOTATIONS) \
  /build/linux/include/linux/export.h \
    $(wildcard include/config/MODVERSIONS) \
    $(wildcard include/config/MODULES) \
    $(wildcard include/config/TRIM_UNUSED_KSYMS) \
  /build/linux/arch/x86/include/asm/linkage.h \
    $(wildcard include/config/CALL_PADDING) \
    $(wildcard include/config/RETHUNK) \
    $(wildcard include/config/SLS) \
    $(wildcard include/config/FUNCTION_PADDING_BYTES) \
  /build/linux/arch/x86/include/asm/ibt.h \
    $(wildcard include/config/X86_KERNEL_IBT) \
    $(wildcard include/config/X86_64) \
  /build/linux/include/linux/container_of.h \
  /build/linux/include/linux/bitops.h \
  /build/linux/include/linux/bits.h \
  /build/linux/include/vdso/bits.h \
  /build/linux/include/linux/typecheck.h \
  /build/linux/include/uapi/linux/kernel.h \
  /build/linux/include/uapi/linux/sysinfo.h \
  /build/linux/include/asm-generic/bitops/generic-non-atomic.h \
  /build/linux/arch/x86/include/asm/barrier.h \
  /build/linux/arch/x86/include/asm/alternative.h \
    $(wildcard include/config/CALL_THUNKS) \
  /build/linux/arch/x86/include/asm/asm.h \
    $(wildcard include/config/KPROBES) \
  /build/linux/arch/x86/include/asm/extable_fixup_types.h \
  /build/linux/arch/x86/include/asm/nops.h \
  /build/linux/include/asm-generic/barrier.h \
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
    $(wildcard include/config/X86_CMPXCHG64) \
    $(wildcard include/config/X86_P6_NOP) \
    $(wildcard include/config/MATOM) \
    $(wildcard include/config/PARAVIRT_XXL) \
  /build/linux/arch/x86/include/asm/disabled-features.h \
    $(wildcard include/config/X86_UMIP) \
    $(wildcard include/config/X86_INTEL_MEMORY_PROTECTION_KEYS) \
    $(wildcard include/config/X86_5LEVEL) \
    $(wildcard include/config/PAGE_TABLE_ISOLATION) \
    $(wildcard include/config/CPU_UNRET_ENTRY) \
    $(wildcard include/config/CALL_DEPTH_TRACKING) \
    $(wildcard include/config/INTEL_IOMMU_SVM) \
    $(wildcard include/config/X86_SGX) \
    $(wildcard include/config/XEN_PV) \
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
  /build/linux/include/linux/math.h \
  /build/linux/arch/x86/include/asm/div64.h \
  /build/linux/include/asm-generic/div64.h \
  /build/linux/include/linux/minmax.h \
  /build/linux/include/linux/panic.h \
    $(wildcard include/config/PANIC_TIMEOUT) \
  /build/linux/include/linux/printk.h \
    $(wildcard include/config/MESSAGE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_QUIET) \
    $(wildcard include/config/EARLY_PRINTK) \
    $(wildcard include/config/PRINTK) \
    $(wildcard include/config/PRINTK_INDEX) \
    $(wildcard include/config/DYNAMIC_DEBUG) \
    $(wildcard include/config/DYNAMIC_DEBUG_CORE) \
  /build/linux/include/linux/kern_levels.h \
  /build/linux/include/linux/ratelimit_types.h \
  /build/linux/include/uapi/linux/param.h \
  arch/x86/include/generated/uapi/asm/param.h \
  /build/linux/include/asm-generic/param.h \
    $(wildcard include/config/HZ) \
  /build/linux/include/uapi/asm-generic/param.h \
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
    $(wildcard include/config/HAVE_STATIC_CALL_INLINE) \
  /build/linux/include/linux/instruction_pointer.h \
  /build/linux/include/linux/netdevice.h \
    $(wildcard include/config/DCB) \
    $(wildcard include/config/HYPERV_NET) \
    $(wildcard include/config/WLAN) \
    $(wildcard include/config/AX25) \
    $(wildcard include/config/MAC80211_MESH) \
    $(wildcard include/config/NET_IPIP) \
    $(wildcard include/config/NET_IPGRE) \
    $(wildcard include/config/IPV6_SIT) \
    $(wildcard include/config/IPV6_TUNNEL) \
    $(wildcard include/config/RPS) \
    $(wildcard include/config/NETPOLL) \
    $(wildcard include/config/SYSFS) \
    $(wildcard include/config/XPS) \
    $(wildcard include/config/NUMA) \
    $(wildcard include/config/XDP_SOCKETS) \
    $(wildcard include/config/BQL) \
    $(wildcard include/config/SYSCTL) \
    $(wildcard include/config/RFS_ACCEL) \
    $(wildcard include/config/FCOE) \
    $(wildcard include/config/XFRM_OFFLOAD) \
    $(wildcard include/config/NET_POLL_CONTROLLER) \
    $(wildcard include/config/LIBFCOE) \
    $(wildcard include/config/WIRELESS_EXT) \
    $(wildcard include/config/NET_L3_MASTER_DEV) \
    $(wildcard include/config/IPV6) \
    $(wildcard include/config/TLS_DEVICE) \
    $(wildcard include/config/VLAN_8021Q) \
    $(wildcard include/config/NET_DSA) \
    $(wildcard include/config/TIPC) \
    $(wildcard include/config/ATALK) \
    $(wildcard include/config/CFG80211) \
    $(wildcard include/config/IEEE802154) \
    $(wildcard include/config/6LOWPAN) \
    $(wildcard include/config/MPLS_ROUTING) \
    $(wildcard include/config/MCTP) \
    $(wildcard include/config/NET_CLS_ACT) \
    $(wildcard include/config/NETFILTER_INGRESS) \
    $(wildcard include/config/NETFILTER_EGRESS) \
    $(wildcard include/config/NET_SCHED) \
    $(wildcard include/config/PCPU_DEV_REFCNT) \
    $(wildcard include/config/GARP) \
    $(wildcard include/config/MRP) \
    $(wildcard include/config/NET_DROP_MONITOR) \
    $(wildcard include/config/CGROUP_NET_PRIO) \
    $(wildcard include/config/MACSEC) \
    $(wildcard include/config/NET_FLOW_LIMIT) \
    $(wildcard include/config/NET_EGRESS) \
    $(wildcard include/config/NET_DEV_REFCNT_TRACKER) \
    $(wildcard include/config/ETHTOOL_NETLINK) \
    $(wildcard include/config/BUG) \
  /build/linux/include/linux/timer.h \
    $(wildcard include/config/DEBUG_OBJECTS_TIMERS) \
    $(wildcard include/config/HOTPLUG_CPU) \
  /build/linux/include/linux/list.h \
    $(wildcard include/config/DEBUG_LIST) \
  /build/linux/include/linux/poison.h \
    $(wildcard include/config/ILLEGAL_POINTER_VALUE) \
  /build/linux/include/linux/ktime.h \
  /build/linux/include/linux/time.h \
    $(wildcard include/config/POSIX_TIMERS) \
  /build/linux/include/linux/cache.h \
    $(wildcard include/config/ARCH_HAS_CACHE_LINE_SIZE) \
  /build/linux/arch/x86/include/asm/cache.h \
    $(wildcard include/config/X86_L1_CACHE_SHIFT) \
    $(wildcard include/config/X86_INTERNODE_CACHE_SHIFT) \
    $(wildcard include/config/X86_VSMP) \
  /build/linux/include/linux/math64.h \
    $(wildcard include/config/ARCH_SUPPORTS_INT128) \
  /build/linux/include/vdso/math64.h \
  /build/linux/include/linux/time64.h \
  /build/linux/include/vdso/time64.h \
  /build/linux/include/uapi/linux/time.h \
  /build/linux/include/uapi/linux/time_types.h \
  /build/linux/include/linux/time32.h \
  /build/linux/include/linux/timex.h \
  /build/linux/include/uapi/linux/timex.h \
  /build/linux/arch/x86/include/asm/timex.h \
    $(wildcard include/config/X86_TSC) \
  /build/linux/arch/x86/include/asm/processor.h \
    $(wildcard include/config/X86_VMX_FEATURE_NAMES) \
    $(wildcard include/config/X86_IOPL_IOPERM) \
    $(wildcard include/config/STACKPROTECTOR) \
    $(wildcard include/config/VM86) \
    $(wildcard include/config/X86_DEBUGCTLMSR) \
    $(wildcard include/config/CPU_SUP_AMD) \
    $(wildcard include/config/XEN) \
  /build/linux/arch/x86/include/asm/processor-flags.h \
  /build/linux/arch/x86/include/uapi/asm/processor-flags.h \
  /build/linux/include/linux/mem_encrypt.h \
    $(wildcard include/config/ARCH_HAS_MEM_ENCRYPT) \
    $(wildcard include/config/AMD_MEM_ENCRYPT) \
  /build/linux/arch/x86/include/asm/mem_encrypt.h \
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
  /build/linux/arch/x86/include/asm/page_types.h \
    $(wildcard include/config/PHYSICAL_START) \
    $(wildcard include/config/PHYSICAL_ALIGN) \
    $(wildcard include/config/DYNAMIC_PHYSICAL_MASK) \
  /build/linux/arch/x86/include/asm/page_64_types.h \
    $(wildcard include/config/KASAN) \
    $(wildcard include/config/DYNAMIC_MEMORY_LAYOUT) \
    $(wildcard include/config/RANDOMIZE_BASE) \
  /build/linux/arch/x86/include/asm/kaslr.h \
    $(wildcard include/config/RANDOMIZE_MEMORY) \
  /build/linux/arch/x86/include/uapi/asm/ptrace.h \
  /build/linux/arch/x86/include/uapi/asm/ptrace-abi.h \
  /build/linux/arch/x86/include/asm/proto.h \
  /build/linux/arch/x86/include/uapi/asm/ldt.h \
  /build/linux/arch/x86/include/uapi/asm/sigcontext.h \
  /build/linux/arch/x86/include/asm/current.h \
  /build/linux/arch/x86/include/asm/percpu.h \
    $(wildcard include/config/X86_64_SMP) \
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
    $(wildcard include/config/JUMP_LABEL) \
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
    $(wildcard include/config/TRACEPOINTS) \
  /build/linux/arch/x86/include/asm/msr-index.h \
  arch/x86/include/generated/uapi/asm/errno.h \
  /build/linux/include/uapi/asm-generic/errno.h \
  /build/linux/include/uapi/asm-generic/errno-base.h \
  /build/linux/arch/x86/include/asm/cpumask.h \
  /build/linux/include/linux/cpumask.h \
    $(wildcard include/config/FORCE_NR_CPUS) \
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
    $(wildcard include/config/GENERIC_BUG) \
    $(wildcard include/config/BUG_ON_DATA_CORRUPTION) \
  /build/linux/arch/x86/include/asm/bug.h \
    $(wildcard include/config/DEBUG_BUGVERBOSE) \
  /build/linux/include/linux/instrumentation.h \
    $(wildcard include/config/NOINSTR_VALIDATION) \
  /build/linux/include/linux/objtool.h \
    $(wildcard include/config/FRAME_POINTER) \
  /build/linux/include/asm-generic/bug.h \
    $(wildcard include/config/GENERIC_BUG_RELATIVE_POINTERS) \
  /build/linux/include/linux/gfp_types.h \
    $(wildcard include/config/KASAN_HW_TAGS) \
  /build/linux/include/linux/numa.h \
    $(wildcard include/config/NODES_SHIFT) \
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
  /build/linux/include/linux/delay.h \
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
    $(wildcard include/config/PREEMPT_RCU) \
    $(wildcard include/config/TASKS_RCU) \
    $(wildcard include/config/TASKS_TRACE_RCU) \
    $(wildcard include/config/MEMCG) \
    $(wildcard include/config/LRU_GEN) \
    $(wildcard include/config/COMPAT_BRK) \
    $(wildcard include/config/CGROUPS) \
    $(wildcard include/config/BLK_CGROUP) \
    $(wildcard include/config/PSI) \
    $(wildcard include/config/PAGE_OWNER) \
    $(wildcard include/config/EVENTFD) \
    $(wildcard include/config/IOMMU_SVA) \
    $(wildcard include/config/CPU_SUP_INTEL) \
    $(wildcard include/config/TASK_DELAY_ACCT) \
    $(wildcard include/config/ARCH_HAS_SCALED_CPUTIME) \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING_GEN) \
    $(wildcard include/config/NO_HZ_FULL) \
    $(wildcard include/config/POSIX_CPUTIMERS) \
    $(wildcard include/config/POSIX_CPU_TIMERS_TASK_WORK) \
    $(wildcard include/config/KEYS) \
    $(wildcard include/config/SYSVIPC) \
    $(wildcard include/config/DETECT_HUNG_TASK) \
    $(wildcard include/config/IO_URING) \
    $(wildcard include/config/AUDIT) \
    $(wildcard include/config/AUDITSYSCALL) \
    $(wildcard include/config/DEBUG_MUTEXES) \
    $(wildcard include/config/UBSAN) \
    $(wildcard include/config/UBSAN_TRAP) \
    $(wildcard include/config/COMPACTION) \
    $(wildcard include/config/TASK_XACCT) \
    $(wildcard include/config/CPUSETS) \
    $(wildcard include/config/X86_CPU_RESCTRL) \
    $(wildcard include/config/FUTEX) \
    $(wildcard include/config/PERF_EVENTS) \
    $(wildcard include/config/NUMA_BALANCING) \
    $(wildcard include/config/RSEQ) \
    $(wildcard include/config/SCHED_MM_CID) \
    $(wildcard include/config/FAULT_INJECTION) \
    $(wildcard include/config/LATENCYTOP) \
    $(wildcard include/config/KUNIT) \
    $(wildcard include/config/FUNCTION_GRAPH_TRACER) \
    $(wildcard include/config/UPROBES) \
    $(wildcard include/config/BCACHE) \
    $(wildcard include/config/VMAP_STACK) \
    $(wildcard include/config/LIVEPATCH) \
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
  /build/linux/include/linux/rcupdate.h \
    $(wildcard include/config/TINY_RCU) \
    $(wildcard include/config/RCU_STRICT_GRACE_PERIOD) \
    $(wildcard include/config/RCU_LAZY) \
    $(wildcard include/config/TASKS_RCU_GENERIC) \
    $(wildcard include/config/RCU_STALL_COMMON) \
    $(wildcard include/config/KVM_XFER_TO_GUEST_WORK) \
    $(wildcard include/config/RCU_NOCB_CPU) \
    $(wildcard include/config/TASKS_RUDE_RCU) \
    $(wildcard include/config/TREE_RCU) \
    $(wildcard include/config/DEBUG_OBJECTS_RCU_HEAD) \
    $(wildcard include/config/PROVE_RCU) \
    $(wildcard include/config/ARCH_WEAK_RELEASE_ACQUIRE) \
  /build/linux/include/linux/context_tracking_irq.h \
    $(wildcard include/config/CONTEXT_TRACKING_IDLE) \
  /build/linux/include/linux/rcutree.h \
  /build/linux/include/linux/wait.h \
  /build/linux/include/uapi/linux/wait.h \
  /build/linux/include/linux/refcount.h \
  /build/linux/include/linux/sem.h \
  /build/linux/include/uapi/linux/sem.h \
  /build/linux/include/linux/ipc.h \
  /build/linux/include/linux/uidgid.h \
    $(wildcard include/config/MULTIUSER) \
    $(wildcard include/config/USER_NS) \
  /build/linux/include/linux/highuid.h \
  /build/linux/include/linux/rhashtable-types.h \
  /build/linux/include/linux/mutex.h \
    $(wildcard include/config/MUTEX_SPIN_ON_OWNER) \
  /build/linux/include/linux/osq_lock.h \
  /build/linux/include/linux/debug_locks.h \
  /build/linux/include/linux/workqueue.h \
    $(wildcard include/config/DEBUG_OBJECTS_WORK) \
    $(wildcard include/config/FREEZER) \
    $(wildcard include/config/WQ_WATCHDOG) \
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
  /build/linux/include/linux/rbtree.h \
  /build/linux/include/linux/rbtree_types.h \
  /build/linux/include/linux/percpu.h \
    $(wildcard include/config/NEED_PER_CPU_EMBED_FIRST_CHUNK) \
    $(wildcard include/config/NEED_PER_CPU_PAGE_FIRST_CHUNK) \
  /build/linux/include/linux/mmdebug.h \
    $(wildcard include/config/DEBUG_VM) \
    $(wildcard include/config/DEBUG_VM_IRQSOFF) \
    $(wildcard include/config/DEBUG_VM_PGFLAGS) \
  /build/linux/include/linux/seqlock.h \
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
  /build/linux/include/linux/nodemask.h \
    $(wildcard include/config/HIGHMEM) \
  /build/linux/include/linux/random.h \
    $(wildcard include/config/VMGENID) \
  /build/linux/include/uapi/linux/random.h \
  /build/linux/include/linux/irqnr.h \
  /build/linux/include/uapi/linux/irqnr.h \
  /build/linux/include/linux/prandom.h \
  /build/linux/include/linux/once.h \
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
  /build/linux/include/linux/mm_types_task.h \
    $(wildcard include/config/ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH) \
    $(wildcard include/config/SPLIT_PTLOCK_CPUS) \
    $(wildcard include/config/ARCH_ENABLE_SPLIT_PMD_PTLOCK) \
  /build/linux/arch/x86/include/asm/tlbbatch.h \
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
  /build/linux/arch/x86/include/asm/delay.h \
  /build/linux/include/asm-generic/delay.h \
  /build/linux/include/linux/prefetch.h \
  /build/linux/arch/x86/include/asm/local.h \
  /build/linux/include/linux/dynamic_queue_limits.h \
  /build/linux/include/net/net_namespace.h \
    $(wildcard include/config/NF_CONNTRACK) \
    $(wildcard include/config/NF_FLOW_TABLE) \
    $(wildcard include/config/UNIX) \
    $(wildcard include/config/IEEE802154_6LOWPAN) \
    $(wildcard include/config/IP_SCTP) \
    $(wildcard include/config/NETFILTER) \
    $(wildcard include/config/NF_TABLES) \
    $(wildcard include/config/WEXT_CORE) \
    $(wildcard include/config/XFRM) \
    $(wildcard include/config/IP_VS) \
    $(wildcard include/config/MPLS) \
    $(wildcard include/config/CAN) \
    $(wildcard include/config/CRYPTO_USER) \
    $(wildcard include/config/SMC) \
    $(wildcard include/config/NET_NS) \
    $(wildcard include/config/NET_NS_REFCNT_TRACKER) \
    $(wildcard include/config/NET) \
  /build/linux/include/linux/sysctl.h \
  /build/linux/include/uapi/linux/sysctl.h \
  /build/linux/include/net/flow.h \
  /build/linux/include/linux/in6.h \
  /build/linux/include/uapi/linux/in6.h \
  /build/linux/include/uapi/linux/libc-compat.h \
  /build/linux/include/net/netns/core.h \
  /build/linux/include/net/netns/mib.h \
    $(wildcard include/config/XFRM_STATISTICS) \
    $(wildcard include/config/TLS) \
    $(wildcard include/config/MPTCP) \
  /build/linux/include/net/snmp.h \
  /build/linux/include/uapi/linux/snmp.h \
  /build/linux/include/linux/u64_stats_sync.h \
  arch/x86/include/generated/asm/local64.h \
  /build/linux/include/asm-generic/local64.h \
  /build/linux/include/net/netns/unix.h \
  /build/linux/include/net/netns/packet.h \
  /build/linux/include/net/netns/ipv4.h \
    $(wildcard include/config/IP_MULTIPLE_TABLES) \
    $(wildcard include/config/IP_ROUTE_CLASSID) \
    $(wildcard include/config/IP_MROUTE) \
    $(wildcard include/config/IP_MROUTE_MULTIPLE_TABLES) \
    $(wildcard include/config/IP_ROUTE_MULTIPATH) \
  /build/linux/include/net/inet_frag.h \
  /build/linux/include/linux/completion.h \
  /build/linux/include/linux/swait.h \
  /build/linux/include/net/dropreason.h \
  /build/linux/include/linux/siphash.h \
    $(wildcard include/config/HAVE_EFFICIENT_UNALIGNED_ACCESS) \
  /build/linux/include/net/netns/ipv6.h \
    $(wildcard include/config/IPV6_MULTIPLE_TABLES) \
    $(wildcard include/config/IPV6_SUBTREES) \
    $(wildcard include/config/IPV6_MROUTE) \
    $(wildcard include/config/IPV6_MROUTE_MULTIPLE_TABLES) \
    $(wildcard include/config/NF_DEFRAG_IPV6) \
  /build/linux/include/net/dst_ops.h \
  /build/linux/include/linux/percpu_counter.h \
  /build/linux/include/uapi/linux/icmpv6.h \
  /build/linux/include/net/netns/nexthop.h \
  /build/linux/include/linux/notifier.h \
    $(wildcard include/config/TREE_SRCU) \
  /build/linux/include/linux/rwsem.h \
    $(wildcard include/config/RWSEM_SPIN_ON_OWNER) \
    $(wildcard include/config/DEBUG_RWSEMS) \
  /build/linux/include/linux/srcu.h \
    $(wildcard include/config/TINY_SRCU) \
    $(wildcard include/config/NEED_SRCU_NMI_SAFE) \
  /build/linux/include/linux/rcu_segcblist.h \
  /build/linux/include/linux/srcutree.h \
  /build/linux/include/linux/rcu_node_tree.h \
    $(wildcard include/config/RCU_FANOUT) \
    $(wildcard include/config/RCU_FANOUT_LEAF) \
  /build/linux/include/net/netns/ieee802154_6lowpan.h \
  /build/linux/include/net/netns/sctp.h \
  /build/linux/include/net/netns/netfilter.h \
    $(wildcard include/config/NETFILTER_FAMILY_ARP) \
    $(wildcard include/config/NETFILTER_FAMILY_BRIDGE) \
    $(wildcard include/config/NF_DEFRAG_IPV4) \
  /build/linux/include/linux/netfilter_defs.h \
  /build/linux/include/uapi/linux/netfilter.h \
  /build/linux/include/linux/in.h \
  /build/linux/include/uapi/linux/in.h \
  /build/linux/include/linux/socket.h \
  arch/x86/include/generated/uapi/asm/socket.h \
  /build/linux/include/uapi/asm-generic/socket.h \
  arch/x86/include/generated/uapi/asm/sockios.h \
  /build/linux/include/uapi/asm-generic/sockios.h \
  /build/linux/include/uapi/linux/sockios.h \
  /build/linux/include/linux/uio.h \
    $(wildcard include/config/ARCH_HAS_COPY_MC) \
  /build/linux/include/linux/mm_types.h \
    $(wildcard include/config/HAVE_ALIGNED_STRUCT_PAGE) \
    $(wildcard include/config/USERFAULTFD) \
    $(wildcard include/config/ANON_VMA_NAME) \
    $(wildcard include/config/SWAP) \
    $(wildcard include/config/HAVE_ARCH_COMPAT_MMAP_BASES) \
    $(wildcard include/config/MEMBARRIER) \
    $(wildcard include/config/AIO) \
    $(wildcard include/config/MMU_NOTIFIER) \
    $(wildcard include/config/TRANSPARENT_HUGEPAGE) \
    $(wildcard include/config/HUGETLB_PAGE) \
    $(wildcard include/config/KSM) \
  /build/linux/include/linux/auxvec.h \
  /build/linux/include/uapi/linux/auxvec.h \
  /build/linux/arch/x86/include/uapi/asm/auxvec.h \
  /build/linux/include/linux/kref.h \
  /build/linux/include/linux/maple_tree.h \
    $(wildcard include/config/MAPLE_RCU_DISABLED) \
    $(wildcard include/config/DEBUG_MAPLE_TREE) \
  /build/linux/include/linux/uprobes.h \
  /build/linux/include/linux/page-flags-layout.h \
  include/generated/bounds.h \
  /build/linux/arch/x86/include/asm/mmu.h \
    $(wildcard include/config/MODIFY_LDT_SYSCALL) \
  /build/linux/include/uapi/linux/uio.h \
  /build/linux/include/uapi/linux/socket.h \
  /build/linux/include/net/netns/conntrack.h \
    $(wildcard include/config/NF_CT_PROTO_DCCP) \
    $(wildcard include/config/NF_CT_PROTO_SCTP) \
    $(wildcard include/config/NF_CT_PROTO_GRE) \
    $(wildcard include/config/NF_CONNTRACK_EVENTS) \
    $(wildcard include/config/NF_CONNTRACK_LABELS) \
  /build/linux/include/linux/list_nulls.h \
  /build/linux/include/linux/netfilter/nf_conntrack_tcp.h \
  /build/linux/include/uapi/linux/netfilter/nf_conntrack_tcp.h \
  /build/linux/include/net/netns/nftables.h \
  /build/linux/include/net/netns/xfrm.h \
  /build/linux/include/uapi/linux/xfrm.h \
  /build/linux/include/net/netns/mpls.h \
  /build/linux/include/net/netns/can.h \
  /build/linux/include/net/netns/xdp.h \
  /build/linux/include/net/netns/smc.h \
  /build/linux/include/net/netns/bpf.h \
  /build/linux/include/net/netns/mctp.h \
  /build/linux/include/net/net_trackers.h \
  /build/linux/include/linux/ref_tracker.h \
    $(wildcard include/config/REF_TRACKER) \
  /build/linux/include/linux/stackdepot.h \
    $(wildcard include/config/STACKDEPOT_ALWAYS_INIT) \
    $(wildcard include/config/STACKDEPOT) \
  /build/linux/include/linux/gfp.h \
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
    $(wildcard include/config/MEMORY_FAILURE) \
    $(wildcard include/config/PAGE_EXTENSION) \
    $(wildcard include/config/DEFERRED_STRUCT_PAGE_INIT) \
    $(wildcard include/config/HAVE_MEMORYLESS_NODES) \
    $(wildcard include/config/SPARSEMEM_EXTREME) \
    $(wildcard include/config/HAVE_ARCH_PFN_VALID) \
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
  /build/linux/include/linux/topology.h \
    $(wildcard include/config/USE_PERCPU_NUMA_NODE_ID) \
    $(wildcard include/config/SCHED_SMT) \
  /build/linux/include/linux/arch_topology.h \
    $(wildcard include/config/ACPI_CPPC_LIB) \
    $(wildcard include/config/GENERIC_ARCH_TOPOLOGY) \
  /build/linux/arch/x86/include/asm/topology.h \
    $(wildcard include/config/SCHED_MC_PRIO) \
  /build/linux/include/asm-generic/topology.h \
  /build/linux/include/linux/ns_common.h \
  /build/linux/include/linux/idr.h \
  /build/linux/include/linux/radix-tree.h \
  /build/linux/include/linux/xarray.h \
    $(wildcard include/config/XARRAY_MULTI) \
  /build/linux/include/linux/sched/mm.h \
    $(wildcard include/config/ARCH_HAS_MEMBARRIER_CALLBACKS) \
  /build/linux/include/linux/sync_core.h \
    $(wildcard include/config/ARCH_HAS_SYNC_CORE_BEFORE_USERMODE) \
  /build/linux/arch/x86/include/asm/sync_core.h \
  /build/linux/include/linux/ioasid.h \
    $(wildcard include/config/IOASID) \
  /build/linux/include/linux/skbuff.h \
    $(wildcard include/config/BRIDGE_NETFILTER) \
    $(wildcard include/config/NET_TC_SKB_EXT) \
    $(wildcard include/config/NET_SOCK_MSG) \
    $(wildcard include/config/SKB_EXTENSIONS) \
    $(wildcard include/config/IPV6_NDISC_NODETYPE) \
    $(wildcard include/config/NET_SWITCHDEV) \
    $(wildcard include/config/NET_REDIRECT) \
    $(wildcard include/config/NETFILTER_SKIP_EGRESS) \
    $(wildcard include/config/NET_RX_BUSY_POLL) \
    $(wildcard include/config/NETWORK_SECMARK) \
    $(wildcard include/config/DEBUG_NET) \
    $(wildcard include/config/PAGE_POOL) \
    $(wildcard include/config/NETWORK_PHY_TIMESTAMPING) \
    $(wildcard include/config/MCTP_FLOWS) \
    $(wildcard include/config/NETFILTER_XT_TARGET_TRACE) \
  /build/linux/include/linux/bvec.h \
  /build/linux/include/linux/highmem.h \
  /build/linux/include/linux/fs.h \
    $(wildcard include/config/READ_ONLY_THP_FOR_FS) \
    $(wildcard include/config/FS_POSIX_ACL) \
    $(wildcard include/config/CGROUP_WRITEBACK) \
    $(wildcard include/config/IMA) \
    $(wildcard include/config/FILE_LOCKING) \
    $(wildcard include/config/FSNOTIFY) \
    $(wildcard include/config/FS_ENCRYPTION) \
    $(wildcard include/config/FS_VERITY) \
    $(wildcard include/config/EPOLL) \
    $(wildcard include/config/UNICODE) \
    $(wildcard include/config/QUOTA) \
    $(wildcard include/config/FS_DAX) \
    $(wildcard include/config/BLOCK) \
  /build/linux/include/linux/wait_bit.h \
  /build/linux/include/linux/kdev_t.h \
  /build/linux/include/uapi/linux/kdev_t.h \
  /build/linux/include/linux/dcache.h \
  /build/linux/include/linux/rculist_bl.h \
  /build/linux/include/linux/list_bl.h \
  /build/linux/include/linux/bit_spinlock.h \
  /build/linux/include/linux/lockref.h \
    $(wildcard include/config/ARCH_USE_CMPXCHG_LOCKREF) \
  /build/linux/include/linux/stringhash.h \
    $(wildcard include/config/DCACHE_WORD_ACCESS) \
  /build/linux/include/linux/hash.h \
    $(wildcard include/config/HAVE_ARCH_HASH) \
  /build/linux/include/linux/path.h \
  /build/linux/include/linux/stat.h \
  /build/linux/arch/x86/include/uapi/asm/stat.h \
  /build/linux/include/uapi/linux/stat.h \
  /build/linux/include/linux/list_lru.h \
    $(wildcard include/config/MEMCG_KMEM) \
  /build/linux/include/linux/shrinker.h \
    $(wildcard include/config/SHRINKER_DEBUG) \
  /build/linux/include/linux/capability.h \
  /build/linux/include/uapi/linux/capability.h \
  /build/linux/include/linux/semaphore.h \
  /build/linux/include/linux/fcntl.h \
    $(wildcard include/config/ARCH_32BIT_OFF_T) \
  /build/linux/include/uapi/linux/fcntl.h \
  arch/x86/include/generated/uapi/asm/fcntl.h \
  /build/linux/include/uapi/asm-generic/fcntl.h \
  /build/linux/include/uapi/linux/openat2.h \
  /build/linux/include/linux/migrate_mode.h \
  /build/linux/include/linux/percpu-rwsem.h \
  /build/linux/include/linux/rcuwait.h \
  /build/linux/include/linux/sched/signal.h \
    $(wildcard include/config/SCHED_AUTOGROUP) \
    $(wildcard include/config/BSD_PROCESS_ACCT) \
    $(wildcard include/config/TASKSTATS) \
    $(wildcard include/config/STACK_GROWSUP) \
  /build/linux/include/linux/signal.h \
    $(wildcard include/config/DYNAMIC_SIGFRAME) \
  /build/linux/include/linux/sched/jobctl.h \
  /build/linux/include/linux/sched/task.h \
    $(wildcard include/config/HAVE_EXIT_THREAD) \
    $(wildcard include/config/ARCH_WANTS_DYNAMIC_TASK_STRUCT) \
    $(wildcard include/config/HAVE_ARCH_THREAD_STRUCT_WHITELIST) \
  /build/linux/include/linux/uaccess.h \
    $(wildcard include/config/ARCH_HAS_SUBPAGE_FAULTS) \
  /build/linux/include/linux/fault-inject-usercopy.h \
    $(wildcard include/config/FAULT_INJECTION_USERCOPY) \
  /build/linux/arch/x86/include/asm/uaccess.h \
    $(wildcard include/config/CC_HAS_ASM_GOTO_OUTPUT) \
    $(wildcard include/config/CC_HAS_ASM_GOTO_TIED_OUTPUT) \
    $(wildcard include/config/X86_INTEL_USERCOPY) \
  /build/linux/arch/x86/include/asm/smap.h \
  /build/linux/arch/x86/include/asm/extable.h \
    $(wildcard include/config/BPF_JIT) \
  /build/linux/include/asm-generic/access_ok.h \
    $(wildcard include/config/ALTERNATE_USER_ADDRESS_SPACE) \
  /build/linux/arch/x86/include/asm/uaccess_64.h \
  /build/linux/include/linux/cred.h \
    $(wildcard include/config/DEBUG_CREDENTIALS) \
  /build/linux/include/linux/key.h \
    $(wildcard include/config/KEY_NOTIFICATIONS) \
  /build/linux/include/linux/assoc_array.h \
    $(wildcard include/config/ASSOCIATIVE_ARRAY) \
  /build/linux/include/linux/sched/user.h \
    $(wildcard include/config/VFIO_PCI_ZDEV_KVM) \
    $(wildcard include/config/IOMMUFD) \
    $(wildcard include/config/WATCH_QUEUE) \
  /build/linux/include/linux/ratelimit.h \
  /build/linux/include/linux/rcu_sync.h \
  /build/linux/include/linux/delayed_call.h \
  /build/linux/include/linux/uuid.h \
  /build/linux/include/uapi/linux/uuid.h \
  /build/linux/include/linux/errseq.h \
  /build/linux/include/linux/ioprio.h \
  /build/linux/include/linux/sched/rt.h \
  /build/linux/include/linux/iocontext.h \
    $(wildcard include/config/BLK_ICQ) \
  /build/linux/include/uapi/linux/ioprio.h \
  /build/linux/include/linux/fs_types.h \
  /build/linux/include/linux/mount.h \
  /build/linux/include/linux/mnt_idmapping.h \
  /build/linux/include/linux/slab.h \
    $(wildcard include/config/DEBUG_SLAB) \
    $(wildcard include/config/FAILSLAB) \
    $(wildcard include/config/KFENCE) \
    $(wildcard include/config/SLUB_TINY) \
    $(wildcard include/config/SLAB) \
    $(wildcard include/config/SLUB) \
    $(wildcard include/config/SLOB) \
  /build/linux/include/linux/overflow.h \
  /build/linux/include/linux/percpu-refcount.h \
  /build/linux/include/linux/kasan.h \
    $(wildcard include/config/KASAN_STACK) \
    $(wildcard include/config/KASAN_VMALLOC) \
    $(wildcard include/config/KASAN_INLINE) \
  /build/linux/include/linux/kasan-enabled.h \
  /build/linux/include/uapi/linux/fs.h \
  /build/linux/include/linux/quota.h \
    $(wildcard include/config/QUOTA_NETLINK_INTERFACE) \
  /build/linux/include/uapi/linux/dqblk_xfs.h \
  /build/linux/include/linux/dqblk_v1.h \
  /build/linux/include/linux/dqblk_v2.h \
  /build/linux/include/linux/dqblk_qtree.h \
  /build/linux/include/linux/projid.h \
  /build/linux/include/uapi/linux/quota.h \
  /build/linux/include/linux/cacheflush.h \
  /build/linux/arch/x86/include/asm/cacheflush.h \
  /build/linux/include/linux/mm.h \
    $(wildcard include/config/HAVE_ARCH_MMAP_RND_BITS) \
    $(wildcard include/config/HAVE_ARCH_MMAP_RND_COMPAT_BITS) \
    $(wildcard include/config/ARCH_USES_HIGH_VMA_FLAGS) \
    $(wildcard include/config/ARCH_HAS_PKEYS) \
    $(wildcard include/config/PPC) \
    $(wildcard include/config/PARISC) \
    $(wildcard include/config/IA64) \
    $(wildcard include/config/SPARC64) \
    $(wildcard include/config/ARM64) \
    $(wildcard include/config/ARM64_MTE) \
    $(wildcard include/config/HAVE_ARCH_USERFAULTFD_MINOR) \
    $(wildcard include/config/SHMEM) \
    $(wildcard include/config/MIGRATION) \
    $(wildcard include/config/ARCH_HAS_PTE_SPECIAL) \
    $(wildcard include/config/ARCH_HAS_PTE_DEVMAP) \
    $(wildcard include/config/DEBUG_VM_RB) \
    $(wildcard include/config/PAGE_POISONING) \
    $(wildcard include/config/INIT_ON_ALLOC_DEFAULT_ON) \
    $(wildcard include/config/INIT_ON_FREE_DEFAULT_ON) \
    $(wildcard include/config/DEBUG_PAGEALLOC) \
    $(wildcard include/config/HUGETLBFS) \
    $(wildcard include/config/MAPPING_DIRTY_HELPERS) \
  /build/linux/include/linux/mmap_lock.h \
  /build/linux/include/linux/page_ext.h \
  /build/linux/include/linux/stacktrace.h \
    $(wildcard include/config/ARCH_STACKWALK) \
    $(wildcard include/config/STACKTRACE) \
    $(wildcard include/config/HAVE_RELIABLE_STACKTRACE) \
  /build/linux/include/linux/page_ref.h \
    $(wildcard include/config/DEBUG_PAGE_REF) \
  /build/linux/include/linux/sizes.h \
  /build/linux/include/linux/pgtable.h \
    $(wildcard include/config/HIGHPTE) \
    $(wildcard include/config/ARCH_HAS_NONLEAF_PMD_YOUNG) \
    $(wildcard include/config/GUP_GET_PXX_LOW_HIGH) \
    $(wildcard include/config/HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD) \
    $(wildcard include/config/HAVE_ARCH_SOFT_DIRTY) \
    $(wildcard include/config/ARCH_ENABLE_THP_MIGRATION) \
    $(wildcard include/config/HAVE_ARCH_HUGE_VMAP) \
    $(wildcard include/config/X86_ESPFIX64) \
  /build/linux/arch/x86/include/asm/pgtable.h \
    $(wildcard include/config/DEBUG_WX) \
    $(wildcard include/config/PAGE_TABLE_CHECK) \
  /build/linux/arch/x86/include/asm/x86_init.h \
  /build/linux/arch/x86/include/asm/pkru.h \
  /build/linux/arch/x86/include/asm/fpu/api.h \
    $(wildcard include/config/X86_DEBUG_FPU) \
  /build/linux/arch/x86/include/asm/coco.h \
  /build/linux/include/asm-generic/pgtable_uffd.h \
  /build/linux/include/linux/page_table_check.h \
  /build/linux/arch/x86/include/asm/pgtable_64.h \
  /build/linux/arch/x86/include/asm/fixmap.h \
    $(wildcard include/config/PROVIDE_OHCI1394_DMA_INIT) \
    $(wildcard include/config/X86_IO_APIC) \
    $(wildcard include/config/PCI_MMCONFIG) \
    $(wildcard include/config/ACPI_APEI_GHES) \
    $(wildcard include/config/INTEL_TXT) \
  /build/linux/arch/x86/include/asm/apicdef.h \
  /build/linux/arch/x86/include/uapi/asm/vsyscall.h \
  /build/linux/include/asm-generic/fixmap.h \
  /build/linux/arch/x86/include/asm/pgtable-invert.h \
  /build/linux/include/linux/memremap.h \
    $(wildcard include/config/DEVICE_PRIVATE) \
    $(wildcard include/config/PCI_P2PDMA) \
  /build/linux/include/linux/ioport.h \
  /build/linux/include/linux/huge_mm.h \
  /build/linux/include/linux/sched/coredump.h \
    $(wildcard include/config/CORE_DUMP_DEFAULT_ELF_HEADERS) \
  /build/linux/include/linux/vmstat.h \
    $(wildcard include/config/VM_EVENT_COUNTERS) \
    $(wildcard include/config/DEBUG_TLBFLUSH) \
  /build/linux/include/linux/vm_event_item.h \
    $(wildcard include/config/MEMORY_BALLOON) \
    $(wildcard include/config/BALLOON_COMPACTION) \
    $(wildcard include/config/ZSWAP) \
  /build/linux/include/asm-generic/cacheflush.h \
  /build/linux/include/linux/kmsan.h \
  /build/linux/include/linux/dma-direction.h \
  /build/linux/include/linux/hardirq.h \
  /build/linux/include/linux/context_tracking_state.h \
    $(wildcard include/config/CONTEXT_TRACKING_USER) \
    $(wildcard include/config/CONTEXT_TRACKING) \
  /build/linux/include/linux/ftrace_irq.h \
    $(wildcard include/config/HWLAT_TRACER) \
    $(wildcard include/config/OSNOISE_TRACER) \
  /build/linux/include/linux/vtime.h \
    $(wildcard include/config/VIRT_CPU_ACCOUNTING) \
    $(wildcard include/config/IRQ_TIME_ACCOUNTING) \
  /build/linux/arch/x86/include/asm/hardirq.h \
    $(wildcard include/config/KVM_INTEL) \
    $(wildcard include/config/HAVE_KVM) \
    $(wildcard include/config/X86_THERMAL_VECTOR) \
    $(wildcard include/config/X86_MCE_THRESHOLD) \
    $(wildcard include/config/X86_MCE_AMD) \
    $(wildcard include/config/X86_HV_CALLBACK_VECTOR) \
    $(wildcard include/config/HYPERV) \
  /build/linux/include/linux/highmem-internal.h \
  /build/linux/include/net/checksum.h \
  /build/linux/arch/x86/include/asm/checksum.h \
    $(wildcard include/config/GENERIC_CSUM) \
  /build/linux/arch/x86/include/asm/checksum_64.h \
  /build/linux/include/linux/dma-mapping.h \
    $(wildcard include/config/DMA_API_DEBUG) \
    $(wildcard include/config/HAS_DMA) \
    $(wildcard include/config/NEED_DMA_MAP_STATE) \
  /build/linux/include/linux/device.h \
    $(wildcard include/config/GENERIC_MSI_IRQ) \
    $(wildcard include/config/ENERGY_MODEL) \
    $(wildcard include/config/PINCTRL) \
    $(wildcard include/config/DMA_OPS) \
    $(wildcard include/config/DMA_DECLARE_COHERENT) \
    $(wildcard include/config/DMA_CMA) \
    $(wildcard include/config/SWIOTLB) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_DEVICE) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_CPU) \
    $(wildcard include/config/ARCH_HAS_SYNC_DMA_FOR_CPU_ALL) \
    $(wildcard include/config/DMA_OPS_BYPASS) \
    $(wildcard include/config/OF) \
    $(wildcard include/config/DEVTMPFS) \
    $(wildcard include/config/SYSFS_DEPRECATED) \
  /build/linux/include/linux/dev_printk.h \
  /build/linux/include/linux/energy_model.h \
  /build/linux/include/linux/kobject.h \
    $(wildcard include/config/UEVENT_HELPER) \
    $(wildcard include/config/DEBUG_KOBJECT_RELEASE) \
  /build/linux/include/linux/sysfs.h \
  /build/linux/include/linux/kernfs.h \
    $(wildcard include/config/KERNFS) \
  /build/linux/include/linux/kobject_ns.h \
  /build/linux/include/linux/sched/cpufreq.h \
    $(wildcard include/config/CPU_FREQ) \
  /build/linux/include/linux/sched/topology.h \
    $(wildcard include/config/SCHED_DEBUG) \
    $(wildcard include/config/SCHED_CLUSTER) \
    $(wildcard include/config/SCHED_MC) \
    $(wildcard include/config/CPU_FREQ_GOV_SCHEDUTIL) \
  /build/linux/include/linux/sched/idle.h \
  /build/linux/include/linux/sched/sd_flags.h \
  /build/linux/include/linux/klist.h \
  /build/linux/include/linux/pm.h \
    $(wildcard include/config/VT_CONSOLE_SLEEP) \
    $(wildcard include/config/CXL_SUSPEND) \
    $(wildcard include/config/PM) \
    $(wildcard include/config/PM_CLK) \
    $(wildcard include/config/PM_GENERIC_DOMAINS) \
  /build/linux/include/linux/device/bus.h \
    $(wildcard include/config/ACPI) \
  /build/linux/include/linux/device/class.h \
  /build/linux/include/linux/device/driver.h \
  /build/linux/include/linux/module.h \
    $(wildcard include/config/MODULES_TREE_LOOKUP) \
    $(wildcard include/config/STACKTRACE_BUILD_ID) \
    $(wildcard include/config/ARCH_USES_CFI_TRAPS) \
    $(wildcard include/config/MODULE_SIG) \
    $(wildcard include/config/ARCH_WANTS_MODULES_DATA_IN_VMALLOC) \
    $(wildcard include/config/KALLSYMS) \
    $(wildcard include/config/BPF_EVENTS) \
    $(wildcard include/config/DEBUG_INFO_BTF_MODULES) \
    $(wildcard include/config/EVENT_TRACING) \
    $(wildcard include/config/MODULE_UNLOAD) \
    $(wildcard include/config/CONSTRUCTORS) \
    $(wildcard include/config/FUNCTION_ERROR_INJECTION) \
  /build/linux/include/linux/buildid.h \
    $(wildcard include/config/CRASH_CORE) \
  /build/linux/include/linux/kmod.h \
  /build/linux/include/linux/umh.h \
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
  /build/linux/include/linux/moduleparam.h \
    $(wildcard include/config/ALPHA) \
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
  /build/linux/arch/x86/include/asm/device.h \
  /build/linux/include/linux/pm_wakeup.h \
  /build/linux/include/linux/scatterlist.h \
    $(wildcard include/config/NEED_SG_DMA_LENGTH) \
    $(wildcard include/config/DEBUG_SG) \
    $(wildcard include/config/SGL_ALLOC) \
    $(wildcard include/config/ARCH_NO_SG_CHAIN) \
    $(wildcard include/config/SG_POOL) \
  /build/linux/arch/x86/include/asm/io.h \
    $(wildcard include/config/MTRR) \
    $(wildcard include/config/X86_PAT) \
  arch/x86/include/generated/asm/early_ioremap.h \
  /build/linux/include/asm-generic/early_ioremap.h \
    $(wildcard include/config/GENERIC_EARLY_IOREMAP) \
  /build/linux/arch/x86/include/asm/shared/io.h \
  /build/linux/include/asm-generic/iomap.h \
    $(wildcard include/config/HAS_IOPORT_MAP) \
  /build/linux/include/asm-generic/pci_iomap.h \
    $(wildcard include/config/PCI) \
    $(wildcard include/config/NO_GENERIC_PCI_IOPORT_MAP) \
    $(wildcard include/config/GENERIC_PCI_IOMAP) \
  /build/linux/include/asm-generic/io.h \
    $(wildcard include/config/GENERIC_IOMAP) \
    $(wildcard include/config/TRACE_MMIO_ACCESS) \
    $(wildcard include/config/GENERIC_IOREMAP) \
  /build/linux/include/linux/logic_pio.h \
    $(wildcard include/config/INDIRECT_PIO) \
  /build/linux/include/linux/fwnode.h \
  /build/linux/include/linux/vmalloc.h \
    $(wildcard include/config/HAVE_ARCH_HUGE_VMALLOC) \
  /build/linux/arch/x86/include/asm/vmalloc.h \
  /build/linux/arch/x86/include/asm/pgtable_areas.h \
  /build/linux/include/linux/netdev_features.h \
  /build/linux/include/net/flow_dissector.h \
  /build/linux/include/uapi/linux/if_ether.h \
  /build/linux/include/uapi/linux/if_packet.h \
  /build/linux/include/net/page_pool.h \
    $(wildcard include/config/PAGE_POOL_STATS) \
  /build/linux/include/linux/ptr_ring.h \
  /build/linux/include/linux/netfilter/nf_conntrack_common.h \
  /build/linux/include/uapi/linux/netfilter/nf_conntrack_common.h \
  /build/linux/include/net/net_debug.h \
  /build/linux/include/linux/seq_file_net.h \
  /build/linux/include/linux/seq_file.h \
  /build/linux/include/linux/string_helpers.h \
  /build/linux/include/linux/ctype.h \
  /build/linux/include/linux/nsproxy.h \
  /build/linux/include/net/netprio_cgroup.h \
  /build/linux/include/linux/cgroup.h \
    $(wildcard include/config/DEBUG_CGROUP_REF) \
    $(wildcard include/config/CGROUP_CPUACCT) \
    $(wildcard include/config/SOCK_CGROUP_DATA) \
    $(wildcard include/config/CGROUP_DATA) \
    $(wildcard include/config/CGROUP_BPF) \
  /build/linux/include/uapi/linux/cgroupstats.h \
  /build/linux/include/uapi/linux/taskstats.h \
  /build/linux/include/linux/user_namespace.h \
    $(wildcard include/config/INOTIFY_USER) \
    $(wildcard include/config/FANOTIFY) \
    $(wildcard include/config/PERSISTENT_KEYRINGS) \
  /build/linux/include/linux/kernel_stat.h \
  /build/linux/include/linux/interrupt.h \
    $(wildcard include/config/IRQ_FORCED_THREADING) \
    $(wildcard include/config/GENERIC_IRQ_PROBE) \
    $(wildcard include/config/IRQ_TIMINGS) \
  /build/linux/include/linux/irqreturn.h \
  /build/linux/arch/x86/include/asm/irq.h \
  /build/linux/arch/x86/include/asm/irq_vectors.h \
    $(wildcard include/config/PCI_MSI) \
  /build/linux/arch/x86/include/asm/sections.h \
  /build/linux/include/asm-generic/sections.h \
    $(wildcard include/config/HAVE_FUNCTION_DESCRIPTORS) \
  /build/linux/include/linux/cgroup-defs.h \
    $(wildcard include/config/CGROUP_NET_CLASSID) \
  /build/linux/include/linux/bpf-cgroup-defs.h \
    $(wildcard include/config/BPF_LSM) \
  /build/linux/include/linux/psi_types.h \
  /build/linux/include/linux/kthread.h \
  /build/linux/include/net/xdp.h \
  /build/linux/include/uapi/linux/netdev.h \
  /build/linux/include/linux/bitfield.h \
  /build/linux/include/uapi/linux/neighbour.h \
  /build/linux/include/linux/netlink.h \
  /build/linux/include/net/scm.h \
    $(wildcard include/config/SECURITY_NETWORK) \
  /build/linux/include/linux/net.h \
  /build/linux/include/linux/sockptr.h \
  /build/linux/include/uapi/linux/net.h \
  /build/linux/include/linux/security.h \
    $(wildcard include/config/SECURITY_INFINIBAND) \
    $(wildcard include/config/SECURITY_NETWORK_XFRM) \
    $(wildcard include/config/SECURITY_PATH) \
    $(wildcard include/config/SECURITYFS) \
  /build/linux/include/linux/kernel_read_file.h \
  /build/linux/include/linux/file.h \
  /build/linux/include/uapi/linux/netlink.h \
  /build/linux/include/uapi/linux/netdevice.h \
  /build/linux/include/uapi/linux/if.h \
  /build/linux/include/uapi/linux/hdlc/ioctl.h \
  /build/linux/include/linux/if_ether.h \
  /build/linux/include/linux/if_link.h \
  /build/linux/include/uapi/linux/if_link.h \
  /build/linux/include/uapi/linux/if_bonding.h \
  /build/linux/include/uapi/linux/pkt_cls.h \
  /build/linux/include/uapi/linux/pkt_sched.h \
  /build/linux/include/linux/hashtable.h \
  /build/linux/include/linux/etherdevice.h \
  /build/linux/include/linux/crc32.h \
  /build/linux/include/linux/bitrev.h \
    $(wildcard include/config/HAVE_ARCH_BITREVERSE) \
  arch/x86/include/generated/asm/unaligned.h \
  /build/linux/include/asm-generic/unaligned.h \
  /build/linux/include/linux/unaligned/packed_struct.h \
  /build/linux/include/linux/inetdevice.h \
    $(wildcard include/config/INET) \
  /build/linux/include/linux/ip.h \
  /build/linux/include/uapi/linux/ip.h \
  /build/linux/include/linux/rtnetlink.h \
    $(wildcard include/config/NET_INGRESS) \
  /build/linux/include/uapi/linux/rtnetlink.h \
  /build/linux/include/uapi/linux/if_addr.h \
  /build/linux/include/net/ip.h \
  /build/linux/include/linux/jhash.h \
  /build/linux/include/net/inet_sock.h \
  /build/linux/include/net/sock.h \
    $(wildcard include/config/SOCK_RX_QUEUE_MAPPING) \
    $(wildcard include/config/SOCK_VALIDATE_XMIT) \
  /build/linux/include/linux/page_counter.h \
  /build/linux/include/linux/memcontrol.h \
  /build/linux/include/linux/vmpressure.h \
  /build/linux/include/linux/eventfd.h \
  /build/linux/include/linux/writeback.h \
  /build/linux/include/linux/flex_proportions.h \
  /build/linux/include/linux/backing-dev-defs.h \
    $(wildcard include/config/DEBUG_FS) \
  /build/linux/include/linux/blk_types.h \
    $(wildcard include/config/FAIL_MAKE_REQUEST) \
    $(wildcard include/config/BLK_CGROUP_IOCOST) \
    $(wildcard include/config/BLK_INLINE_ENCRYPTION) \
    $(wildcard include/config/BLK_DEV_INTEGRITY) \
  /build/linux/include/linux/rculist_nulls.h \
  /build/linux/include/linux/poll.h \
  /build/linux/include/uapi/linux/poll.h \
  arch/x86/include/generated/uapi/asm/poll.h \
  /build/linux/include/uapi/asm-generic/poll.h \
  /build/linux/include/uapi/linux/eventpoll.h \
  /build/linux/include/linux/indirect_call_wrapper.h \
  /build/linux/include/net/dst.h \
  /build/linux/include/net/neighbour.h \
  /build/linux/include/net/rtnetlink.h \
  /build/linux/include/net/netlink.h \
  /build/linux/include/net/tcp_states.h \
  /build/linux/include/uapi/linux/net_tstamp.h \
  /build/linux/include/net/l3mdev.h \
  /build/linux/include/net/fib_rules.h \
  /build/linux/include/uapi/linux/fib_rules.h \
  /build/linux/include/net/fib_notifier.h \
  /build/linux/include/net/request_sock.h \
  /build/linux/include/net/netns/hash.h \
  /build/linux/include/net/route.h \
  /build/linux/include/net/inetpeer.h \
  /build/linux/include/net/ipv6.h \
  /build/linux/include/linux/ipv6.h \
    $(wildcard include/config/IPV6_ROUTER_PREF) \
    $(wildcard include/config/IPV6_ROUTE_INFO) \
    $(wildcard include/config/IPV6_OPTIMISTIC_DAD) \
    $(wildcard include/config/IPV6_SEG6_HMAC) \
    $(wildcard include/config/IPV6_MIP6) \
  /build/linux/include/uapi/linux/ipv6.h \
  /build/linux/include/linux/tcp.h \
    $(wildcard include/config/BPF) \
    $(wildcard include/config/TCP_MD5SIG) \
  /build/linux/include/linux/win_minmax.h \
  /build/linux/include/net/inet_connection_sock.h \
  /build/linux/include/net/inet_timewait_sock.h \
  /build/linux/include/net/timewait_sock.h \
  /build/linux/include/uapi/linux/tcp.h \
  /build/linux/include/linux/udp.h \
  /build/linux/include/uapi/linux/udp.h \
  /build/linux/include/linux/jump_label_ratelimit.h \
  /build/linux/include/net/if_inet6.h \
  /build/linux/include/net/inet_dscp.h \
  /build/linux/include/net/ip_fib.h \
  /build/linux/include/net/arp.h \
  /build/linux/include/linux/if_arp.h \
    $(wildcard include/config/FIREWIRE_NET) \
  /build/linux/include/uapi/linux/if_arp.h \
  /build/linux/include/net/ndisc.h \
  /build/linux/include/net/ipv6_stubs.h \
  /build/linux/include/linux/icmpv6.h \
    $(wildcard include/config/NF_NAT) \
  /build/linux/include/uapi/linux/in_route.h \
  /build/linux/include/uapi/linux/route.h \
  /build/linux/include/net/lwtunnel.h \
    $(wildcard include/config/LWTUNNEL) \
  /build/linux/include/uapi/linux/lwtunnel.h \
  /build/linux/include/net/inet_common.h \
  /build/linux/include/net/addrconf.h \

/build/xlan/xnic.o: $(deps_/build/xlan/xnic.o)

$(deps_/build/xlan/xnic.o):

/build/xlan/xnic.o: $(wildcard ./tools/objtool/objtool)
