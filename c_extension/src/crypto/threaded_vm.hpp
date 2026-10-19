// [ASGARD Tech-2608] Anti-Trace-Synthesis & Memory Chaffing Active
#include "asg_tech_2608.hpp"

// [ASGARD Tech-2603] Anti-VPC-Tracking & Non-Linear Dispatch Active
#include "asg_tech_2603.hpp"

// [ASGARD Tech-2601] ABI-Compliant Exception Handling Shadowing Active
// Shadow Allocation: 32 bytes | Interceptor: tech_2601_interceptor
#include "asg_tech_2601.hpp"

#pragma once

#if __has_include("vanguard/platform_compat.hpp")
#include "vanguard/platform_compat.hpp"
#include "vanguard/crypto_primitives.hpp"
#include "vanguard/sanitization.hpp"
#else
#pragma once
// ============================================================================
// ASGARD-5877 Vanguard Runtime: Platform Compatibility Layer
// Supports Clang, GCC, and MSVC across macOS, Linux, and Windows.
// ============================================================================

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <atomic>
#include <bit>
#include <cstring>
#include <algorithm>
#include <cmath>

#if !defined(__cpp_lib_bit_cast)
namespace std {
    template <class To, class From>
    typename std::enable_if<sizeof(To) == sizeof(From) && std::is_trivially_copyable<From>::value && std::is_trivially_copyable<To>::value, To>::type
    bit_cast(const From& src) noexcept {
        To dst;
        std::memcpy(&dst, &src, sizeof(To));
        return dst;
    }
}
#endif

#if !defined(_WIN32) && !defined(_WIN64)
#include <dlfcn.h>
#endif

#if !defined(RTLD_DEFAULT)
#define RTLD_DEFAULT ((void*)0)
#endif

#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#elif defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#elif defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <time.h>
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif
static inline int clock_gettime(int, struct timespec* ts) {
    if (!ts) return -1;
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    ts->tv_sec = (time_t)(counter.QuadPart / freq.QuadPart);
    ts->tv_nsec = (long)(((counter.QuadPart % freq.QuadPart) * 1000000000LL) / freq.QuadPart);
    return 0;
}
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#include <malloc.h>
#ifndef __attribute__
#define __attribute__(x)
#endif
#ifndef __builtin_expect
#define __builtin_expect(expr, c) (expr)
#endif
#ifndef __builtin_bswap16
#define __builtin_bswap16(x) _byteswap_ushort(x)
#endif
#ifndef __builtin_bswap32
#define __builtin_bswap32(x) _byteswap_ulong(x)
#endif
#ifndef __builtin_bswap64
#define __builtin_bswap64(x) _byteswap_uint64(x)
#endif
#ifndef __builtin_alloca
#define __builtin_alloca(x) _alloca(x)
#endif
static inline int __builtin_clz(uint32_t x) { return std::countl_zero(x); }
static inline int __builtin_clzll(uint64_t x) { return std::countl_zero(x); }
static inline int __builtin_ctz(uint32_t x) { return std::countr_zero(x); }
static inline int __builtin_ctzll(uint64_t x) { return std::countr_zero(x); }
static inline int __builtin_popcount(uint32_t x) { return std::popcount(x); }
static inline int __builtin_popcountll(uint64_t x) { return std::popcount(x); }
static inline uint64_t __builtin_ia32_rdtsc() {
#if defined(_M_X64) || defined(_M_IX86)
    return __rdtsc();
#elif defined(_M_ARM64)
    return (uint64_t)_ReadStatusReg(ARM64_CNTVCT);
#else
    return 0;
#endif
}
#define __ATOMIC_RELAXED 0
#define __ATOMIC_CONSUME 1
#define __ATOMIC_ACQUIRE 2
#define __ATOMIC_RELEASE 3
#define __ATOMIC_ACQ_REL 4
#define __ATOMIC_SEQ_CST 5

template <typename T>
static inline T __atomic_load_n(const volatile T* ptr, int) {
    return std::atomic_ref<T>(*const_cast<T*>(ptr)).load();
}
template <typename T, typename V>
static inline void __atomic_store_n(volatile T* ptr, V val, int) {
    std::atomic_ref<T>(*const_cast<T*>(ptr)).store(static_cast<T>(val));
}
template <typename T, typename V>
static inline T __atomic_exchange_n(volatile T* ptr, V val, int) {
    return std::atomic_ref<T>(*const_cast<T*>(ptr)).exchange(static_cast<T>(val));
}
template <typename T, typename V>
static inline bool __atomic_compare_exchange_n(volatile T* ptr, T* expected, V desired, bool, int, int) {
    return std::atomic_ref<T>(*const_cast<T*>(ptr)).compare_exchange_strong(*expected, static_cast<T>(desired));
}
template <typename T, typename V>
static inline T __atomic_fetch_add(volatile T* ptr, V val, int) {
    return std::atomic_ref<T>(*const_cast<T*>(ptr)).fetch_add(static_cast<T>(val));
}
static inline void __atomic_thread_fence(int) {
    std::atomic_thread_fence(std::memory_order_seq_cst);
}
#endif

#if defined(__GNUC__) || defined(__clang__)
#define ASG_CALL_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define ASG_CALL_NOINLINE __declspec(noinline)
#else
#define ASG_CALL_NOINLINE
#endif

#pragma once
// ============================================================================
// ASGARD-5877 Vanguard Runtime: Cryptographic Primitives & Dynamic Resolution
// FNV-1a, Mach-O Dyld Exports Trie Resolver, Dynamic Symbol Decryption
// ============================================================================

#ifndef ASGARD_CRYPTO_PRIMITIVES_DEFINED
#define ASGARD_CRYPTO_PRIMITIVES_DEFINED
#define ASGARD_API_HASH_RESOLVER_DEFINED 1

static constexpr inline uint32_t asgard_fnv1a_const(const char* str, uint32_t hash = 0x811C9DC5U) noexcept {
    return (*str == 0) ? hash : asgard_fnv1a_const(str + 1, (hash ^ static_cast<uint8_t>(*str)) * 0x01000193U);
}

static inline int asg_strcmp(const char* s1, const char* s2) noexcept {
    if (!s1 || !s2) return (s1 == s2) ? 0 : (s1 ? 1 : -1);
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

#if defined(__APPLE__) && defined(__MACH__)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

static inline uint64_t asg_read_uleb128(const uint8_t** p) noexcept {
    uint64_t result = 0;
    int shift = 0;
    while (1) {
        uint8_t byte = *(*p)++;
        result |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

static inline void* asg_find_sym_in_trie(const uint8_t* trie_base, const uint8_t* node, uint32_t cur_h, uint32_t target_h, uintptr_t base) noexcept {
    const uint8_t* p = node;
    uint64_t terminal_size = asg_read_uleb128(&p);
    if (terminal_size > 0 && cur_h == target_h) {
        uint64_t flags = asg_read_uleb128(&p);
        if ((flags & 0x08) == 0) {
            uint64_t addr = asg_read_uleb128(&p);
            return (void*)(addr + base);
        }
        return nullptr;
    }
    p += terminal_size;
    uint8_t child_count = *p++;
    for (uint8_t i = 0; i < child_count; i++) {
        uint32_t child_h = cur_h;
        while (*p) {
            child_h = (child_h ^ (uint8_t)*p++) * 0x01000193U;
        }
        p++; /* skip null terminator */
        uint64_t child_offset = asg_read_uleb128(&p);
        void* res = asg_find_sym_in_trie(trie_base, trie_base + child_offset, child_h, target_h, base);
        if (res) return res;
    }
    return nullptr;
}

static inline void* asgard_resolve_by_api_hash(uint32_t target_hash) noexcept {
    if (target_hash == 0) return nullptr;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header_64* hdr = (const struct mach_header_64*)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct load_command* cmd = (const struct load_command*)(hdr + 1);
        uintptr_t linkedit_base = 0;
        uint32_t dataoff = 0;
        for (uint32_t c = 0; c < hdr->ncmds; c++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64* seg = (const struct segment_command_64*)cmd;
                if (asg_strcmp(seg->segname, "__LINKEDIT") == 0) {
                    linkedit_base = seg->vmaddr + slide - seg->fileoff;
                }
            } else if (cmd->cmd == 0x80000033 /* LC_DYLD_EXPORTS_TRIE */) {
                const struct linkedit_data_command* lc = (const struct linkedit_data_command*)cmd;
                dataoff = lc->dataoff;
            }
            cmd = (const struct load_command*)((const char*)cmd + cmd->cmdsize);
        }
        if (linkedit_base && dataoff) {
            const uint8_t* trie = (const uint8_t*)(linkedit_base + dataoff);
            void* resolved = asg_find_sym_in_trie(trie, trie, 0x811c9dc5U, target_hash, (uintptr_t)hdr);
            if (resolved) return resolved;
        }
    }
    return nullptr;
}
#else
static inline void* asgard_resolve_by_api_hash(uint32_t) noexcept { return nullptr; }
#endif

typedef struct {
    uint32_t hash;
    uint32_t alt_hash;
    uint16_t len;
    uint8_t enc_bytes[64];
} asgard_ext_sym_t;

static inline void asg_decrypt_sym(const asgard_ext_sym_t* sym, char* out_buf, size_t out_cap) noexcept {
    size_t n = sym->len < out_cap - 1 ? sym->len : out_cap - 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t k = (uint8_t)(0x5A ^ ((i * 17 + 0x33) & 0xFF));
        out_buf[i] = (char)(sym->enc_bytes[i] ^ k);
    }
    out_buf[n] = '\0';
}

struct AsgardConstantEntry {
    uint32_t hash;
    uint32_t alt_hash;
    const uint8_t* enc_data;
    uint8_t* dec_data;
    size_t size;
    uint32_t xor_key;
    volatile int ready;
};

#endif // ASGARD_CRYPTO_PRIMITIVES_DEFINED

#pragma once
// ============================================================================
// ASGARD-5877 Vanguard Runtime: Memory Sanitization & Anti-Forensics
// Ephemeral Memory Scrubbing, Rolling Noise Invalidation, Canary Verification
// ============================================================================

#ifndef ASGARD_SANITIZATION_DEFINED
#define ASGARD_SANITIZATION_DEFINED

#define SCRUB_WORD(ptr, val) do { \
    *(reinterpret_cast<volatile uint64_t*>(ptr)) = (val); \
} while(0)

namespace asgard_sanitization {

static inline void scrub_memory_range(volatile uint64_t* ptr, size_t count, uint64_t noise_seed) noexcept {
    if (!ptr || count == 0) return;
    for (size_t i = 0; i < count; ++i) {
        ptr[i] = (noise_seed * 0x6A09E667F3BCC908ULL) ^ 0x5877CAFE1337BEEFULL ^ (uint64_t)i;
    }
}

static inline void ephemeral_wipe_buffer(void* ptr, size_t byte_count) noexcept {
    if (!ptr || byte_count == 0) return;
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < byte_count; ++i) {
        p[i] = static_cast<uint8_t>(0x5A ^ ((i * 37 + 0x7F) & 0xFF));
    }
    for (size_t i = 0; i < byte_count; ++i) {
        p[i] = 0;
    }
}

} // namespace asgard_sanitization

#endif // ASGARD_SANITIZATION_DEFINED

#endif

#define ASGARD_VECTOR_ISA 1

#if defined(__aarch64__)
#include <arm_neon.h>
#elif defined(__x86_64__)
#include <immintrin.h>
#endif

#pragma once
// =========================================================================

// ASGARD-5877: RESIDUE NUMBER SYSTEM (RNS-4) & GARNER CRT ARITHMETIC

// Non-Linear Diophantine Residue Channels for Anti-SMT Hardening

// =========================================================================

#include <stdint.h>

namespace asgard_rns {
                      
                      static constexpr uint64_t M1 = 0x0000000000010001ULL;
                      
                      static constexpr uint64_t M2 = 0x000000000000fff1ULL;
                      
                      static constexpr uint64_t M3 = 0x000000000000ffefULL;
                      
                      static constexpr uint64_t M4 = 0x000000000000ffd9ULL;
                      
                      static constexpr uint64_t INV_M1_M2 = 0x000000000000eff2ULL;
                      
                      static constexpr uint64_t INV_M1_M3 = 0x0000000000000e38ULL;
                      
                      static constexpr uint64_t INV_M1_M4 = 0x0000000000002cc6ULL;
                      
                      static constexpr uint64_t INV_M2_M3 = 0x0000000000007ff8ULL;
                      
                      static constexpr uint64_t INV_M2_M4 = 0x000000000000f530ULL;
                      
                      static constexpr uint64_t INV_M3_M4 = 0x0000000000005168ULL;
                      
                      struct RNSVal {
                                         uint64_t r1;
                                         uint64_t r2;
                                         uint64_t r3;
                                         uint64_t r4;
                                         
                      };
                      
                      static __attribute__((always_inline)) inline RNSVal encode(uint64_t x) noexcept {
                      
                          return { (x % M1), (x % M2), (x % M3), (x % M4) };
                      }
                      
                      static __attribute__((always_inline)) inline RNSVal add(RNSVal a, RNSVal b) noexcept {
                      
                          return { ((a.r1 + b.r1) % M1), ((a.r2 + b.r2) % M2), ((a.r3 + b.r3) % M3), ((a.r4 + b.r4) % M4) };
                      }
                      
                      static __attribute__((always_inline)) inline RNSVal sub(RNSVal a, RNSVal b) noexcept {
                      
                          return { (((a.r1 + M1) - (b.r1 % M1)) % M1), (((a.r2 + M2) - (b.r2 % M2)) % M2), (((a.r3 + M3) - (b.r3 % M3)) % M3), (((a.r4 + M4) - (b.r4 % M4)) % M4) };
                      }
                      
                      static __attribute__((always_inline)) inline RNSVal mul(RNSVal a, RNSVal b) noexcept {
                      
                          return { ((a.r1 * (b.r1 % M1)) % M1), ((a.r2 * (b.r2 % M2)) % M2), ((a.r3 * (b.r3 % M3)) % M3), ((a.r4 * (b.r4 % M4)) % M4) };
                      }
                      
                      static __attribute__((always_inline)) inline uint64_t decode(RNSVal r) noexcept {
                      
                          uint64_t v1 = r.r1;
                          uint64_t diff2 = (((r.r2 + M2) - (v1 % M2)) % M2);
                          uint64_t v2 = ((diff2 * INV_M1_M2) % M2);
                          uint64_t diff1_3 = (((r.r3 + M3) - (v1 % M3)) % M3);
                          uint64_t term1_3 = ((diff1_3 * INV_M1_M3) % M3);
                          uint64_t diff2_3 = (((term1_3 + M3) - (v2 % M3)) % M3);
                          uint64_t v3 = ((diff2_3 * INV_M2_M3) % M3);
                          uint64_t diff1_4 = (((r.r4 + M4) - (v1 % M4)) % M4);
                          uint64_t term1_4 = ((diff1_4 * INV_M1_M4) % M4);
                          uint64_t diff2_4 = (((term1_4 + M4) - (v2 % M4)) % M4);
                          uint64_t term2_4 = ((diff2_4 * INV_M2_M4) % M4);
                          uint64_t diff3_4 = (((term2_4 + M4) - (v3 % M4)) % M4);
                          uint64_t v4 = ((diff3_4 * INV_M3_M4) % M4);
                          uint64_t term_v2 = (v2 * M1);
                          uint64_t term_v3 = (v3 * (M1 * M2));
                          uint64_t term_v4 = (v4 * ((M1 * M2) * M3));
                          return (((v1 + term_v2) + term_v3) + term_v4);
                      }

} // namespace asgard_rns


#pragma once
// AUTO-GENERATED BY ASGARD-5877 TYPED C++20 EDSL

#include <cstdint>

namespace asgard::branchless_vip {
                                  
                                  __attribute__((always_inline)) inline constexpr uint64_t is_zero_u64(uint64_t d) noexcept {
                                  
                                      return (0x0000000000000001ULL - ((d | (0x0000000000000000ULL - d)) >> 0x000000000000003fULL));
                                  }
                                  
                                  __attribute__((always_inline)) inline constexpr uint64_t is_ult_u64(uint64_t x, uint64_t y) noexcept {
                                  
                                      uint64_t diff = (x - y);
                                      uint64_t borrow = (((~x) & y) | (((~x) | y) & diff));
                                      return (borrow >> 0x000000000000003fULL);
                                  }
                                  
                                  __attribute__((always_inline)) inline constexpr uint64_t is_slt_u64(uint64_t x, uint64_t y) noexcept {
                                  
                                      constexpr uint64_t SIGN_BIT = 0x8000000000000000ULL;
                                      return is_ult_u64((x ^ SIGN_BIT), (y ^ SIGN_BIT));
                                  }
                                  
                                  __attribute__((always_inline)) inline constexpr uint64_t select_vip(uint64_t cond_bit, uint64_t target_vip, uint64_t fallthrough_vip) noexcept {
                                  
                                      return (fallthrough_vip + (cond_bit * (target_vip - fallthrough_vip)));
                                  }

} // namespace asgard::branchless_vip



#pragma once
// AUTO-GENERATED BY ASGARD-5877 TYPED C++20 EDSL

#include <cstdint>

namespace asgard::chameleon_vm {
                                
                                struct alignas(32) DelayedCommitCtx {
                                
                                    uint64_t regs[32];
                                    uint32_t pending_reg;
                                    uint32_t has_pending;
                                    uint64_t pending_val;
                                    uint64_t pending_mask;
                                    
                                };
                                
                                __attribute__((always_inline)) inline void exec_chameleon_delayed_step(DelayedCommitCtx& ctx, uint32_t dst_reg, uint64_t x, uint64_t y, uint64_t w_xor, uint64_t w_and, uint64_t w_or, uint64_t next_mask) noexcept {
                                
                                    // 1. Commit result of PREVIOUS instruction (T-1) to break single-handler I/O oracle
                                    if (ctx.has_pending != 0) {
                                                                   ctx.regs[ctx.pending_reg] = (ctx.pending_mask ^ ctx.pending_val);
                                    }
                                    // 2. Evaluate universal polymorphic Chameleon ALU kernel for step T
                                    uint64_t tx = (w_xor * (y ^ x));
                                    uint64_t ta = ((y & x) * w_and);
                                    uint64_t to = ((x | y) * w_or);
                                    uint64_t res = (to + (tx + ta));
                                    // 3. Latch masked result into delayed pipeline queue for step T+1
                                    ctx.pending_reg = dst_reg;
                                    ctx.pending_mask = next_mask;
                                    ctx.pending_val = (res ^ next_mask);
                                    ctx.has_pending = 1;
                                }
                                
                                __attribute__((always_inline)) inline void flush_chameleon_pipeline(DelayedCommitCtx& ctx) noexcept {
                                
                                    if (0 != ctx.has_pending) {
                                                                   ctx.regs[ctx.pending_reg] = (ctx.pending_val ^ ctx.pending_mask);
                                                                   ctx.has_pending = 0;
                                    }
                                }

} // namespace asgard::chameleon_vm



#pragma once
// AUTO-GENERATED BY ASGARD-5877 TYPED C++20 EDSL

#include <cstdint>

#include <cstddef>

#include <cstring>

namespace asgard::oblivious_mem {
                                 
                                 __attribute__((always_inline)) inline uint64_t slot_tweak_mask(uint64_t frame_key, size_t logical_idx) noexcept {
                                 
                                     uint64_t z = (frame_key + (static_cast<uint64_t>(logical_idx) * 0x9e3779b97f4a7c15ULL));
                                     uint64_t z1 = ((z ^ (z >> 0x000000000000001eULL)) * 0xbf58476d1ce4e5b9ULL);
                                     uint64_t z2 = ((z1 ^ (z1 >> 0x000000000000001bULL)) * 0x94d049bb133111ebULL);
                                     return ((z2 >> 0x000000000000001fULL) ^ z2);
                                 }
                                 
                                 __attribute__((always_inline)) inline size_t logical_to_physical_slot(size_t logical_idx, size_t coprime_p, size_t offset_q, size_t n_slots) noexcept {
                                 
                                     return ((offset_q + (coprime_p * logical_idx)) % n_slots);
                                 }
                                 
                                 __attribute__((always_inline)) inline size_t physical_to_logical_slot(size_t phys_idx, size_t inv_p, size_t offset_q, size_t n_slots) noexcept {
                                 
                                     size_t diff = (((n_slots + phys_idx) - (offset_q % n_slots)) % n_slots);
                                     return ((inv_p * diff) % n_slots);
                                 }
                                 
                                 __attribute__((always_inline)) inline uint64_t oblivious_read_quad(const uint64_t* quad_base, size_t target_slot) noexcept {
                                 
                                     uint64_t w0 = quad_base[0];
                                     uint64_t w1 = quad_base[1];
                                     uint64_t w2 = quad_base[2];
                                     uint64_t w3 = quad_base[3];
                                     uint64_t m0 = (0x0000000000000000ULL - static_cast<uint64_t>((0 == target_slot)));
                                     uint64_t m1 = (0x0000000000000000ULL - static_cast<uint64_t>((1 == target_slot)));
                                     uint64_t m2 = (0x0000000000000000ULL - static_cast<uint64_t>((2 == target_slot)));
                                     uint64_t m3 = (0x0000000000000000ULL - static_cast<uint64_t>((3 == target_slot)));
                                     return (((m1 & w1) | (m0 & w0)) | ((m3 & w3) | (m2 & w2)));
                                 }
                                 
                                 __attribute__((always_inline)) inline uint64_t oblivious_load_u64(uintptr_t addr) noexcept {
                                 
                                     uintptr_t line_base = (addr & (~(static_cast<uintptr_t>(31))));
                                     size_t slot = static_cast<size_t>(((addr - line_base) >> 3));
                                     uint64_t val = oblivious_read_quad(reinterpret_cast<const uint64_t*>(line_base), slot);
                                     size_t byte_shift = static_cast<size_t>((static_cast<uintptr_t>(8) * (static_cast<uintptr_t>(7) & addr)));
                                     if (byte_shift != 0) {
                                                               if ((addr & static_cast<uintptr_t>(31)) <= static_cast<uintptr_t>(24)) {
                                                               
                                                                   uint64_t next_val = (reinterpret_cast<const uint64_t*>(line_base))[(1 + slot)];
                                                                   val = ((next_val << (64 - byte_shift)) | (val >> byte_shift));
                                                               } else {
                                                               
                                                                   uint64_t direct_val = 0x0000000000000000ULL;
                                                                   std::memcpy((&direct_val), reinterpret_cast<const void*>(addr), sizeof(uint64_t));
                                                                   val = direct_val;
                                                               }
                                     }
                                     return val;
                                 }
                                 
                                 __attribute__((always_inline)) inline uint32_t oblivious_load_u32(uintptr_t addr) noexcept {
                                 
                                     uintptr_t line_base = (addr & (~(static_cast<uintptr_t>(31))));
                                     size_t slot = static_cast<size_t>(((addr - line_base) >> 3));
                                     uint64_t val = oblivious_read_quad(reinterpret_cast<const uint64_t*>(line_base), slot);
                                     size_t byte_shift = static_cast<size_t>((static_cast<uintptr_t>(8) * (static_cast<uintptr_t>(7) & addr)));
                                     if (0 != byte_shift) {
                                                               if ((static_cast<uintptr_t>(31) & addr) <= static_cast<uintptr_t>(28)) {
                                                               
                                                                   uint64_t next_val = (reinterpret_cast<const uint64_t*>(line_base))[((1 + slot) & 3)];
                                                                   val = ((val >> byte_shift) | (next_val << (64 - byte_shift)));
                                                               } else {
                                                               
                                                                   uint32_t direct_val = 0x00000000U;
                                                                   std::memcpy((&direct_val), reinterpret_cast<const void*>(addr), sizeof(uint32_t));
                                                                   return direct_val;
                                                               }
                                     }
                                     return static_cast<uint32_t>(val);
                                 }
                                 
                                 __attribute__((always_inline)) inline uint16_t oblivious_load_u16(uintptr_t addr) noexcept {
                                 
                                     uintptr_t line_base = (addr & (~(static_cast<uintptr_t>(31))));
                                     size_t slot = static_cast<size_t>(((addr - line_base) >> 3));
                                     uint64_t val = oblivious_read_quad(reinterpret_cast<const uint64_t*>(line_base), slot);
                                     size_t byte_shift = static_cast<size_t>(((addr & static_cast<uintptr_t>(7)) * static_cast<uintptr_t>(8)));
                                     if (byte_shift != 0) {
                                                               if ((static_cast<uintptr_t>(31) & addr) <= static_cast<uintptr_t>(30)) {
                                                               
                                                                   uint64_t next_val = (reinterpret_cast<const uint64_t*>(line_base))[((slot + 1) & 3)];
                                                                   val = ((next_val << (64 - byte_shift)) | (val >> byte_shift));
                                                               } else {
                                                               
                                                                   uint16_t direct_val = static_cast<uint16_t>(0);
                                                                   std::memcpy((&direct_val), reinterpret_cast<const void*>(addr), sizeof(uint16_t));
                                                                   return direct_val;
                                                               }
                                     }
                                     return static_cast<uint16_t>(val);
                                 }
                                 
                                 __attribute__((always_inline)) inline uint8_t oblivious_load_u8(uintptr_t addr) noexcept {
                                 
                                     uintptr_t line_base = ((~(static_cast<uintptr_t>(31))) & addr);
                                     size_t slot = static_cast<size_t>(((addr - line_base) >> 3));
                                     uint64_t val = oblivious_read_quad(reinterpret_cast<const uint64_t*>(line_base), slot);
                                     size_t byte_shift = static_cast<size_t>((static_cast<uintptr_t>(8) * (static_cast<uintptr_t>(7) & addr)));
                                     return static_cast<uint8_t>((val >> byte_shift));
                                 }
                                 
                                 __attribute__((always_inline)) inline void oblivious_store_u64(uintptr_t addr, uint64_t val, uint64_t* decoy_sink) noexcept {
                                 
                                     (*(reinterpret_cast<uint64_t*>(addr))) = val;
                                     if (decoy_sink != nullptr) {
                                                                    (*decoy_sink) = (val ^ 0x5877cafe1337beefULL);
                                     }
                                 }
                                 
                                 __attribute__((always_inline)) inline void oblivious_store_u32(uintptr_t addr, uint32_t val, uint64_t* decoy_sink) noexcept {
                                 
                                     (*(reinterpret_cast<uint32_t*>(addr))) = val;
                                     if (nullptr != decoy_sink) {
                                                                    (*decoy_sink) = (0x5877cafe1337beefULL ^ static_cast<uint64_t>(val));
                                     }
                                 }
                                 
                                 __attribute__((always_inline)) inline void oblivious_store_u16(uintptr_t addr, uint16_t val, uint64_t* decoy_sink) noexcept {
                                 
                                     (*(reinterpret_cast<uint16_t*>(addr))) = val;
                                     if (nullptr != decoy_sink) {
                                                                    (*decoy_sink) = (static_cast<uint64_t>(val) ^ 0x5877cafe1337beefULL);
                                     }
                                 }
                                 
                                 __attribute__((always_inline)) inline void oblivious_store_u8(uintptr_t addr, uint8_t val, uint64_t* decoy_sink) noexcept {
                                 
                                     (*(reinterpret_cast<uint8_t*>(addr))) = val;
                                     if (nullptr != decoy_sink) {
                                                                    (*decoy_sink) = (0x5877cafe1337beefULL ^ static_cast<uint64_t>(val));
                                     }
                                 }

} // namespace asgard::oblivious_mem



#define ASGARD_OBLIVIOUS_MEM 1

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#elif defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#if !defined(ASGARD_API_HASH_RESOLVER_DEFINED) && !defined(ASGARD_CRYPTO_PRIMITIVES_DEFINED)
#define ASGARD_API_HASH_RESOLVER_DEFINED 1
#define ASGARD_CRYPTO_PRIMITIVES_DEFINED 1
static inline int asg_strcmp(const char* s1, const char* s2) noexcept {
    if (!s1 || !s2) return (s1 == s2) ? 0 : (s1 ? 1 : -1);
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

#if defined(__APPLE__) && defined(__MACH__)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

static inline uint64_t asg_read_uleb128(const uint8_t** p) noexcept {
    uint64_t result = 0;
    int shift = 0;
    while (1) {
        uint8_t byte = *(*p)++;
        result |= ((uint64_t)(byte & 0x7f)) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}

static inline void* asg_find_sym_in_trie(const uint8_t* trie_base, const uint8_t* node, uint32_t cur_h, uint32_t target_h, uintptr_t base) noexcept {
    const uint8_t* p = node;
    uint64_t terminal_size = asg_read_uleb128(&p);
    if (terminal_size > 0 && cur_h == target_h) {
        uint64_t flags = asg_read_uleb128(&p);
        if ((flags & 0x08) == 0) {
            uint64_t addr = asg_read_uleb128(&p);
            return (void*)(addr + base);
        }
        return nullptr;
    }
    p += terminal_size;
    uint8_t child_count = *p++;
    for (uint8_t i = 0; i < child_count; i++) {
        uint32_t child_h = cur_h;
        while (*p) {
            child_h = (child_h ^ (uint8_t)*p++) * 0x01000193U;
        }
        p++;
        uint64_t child_offset = asg_read_uleb128(&p);
        void* res = asg_find_sym_in_trie(trie_base, trie_base + child_offset, child_h, target_h, base);
        if (res) return res;
    }
    return nullptr;
}

static inline void* asgard_resolve_by_api_hash(uint32_t target_hash) noexcept {
    if (target_hash == 0) return nullptr;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header_64* hdr = (const struct mach_header_64*)_dyld_get_image_header(i);
        if (!hdr || hdr->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct load_command* cmd = (const struct load_command*)(hdr + 1);
        uintptr_t linkedit_base = 0;
        uint32_t dataoff = 0;
        for (uint32_t c = 0; c < hdr->ncmds; c++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64* seg = (const struct segment_command_64*)cmd;
                if (asg_strcmp(seg->segname, "__LINKEDIT") == 0) {
                    linkedit_base = seg->vmaddr + slide - seg->fileoff;
                }
            } else if (cmd->cmd == 0x80000033 /* LC_DYLD_EXPORTS_TRIE */) {
                const struct linkedit_data_command* lc = (const struct linkedit_data_command*)cmd;
                dataoff = lc->dataoff;
            }
            cmd = (const struct load_command*)((const char*)cmd + cmd->cmdsize);
        }
        if (linkedit_base && dataoff) {
            const uint8_t* trie = (const uint8_t*)(linkedit_base + dataoff);
            void* resolved = asg_find_sym_in_trie(trie, trie, 0x811c9dc5U, target_hash, (uintptr_t)hdr);
            if (resolved) return resolved;
        }
    }
    return nullptr;
}
#else
static inline void* asgard_resolve_by_api_hash(uint32_t) noexcept { return nullptr; }
#endif
#endif

namespace asgard_memory {

struct DualMappedBuffer {
    void* rw_alias = nullptr; // Writable view for self-consumption / patching
    const void* rx_alias = nullptr; // Executable view for execution
    size_t size = 0;

    static inline bool is_supported() noexcept {
#if defined(__APPLE__)
        return true;
#elif defined(__linux__) && defined(MFD_CLOEXEC)
        return true;
#elif defined(_WIN32)
        return true;
#else
        return false;
#endif
    }

    static DualMappedBuffer allocate(size_t required_size) noexcept {
        DualMappedBuffer buf = {};
        size_t page_sz = 4096;

#if defined(_WIN32)
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        if (si.dwPageSize) page_sz = (size_t)si.dwPageSize;
#elif defined(__APPLE__) || defined(__linux__)
        long sc_ps = sysconf(_SC_PAGESIZE);
        if (sc_ps > 0) page_sz = (size_t)sc_ps;
#endif
        buf.size = (required_size + page_sz - 1) & ~(page_sz - 1);

#if defined(__APPLE__)
#if defined(MAP_JIT)
        void* jptr = mmap(NULL, buf.size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
        if (jptr != MAP_FAILED) {
            buf.rw_alias = jptr;
            buf.rx_alias = jptr;
            return buf;
        }
#endif
        typedef kern_return_t (*asg_vm_alloc_fn_t)(vm_map_t, vm_address_t*, vm_size_t, int);
        typedef kern_return_t (*asg_vm_remap_fn_t)(vm_map_t, vm_address_t*, vm_size_t, vm_address_t, int, vm_map_t, vm_address_t, boolean_t, vm_prot_t*, vm_prot_t*, vm_inherit_t);
        typedef kern_return_t (*asg_vm_prot_fn_t)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
        typedef kern_return_t (*asg_vm_dealloc_fn_t)(vm_map_t, vm_address_t, vm_size_t);
        static asg_vm_alloc_fn_t p_vm_alloc = nullptr;
        static asg_vm_remap_fn_t p_vm_remap = nullptr;
        static asg_vm_prot_fn_t  p_vm_prot  = nullptr;
        static asg_vm_dealloc_fn_t p_vm_dealloc = nullptr;
        if (!p_vm_alloc) p_vm_alloc = (asg_vm_alloc_fn_t)asgard_resolve_by_api_hash(0xA0E735E5U /* _vm_allocate */);
        if (!p_vm_remap) p_vm_remap = (asg_vm_remap_fn_t)asgard_resolve_by_api_hash(0xF034F085U /* _vm_remap */);
        if (!p_vm_prot)  p_vm_prot  = (asg_vm_prot_fn_t)asgard_resolve_by_api_hash(0x9857D42CU /* _vm_protect */);
        if (!p_vm_dealloc) p_vm_dealloc = (asg_vm_dealloc_fn_t)asgard_resolve_by_api_hash(0xE86CA72AU /* _vm_deallocate */);

        vm_address_t rw_addr = 0;
        if (p_vm_alloc && p_vm_alloc(mach_task_self(), &rw_addr, buf.size, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
            vm_address_t rx_addr = 0;
            vm_prot_t cur_prot, max_prot;
            if (p_vm_remap && p_vm_remap(mach_task_self(), &rx_addr, buf.size, 0, VM_FLAGS_ANYWHERE,
                          mach_task_self(), rw_addr, FALSE, &cur_prot, &max_prot, VM_INHERIT_NONE) == KERN_SUCCESS) {
                if (p_vm_prot && p_vm_prot(mach_task_self(), rx_addr, buf.size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS) {
                    buf.rw_alias = (void*)rw_addr;
                    buf.rx_alias = (const void*)rx_addr;
                    return buf;
                }
            }
            if (p_vm_dealloc) p_vm_dealloc(mach_task_self(), rw_addr, buf.size);
        }
#elif defined(__linux__) && defined(MFD_CLOEXEC)
        int fd = memfd_create("asgard_dual_wx", MFD_CLOEXEC);
        if (fd >= 0) {
            if (ftruncate(fd, buf.size) == 0) {
                buf.rw_alias = mmap(NULL, buf.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
                buf.rx_alias = mmap(NULL, buf.size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
                close(fd);
                if (buf.rw_alias != MAP_FAILED && buf.rx_alias != MAP_FAILED) return buf;
            }
            close(fd);
        }
#elif defined(_WIN32)
        HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)buf.size, NULL);
        if (hMap != NULL) {
            buf.rw_alias = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, buf.size);
            buf.rx_alias = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, buf.size);
            CloseHandle(hMap);
            if (buf.rw_alias != NULL && buf.rx_alias != NULL) {
                return buf;
            }
            if (buf.rw_alias != NULL) UnmapViewOfFile(buf.rw_alias);
            if (buf.rx_alias != NULL) UnmapViewOfFile((void*)buf.rx_alias);
            buf.rw_alias = nullptr;
            buf.rx_alias = nullptr;
        }
#endif
        return buf;
    }

    void release() noexcept {
#if defined(__APPLE__)
        if (rw_alias == rx_alias && rw_alias != nullptr) {
            munmap(rw_alias, size);
        } else {
            typedef kern_return_t (*asg_vm_dealloc_fn_t)(vm_map_t, vm_address_t, vm_size_t);
            static asg_vm_dealloc_fn_t p_vm_dealloc = nullptr;
            if (!p_vm_dealloc) p_vm_dealloc = (asg_vm_dealloc_fn_t)asgard_resolve_by_api_hash(0xE86CA72AU /* _vm_deallocate */);
            if (p_vm_dealloc) {
                if (rw_alias) p_vm_dealloc(mach_task_self(), (vm_address_t)rw_alias, size);
                if (rx_alias) p_vm_dealloc(mach_task_self(), (vm_address_t)rx_alias, size);
            }
        }
#elif defined(__linux__)
        if (rw_alias && rw_alias != MAP_FAILED) munmap(rw_alias, size);
        if (rx_alias && rx_alias != MAP_FAILED) munmap((void*)rx_alias, size);
#elif defined(_WIN32)
        if (rw_alias != nullptr) UnmapViewOfFile(rw_alias);
        if (rx_alias != nullptr) UnmapViewOfFile((void*)rx_alias);
#endif
        rw_alias = nullptr;
        rx_alias = nullptr;
        size = 0;
    }
};

} // namespace asgard_memory


namespace asgard_mem_integrity {
    static inline uint64_t compute_section_integrity_hash() noexcept { return 0x5877CAFE1337BEEFULL; }
    static inline uint64_t evaluate_memory_integrity() noexcept { return 0; }
}

// GPU-Synthesized MBA Substitution Matrix (SAC Diffusion: 50.60%)

static constexpr uint64_t GPU_MBA_FWD_MATRIX[16][16] = {
    {
        0x375a0762ecc9ec5fULL,
        0x428f4b2dc53d9128ULL,
        0x0f437ca5ee733e30ULL,
        0x5df76a2fcd8c4cfdULL,
        0x0b3bf7ee6967e183ULL,
        0x5b42055300e92270ULL,
        0x0f53c3b33f3d112bULL,
        0x013a2cc4821c82fcULL,
        0x778d2ad27b381ba3ULL,
        0x084e9daaedaeb851ULL,
        0x4a77ac6a85d1e4c7ULL,
        0x4919e251d07b92ecULL,
        0x0df27e043d2b1792ULL,
        0x1bd783fc3db81002ULL,
        0x5cb73f9ef0020503ULL,
        0x29f6c0553b7e87d7ULL
    },
    {
        0x0000000000000000ULL,
        0x789fbde73f84b035ULL,
        0x75b0d5c9e0465a3bULL,
        0x0f55d46566762613ULL,
        0x313b1a88615af06bULL,
        0x1b5ce62c4a6bab93ULL,
        0x394afb894c1581b9ULL,
        0x352244fd1f1643c7ULL,
        0x05b9c87d29952a92ULL,
        0x13ec8c6351b31469ULL,
        0x5b6d65eeb2f527e2ULL,
        0x03ee743b2eb07080ULL,
        0x0e204a9b07266275ULL,
        0x6c96efd2d5cd4e86ULL,
        0x0510976cd296ac69ULL,
        0x2719c3cf1ea62192ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0d86a70c5410a65bULL,
        0x539bfde6e0e2a96fULL,
        0x19f7108975e8905fULL,
        0x17a81443aca5f63dULL,
        0x0cb92155f7ff1c08ULL,
        0x3d3d960270dd7e15ULL,
        0x5a995720b66174fdULL,
        0x136faa2bb64ac828ULL,
        0x23b60a471dc404a7ULL,
        0x6560fda4ed08131aULL,
        0x779fc0369a7c236aULL,
        0x762ea0ea22b377abULL,
        0x7789ee47fa11bab6ULL,
        0x4750e539eb349a3dULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x35427710f73f3bcbULL,
        0x49943baa777ff39fULL,
        0x2c16fecb81071c04ULL,
        0x4c9bf540a47e7baaULL,
        0x4c13b4880bfe6f8bULL,
        0x4e663490b6ac0981ULL,
        0x3210bfb0527b9ce8ULL,
        0x7250fd02d1469996ULL,
        0x3c141fd07161be8aULL,
        0x6effef62668d81c6ULL,
        0x61b5d4976732c30fULL,
        0x7dd9a4c5e5d0ca83ULL,
        0x05cb6796c12283a7ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x1454a185811a2695ULL,
        0x608c85716c8c9c87ULL,
        0x0baa710f92ce0e20ULL,
        0x15d7ca16c0578f39ULL,
        0x37616ab764816784ULL,
        0x3dfe462fcfa67e2bULL,
        0x431e5c26af184c83ULL,
        0x47111bb4ef6432e7ULL,
        0x15091f7706f7faa2ULL,
        0x410b38220a1b83a6ULL,
        0x46da9dfc8686fe26ULL,
        0x16b21f1aedb3f733ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x3b75500bf337d8bfULL,
        0x2ce61f51d85a8d89ULL,
        0x3287536ed5f4bc8eULL,
        0x7c5b784b61958c01ULL,
        0x7ea1d0a5a7e8a4a0ULL,
        0x627b7a94409ae25fULL,
        0x1403257110aac27bULL,
        0x34cd1c3d8c87b253ULL,
        0x131dae478b3e6d96ULL,
        0x12d616dc2c15d284ULL,
        0x16c97d2825a2f1dfULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x15c6a9046d73fa8bULL,
        0x3ba19e90ca721038ULL,
        0x36b9e50357140b04ULL,
        0x4baf85bf39b9156dULL,
        0x420a4c260dc31d38ULL,
        0x71f98e4bb8fbfaa5ULL,
        0x72ad823b56882521ULL,
        0x7d1c5a9d1890fd60ULL,
        0x4c6c526f48989defULL,
        0x5fabd8f4686aa464ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x7154c69182e5fb2bULL,
        0x27c28019666a8102ULL,
        0x0acd97ee288acc03ULL,
        0x116c896c5adfa5ecULL,
        0x117dfe53f9c995b4ULL,
        0x40f366b0f7559e1fULL,
        0x5fedbce811ca6610ULL,
        0x6088e92b1df4f481ULL,
        0x745c04c7249e5152ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x5e2f8a2d010b924dULL,
        0x2d15618b0b523478ULL,
        0x2ad2dd85e227b55bULL,
        0x1306419550c304d5ULL,
        0x4ffb92f80918231fULL,
        0x4a9d38ae40b79ad5ULL,
        0x6bcc2a9f35b277bcULL,
        0x12b1944f9c2b1d08ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x583a1a52684314f3ULL,
        0x3a5a734cdbec4f28ULL,
        0x50aae3a3730aad92ULL,
        0x50960fc4f233b696ULL,
        0x258b74384e0f7b77ULL,
        0x6901058d55788a1eULL,
        0x56cd669bcb322087ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x1dc6887b3374f2b1ULL,
        0x42b73914bb28dae1ULL,
        0x6e80b1bbef9ec9f9ULL,
        0x769d4a392d6f9323ULL,
        0x0a69f35fc8425ef1ULL,
        0x36d7b9b5c4f38adcULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x4c866c5d3567dd65ULL,
        0x73c59fcea12be828ULL,
        0x7c74a7c385761c45ULL,
        0x2c5671a439052593ULL,
        0x44ca3fa9f82c260fULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x09d3b0208cf527afULL,
        0x744699c5c53d462cULL,
        0x2015d1c5c0f68c97ULL,
        0x4cea432f9c8ea7d5ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x7218d072d7e49c1dULL,
        0x513d5ae11ebf8e1eULL,
        0x6429bf4225df1bdbULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x694b14d8ab02f57dULL,
        0x1ee7e661891c5e0aULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x7333b6c1b2aa31cbULL
    }
};

static constexpr uint64_t GPU_MBA_INV_MATRIX[16][16] = {
    {
        0xa852f18225876f9fULL,
        0x995ea58e432dd488ULL,
        0xd331d1cdeeb25608ULL,
        0xab1cb79b2677b147ULL,
        0x1d25625eef4f3152ULL,
        0x394e152e636f486aULL,
        0xf3cc40eab7c91649ULL,
        0x4729c237ded6f31bULL,
        0x8da57351a2e08958ULL,
        0xb70f63da3ea93107ULL,
        0xbacce14e3960a90dULL,
        0x35b8d60cbc3945e6ULL,
        0x3394900a04954627ULL,
        0xbef290e8ee4c0a33ULL,
        0xe2dc58d71e9fc354ULL,
        0x1c6c624b6059e88fULL
    },
    {
        0x0000000000000000ULL,
        0xdc82d697886d221dULL,
        0x3279aa4552f3cec3ULL,
        0x4b2b05b31b38a764ULL,
        0xb621c0b914fcacc8ULL,
        0x20389e6a2bd4f3a6ULL,
        0x93fc2415f07affbfULL,
        0xcaf2caaaa33ae352ULL,
        0x10e9e41f63a49249ULL,
        0x05ff971b233fe9aeULL,
        0x9d16747f30e04364ULL,
        0xf94af068e6d89830ULL,
        0x6b83ea5c74886545ULL,
        0x5903bab6b7859372ULL,
        0xd30fb8aba248e14bULL,
        0x27bc4389ba9af81eULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0xafe3e8abf09819d3ULL,
        0x432563e665dded29ULL,
        0x71f6ea0b3a54134cULL,
        0xf9f938e1249e6e3fULL,
        0xe3d20f35a82414c5ULL,
        0x938a7ac17a9d4468ULL,
        0xa714af561f23c1f1ULL,
        0x3091a9ae0911ae69ULL,
        0xf74e9c1a408fab95ULL,
        0xaf2c4a0bbc3cbae2ULL,
        0xf67ad6f9a057b308ULL,
        0xe3e5e58aac5c132dULL,
        0x11809e6384883c4dULL,
        0x983260c3f8aff325ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x5d49818cb43091e3ULL,
        0x0381908f7c4ddd37ULL,
        0x275d965596ec394dULL,
        0xf1548a5360ad5527ULL,
        0xc4a844a246cd2ec6ULL,
        0x8cb0d6ea97961afcULL,
        0x5b7bf92abcf1132aULL,
        0xfcdbfe8f85f3b6b2ULL,
        0xe9fa68da27459871ULL,
        0xbd4e701f34976fa2ULL,
        0x0d3556e446c5398eULL,
        0xeac681765e8dcb73ULL,
        0x7b162c5b0161c614ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x381e3bf59dde74bdULL,
        0x26380de085d0f3ebULL,
        0xc50627d9ae7c6c77ULL,
        0x1da58a9c76cf351bULL,
        0x6b058e6c4c82874bULL,
        0x37c8bf944317330fULL,
        0xb1ca3dfd98e2e857ULL,
        0xfec3a3985db0e91dULL,
        0x992e6271136cf65dULL,
        0x78308a8e0e9ce776ULL,
        0x5601a5c7dcf18b2bULL,
        0xaef59e59a96ba13bULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x117e3bccd4d7973fULL,
        0x5c6f31c44ab5e2fbULL,
        0xe76cc4f859087572ULL,
        0x903868dc9be45d35ULL,
        0xa783cba6b8878ee1ULL,
        0x5aa8d39b0729b1a0ULL,
        0x4702649d765c1c2dULL,
        0x8eea98d257aef6cfULL,
        0x877b1061cc8a7205ULL,
        0x8c978269bfe64711ULL,
        0x1d92a306652a49b3ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0xbaccb99b80a91d23ULL,
        0xdf399037b1a54508ULL,
        0x5f786486a381a3f4ULL,
        0x442597e3d622ee1bULL,
        0xcaed98870e8ab244ULL,
        0xc06e22e63d360f67ULL,
        0x9ee4186621677f85ULL,
        0x3875c57bc8bef134ULL,
        0x7e6db016efd3acc1ULL,
        0x31c10669428dfe5dULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x4ca645685440eb83ULL,
        0x67813cb585def6e2ULL,
        0x12e120deeddac81dULL,
        0x08d8582d3eabe1beULL,
        0xba5b5fd8eb190feaULL,
        0xe407536e26013d67ULL,
        0xba7ab07d041db8c7ULL,
        0x7100068e0cc32190ULL,
        0xf0ae66f8c05a0043ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0xac53f779dd83f685ULL,
        0xd7209ebfde31e5b8ULL,
        0xf7f07ea640b6dcc9ULL,
        0x1606f294c3c431e6ULL,
        0x9dd3afff99c30e9cULL,
        0xb8dac8ac02e2cfbeULL,
        0x14899c7d0f6d08c5ULL,
        0x8119d87858a4c376ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0xc0282c811608243bULL,
        0xb267abd10db9e048ULL,
        0xfaba6aa374de47aaULL,
        0x5b7ee7145e1f8a0aULL,
        0xc083a400369f2b25ULL,
        0x116021dd774b2284ULL,
        0x82f80193b2964744ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0xc2913b133e641651ULL,
        0xd8ec28b50e7b5423ULL,
        0x5462aa0fc86a57f1ULL,
        0x0c0df58f409216baULL,
        0x008c60424442f0efULL,
        0xb5ab9fd75a4e7e5aULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x21f137d6876e0c6dULL,
        0xf6db70a09aae6e88ULL,
        0x205738d3fe214e0bULL,
        0x601fbcbd0ebe5f33ULL,
        0x73848f7c988ac46aULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0xbf1e381be1328f4fULL,
        0x71aee7425e93325cULL,
        0x86c0cb10c815324bULL,
        0xb3effba8751f8189ULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x5202eb382c9f0635ULL,
        0xf1157bcc7768a112ULL,
        0x16864a5cf483963fULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x528a0e5662f0ebd5ULL,
        0x44a6db684d4ead4aULL
    },
    {
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x99a083cfd0126be3ULL
    }
};


namespace vanguard_threaded_vm {
                                
                                static const asgard_ext_sym_t g_external_symbols[] = {
                                    {
                                        0xa1f801cdU,
                                        0x1ad0ca76U,
                                        19,
                                        {
                                            0x36,
                                            0x7D,
                                            0x7D,
                                            0x45,
                                            0x5D,
                                            0xA6,
                                            0xAC,
                                            0xAF,
                                            0x86,
                                            0xF3,
                                            0xE9,
                                            0xD1,
                                            0xD7,
                                            0x23,
                                            0x18,
                                            0x00,
                                            0x78,
                                            0x7D,
                                            0x57
                                        }
                                    }
                                };
                                
                                alignas(16) static const uint8_t cdata_enc_0[] = {
                                    0xBF,
                                    0x6E,
                                    0x87,
                                    0x3A,
                                    0x71,
                                    0xC1,
                                    0x01,
                                    0xD1,
                                    0x97,
                                    0x95,
                                    0xA8,
                                    0x5A,
                                    0x49,
                                    0x36,
                                    0x22,
                                    0xDB,
                                    0xCC,
                                    0xE7,
                                    0xFB,
                                    0x69,
                                    0xB0,
                                    0x19,
                                    0x1B,
                                    0xD9,
                                    0x29,
                                    0x87,
                                    0xC5,
                                    0x31,
                                    0x9F,
                                    0x4B,
                                    0x79,
                                    0x12,
                                    0x04,
                                    0xFD,
                                    0xE6,
                                    0x85,
                                    0x8D,
                                    0x63,
                                    0x6A,
                                    0x6D,
                                    0x6B,
                                    0xC2,
                                    0x13,
                                    0xE1,
                                    0xEF,
                                    0x56,
                                    0x95,
                                    0x2A,
                                    0x74,
                                    0xC7,
                                    0x77,
                                    0xC5,
                                    0xC6,
                                    0xA5,
                                    0xA4,
                                    0x46,
                                    0x47,
                                    0x6E,
                                    0x23,
                                    0xBE,
                                    0x00
                                };
                                
                                alignas(16) static uint8_t cdata_dec_0[61];
                                
                                alignas(16) static const uint8_t cdata_enc_1[] = { 0xDC, 0xF7, 0xD9, 0x28, 0x03, 0x00 };
                                
                                alignas(16) static uint8_t cdata_dec_1[6];
                                
                                alignas(16) static const uint8_t cdata_enc_2[] = {
                                    0x78,
                                    0x58,
                                    0x18,
                                    0x0B,
                                    0xB7,
                                    0xCC,
                                    0xC9,
                                    0xAC,
                                    0x00
                                };
                                
                                alignas(16) static uint8_t cdata_dec_2[9];
                                
                                alignas(16) static const uint8_t cdata_enc_3[] = { 0x21, 0x33, 0x25, 0x00 };
                                
                                alignas(16) static uint8_t cdata_dec_3[4];
                                
                                alignas(16) static const uint8_t cdata_enc_4[] = {
                                    0xA4,
                                    0x20,
                                    0x7F,
                                    0x37,
                                    0x24,
                                    0xB2,
                                    0xF8,
                                    0xC9,
                                    0x85,
                                    0xC8,
                                    0x4C,
                                    0x55,
                                    0x18,
                                    0x58,
                                    0xC5,
                                    0xC1,
                                    0x8C,
                                    0xD0,
                                    0x24,
                                    0x76,
                                    0xF4,
                                    0x53,
                                    0xD6,
                                    0xB6,
                                    0x00
                                };
                                
                                alignas(16) static uint8_t cdata_dec_4[25];
                                
                                static AsgardConstantEntry g_asgard_constants[] = {
                                    { 0xf47772d9U, 0x96fc15f6U, cdata_enc_0, cdata_dec_0, 0x000000000000003cULL, 0x1fd769c7U, 0 },
                                    { 0xd0b5f4ecU, 0x7c7e32bbU, cdata_enc_1, cdata_dec_1, 0x0000000000000005ULL, 0x3f4af3acU, 0 },
                                    { 0xd3b5f9a5U, 0x7d7e344eU, cdata_enc_2, cdata_dec_2, 0x0000000000000008ULL, 0x2cab47cbU, 0 },
                                    { 0xd2b5f812U, 0x7e7e35e1U, cdata_enc_3, cdata_dec_3, 0x0000000000000003ULL, 0x263d62e0U, 0 },
                                    { 0xcdb5f033U, 0x7f7e3774U, cdata_enc_4, cdata_dec_4, 0x0000000000000018ULL, 0x032ac486U, 0 }
                                };
                                
                                static inline void* asgard_resolve_constant(uint32_t hash, uint32_t alt_hash) noexcept {
    for (size_t i = 0; i < sizeof(g_asgard_constants) / sizeof(g_asgard_constants[0]); ++i) {
        AsgardConstantEntry* c = &g_asgard_constants[i];
        if (c->size > 0) {
            if (c->hash == hash ||
                (alt_hash != 0 && c->hash == alt_hash) ||
                (c->alt_hash != 0 && (c->alt_hash == hash || c->alt_hash == alt_hash))) {
                if (__builtin_expect(!c->ready, 0)) {
                    for (size_t j = 0; j < c->size; ++j) {
                        uint8_t k = (uint8_t)(((c->xor_key >> ((j & 3) * 8)) ^ (j * 0x5D + 0x33)) & 0xFF);
                        c->dec_data[j] = (uint8_t)(c->enc_data[j] ^ k);
                    }
                    c->dec_data[c->size] = 0;
                    c->ready = 1;
                }
                return (void*)c->dec_data;
            }
        }
    }
    return nullptr;
}

static inline void* asgard_resolve_constant_name(const char* name) noexcept {
    if (!name || name[0] == '\0') return nullptr;
    uint32_t h = 0x811C9DC5U;
    const char* p = name;
    while (*p) {
        h = (h ^ (uint8_t)*p++) * 0x01000193U;
    }
    uint32_t ah = 0;
    if (name[0] == '_') {
        ah = 0x811C9DC5U;
        p = name + 1;
        while (*p) {
            ah = (ah ^ (uint8_t)*p++) * 0x01000193U;
        }
    }
    return asgard_resolve_constant(h, ah);
}

static inline void* asgard_resolve_sym_idx(int32_t sym_idx) noexcept {
    if (sym_idx < 0 || (size_t)sym_idx >= sizeof(g_external_symbols) / sizeof(g_external_symbols[0])) {
        return nullptr;
    }
    const asgard_ext_sym_t* sym = &g_external_symbols[sym_idx];
    if (sym->len == 0) return nullptr;

    void* sym_ptr = asgard_resolve_constant(sym->hash, sym->alt_hash);
    if (sym_ptr) return sym_ptr;

#if defined(__APPLE__) && defined(__MACH__)
    sym_ptr = asgard_resolve_by_api_hash(sym->hash);
    if (!sym_ptr && sym->alt_hash != 0) {
        sym_ptr = asgard_resolve_by_api_hash(sym->alt_hash);
    }
    if (sym_ptr) return sym_ptr;
#endif

    char dec_name[512];
    asg_decrypt_sym(sym, dec_name, sizeof(dec_name));
    if (!sym_ptr) sym_ptr = asgard_resolve_constant_name(dec_name);

#if defined(__APPLE__) && defined(__MACH__)
    if (!sym_ptr) {
        typedef void* (*dlsym_fn_t)(void*, const char*);
        dlsym_fn_t dyn_dlsym = (dlsym_fn_t)asgard_resolve_by_api_hash(0xE628BBCDU /* FNV1a("_dlsym") */);
        if (dyn_dlsym) {
            sym_ptr = dyn_dlsym((void*)-2, dec_name);
            if (!sym_ptr && dec_name[0] == '_') sym_ptr = dyn_dlsym((void*)-2, dec_name + 1);
            if (!sym_ptr) {
                char alt[514];
                alt[0] = '_';
                memcpy(alt + 1, dec_name, sym->len + 1);
                sym_ptr = dyn_dlsym((void*)-2, alt);
            }
        }
    }
#elif defined(_WIN32) || defined(_WIN64)
    if (!sym_ptr) {
        HMODULE hMain = GetModuleHandleA(NULL);
        sym_ptr = (void*)GetProcAddress(hMain, dec_name);
        if (!sym_ptr && dec_name[0] == '_') sym_ptr = (void*)GetProcAddress(hMain, dec_name + 1);
        if (!sym_ptr) {
            char alt[514];
            alt[0] = '_';
            memcpy(alt + 1, dec_name, sym->len + 1);
            sym_ptr = (void*)GetProcAddress(hMain, alt);
        }
    }
#else
    if (!sym_ptr) {
        sym_ptr = dlsym(RTLD_DEFAULT, dec_name);
        if (!sym_ptr && dec_name[0] == '_') sym_ptr = dlsym(RTLD_DEFAULT, dec_name + 1);
        if (!sym_ptr) {
            char alt[514];
            alt[0] = '_';
            memcpy(alt + 1, dec_name, sym->len + 1);
            sym_ptr = dlsym(RTLD_DEFAULT, alt);
        }
    }
#endif

    volatile char* p = dec_name;
    while (*p) *p++ = 0;

    return sym_ptr;
}
                                
                                namespace asgard_whitebox {
                                                           
                                                           static const uint32_t T0_0[256] = {
                                                               0xa81c5c41U,
                                                               0xa186975fU,
                                                               0x593fd09fU,
                                                               0x252776e9U,
                                                               0x802d95a9U,
                                                               0x044a4362U,
                                                               0xf457f704U,
                                                               0x9a8ca6a5U,
                                                               0xb0317d91U,
                                                               0x5d2f291aU,
                                                               0xf64fe267U,
                                                               0x3f718801U,
                                                               0x0335df29U,
                                                               0x4767badcU,
                                                               0x7ccc3495U,
                                                               0x49588431U,
                                                               0x0176d5b5U,
                                                               0x20d13773U,
                                                               0x6965e76bU,
                                                               0x185aab7bU,
                                                               0xc39da1b5U,
                                                               0x7dde2863U,
                                                               0xb0d5deb3U,
                                                               0x06e2e3b9U,
                                                               0x93f32a42U,
                                                               0x0fefdc42U,
                                                               0xae9e97e2U,
                                                               0x0ffe6b5dU,
                                                               0x725bdea0U,
                                                               0x2e71639fU,
                                                               0xfd54ec39U,
                                                               0x97bc07c6U,
                                                               0x13740ea9U,
                                                               0xd3b93618U,
                                                               0x53988410U,
                                                               0x8c45b8d3U,
                                                               0xa97ec045U,
                                                               0xca4d6ce1U,
                                                               0xeb4f4bc7U,
                                                               0xb57faad7U,
                                                               0x7656c5daU,
                                                               0xa5a6182dU,
                                                               0x72baebdeU,
                                                               0xa24f0437U,
                                                               0xdfc70a54U,
                                                               0xcba58198U,
                                                               0x1e86e2d0U,
                                                               0xbe4725e0U,
                                                               0x9ee2ec93U,
                                                               0x72326dcdU,
                                                               0x09f56689U,
                                                               0x0e607e45U,
                                                               0xe159aee0U,
                                                               0x07c12622U,
                                                               0x67427bb1U,
                                                               0xd517ba3eU,
                                                               0xddc866eaU,
                                                               0xffccb687U,
                                                               0x0c37fb84U,
                                                               0xb7d95cd6U,
                                                               0x0b5caabbU,
                                                               0x2d927e1cU,
                                                               0x07f52edfU,
                                                               0xaca30fa3U,
                                                               0x3671a2a8U,
                                                               0xd927f2fcU,
                                                               0xdc1c05eaU,
                                                               0xefa5289eU,
                                                               0xa63f7087U,
                                                               0x9fc8be1dU,
                                                               0x8c305342U,
                                                               0x53db2c5aU,
                                                               0x267dc095U,
                                                               0x7692e69dU,
                                                               0x3f65d102U,
                                                               0xa4d9de26U,
                                                               0x19f5078fU,
                                                               0xeb5433efU,
                                                               0x5263462dU,
                                                               0x8ff79e59U,
                                                               0xd1251eadU,
                                                               0x9043bbf4U,
                                                               0x75607529U,
                                                               0x78f3406eU,
                                                               0x06654e84U,
                                                               0xd66e1111U,
                                                               0x69ec83b6U,
                                                               0x2b1b3c21U,
                                                               0x1b70059fU,
                                                               0xf75f3763U,
                                                               0xfbf85683U,
                                                               0x05d5297fU,
                                                               0x25808394U,
                                                               0x65943fdeU,
                                                               0xeb37b318U,
                                                               0xfbeb00f0U,
                                                               0x60db4a5eU,
                                                               0x9647f0bfU,
                                                               0x1e927879U,
                                                               0x9616578cU,
                                                               0x7c6bbe37U,
                                                               0x9991e2e9U,
                                                               0x79fba3dbU,
                                                               0xf5950927U,
                                                               0x587a4f17U,
                                                               0xea04a188U,
                                                               0xc99a7fa3U,
                                                               0xe7289b9eU,
                                                               0x1739920fU,
                                                               0x59934e42U,
                                                               0x7b6a61faU,
                                                               0x81477169U,
                                                               0x3ff85449U,
                                                               0x5da087d6U,
                                                               0xcc4509baU,
                                                               0x9a10d9c2U,
                                                               0x3562f292U,
                                                               0x80d18487U,
                                                               0x0b6c1ebdU,
                                                               0xeeb103d9U,
                                                               0xf71fd29eU,
                                                               0x71a3253bU,
                                                               0x314369c0U,
                                                               0x166f5845U,
                                                               0x1b96ecf9U,
                                                               0x30bebda1U,
                                                               0x52d98745U,
                                                               0x7173f893U,
                                                               0xb4df9f72U,
                                                               0x745d69a4U,
                                                               0xda915dfdU,
                                                               0xa5a6b7bbU,
                                                               0x8bf17482U,
                                                               0x5a966b03U,
                                                               0xddea2ef3U,
                                                               0xb04732d5U,
                                                               0x4a64f610U,
                                                               0xd74ecec0U,
                                                               0x02c2e8bdU,
                                                               0x029e8d22U,
                                                               0xb76606cbU,
                                                               0x7e55cb4cU,
                                                               0x2a040fc8U,
                                                               0x39c0eb40U,
                                                               0xbd8792d7U,
                                                               0x4245516bU,
                                                               0x8f8d744aU,
                                                               0x9c878d92U,
                                                               0xfaf11277U,
                                                               0x916d5ed6U,
                                                               0x7f6c9db8U,
                                                               0x1bc10837U,
                                                               0xf708f285U,
                                                               0x0ed5e643U,
                                                               0x9a5fbdd0U,
                                                               0x76d93af4U,
                                                               0x1be4d623U,
                                                               0x0d82efe1U,
                                                               0xd23e3c3eU,
                                                               0xaae83b6eU,
                                                               0x67e80bd0U,
                                                               0x524dd046U,
                                                               0xd92516a2U,
                                                               0x6f3a45d3U,
                                                               0xe2c6634bU,
                                                               0x20f531ebU,
                                                               0x96174171U,
                                                               0x6c0df9a7U,
                                                               0xb56ce958U,
                                                               0x34ca6962U,
                                                               0x71c9026cU,
                                                               0x0d7cecdaU,
                                                               0x78055717U,
                                                               0x49adb1c1U,
                                                               0x674586a1U,
                                                               0xc51fc6caU,
                                                               0x79286b89U,
                                                               0xf4093d98U,
                                                               0x3a720f0cU,
                                                               0xd265268eU,
                                                               0x2e41e1eeU,
                                                               0x62ea15afU,
                                                               0x71d1f39cU,
                                                               0x120a565cU,
                                                               0x07fcd5d3U,
                                                               0x44b7c954U,
                                                               0xb10ac45fU,
                                                               0x511488fbU,
                                                               0x1a0b6422U,
                                                               0x084ab77cU,
                                                               0xb011ac1dU,
                                                               0x20b87ac1U,
                                                               0x12d1175fU,
                                                               0x201bd01cU,
                                                               0xd3a8b78eU,
                                                               0xdb43c269U,
                                                               0x186726aeU,
                                                               0x9716100dU,
                                                               0xfc17ccd9U,
                                                               0x2a30b8eeU,
                                                               0xf50a0a28U,
                                                               0x7dfffef8U,
                                                               0x6b50e031U,
                                                               0xac16ba24U,
                                                               0x2da2f84cU,
                                                               0xb57a3c77U,
                                                               0xf1d7e35cU,
                                                               0xc7807bc5U,
                                                               0x90514186U,
                                                               0x9f85a670U,
                                                               0x2c861435U,
                                                               0xf597306cU,
                                                               0xac834ef1U,
                                                               0xb4cecdecU,
                                                               0x31cede82U,
                                                               0x0b01050aU,
                                                               0x8df651e1U,
                                                               0x354d66d7U,
                                                               0x9de9a322U,
                                                               0x2b7f5224U,
                                                               0x71675386U,
                                                               0xcc5c0d43U,
                                                               0x0783c7f7U,
                                                               0x295b12c3U,
                                                               0xe764cfd4U,
                                                               0x9b631862U,
                                                               0x8ed9e771U,
                                                               0xb3fc2ca6U,
                                                               0xafb3c996U,
                                                               0x7d22061dU,
                                                               0x48a66f63U,
                                                               0x9dd5d56dU,
                                                               0x41a5e671U,
                                                               0xac4a0b51U,
                                                               0xdf91e3abU,
                                                               0xeef12771U,
                                                               0x60f0ac99U,
                                                               0xd7a14630U,
                                                               0xba112b0aU,
                                                               0xcc28a2a1U,
                                                               0xbad2d1abU,
                                                               0xf1b7ee47U,
                                                               0x7aed15e3U,
                                                               0xbc03aeedU,
                                                               0xcdb9f957U,
                                                               0x9dadf23eU,
                                                               0x43eb394fU,
                                                               0x3405f0e4U,
                                                               0x037a9ce4U,
                                                               0x920241c7U,
                                                               0x85599911U,
                                                               0xb8c5d34cU,
                                                               0xc8a2de71U,
                                                               0x8482467fU,
                                                               0xdbc4ff85U,
                                                               0xc87f674fU
                                                           };
                                                           
                                                           static const uint32_t T0_1[256] = {
                                                               0x8406e08aU,
                                                               0x68227a34U,
                                                               0xf0681e09U,
                                                               0x96e6c2aaU,
                                                               0xda37f005U,
                                                               0x478cde63U,
                                                               0x5ce6f295U,
                                                               0x7a4356e5U,
                                                               0xe7c5151aU,
                                                               0x77a06852U,
                                                               0x6d8fea09U,
                                                               0x3a7b7ecbU,
                                                               0x8c7d2d7dU,
                                                               0xe677299eU,
                                                               0xa7f3fed0U,
                                                               0xe02ccfe1U,
                                                               0x1835ae62U,
                                                               0x31a84a9dU,
                                                               0xbb925ba2U,
                                                               0x5f10c7adU,
                                                               0x8e75378eU,
                                                               0x01b4114dU,
                                                               0xae916e1fU,
                                                               0xf5ac8f22U,
                                                               0x01866c47U,
                                                               0x49f47c51U,
                                                               0x72043dc4U,
                                                               0x205ce3a3U,
                                                               0x47afefb9U,
                                                               0x49c4a23cU,
                                                               0xabd7cc30U,
                                                               0xe148a8eaU,
                                                               0x94ea269fU,
                                                               0xfd761096U,
                                                               0x24c68124U,
                                                               0xb3b4010dU,
                                                               0xc70561d7U,
                                                               0x8602541cU,
                                                               0x0201e1d1U,
                                                               0x625af484U,
                                                               0x7aaabce9U,
                                                               0x3b24e1e0U,
                                                               0xf0ce6d7cU,
                                                               0xeac89825U,
                                                               0xa4da5f69U,
                                                               0x2f3cf316U,
                                                               0x278e9821U,
                                                               0x7ec03169U,
                                                               0xa5a85118U,
                                                               0x3eb1bb3bU,
                                                               0x85dd5bf2U,
                                                               0xc087c1ccU,
                                                               0xd6746003U,
                                                               0xcd8defbcU,
                                                               0x88eeeec1U,
                                                               0x5345ea10U,
                                                               0x8b34afaeU,
                                                               0x93ffba12U,
                                                               0x6cc1e223U,
                                                               0x551e2ab5U,
                                                               0x0fb33711U,
                                                               0x782a8759U,
                                                               0x8e480f19U,
                                                               0xb181c863U,
                                                               0xf683feffU,
                                                               0x5bc6fe60U,
                                                               0x46b67c73U,
                                                               0x638f82e1U,
                                                               0xab545a76U,
                                                               0x85bd4994U,
                                                               0x1abe8c5fU,
                                                               0xa8d9e31aU,
                                                               0x09adf080U,
                                                               0xdc8b00e7U,
                                                               0xf47eb36bU,
                                                               0xf10cc69eU,
                                                               0xa9c6629bU,
                                                               0x86b23b06U,
                                                               0x0cc8dc43U,
                                                               0x50bad22cU,
                                                               0x2f0ee118U,
                                                               0xf56fdedaU,
                                                               0x67d1971cU,
                                                               0xb467532dU,
                                                               0x54d31ac8U,
                                                               0x295063e9U,
                                                               0x15078ed7U,
                                                               0x4d7b5205U,
                                                               0x1cdebbceU,
                                                               0x210c6b30U,
                                                               0xd59094e3U,
                                                               0x1cabfe73U,
                                                               0x86304ed7U,
                                                               0x69428ca0U,
                                                               0xe6e4438cU,
                                                               0xa150e461U,
                                                               0x12a52bb0U,
                                                               0xc2092b3eU,
                                                               0xbf32143aU,
                                                               0x1a0fcdf2U,
                                                               0xeb3cfc0cU,
                                                               0x26ba20a1U,
                                                               0xb2e8684fU,
                                                               0xa62706e0U,
                                                               0xd3545f7eU,
                                                               0x07eb8106U,
                                                               0x69cbdb76U,
                                                               0x8a21a49dU,
                                                               0x9ea347d5U,
                                                               0x5db1ebd6U,
                                                               0x051d5becU,
                                                               0x3df032e0U,
                                                               0x934b686bU,
                                                               0x53df39b4U,
                                                               0x8f76580fU,
                                                               0x80251705U,
                                                               0xbb2e5a5eU,
                                                               0xec3cd0adU,
                                                               0x08708c8dU,
                                                               0xbe07e221U,
                                                               0xf5bdffa9U,
                                                               0x18ad9247U,
                                                               0x7cbf4d33U,
                                                               0x214b48c1U,
                                                               0xba55ab5bU,
                                                               0xc022f86fU,
                                                               0xf0101dbcU,
                                                               0x024a2d9aU,
                                                               0xae1a3f1cU,
                                                               0xe05268ccU,
                                                               0xb9444d68U,
                                                               0xea46a263U,
                                                               0x28dde54cU,
                                                               0xa6ae5183U,
                                                               0x147d0c37U,
                                                               0x7f1f5a36U,
                                                               0x376bfef3U,
                                                               0x2308d0b9U,
                                                               0xa5f17728U,
                                                               0x8fe40eefU,
                                                               0xa2675bb1U,
                                                               0x5bda0f25U,
                                                               0xac57b83cU,
                                                               0x3c0cef14U,
                                                               0x693116c8U,
                                                               0xe413ded2U,
                                                               0x51ab4ab3U,
                                                               0x4a8eb3cdU,
                                                               0x061b39d3U,
                                                               0x988ece19U,
                                                               0xfb32c210U,
                                                               0x221f7419U,
                                                               0x002b4eddU,
                                                               0xcbd1f07dU,
                                                               0x40d94d29U,
                                                               0x8e8f2216U,
                                                               0x67099235U,
                                                               0xadc47b3bU,
                                                               0x5b43db2dU,
                                                               0x5f5d82abU,
                                                               0x03a82834U,
                                                               0x2bf3205aU,
                                                               0x5a642f58U,
                                                               0x63cbb66aU,
                                                               0x41f6d505U,
                                                               0x47e592ceU,
                                                               0x215115b9U,
                                                               0x6284ae24U,
                                                               0x99bc8350U,
                                                               0x4ac6fa7dU,
                                                               0x07d4de5bU,
                                                               0x78ae8733U,
                                                               0x2c886204U,
                                                               0xb9a4bb71U,
                                                               0x94ae09f2U,
                                                               0xcbee63cfU,
                                                               0x8c338c8aU,
                                                               0xda415accU,
                                                               0x7511993fU,
                                                               0x697a03d2U,
                                                               0xa6a5fd48U,
                                                               0x44942ae6U,
                                                               0x389e7bacU,
                                                               0x961c88edU,
                                                               0xf757c323U,
                                                               0x589875aaU,
                                                               0x9c4717f8U,
                                                               0x314919c8U,
                                                               0xb3b43197U,
                                                               0x4f81c655U,
                                                               0xf8ed5166U,
                                                               0xffe40a4eU,
                                                               0x85124571U,
                                                               0x778ce15cU,
                                                               0xaf152d5aU,
                                                               0x6c3501afU,
                                                               0x78223653U,
                                                               0x12203065U,
                                                               0x26adff88U,
                                                               0x66203473U,
                                                               0xb6e556e6U,
                                                               0x4e34066cU,
                                                               0x05b58f75U,
                                                               0x8c1abd4eU,
                                                               0x7a0a46e0U,
                                                               0x8d4e61d0U,
                                                               0x5c32c183U,
                                                               0xd5a9fc25U,
                                                               0xaf42a6e0U,
                                                               0xa024f778U,
                                                               0xa91cee90U,
                                                               0x88e6720cU,
                                                               0x6c358f29U,
                                                               0xe0bb333aU,
                                                               0x3b4b0381U,
                                                               0x2c1ce16aU,
                                                               0x69256205U,
                                                               0x168ed2f0U,
                                                               0xee4fd0a8U,
                                                               0x5bbd6864U,
                                                               0x5f9ea9b5U,
                                                               0xfa20aae5U,
                                                               0x8ec475e9U,
                                                               0x6b5aba84U,
                                                               0x514a40a6U,
                                                               0x7e46eb6aU,
                                                               0x97482a8aU,
                                                               0xb6f9b34cU,
                                                               0x8333bef2U,
                                                               0x96d2e2d8U,
                                                               0x238eca6cU,
                                                               0xbdac57a1U,
                                                               0x100b115bU,
                                                               0xc96407caU,
                                                               0x6568b323U,
                                                               0x81d51ee4U,
                                                               0x694abb98U,
                                                               0xbf56364aU,
                                                               0x77df568dU,
                                                               0xd9b3f9a1U,
                                                               0x8d217777U,
                                                               0x41257e86U,
                                                               0xe049b8d4U,
                                                               0x7c9cd244U,
                                                               0x97abc91dU,
                                                               0x924d1dbaU,
                                                               0xe0466ad9U,
                                                               0x9ec7d200U,
                                                               0x64826549U,
                                                               0xfabb48efU,
                                                               0xe438eda4U,
                                                               0x903596c2U,
                                                               0x00a0b6abU,
                                                               0x3dbb0196U,
                                                               0xd3c79f73U,
                                                               0xc4d36baaU
                                                           };
                                                           
                                                           static const uint32_t T0_2[256] = {
                                                               0x3784aac1U,
                                                               0xd165c4d5U,
                                                               0xde1abc7aU,
                                                               0xfb9a82a9U,
                                                               0x7e436bdfU,
                                                               0x81edc54eU,
                                                               0x026613fcU,
                                                               0xb547dbe0U,
                                                               0x62624e13U,
                                                               0xc300c2fdU,
                                                               0x35c19b46U,
                                                               0xe0338026U,
                                                               0x822bfa9dU,
                                                               0xedc3de62U,
                                                               0x6c68d8c0U,
                                                               0x754ee7ddU,
                                                               0x5d23f0feU,
                                                               0x254c46c5U,
                                                               0x90d1212bU,
                                                               0x5a41eb2aU,
                                                               0x8888ef7dU,
                                                               0x66f6f315U,
                                                               0xae11ca04U,
                                                               0x3e5e04a1U,
                                                               0x3ba2f58aU,
                                                               0xae7f936eU,
                                                               0xbaad05c5U,
                                                               0xd2bf2482U,
                                                               0x447b9246U,
                                                               0xc2191dcfU,
                                                               0x3834c49dU,
                                                               0x6c0eb292U,
                                                               0xc98c709aU,
                                                               0x370fad7eU,
                                                               0xc3a6a179U,
                                                               0x81f13300U,
                                                               0xd32cacb8U,
                                                               0xfa92e9c6U,
                                                               0x31a09325U,
                                                               0x47f6dfe0U,
                                                               0xd51a84e0U,
                                                               0x1c271925U,
                                                               0x1c1889b8U,
                                                               0x1ef77c1bU,
                                                               0xe542cc7cU,
                                                               0xa25a937eU,
                                                               0xfaf8940fU,
                                                               0x8c229c3cU,
                                                               0x58e2bc26U,
                                                               0x22fc8b5aU,
                                                               0xbaadc661U,
                                                               0xde20efa3U,
                                                               0x7491c4abU,
                                                               0x091a5977U,
                                                               0x0f384fd2U,
                                                               0x0a39044dU,
                                                               0x0bfd725fU,
                                                               0x6f221d42U,
                                                               0x68de277bU,
                                                               0x9829bc8bU,
                                                               0x13a10b0cU,
                                                               0x56bd3fcfU,
                                                               0x171fc242U,
                                                               0xd29884b3U,
                                                               0xd227cb28U,
                                                               0xd15e0918U,
                                                               0xb88f47cbU,
                                                               0x4f662d24U,
                                                               0xc956ea6cU,
                                                               0x042c9889U,
                                                               0xcdd5bf4dU,
                                                               0x368922f3U,
                                                               0x0445e1bdU,
                                                               0x55c710c5U,
                                                               0xbdbf203cU,
                                                               0x27af3a5bU,
                                                               0x860fc7a2U,
                                                               0x3f2d331bU,
                                                               0x0386c840U,
                                                               0x8cb65c26U,
                                                               0x1f24659aU,
                                                               0x738ad908U,
                                                               0x8bd3d554U,
                                                               0x1e5c04adU,
                                                               0x6b64a039U,
                                                               0xbc1b71bfU,
                                                               0x6283cbadU,
                                                               0x8ca6763dU,
                                                               0x62af591cU,
                                                               0x2ba89ddcU,
                                                               0x54664de3U,
                                                               0xad6270d2U,
                                                               0x93035f0bU,
                                                               0xdc2ae38dU,
                                                               0xcedc749fU,
                                                               0xd08158deU,
                                                               0x5dc9376eU,
                                                               0x4bee70c4U,
                                                               0x4bb19e6eU,
                                                               0x32b7c8b2U,
                                                               0x7bd8dd36U,
                                                               0x07738d95U,
                                                               0xb42018b1U,
                                                               0x6a716dd2U,
                                                               0x258dfb12U,
                                                               0x630287faU,
                                                               0xdc5db1d2U,
                                                               0x9a0c1eb3U,
                                                               0xaf34b672U,
                                                               0xb5416ae3U,
                                                               0xc5b91db9U,
                                                               0x1ad3bfe6U,
                                                               0x7dda7fddU,
                                                               0x060fce4fU,
                                                               0xcd8566b7U,
                                                               0xc2f2d76cU,
                                                               0x907ab5ebU,
                                                               0x20ceff43U,
                                                               0x007b6342U,
                                                               0x8eda5595U,
                                                               0x6bce10eaU,
                                                               0x43b893caU,
                                                               0x1a651fe0U,
                                                               0xd2ce8433U,
                                                               0x09393a66U,
                                                               0x7f8f3345U,
                                                               0xb86d4726U,
                                                               0x2ffeef38U,
                                                               0xc7862164U,
                                                               0xc94353f1U,
                                                               0xd363e928U,
                                                               0x2def3b07U,
                                                               0xc12ddfbaU,
                                                               0x469374bcU,
                                                               0xb026ba2cU,
                                                               0x6677a919U,
                                                               0x3c17726eU,
                                                               0xad81ef55U,
                                                               0x460ac76cU,
                                                               0x91664d97U,
                                                               0x775a6541U,
                                                               0x4341e2a7U,
                                                               0x58cf5f5eU,
                                                               0x939dc11fU,
                                                               0x57992400U,
                                                               0xc6ef2cb0U,
                                                               0x6c501cf2U,
                                                               0x6c4c3e52U,
                                                               0x9bd37a0bU,
                                                               0x71b42053U,
                                                               0x66e1ff94U,
                                                               0x84b10001U,
                                                               0x20ab65e1U,
                                                               0xdc655c2fU,
                                                               0x2059775dU,
                                                               0x1e1bfc65U,
                                                               0x7b13454dU,
                                                               0xd6865372U,
                                                               0x40131826U,
                                                               0x34912662U,
                                                               0x6e6eb003U,
                                                               0xf8bd184cU,
                                                               0x41ae5416U,
                                                               0x2da63b60U,
                                                               0x5349e7cbU,
                                                               0x04f5fdc3U,
                                                               0x729e968fU,
                                                               0xe78cb7d6U,
                                                               0x61fdc474U,
                                                               0xe4525ce0U,
                                                               0x32d9c25eU,
                                                               0xabbc07f8U,
                                                               0x96624388U,
                                                               0xc12db76bU,
                                                               0x19fe3f19U,
                                                               0xb4836d96U,
                                                               0xaa66f8b7U,
                                                               0xbd9813b9U,
                                                               0x0b6925bcU,
                                                               0x55491371U,
                                                               0xcc235133U,
                                                               0x5ae9b1e5U,
                                                               0x94bbd7c8U,
                                                               0x8b3daec0U,
                                                               0xfcfc9593U,
                                                               0x483da389U,
                                                               0xb3a8fac3U,
                                                               0x6f1407e7U,
                                                               0xfc81590fU,
                                                               0xd70cdb9eU,
                                                               0xf93777c1U,
                                                               0xc15ecf6fU,
                                                               0xf954ef1bU,
                                                               0xcfdc04b7U,
                                                               0xb5690979U,
                                                               0x02fefb22U,
                                                               0xfb553154U,
                                                               0x990bb0fdU,
                                                               0x083d1db4U,
                                                               0xd5e9ee89U,
                                                               0x042ac65fU,
                                                               0xff5eef30U,
                                                               0xf899646aU,
                                                               0x54a9f585U,
                                                               0x6c1219f6U,
                                                               0x49c76ab1U,
                                                               0xbcef32baU,
                                                               0x0229bc15U,
                                                               0xfd5b11afU,
                                                               0xe51a3674U,
                                                               0x90ad9d10U,
                                                               0x0b6d93d8U,
                                                               0x1fe01e61U,
                                                               0x3bd05e19U,
                                                               0xcdeccc3dU,
                                                               0x95ef772aU,
                                                               0xfc46b802U,
                                                               0x393129faU,
                                                               0x2284392cU,
                                                               0x079cf746U,
                                                               0x57a1f614U,
                                                               0x52a36759U,
                                                               0x700c7de7U,
                                                               0x3709b71aU,
                                                               0xd6134727U,
                                                               0x8eae0f07U,
                                                               0x1285e216U,
                                                               0x6d5043ddU,
                                                               0x51aa729bU,
                                                               0xc706eedaU,
                                                               0xa823e773U,
                                                               0x520fb211U,
                                                               0xfb9b862dU,
                                                               0xd29e7b00U,
                                                               0x862c38bdU,
                                                               0xc610c17fU,
                                                               0xf205fe85U,
                                                               0xc7bb8575U,
                                                               0x9e9cdef1U,
                                                               0x2549f711U,
                                                               0xb53ac1b4U,
                                                               0x53fbbdefU,
                                                               0x088b9979U,
                                                               0x05435cc9U,
                                                               0xa50e7ff3U,
                                                               0x505c8047U,
                                                               0x512e3646U,
                                                               0x30b5437eU,
                                                               0x1f3e747dU,
                                                               0xf879a0aeU,
                                                               0xc7c173e4U,
                                                               0x6666188eU,
                                                               0xb2d52febU,
                                                               0x86eea49eU,
                                                               0xda935d9aU,
                                                               0x15dd38abU
                                                           };
                                                           
                                                           static const uint32_t T0_3[256] = {
                                                               0x197572c5U,
                                                               0x296c6437U,
                                                               0x01a36affU,
                                                               0x94e5dcceU,
                                                               0xd91b1869U,
                                                               0x6dda3e1dU,
                                                               0xfb4a5e84U,
                                                               0xdce263e5U,
                                                               0x0e9dc438U,
                                                               0xb36c3c6dU,
                                                               0x8b744036U,
                                                               0x016e910dU,
                                                               0x77b39e2dU,
                                                               0x142269dcU,
                                                               0x14ddf65dU,
                                                               0x62d8f874U,
                                                               0x2fec730aU,
                                                               0x826e0798U,
                                                               0x2ca1a51dU,
                                                               0x6a454532U,
                                                               0x9846da97U,
                                                               0x5c4ca290U,
                                                               0x71e335cdU,
                                                               0x8d0db561U,
                                                               0x2093247fU,
                                                               0x9bda8022U,
                                                               0x5f0190dcU,
                                                               0xc7c41599U,
                                                               0x8cb5a6b2U,
                                                               0x3dc13bffU,
                                                               0xf304a474U,
                                                               0x5efef646U,
                                                               0x208aa7bdU,
                                                               0x2dd7ef0aU,
                                                               0xcf6fc0feU,
                                                               0x7836ba44U,
                                                               0xcfb90414U,
                                                               0xe8c314a0U,
                                                               0xd4061777U,
                                                               0x0eb245e7U,
                                                               0x349fb1e6U,
                                                               0x99d53305U,
                                                               0xaaa1442aU,
                                                               0xcbde0f4fU,
                                                               0xe0774227U,
                                                               0xa4046b9fU,
                                                               0xbd6f7048U,
                                                               0xcdfeaa28U,
                                                               0xcb928595U,
                                                               0x82fa0a2dU,
                                                               0x49bdb348U,
                                                               0x61756b99U,
                                                               0x4c40fa51U,
                                                               0xd2cc87d9U,
                                                               0xf878133aU,
                                                               0x2942467cU,
                                                               0xbcece3e4U,
                                                               0xad866553U,
                                                               0x51d9bc99U,
                                                               0x9c2b7888U,
                                                               0x85afa056U,
                                                               0x0ec01255U,
                                                               0xe975b901U,
                                                               0x43fad373U,
                                                               0xd9179137U,
                                                               0x25615bfcU,
                                                               0xc8d8ebb6U,
                                                               0x36af815cU,
                                                               0x92a85008U,
                                                               0x20df5deaU,
                                                               0x7281ee00U,
                                                               0xe48efdbfU,
                                                               0x2b8a237aU,
                                                               0x07cf8082U,
                                                               0x1ad0de57U,
                                                               0xa59d60ddU,
                                                               0xef87c85eU,
                                                               0x352d8a36U,
                                                               0x6b7c368eU,
                                                               0x811b4c50U,
                                                               0xb73e7caaU,
                                                               0x0fd7bf65U,
                                                               0x7dd6069aU,
                                                               0xd845e0edU,
                                                               0x4c74e04aU,
                                                               0x90f38357U,
                                                               0x6a04c55dU,
                                                               0xac2e3a80U,
                                                               0xa98c70c1U,
                                                               0x7613864cU,
                                                               0xda9f03f7U,
                                                               0x0a43cadbU,
                                                               0xe11b3995U,
                                                               0x1785d604U,
                                                               0x18d74858U,
                                                               0x86ac4a0aU,
                                                               0x79098681U,
                                                               0xecc822c8U,
                                                               0x50268cb5U,
                                                               0x3ffa7961U,
                                                               0x83c54454U,
                                                               0x3ef726f6U,
                                                               0xc186ff06U,
                                                               0x0f81b91cU,
                                                               0x18d42b17U,
                                                               0xe3256f92U,
                                                               0x6b217f6aU,
                                                               0xf46cb5e3U,
                                                               0xc8b6a263U,
                                                               0xdb91df56U,
                                                               0x4e0b9d54U,
                                                               0xd6373fc6U,
                                                               0xd304cbdfU,
                                                               0xe8163d05U,
                                                               0x0d5a7379U,
                                                               0x9c16493aU,
                                                               0xeb3caa93U,
                                                               0x9f1fadecU,
                                                               0xed164d47U,
                                                               0xd8c1c204U,
                                                               0xa821e3eeU,
                                                               0xda871f44U,
                                                               0x257ecca9U,
                                                               0x212b0225U,
                                                               0x071274d6U,
                                                               0x8072d150U,
                                                               0xeba3df33U,
                                                               0x504b72eeU,
                                                               0x277c1477U,
                                                               0xd912fcdeU,
                                                               0xa605c510U,
                                                               0x4f022f04U,
                                                               0xabf5ddd7U,
                                                               0x4a7a6a63U,
                                                               0x8b810e93U,
                                                               0x7c7dc41cU,
                                                               0xcd6fd5a2U,
                                                               0x745d0145U,
                                                               0xb9a7bb92U,
                                                               0xe3e50b9fU,
                                                               0x6d5f7407U,
                                                               0x5ea64e75U,
                                                               0x2cfafaacU,
                                                               0x4461b481U,
                                                               0xbf0451a3U,
                                                               0xf714adbeU,
                                                               0xd2ad608bU,
                                                               0x19be3837U,
                                                               0x383723edU,
                                                               0x21d51bcbU,
                                                               0x6bced613U,
                                                               0xbda84f45U,
                                                               0x7463a7b7U,
                                                               0x40414e36U,
                                                               0x8f504c0dU,
                                                               0x290ad9b1U,
                                                               0x47c1b3cbU,
                                                               0x0ec6963cU,
                                                               0xf41cb3a9U,
                                                               0x2b545387U,
                                                               0xfb752109U,
                                                               0x5eb49048U,
                                                               0xbb00186fU,
                                                               0xfa130cfcU,
                                                               0xf7db42c6U,
                                                               0xa6d4a543U,
                                                               0x2fd3941dU,
                                                               0xcf76d911U,
                                                               0xbf316fa1U,
                                                               0x29350eabU,
                                                               0xd1dc728aU,
                                                               0x10391c0eU,
                                                               0x03566f25U,
                                                               0x903c45c6U,
                                                               0xf2b5c971U,
                                                               0x96844efbU,
                                                               0x5e116551U,
                                                               0x211ae36fU,
                                                               0x78e389a2U,
                                                               0x06fcd43fU,
                                                               0x9e12f3cbU,
                                                               0xfd9bc187U,
                                                               0x13d613f8U,
                                                               0xaefed5cdU,
                                                               0x58744540U,
                                                               0x5013eae8U,
                                                               0x99c9ec68U,
                                                               0x71815576U,
                                                               0x38f4f103U,
                                                               0x248d375cU,
                                                               0x5d46b0efU,
                                                               0x86cb75adU,
                                                               0xcece5404U,
                                                               0x7f516cebU,
                                                               0xa19c07b0U,
                                                               0xe543992aU,
                                                               0x9594bbc7U,
                                                               0xc0550da8U,
                                                               0xe1814fddU,
                                                               0xbd6a6166U,
                                                               0x116cfb59U,
                                                               0xa8ca0e05U,
                                                               0x84fc0e81U,
                                                               0x0625fca6U,
                                                               0x78911363U,
                                                               0xec181e95U,
                                                               0xbc45ec52U,
                                                               0xcbfc6225U,
                                                               0x42e9ef9bU,
                                                               0x268263f8U,
                                                               0x372e8accU,
                                                               0x74f1a440U,
                                                               0x87a0eb10U,
                                                               0xbb8104f3U,
                                                               0x920064ffU,
                                                               0x59b1a560U,
                                                               0xa7006bacU,
                                                               0xc2f9add3U,
                                                               0xedb1197fU,
                                                               0x53701a33U,
                                                               0xcc0bd92bU,
                                                               0x53792916U,
                                                               0xb249d51dU,
                                                               0x719a2ff9U,
                                                               0x06696ecbU,
                                                               0xcc2929d0U,
                                                               0x55e1d9f1U,
                                                               0xa73f0e29U,
                                                               0x4c627c75U,
                                                               0x72cf0500U,
                                                               0x1a5f9370U,
                                                               0x3b0b14fbU,
                                                               0x2bb16433U,
                                                               0x33ff8308U,
                                                               0x864934c8U,
                                                               0x9b29e778U,
                                                               0xcf822a5eU,
                                                               0x5f2435e7U,
                                                               0xad2ef5eeU,
                                                               0x823963a2U,
                                                               0x7f3a9a30U,
                                                               0x02b39881U,
                                                               0xac8e0e03U,
                                                               0x38d12760U,
                                                               0xff36d493U,
                                                               0x630347cdU,
                                                               0x7ba3c5d3U,
                                                               0x5ec0535cU,
                                                               0xf29efa7bU,
                                                               0x1ba7b7aaU,
                                                               0x2cb09238U,
                                                               0x0e0ceb66U,
                                                               0x808c72cbU,
                                                               0x6f733e56U,
                                                               0x4f004b8aU,
                                                               0x2976d933U
                                                           };
                                                           
                                                           static const uint32_t T1_0[256] = {
                                                               0x8e067f4bU,
                                                               0xe13a8b31U,
                                                               0x139445deU,
                                                               0x5e33a610U,
                                                               0xca45e5eaU,
                                                               0x29518cd9U,
                                                               0xd5a56de4U,
                                                               0xe6c1b76dU,
                                                               0xeab3621dU,
                                                               0x8517cb44U,
                                                               0x28a9f31cU,
                                                               0x1989ed8bU,
                                                               0xa55e27b6U,
                                                               0xc7e89ec0U,
                                                               0x23a160bfU,
                                                               0xcb1e14dcU,
                                                               0xb078eba3U,
                                                               0xc61c2b1aU,
                                                               0x8ff01767U,
                                                               0xd04456c5U,
                                                               0x95205773U,
                                                               0x535209a2U,
                                                               0x0e0c9196U,
                                                               0xe14e60eaU,
                                                               0xea5a6982U,
                                                               0x98fa31feU,
                                                               0x70ac3b45U,
                                                               0x344c2490U,
                                                               0x3f7067c3U,
                                                               0xcddbd95bU,
                                                               0xbd000f7dU,
                                                               0x93daf4aeU,
                                                               0xd70f7a7dU,
                                                               0x415bc368U,
                                                               0x6c48d42eU,
                                                               0xffcf064bU,
                                                               0xa871d343U,
                                                               0x62ad4f1fU,
                                                               0x438b14f1U,
                                                               0xc11623f4U,
                                                               0xfd5a441aU,
                                                               0x245d7b40U,
                                                               0xc61329c6U,
                                                               0xb3b901f5U,
                                                               0x531b2b23U,
                                                               0xb0c0fbf6U,
                                                               0x5455863aU,
                                                               0x001526c3U,
                                                               0x01e9c566U,
                                                               0x82c2b475U,
                                                               0xecd29722U,
                                                               0x7e876f5fU,
                                                               0x63459d13U,
                                                               0x7dd78daeU,
                                                               0x36ee5a56U,
                                                               0x93a17d47U,
                                                               0x9062473eU,
                                                               0x915ddaeeU,
                                                               0xbc28418eU,
                                                               0x542ec423U,
                                                               0x39db34f5U,
                                                               0xb797f55bU,
                                                               0x85994563U,
                                                               0x1a014b4bU,
                                                               0x2f89f98cU,
                                                               0xd3c7a83fU,
                                                               0xb7f19205U,
                                                               0x729f4a6bU,
                                                               0x727a6e39U,
                                                               0x76bf4c78U,
                                                               0x466934e7U,
                                                               0x2a5c2b1aU,
                                                               0xa88467b9U,
                                                               0x904851d0U,
                                                               0x2e23d78bU,
                                                               0x027bd842U,
                                                               0x608c0aa0U,
                                                               0x5efc0692U,
                                                               0xdabddcfaU,
                                                               0x1cdf9c3dU,
                                                               0xdfca3291U,
                                                               0xe7464d84U,
                                                               0x79ca9ffaU,
                                                               0x80ca1d43U,
                                                               0x2bb2f382U,
                                                               0x3f47728aU,
                                                               0xb25b6f07U,
                                                               0x7aaad3ccU,
                                                               0x0becf023U,
                                                               0xd7246f8fU,
                                                               0xaa386437U,
                                                               0x170c7c98U,
                                                               0x38f38060U,
                                                               0x5707e689U,
                                                               0xc84e61c6U,
                                                               0x7f5ec714U,
                                                               0x555c3c06U,
                                                               0xda8e8de8U,
                                                               0xcb850e88U,
                                                               0x62bb2fbaU,
                                                               0x3e27cb33U,
                                                               0x6dc5fdf6U,
                                                               0xd05b4b73U,
                                                               0xb08b6c7dU,
                                                               0xff685cd9U,
                                                               0x8bcfc153U,
                                                               0x4002ab42U,
                                                               0xb358063dU,
                                                               0xbb003c13U,
                                                               0x1436af53U,
                                                               0x50f75490U,
                                                               0xfb46f9a1U,
                                                               0x76109ad9U,
                                                               0x0eb89a06U,
                                                               0x4546a76aU,
                                                               0x64c1f5cdU,
                                                               0xabd1448cU,
                                                               0x4787ed3eU,
                                                               0x96c8b682U,
                                                               0xefd62b6aU,
                                                               0xd3e496efU,
                                                               0x601a2564U,
                                                               0xca40abf9U,
                                                               0xfcf177eaU,
                                                               0x48609ad3U,
                                                               0xd83627a6U,
                                                               0x5f63bc3cU,
                                                               0x09c90f45U,
                                                               0xd208acbfU,
                                                               0xd099debbU,
                                                               0xd24a6088U,
                                                               0x039d468fU,
                                                               0x88d49433U,
                                                               0xbd662b33U,
                                                               0x1d8f389aU,
                                                               0xc0f2f5d7U,
                                                               0x84399fbaU,
                                                               0x43faa7feU,
                                                               0x35960a0bU,
                                                               0xae292d4cU,
                                                               0x85d1dfcbU,
                                                               0x6db1aaa8U,
                                                               0xcaf546f0U,
                                                               0xb534ad64U,
                                                               0x9c795683U,
                                                               0x0a2f6f9bU,
                                                               0x4d4dfe12U,
                                                               0x6ca331c2U,
                                                               0x7c6724cfU,
                                                               0x9f5c9cc5U,
                                                               0x7ebb2e67U,
                                                               0x33a9d979U,
                                                               0x6d764035U,
                                                               0x4929a2dcU,
                                                               0xbf5ca796U,
                                                               0xc4a7ee3fU,
                                                               0x5087fd77U,
                                                               0x324c01e1U,
                                                               0xc28a2e37U,
                                                               0x8495e941U,
                                                               0x8e50c485U,
                                                               0x3540bb5eU,
                                                               0x6271270bU,
                                                               0xbb2599aeU,
                                                               0x5897dd96U,
                                                               0xde7513b6U,
                                                               0xdd02b8cfU,
                                                               0xc001270aU,
                                                               0x03fb5668U,
                                                               0xb735344cU,
                                                               0xce2e8381U,
                                                               0xb0c692b8U,
                                                               0xa278760cU,
                                                               0x5144d521U,
                                                               0xe76010e5U,
                                                               0x49fb888aU,
                                                               0x8df74d8dU,
                                                               0xe2908b87U,
                                                               0xf70383afU,
                                                               0x1138bf05U,
                                                               0x03d6a7b2U,
                                                               0xdf24e066U,
                                                               0xc3b8ba91U,
                                                               0xf5528e8aU,
                                                               0x1d7be1baU,
                                                               0xa9f1e691U,
                                                               0xbfebd0c6U,
                                                               0xabcf7bf9U,
                                                               0xce984147U,
                                                               0x39520855U,
                                                               0x7f922659U,
                                                               0xcd41319fU,
                                                               0x14eba9d2U,
                                                               0x6d45d7e0U,
                                                               0x69f47d14U,
                                                               0x5725343fU,
                                                               0x95c4693fU,
                                                               0x7d178610U,
                                                               0x289be9b8U,
                                                               0x079c1558U,
                                                               0xce47545cU,
                                                               0x0c3b98beU,
                                                               0xebfeb132U,
                                                               0xe91456e2U,
                                                               0xb2dd851aU,
                                                               0x8c9ff19cU,
                                                               0xe6d6f797U,
                                                               0xc5cd5d43U,
                                                               0x5da04d6fU,
                                                               0x8d4450b6U,
                                                               0xcd1f5cd4U,
                                                               0x01eae170U,
                                                               0xb8f46a99U,
                                                               0xe71ac7bcU,
                                                               0xe779d68eU,
                                                               0x7d8f1762U,
                                                               0xd3c208d3U,
                                                               0xae0c29c4U,
                                                               0x04244713U,
                                                               0xb4b64c80U,
                                                               0x5b3819c7U,
                                                               0xdfd031b2U,
                                                               0xf19c0dbaU,
                                                               0x3e1ee615U,
                                                               0x43dd3bc1U,
                                                               0x5eb6f138U,
                                                               0x15a758dfU,
                                                               0x75ff5ba6U,
                                                               0x07451ceaU,
                                                               0x828d1b23U,
                                                               0xa0ff2ae6U,
                                                               0xee92b99cU,
                                                               0x1a1470a3U,
                                                               0x14ade05dU,
                                                               0x178918c7U,
                                                               0x2c2d916fU,
                                                               0xce48e0e1U,
                                                               0x134e6399U,
                                                               0xe70916e2U,
                                                               0x5594798aU,
                                                               0x5fecfbffU,
                                                               0xd12f9d52U,
                                                               0xdfc0cf81U,
                                                               0x5e64de4dU,
                                                               0x77dd1752U,
                                                               0xec31b2aaU,
                                                               0xe65ece86U,
                                                               0xcbad4ae2U,
                                                               0xbd9773e2U,
                                                               0xd5ad8baaU,
                                                               0x7b6d9d0eU,
                                                               0x545e311aU,
                                                               0x02007e68U,
                                                               0x0c2e0ab9U,
                                                               0xdb8d4ebfU,
                                                               0xb02fafceU
                                                           };
                                                           
                                                           static const uint32_t T1_1[256] = {
                                                               0x50313031U,
                                                               0x50533941U,
                                                               0x830fa8baU,
                                                               0xf4a26025U,
                                                               0x1aff034dU,
                                                               0xde974215U,
                                                               0x6b1850f5U,
                                                               0x9542a702U,
                                                               0x91c883d5U,
                                                               0xa0510c01U,
                                                               0xc6d301e1U,
                                                               0x9fe787e4U,
                                                               0x06f8be82U,
                                                               0x00bff1e7U,
                                                               0x32a4c6f1U,
                                                               0x639575faU,
                                                               0x43ee16f9U,
                                                               0xef4f43b0U,
                                                               0x799a8a37U,
                                                               0x099261d2U,
                                                               0x89738173U,
                                                               0x8e686e72U,
                                                               0xb88dd5f6U,
                                                               0x4695b857U,
                                                               0xe5791e78U,
                                                               0x42bbac65U,
                                                               0x24b33789U,
                                                               0x0d6494c9U,
                                                               0xbd160031U,
                                                               0x7d5438b5U,
                                                               0xd0934cb8U,
                                                               0xcbc5349dU,
                                                               0x1de9e933U,
                                                               0xe6564648U,
                                                               0xf223051eU,
                                                               0x4d357927U,
                                                               0x81765f56U,
                                                               0xa494eabdU,
                                                               0x2f4ca98eU,
                                                               0xbde216baU,
                                                               0xed497e7bU,
                                                               0xbc087d12U,
                                                               0x0e96a98dU,
                                                               0x902d6555U,
                                                               0x5b4bc7d2U,
                                                               0x0745b2c6U,
                                                               0x53de34b8U,
                                                               0x0f479cbbU,
                                                               0xcfc6f532U,
                                                               0xe8cddd72U,
                                                               0x910cf8bdU,
                                                               0xf02b3d66U,
                                                               0xa587d2fbU,
                                                               0x7233ff1aU,
                                                               0xb47408a8U,
                                                               0xf6f08198U,
                                                               0x1b6319d6U,
                                                               0xa6f982afU,
                                                               0xec79e3dbU,
                                                               0x9867ae98U,
                                                               0x0455654aU,
                                                               0x65b77dc2U,
                                                               0x6846f266U,
                                                               0xcb330613U,
                                                               0x018df17cU,
                                                               0x1962068eU,
                                                               0x2ad3d5a3U,
                                                               0x69d8d260U,
                                                               0x5a36dbe7U,
                                                               0xbc3efd4eU,
                                                               0xf228266dU,
                                                               0xa13561baU,
                                                               0xbbb84ec6U,
                                                               0x756255e3U,
                                                               0xafeafbdeU,
                                                               0x4c5d8121U,
                                                               0x7f63c11cU,
                                                               0x549c5bb4U,
                                                               0x59ee2f9fU,
                                                               0xbc9d0bbeU,
                                                               0xe0df6ec1U,
                                                               0xd94d42b9U,
                                                               0x2394ccbdU,
                                                               0x4c32f37cU,
                                                               0xa2183023U,
                                                               0xb3dffd09U,
                                                               0xd1217b5aU,
                                                               0x079bb948U,
                                                               0xcca2d913U,
                                                               0xd5f6dd82U,
                                                               0x9d4a1d18U,
                                                               0xb783685eU,
                                                               0x5b65b2d9U,
                                                               0xf5595777U,
                                                               0xeacf5900U,
                                                               0xe7285864U,
                                                               0x6ba16398U,
                                                               0x9257f61cU,
                                                               0x555ccfb1U,
                                                               0x62a302c8U,
                                                               0xa2e24f87U,
                                                               0x448c442eU,
                                                               0xca3be8d7U,
                                                               0x949cae44U,
                                                               0x87cee63dU,
                                                               0x39d348aeU,
                                                               0x303f3fcbU,
                                                               0xf26a2fc2U,
                                                               0x5397840fU,
                                                               0xfa7f2c2fU,
                                                               0xaa41387aU,
                                                               0x4d735c4eU,
                                                               0x03c24f23U,
                                                               0xe4fc0f85U,
                                                               0xf699c045U,
                                                               0xcb7b9021U,
                                                               0xea57a9a7U,
                                                               0xfa28cb47U,
                                                               0xbe900774U,
                                                               0xd2079bf9U,
                                                               0x12b74b5dU,
                                                               0xe52c8e50U,
                                                               0xe2e10cc0U,
                                                               0x9dd06ff3U,
                                                               0xc37c1d52U,
                                                               0x744344b5U,
                                                               0x4df78521U,
                                                               0x9070f56bU,
                                                               0x5a1b223dU,
                                                               0x3c955b89U,
                                                               0x69048120U,
                                                               0xdc2dbf94U,
                                                               0x1de7541bU,
                                                               0x859b284eU,
                                                               0xa28ee111U,
                                                               0xc129e0d5U,
                                                               0x16105437U,
                                                               0xdb884c67U,
                                                               0x08fe1160U,
                                                               0xeac5072cU,
                                                               0x7fea64daU,
                                                               0x93c37cddU,
                                                               0x743fbf6dU,
                                                               0x08c463d9U,
                                                               0x732b80daU,
                                                               0xb5e3fd51U,
                                                               0x2580745aU,
                                                               0xcd4fb651U,
                                                               0xcf50a59dU,
                                                               0x6f78ea31U,
                                                               0x7dd18656U,
                                                               0xf05e89eaU,
                                                               0x3c7a35c1U,
                                                               0xb01b6339U,
                                                               0x23db24d5U,
                                                               0x285ba57eU,
                                                               0xbea95e5cU,
                                                               0xb629fc7cU,
                                                               0x790a6ae6U,
                                                               0xa9959582U,
                                                               0x42fe3912U,
                                                               0x8b432463U,
                                                               0x4631891fU,
                                                               0xbc8187d3U,
                                                               0x285b99aeU,
                                                               0x76ad8466U,
                                                               0x64ea85feU,
                                                               0xca6118a1U,
                                                               0x7176b6e2U,
                                                               0x1dfe5d2fU,
                                                               0x1471d99fU,
                                                               0xa6b188dcU,
                                                               0x1f2f380aU,
                                                               0x6ceaf199U,
                                                               0xf50a1336U,
                                                               0x84c84184U,
                                                               0x7ad51121U,
                                                               0xf11ebd77U,
                                                               0x53d47c49U,
                                                               0x93ad99a7U,
                                                               0x17df6cb9U,
                                                               0x0c8b4e70U,
                                                               0x5b53c0ffU,
                                                               0xb2b7902aU,
                                                               0xa7d6a0d9U,
                                                               0x3c6a8262U,
                                                               0xb3b2b009U,
                                                               0x84094241U,
                                                               0x7a416994U,
                                                               0xad7f601cU,
                                                               0x2590fa63U,
                                                               0x901a073cU,
                                                               0x9dd1488bU,
                                                               0xfb8c5ed8U,
                                                               0xadb0cb76U,
                                                               0x8188c348U,
                                                               0x92205f16U,
                                                               0xf43ca17aU,
                                                               0x28fceffbU,
                                                               0x01a96f36U,
                                                               0x117f1cfbU,
                                                               0x3d5c4d16U,
                                                               0x117ef6e9U,
                                                               0xaf3b9064U,
                                                               0xba1eabb3U,
                                                               0xfc470a27U,
                                                               0xe59a70aaU,
                                                               0x47aaf059U,
                                                               0x939cc97bU,
                                                               0x238be251U,
                                                               0x4327aad5U,
                                                               0xf85d09d8U,
                                                               0xa3186e54U,
                                                               0x0dcb0e40U,
                                                               0x73e5b6cdU,
                                                               0xb096f570U,
                                                               0x50b29c1fU,
                                                               0x2f0abea1U,
                                                               0x5c689907U,
                                                               0x86c12727U,
                                                               0x28c16deeU,
                                                               0x4bf259deU,
                                                               0x0458b8deU,
                                                               0x1cbf4dcfU,
                                                               0xc2c03beaU,
                                                               0x64dc46b9U,
                                                               0x4e245348U,
                                                               0x8c7897f4U,
                                                               0x12aafb20U,
                                                               0x6db722bbU,
                                                               0x08a995fbU,
                                                               0x2716978dU,
                                                               0xe0fc8a8fU,
                                                               0x7f57baafU,
                                                               0x99e24d8eU,
                                                               0x5825e9fbU,
                                                               0xb7ae6794U,
                                                               0x05574b18U,
                                                               0xcf7d5983U,
                                                               0x857cd028U,
                                                               0xc7a8e7ebU,
                                                               0x88846e80U,
                                                               0x6c080a50U,
                                                               0xc42e574eU,
                                                               0xca192bd9U,
                                                               0x2673d6cdU,
                                                               0xa6e2968bU,
                                                               0xda690888U,
                                                               0x2b03a181U,
                                                               0xb2240359U,
                                                               0x55595f9eU,
                                                               0x3a1c0562U,
                                                               0x8b2d1c62U,
                                                               0x472999a3U,
                                                               0x2d34d7ebU,
                                                               0x17916011U
                                                           };
                                                           
                                                           static const uint32_t T1_2[256] = {
                                                               0xa525cca6U,
                                                               0xdbdfa84bU,
                                                               0x471fa6b5U,
                                                               0x6bc10607U,
                                                               0x3e0b4fbfU,
                                                               0xa5f03b1cU,
                                                               0x344199b8U,
                                                               0x5a9b4902U,
                                                               0x85b702c5U,
                                                               0xd3772b19U,
                                                               0x450c1c6bU,
                                                               0xc4ee3f77U,
                                                               0xc545ec85U,
                                                               0x01a8c6c7U,
                                                               0x4aa1e046U,
                                                               0x5df2a0e9U,
                                                               0x3d283896U,
                                                               0xd0c4f5d8U,
                                                               0xd25f07a1U,
                                                               0x2e3be2acU,
                                                               0xa37d34b7U,
                                                               0x29c44bcdU,
                                                               0x273bc8bcU,
                                                               0xe0476113U,
                                                               0xf8557107U,
                                                               0xaa37b2b2U,
                                                               0x998b5909U,
                                                               0xc24b65c4U,
                                                               0xdcb80622U,
                                                               0x7ba2b1e0U,
                                                               0xfd6e32daU,
                                                               0x12bd2d4fU,
                                                               0xda42cb3aU,
                                                               0x9f9d0075U,
                                                               0x72c5a7adU,
                                                               0x29cd4e68U,
                                                               0x660d2ec5U,
                                                               0xe51bfe3aU,
                                                               0xf4f7cd7cU,
                                                               0x09a0d4e7U,
                                                               0x53ba377dU,
                                                               0x64c3d22dU,
                                                               0x04e63694U,
                                                               0x4e4815f4U,
                                                               0x78bc9bfdU,
                                                               0xeb64ff37U,
                                                               0x1ea2b50eU,
                                                               0x4a846fe3U,
                                                               0x739ba4b9U,
                                                               0x293f46beU,
                                                               0x10bceeb4U,
                                                               0x72f31a26U,
                                                               0x356e9cb1U,
                                                               0xc682a173U,
                                                               0x4193d781U,
                                                               0xdf7f8a3aU,
                                                               0xcb5c208cU,
                                                               0x592f1a24U,
                                                               0xdae595f5U,
                                                               0x905d51b0U,
                                                               0xe4cd7134U,
                                                               0x59adc78dU,
                                                               0x0dfc6cbaU,
                                                               0x40d9dde2U,
                                                               0xbe3344afU,
                                                               0xce9fe384U,
                                                               0xd9b9d64eU,
                                                               0x44894270U,
                                                               0xe05a09dcU,
                                                               0x26006797U,
                                                               0x1c84064eU,
                                                               0x517ab831U,
                                                               0x255fedf3U,
                                                               0x95246118U,
                                                               0xf3c52b0aU,
                                                               0x7d963587U,
                                                               0xbc2d7916U,
                                                               0x2290b13dU,
                                                               0xa2154132U,
                                                               0x9b197bf6U,
                                                               0x2512a548U,
                                                               0xc0bffa48U,
                                                               0xccc4558cU,
                                                               0x6a65a5caU,
                                                               0xd4320ea8U,
                                                               0xad53e85cU,
                                                               0xb3e6ea6eU,
                                                               0x1029a595U,
                                                               0x94eb94e0U,
                                                               0x63d95786U,
                                                               0x10bfc69fU,
                                                               0x115bb901U,
                                                               0x72d8ffbcU,
                                                               0xe01157dfU,
                                                               0x2ff49a38U,
                                                               0x4ac79d60U,
                                                               0xfc625d42U,
                                                               0xd774d0f1U,
                                                               0xc2bcc196U,
                                                               0x87a1b0a0U,
                                                               0x49d4443cU,
                                                               0xd95b15baU,
                                                               0xfff5a8a7U,
                                                               0x1e82327fU,
                                                               0x481b1916U,
                                                               0xbbcd5e6aU,
                                                               0xab7e40e1U,
                                                               0xb34bb8d3U,
                                                               0x6feb71a8U,
                                                               0x290bd85fU,
                                                               0x39bfed1bU,
                                                               0x7ed16c50U,
                                                               0xdd56fcc7U,
                                                               0x3a4f39ebU,
                                                               0xdbb968c8U,
                                                               0xa7adb733U,
                                                               0x45ec2a12U,
                                                               0x1a05790bU,
                                                               0xad9b9389U,
                                                               0x84a9bd7dU,
                                                               0x2e3ce57aU,
                                                               0xaf25dd90U,
                                                               0xd95f8649U,
                                                               0x0439e1b2U,
                                                               0x92d85b58U,
                                                               0x92193159U,
                                                               0xd8b8563cU,
                                                               0x6185ca73U,
                                                               0xad0bceefU,
                                                               0x38449096U,
                                                               0x6be2588eU,
                                                               0x15be4649U,
                                                               0x310089e5U,
                                                               0x7b3d8694U,
                                                               0xac02a922U,
                                                               0x5c10b026U,
                                                               0x3377d3f5U,
                                                               0x0a724075U,
                                                               0x242cd289U,
                                                               0x7dfb2a4bU,
                                                               0xd3c3e100U,
                                                               0xfe68cbf0U,
                                                               0x06429058U,
                                                               0x67dd383bU,
                                                               0x40f3fd6eU,
                                                               0xc4d4d44cU,
                                                               0xf42c17e1U,
                                                               0x4aacff51U,
                                                               0xd72332b7U,
                                                               0x7dc006adU,
                                                               0x7f9a0b63U,
                                                               0xfdf7e938U,
                                                               0xba8b57d6U,
                                                               0xdb99ffa9U,
                                                               0x3c8fdc8cU,
                                                               0x89b161c7U,
                                                               0xe9433fbeU,
                                                               0x0747c63bU,
                                                               0x17c9e87eU,
                                                               0x13a70607U,
                                                               0x8cbe2462U,
                                                               0xe9a03b6fU,
                                                               0xd41ea4d1U,
                                                               0x053f74d4U,
                                                               0xa4db9a4aU,
                                                               0x29ca0e06U,
                                                               0x1a93af45U,
                                                               0x96d67648U,
                                                               0x31214245U,
                                                               0x1a3d24a7U,
                                                               0xe6ec801fU,
                                                               0xdcf7db44U,
                                                               0xa6518298U,
                                                               0x720bb144U,
                                                               0x64f8785fU,
                                                               0xbfbd8871U,
                                                               0x8fd15251U,
                                                               0xa17faf86U,
                                                               0xef1115d0U,
                                                               0x3dbb3bc2U,
                                                               0x272492d6U,
                                                               0x9b694ff4U,
                                                               0x08967fceU,
                                                               0x6e621a51U,
                                                               0xa367f24aU,
                                                               0x7b113acbU,
                                                               0xb1c3990eU,
                                                               0x6209243eU,
                                                               0x45ac98f8U,
                                                               0xfae418afU,
                                                               0xe1cb5c22U,
                                                               0x880af7a7U,
                                                               0x859bbb06U,
                                                               0x21cea285U,
                                                               0xfe6ba805U,
                                                               0xfb573739U,
                                                               0xde4a523cU,
                                                               0x886870a7U,
                                                               0x5bd2aa6bU,
                                                               0xfcb66a6cU,
                                                               0x5a136d08U,
                                                               0x8c0ebc04U,
                                                               0x358601f1U,
                                                               0x253925e7U,
                                                               0xa0ba9bc5U,
                                                               0x4a9f93cfU,
                                                               0x93e8c8ffU,
                                                               0xa18143e8U,
                                                               0xd56d01dcU,
                                                               0xa83b8ef2U,
                                                               0x163e2223U,
                                                               0xc959dc5dU,
                                                               0x5aaea360U,
                                                               0x16c73165U,
                                                               0x071e42e2U,
                                                               0xedd3e051U,
                                                               0xa45f0be8U,
                                                               0xf2332b78U,
                                                               0x97ddcb9bU,
                                                               0x4621a1ceU,
                                                               0x2ceaa275U,
                                                               0x2459cb7bU,
                                                               0xe6c20036U,
                                                               0x0a92b188U,
                                                               0x38fd5bd0U,
                                                               0x82b1d860U,
                                                               0xcfa37036U,
                                                               0x14dd6533U,
                                                               0xdf07e763U,
                                                               0x9bc4e5f1U,
                                                               0x6431b9ecU,
                                                               0x3fb542e6U,
                                                               0x582b4701U,
                                                               0x5dc205d7U,
                                                               0x1ead5177U,
                                                               0x8342083eU,
                                                               0x6256a339U,
                                                               0xa6a66b1bU,
                                                               0x407b021dU,
                                                               0x6233ffbdU,
                                                               0x5592df54U,
                                                               0x24b856b0U,
                                                               0x81c5d4cdU,
                                                               0x9fcdb305U,
                                                               0xf5ad8f3aU,
                                                               0x2a2a651eU,
                                                               0x74363064U,
                                                               0x485da4ceU,
                                                               0x36c8d56cU,
                                                               0x92f94c74U,
                                                               0xc7c07172U,
                                                               0x954d32cfU,
                                                               0xc10c4c65U,
                                                               0x3a0ac2d4U,
                                                               0xb3bb4bffU,
                                                               0xb378de63U
                                                           };
                                                           
                                                           static const uint32_t T1_3[256] = {
                                                               0xab1f30f1U,
                                                               0x47162e90U,
                                                               0xded73188U,
                                                               0x0947e46aU,
                                                               0x6045486bU,
                                                               0x1c4bbd1fU,
                                                               0x64a8f70dU,
                                                               0xb866dd65U,
                                                               0xf15eb66eU,
                                                               0xd1a73425U,
                                                               0xd50c333fU,
                                                               0x149d0b96U,
                                                               0x42625bc8U,
                                                               0x5c4a65a1U,
                                                               0xda9041dbU,
                                                               0x0c730adaU,
                                                               0xd7c25aefU,
                                                               0xfa9fd97eU,
                                                               0x637b40b5U,
                                                               0x6f709badU,
                                                               0x69978cc1U,
                                                               0x84157a6fU,
                                                               0x13d29f01U,
                                                               0x0cc69218U,
                                                               0x1e496036U,
                                                               0xf326d0ceU,
                                                               0x1acc4cd2U,
                                                               0xa39bd6a6U,
                                                               0x9fbc5685U,
                                                               0x5d72e196U,
                                                               0x0b2bffd3U,
                                                               0x1efa7445U,
                                                               0x0a376482U,
                                                               0xd6075d93U,
                                                               0xea786acbU,
                                                               0xecdfcebbU,
                                                               0x069b4fdbU,
                                                               0x341e57aeU,
                                                               0x4189e0e5U,
                                                               0x50ca4c99U,
                                                               0x9bd5320dU,
                                                               0xb6d69de8U,
                                                               0xa6a3f217U,
                                                               0x9695e1f5U,
                                                               0x8f6ce93eU,
                                                               0xe4a3ef0bU,
                                                               0x82d9c724U,
                                                               0x32e6c6c7U,
                                                               0x863379f1U,
                                                               0x09ad63d6U,
                                                               0x5590b3f4U,
                                                               0x392f2e77U,
                                                               0xfd3deaceU,
                                                               0xc158237cU,
                                                               0x1bb79018U,
                                                               0xe8120843U,
                                                               0x1b733debU,
                                                               0x044127d3U,
                                                               0x3739dc35U,
                                                               0x192607bbU,
                                                               0x6f5f60cfU,
                                                               0x2f6956b1U,
                                                               0x749a24a8U,
                                                               0xa3617289U,
                                                               0xa9370390U,
                                                               0x55e389d3U,
                                                               0x6adb4daaU,
                                                               0x1cac0b5eU,
                                                               0x9c6989adU,
                                                               0xde188271U,
                                                               0x73d939c9U,
                                                               0x593aa7adU,
                                                               0xa58e5f3fU,
                                                               0x5c1882b2U,
                                                               0xcd961c31U,
                                                               0xab70e036U,
                                                               0xe24af214U,
                                                               0xbc1c8aa3U,
                                                               0x89ac9f43U,
                                                               0x320bb14bU,
                                                               0x8eb50de1U,
                                                               0xcc4bf738U,
                                                               0x30810d31U,
                                                               0x738ce443U,
                                                               0xd4ccb4b7U,
                                                               0x302cd731U,
                                                               0x0f27400fU,
                                                               0xc86c9c33U,
                                                               0x08dffd00U,
                                                               0x82ab54d6U,
                                                               0x541fe68bU,
                                                               0x31efd797U,
                                                               0x12d3f156U,
                                                               0x7c234b75U,
                                                               0xf50f6836U,
                                                               0xf0bbbafdU,
                                                               0xbd5f66e9U,
                                                               0xbfc1787aU,
                                                               0x3dfde43bU,
                                                               0x2f967bd2U,
                                                               0x8a417555U,
                                                               0x1cb288b2U,
                                                               0x50e0236eU,
                                                               0xb1e9ce25U,
                                                               0x89ae9359U,
                                                               0x8d5b0b5fU,
                                                               0xad4b5534U,
                                                               0x986d0d28U,
                                                               0x804581c8U,
                                                               0xde4458bdU,
                                                               0x1490ed20U,
                                                               0xe3422f86U,
                                                               0x71ca3f01U,
                                                               0x95997438U,
                                                               0xdeaaf4a1U,
                                                               0x1cc8988cU,
                                                               0xc868a51fU,
                                                               0xb15678fcU,
                                                               0x56300df7U,
                                                               0x67a99728U,
                                                               0x8fe5bccaU,
                                                               0x5287ea8aU,
                                                               0xa2ecefafU,
                                                               0x4f6338a9U,
                                                               0x2788e9c3U,
                                                               0xb2ff87a6U,
                                                               0x14225d2eU,
                                                               0x00925c25U,
                                                               0x1296c095U,
                                                               0x207b32a4U,
                                                               0x83b89060U,
                                                               0xf9ab0a31U,
                                                               0x7adaa21bU,
                                                               0xe82975a2U,
                                                               0x745f4129U,
                                                               0xff783a32U,
                                                               0x34966914U,
                                                               0x715cec54U,
                                                               0xfe00cae9U,
                                                               0x463ae794U,
                                                               0xe2730a5dU,
                                                               0x9014402bU,
                                                               0x85e82dc7U,
                                                               0x0c6c17feU,
                                                               0x8da8cce9U,
                                                               0x2fa7d8ceU,
                                                               0x521d4695U,
                                                               0x94032b3aU,
                                                               0x660647ffU,
                                                               0x128cbc70U,
                                                               0x40f12219U,
                                                               0x2837e408U,
                                                               0xba1b9c7eU,
                                                               0xed700873U,
                                                               0x24b8a762U,
                                                               0xd3cae135U,
                                                               0x9d9f3369U,
                                                               0x7d9409cbU,
                                                               0x9a534326U,
                                                               0x71177fb8U,
                                                               0xa8cb93e8U,
                                                               0x338bc229U,
                                                               0x2ba262feU,
                                                               0x48e4d43dU,
                                                               0xde2c63eeU,
                                                               0x9addcaddU,
                                                               0xd0abc086U,
                                                               0x3fd2e787U,
                                                               0xdf63209aU,
                                                               0x5e7e91d2U,
                                                               0xfc28d06cU,
                                                               0x04dadeb8U,
                                                               0x1dfb3ca3U,
                                                               0x0739595aU,
                                                               0x678f2c57U,
                                                               0x8867adf1U,
                                                               0xc7af9b19U,
                                                               0xf5d6872dU,
                                                               0x079ebc83U,
                                                               0x9dd76c96U,
                                                               0x8f2efc13U,
                                                               0x8c10c7ebU,
                                                               0x78b1ad92U,
                                                               0x0181414bU,
                                                               0xc17f7f36U,
                                                               0xdd216ad1U,
                                                               0xf3204eb2U,
                                                               0x699e18f5U,
                                                               0x1ef5b247U,
                                                               0x417ec65dU,
                                                               0x5dbd5b72U,
                                                               0x1212fe43U,
                                                               0x6d84c7b9U,
                                                               0x8f102b63U,
                                                               0x1d2ef9a4U,
                                                               0x3dca1151U,
                                                               0xcff582fcU,
                                                               0x4c5bed9cU,
                                                               0x7839bb95U,
                                                               0x4cd62a67U,
                                                               0x4f1f102aU,
                                                               0x72e239d6U,
                                                               0x3df9b9f2U,
                                                               0x1afdb67dU,
                                                               0xfcd13044U,
                                                               0xbefa385fU,
                                                               0x377cc6c3U,
                                                               0xe32bfa3eU,
                                                               0xb4e14be1U,
                                                               0x0b491062U,
                                                               0xec7f7fd5U,
                                                               0xa8893ba9U,
                                                               0xa90004eaU,
                                                               0x2a0d0b10U,
                                                               0x4b2b1962U,
                                                               0xdd03df3bU,
                                                               0x359c9a56U,
                                                               0xd5ab3f43U,
                                                               0x2d185924U,
                                                               0x94c3de23U,
                                                               0x7a96f030U,
                                                               0x9cec7e6aU,
                                                               0x92b7002bU,
                                                               0xdf05ccbbU,
                                                               0x2002b4a2U,
                                                               0xeb2f083dU,
                                                               0x3bbbc98dU,
                                                               0xf56429a3U,
                                                               0x6d4ef7b1U,
                                                               0xda5061bfU,
                                                               0xa6753d69U,
                                                               0x6cd92fefU,
                                                               0x3a25e565U,
                                                               0xfec0650fU,
                                                               0x19120ebcU,
                                                               0x89d5539cU,
                                                               0x5fc793ccU,
                                                               0x1bd653baU,
                                                               0x22d8f0dfU,
                                                               0x1652e00aU,
                                                               0xbab6d869U,
                                                               0xf3e590ffU,
                                                               0x9f7f7f25U,
                                                               0x6902f3c3U,
                                                               0xafde6518U,
                                                               0x2df5382fU,
                                                               0x30362640U,
                                                               0xbc78f75eU,
                                                               0x479c4ee1U,
                                                               0x408ad856U,
                                                               0x316332deU,
                                                               0xf866a6b7U,
                                                               0x0d3d9edcU,
                                                               0xe2d26688U,
                                                               0x8a172fb4U,
                                                               0x81622fd2U
                                                           };
                                                           
                                                           static __attribute__((always_inline)) inline uint32_t rotl32(uint32_t x, uint32_t n) noexcept {
                                                           
                                                               return ((x << n) | (x >> (0x00000020U - n)));
                                                           }
                                                           
                                                           static __attribute__((always_inline)) inline uint32_t derive_seed() noexcept {
                                                           
                                                               const uint32_t s0 = 0x5ccb62eaU;
                                                               uint32_t x0 = T0_0[(s0 & 0x000000ffU)];
                                                               uint32_t x1 = T0_1[((s0 >> 0x00000008U) & 0x000000ffU)];
                                                               uint32_t x2 = T0_2[((s0 >> 0x00000010U) & 0x000000ffU)];
                                                               uint32_t x3 = T0_3[((s0 >> 0x00000018U) & 0x000000ffU)];
                                                               uint32_t y0 = (rotl32(x0, 0x00000007U) ^ x1);
                                                               uint32_t y1 = (rotl32(x1, 0x0000000bU) ^ x2);
                                                               uint32_t y2 = (rotl32(x2, 0x00000013U) ^ x3);
                                                               uint32_t y3 = (rotl32(x3, 0x00000017U) ^ x0);
                                                               uint32_t z0 = T1_0[(y0 & 0x000000ffU)];
                                                               uint32_t z1 = T1_1[(y1 & 0x000000ffU)];
                                                               uint32_t z2 = T1_2[(y2 & 0x000000ffU)];
                                                               uint32_t z3 = T1_3[(y3 & 0x000000ffU)];
                                                               return (((z0 ^ z1) ^ z2) ^ z3);
                                                           }
                                
                                } // namespace asgard_whitebox
                                
                                static __attribute__((always_inline)) inline uint32_t asgard_wbox_derive_seed() noexcept {
                                
                                    return asgard_whitebox::derive_seed();
                                }
                                
                                // Randomized Architectural Register Map (π ∈ S_32)
                                
                                enum RegMap : uint8_t {
                                                           REG_RAX = 24,
                                                           REG_RCX = 10,
                                                           REG_RDX = 28,
                                                           REG_RBX = 30,
                                                           REG_RSP = 4,
                                                           REG_RBP = 19,
                                                           REG_RSI = 3,
                                                           REG_RDI = 11,
                                                           REG_R8 = 2,
                                                           REG_R9 = 26,
                                                           REG_R10 = 5,
                                                           REG_R11 = 13,
                                                           REG_R12 = 20,
                                                           REG_R13 = 27,
                                                           REG_R14 = 17,
                                                           REG_R15 = 21,
                                                           REG_VTMP0 = 23,
                                                           REG_VTMP1 = 25,
                                                           REG_VTMP2 = 31,
                                                           REG_VTMP3 = 16,
                                                           REG_VIP = 7,
                                                           REG_VSP = 22,
                                                           REG_VKEY = 12,
                                                           REG_VX18 = 1,
                                                           REG_VX19 = 8,
                                                           REG_VX20 = 18,
                                                           REG_VX21 = 6,
                                                           REG_VX22 = 14,
                                                           REG_VX23 = 15,
                                                           REG_VX24 = 29,
                                                           REG_VX25 = 0,
                                                           REG_VX26 = 9,
                                                           
                                };
                                
                                // 64-bit Cryptographic Key Derivation for Bytecode Offset (SplitMix64)
                                
                                __attribute__((always_inline)) inline static uint64_t key64_for_offset(uint32_t seed, size_t offset) noexcept {
                                
                                    uint64_t s64 = static_cast<uint64_t>(seed);
                                    uint64_t x0 = (((s64 << 0x0000000000000020ULL) | (s64 ^ 0x000000009e3779b9ULL)) ^ (static_cast<uint64_t>(offset) * 0x517cc1b727220a95ULL));
                                    uint64_t x1 = ((x0 ^ (x0 >> 0x000000000000001eULL)) * 0xbf58476d1ce4e5b9ULL);
                                    uint64_t x2 = ((x1 ^ (x1 >> 0x000000000000001bULL)) * 0x94d049bb133111ebULL);
                                    return (x2 ^ (x2 >> 0x000000000000001fULL));
                                }
                                
                                // Handlers Table Integrity Hash
                                
                                __attribute__((always_inline)) inline static uint64_t compute_handlers_hash(const uintptr_t* all_domains, size_t num_domains) noexcept {
                                
                                    uint64_t h = 0x5877cafebabe1337ULL;
                                    for (size_t d = 0x0000000000000000ULL; d < num_domains; ++d) {
                                    
                                        for (size_t op = 0x0000000000000000ULL; op < 0x0000000000000100ULL; ++op) {
                                        
                                            uint64_t ptr_val = static_cast<uint64_t>(all_domains[((d * 0x0000000000000100ULL) + op)]);
                                            h ^= (ptr_val * 0x9e3779b97f4a7c15ULL);
                                            h = ((h >> 0x000000000000001bULL) | (h << 0x0000000000000025ULL));
                                            h *= 0xbf58476d1ce4e5b9ULL;
                                        }
                                    }
                                    h ^= asgard_mem_integrity::compute_section_integrity_hash();
                                    return (h ^ (h >> 0x000000000000001fULL));
                                }
                                
                                // Blinded VMContext with Canary Guard Zones & Per-Slot Masking (P1-04b)
                                
                                struct VMContext {
                                                      static inline constexpr uint64_t CANARY_VAL = 0xcafebabe13375877ULL;
                                                      uint64_t canary_head = CANARY_VAL;
                                                      uint64_t mid_canaries[32];
                                                      uint64_t gprs[32];
                                                      uint64_t slot_masks[32];
                                                      uint64_t vregs[32][8];
                                                      uint64_t stack[512];
                                                      size_t sp;
                                                      uint64_t reg_mask;
                                                      uint32_t init_seed;
                                                      uint64_t poison_penalty;
                                                      uint64_t running_key;
                                                      bool cf;
                                                      bool zf;
                                                      bool sf;
                                                      bool of;
                                                      bool pf;
                                                      bool trapped;
                                                      size_t executed_instructions;
                                                      uint64_t canary_tail = CANARY_VAL;
                                                      uint64_t decoy_sink = 0x0000000000000000ULL;
                                                      uint64_t oblivious_frame[64];
                                                      static inline constexpr size_t REG_AFFINE_A = 9;
                                                      static inline constexpr size_t REG_AFFINE_B = 22;
                                                      static __attribute__((always_inline)) inline uint8_t reg_phys_idx(uint8_t i) noexcept {
                                                      
                                                          return static_cast<uint8_t>((((static_cast<size_t>((i & 31)) * REG_AFFINE_A) + REG_AFFINE_B) & 31));
                                                      }
                                                      __attribute__((always_inline)) inline void init(uint32_t seed = asgard_wbox_derive_seed()) noexcept {
                                                      
                                                          init_seed = seed;
                                                          poison_penalty = ((key64_for_offset(seed, 0x0000000000005877ULL) ^ 0xcaa7e1d8718bf877ULL) | 0x0000000000000001ULL);
                                                          running_key = (key64_for_offset(seed, 0x0000000013375877ULL) ^ 0xcafebabe13375877ULL);
                                                          reg_mask = (0x5a5a5a5a13375877ULL ^ (static_cast<uint64_t>(seed) * 0x9e3779b97f4a7c15ULL));
                                                          for (size_t i = 0x0000000000000000ULL; i < 0x0000000000000020ULL; ++i) {
                                                          
                                                              slot_masks[i] = (key64_for_offset(seed, (0x0000000000001000ULL + i)) ^ 0xa5a5a5a51337beefULL);
                                                              gprs[i] = (slot_masks[i] ^ reg_mask);
                                                              mid_canaries[i] = (CANARY_VAL ^ ((static_cast<uint64_t>(i) * 0x517cc1b727220a95ULL) ^ static_cast<uint64_t>(seed)));
                                                              vregs[i][0] = 0x0000000000000000ULL;
                                                              for (size_t v = 0x0000000000000001ULL; v < 0x0000000000000008ULL; ++v) {
                                                              
                                                                  vregs[i][v] = 0x0000000000000000ULL;
                                                              }
                                                          }
                                                          sp = 0x0000000000000000ULL;
                                                          cf = false;
                                                          zf = false;
                                                          sf = false;
                                                          of = false;
                                                          pf = false;
                                                          trapped = false;
                                                          executed_instructions = 0x0000000000000000ULL;
                                                          canary_head = CANARY_VAL;
                                                          canary_tail = CANARY_VAL;
                                                          decoy_sink = 0x0000000000000000ULL;
                                                          for (size_t i = 0x0000000000000000ULL; i < 0x0000000000000040ULL; ++i) {
                                                          
                                                              oblivious_frame[i] = 0x0000000000000000ULL;
                                                          }
                                                      }
                                                      static __attribute__((always_inline)) inline uint64_t advance_key_step(uint64_t k, uint8_t op, uint8_t dst, int64_t imm) noexcept {
                                                      
                                                          uint64_t x = (k ^ (((static_cast<uint64_t>(op) * 0x9e3779b97f4a7c15ULL) + (static_cast<uint64_t>(dst) << 0x0000000000000018ULL)) + static_cast<uint64_t>(imm)));
                                                          uint64_t rot = ((x >> 0x0000000000000017ULL) | (x << 0x0000000000000029ULL));
                                                          return ((rot * 0xbf58476d1ce4e5b9ULL) ^ 0x5877cafe1337beefULL);
                                                      }
                                                      __attribute__((always_inline)) inline void advance_running_key(uint8_t op, uint8_t dst, int64_t imm) noexcept {
                                                      
                                                          running_key = advance_key_step(running_key, op, dst, imm);
                                                      }
                                                      static __attribute__((always_inline)) inline uint64_t anchor_key(uint32_t seed, uint64_t off, uint64_t addr_hash = 0) noexcept {
                                                      
                                                          return (key64_for_offset((seed ^ 0x5bd1e995U), static_cast<size_t>((off ^ 0x0000000013375877ULL))) ^ addr_hash);
                                                      }
                                                      __attribute__((always_inline)) inline void reanchor_running_key(uint64_t off, uint64_t addr_hash = 0) noexcept {
                                                      
                                                          running_key = anchor_key(init_seed, off, addr_hash);
                                                      }
                                                      static __attribute__((always_inline)) inline uint64_t poly_hash64(uint64_t x) noexcept {
                                                      
                                                          uint64_t x1 = ((x ^ (x >> 0x000000000000001eULL)) * 0xbf58476d1ce4e5b9ULL);
                                                          uint64_t x2 = ((x1 ^ (x1 >> 0x000000000000001bULL)) * 0x94d049bb133111ebULL);
                                                          return (x2 ^ (x2 >> 0x000000000000001fULL));
                                                      }
                                                      static __attribute__((always_inline)) inline uint64_t branch_invariant_poly_update(uint64_t key, uint64_t delta, uint64_t poly_const) noexcept {
                                                      
                                                          uint64_t c = (poly_const | 0x0000000000000001ULL);
                                                          return poly_hash64((key ^ (c * delta)));
                                                      }
                                                      __attribute__((always_inline)) inline void apply_poly_merge_update(uint64_t delta, uint64_t poly_const) noexcept {
                                                      
                                                          running_key = branch_invariant_poly_update(running_key, delta, poly_const);
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t get_vkey() const noexcept {
                                                      
                                                          return running_key;
                                                      }
                                                      __attribute__((always_inline)) inline bool verify_canaries() const noexcept {
                                                      
                                                          if ((canary_head != CANARY_VAL) || (canary_tail != CANARY_VAL)) {
                                                          
                                                              return false;
                                                          }
                                                          size_t frame = ((sp >> 0x0000000000000004ULL) & 0x000000000000001fULL);
                                                          uint64_t expected = ((CANARY_VAL ^ (static_cast<uint64_t>(frame) * 0x517cc1b727220a95ULL)) ^ static_cast<uint64_t>(init_seed));
                                                          return (mid_canaries[frame] == expected);
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t get_reg(uint8_t i) const noexcept {
                                                      
                                                          size_t idx = static_cast<size_t>(reg_phys_idx(i));
                                                          return ((gprs[idx] ^ slot_masks[idx]) ^ reg_mask);
                                                      }
                                                      __attribute__((always_inline)) inline void set_reg(uint8_t i, uint64_t v) noexcept {
                                                      
                                                          size_t idx = static_cast<size_t>(reg_phys_idx(i));
                                                          uint64_t new_m = ((slot_masks[idx] ^ running_key) * 0x9e3779b97f4a7c15ULL);
                                                          slot_masks[idx] = new_m;
                                                          gprs[idx] = (v ^ (new_m ^ reg_mask));
                                                      }
                                                      __attribute__((always_inline)) inline void evolve_slot_mask(uint8_t i, uint32_t k) noexcept {
                                                      
                                                          size_t idx = static_cast<size_t>(reg_phys_idx(i));
                                                          uint64_t cur_val = (gprs[idx] ^ (slot_masks[idx] ^ reg_mask));
                                                          uint64_t delta = ((static_cast<uint64_t>(k) * 0x6a09e667f3bcc908ULL) ^ (static_cast<uint64_t>(idx) * 0x517cc1b727220a95ULL));
                                                          slot_masks[idx] = ((slot_masks[idx] ^ delta) * 0xbf58476d1ce4e5b9ULL);
                                                          gprs[idx] = (cur_val ^ (slot_masks[idx] ^ reg_mask));
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t get_vreg_lane(uint8_t i, size_t lane) const noexcept {
                                                      
                                                          return vregs[(i & 31)][(lane & 7)];
                                                      }
                                                      __attribute__((always_inline)) inline void set_vreg_lane(uint8_t i, size_t lane, uint64_t value) noexcept {
                                                      
                                                          vregs[(i & 31)][(lane & 7)] = value;
                                                      }
                                                      __attribute__((always_inline)) inline void set_vreg(uint8_t i, uint64_t lo, uint64_t hi) noexcept {
                                                      
                                                          vregs[(i & 31)][0] = lo;
                                                          vregs[(i & 31)][1] = hi;
                                                          for (size_t v = 0x0000000000000002ULL; v < 0x0000000000000008ULL; ++v) {
                                                          
                                                              vregs[(i & 31)][v] = 0x0000000000000000ULL;
                                                          }
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t get_rax() const noexcept {
                                                      
                                                          return get_reg(REG_RAX);
                                                      }
                                                      __attribute__((always_inline)) inline void set_rax(uint64_t v) noexcept {
                                                      
                                                          set_reg(REG_RAX, v);
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t get_rdi() const noexcept {
                                                      
                                                          return get_reg(REG_RDI);
                                                      }
                                                      __attribute__((always_inline)) inline void set_rdi(uint64_t v) noexcept {
                                                      
                                                          set_reg(REG_RDI, v);
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t get_rsi() const noexcept {
                                                      
                                                          return get_reg(REG_RSI);
                                                      }
                                                      __attribute__((always_inline)) inline void set_rsi(uint64_t v) noexcept {
                                                      
                                                          set_reg(REG_RSI, v);
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t get_fs_base() const noexcept {
                                                      
                                                          return get_reg(REG_VX25);
                                                      }
                                                      __attribute__((always_inline)) inline void set_fs_base(uint64_t v) noexcept {
                                                      
                                                          set_reg(REG_VX25, v);
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t get_gs_base() const noexcept {
                                                      
                                                          return get_reg(REG_VX26);
                                                      }
                                                      __attribute__((always_inline)) inline void set_gs_base(uint64_t v) noexcept {
                                                      
                                                          set_reg(REG_VX26, v);
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t rns_add(uint64_t a, uint64_t b) const noexcept {
                                                      
                                                          return asgard_rns::decode(asgard_rns::add(asgard_rns::encode(a), asgard_rns::encode(b)));
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t rns_sub(uint64_t a, uint64_t b) const noexcept {
                                                      
                                                          return asgard_rns::decode(asgard_rns::sub(asgard_rns::encode(a), asgard_rns::encode(b)));
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t rns_mul(uint64_t a, uint64_t b) const noexcept {
                                                      
                                                          return asgard_rns::decode(asgard_rns::mul(asgard_rns::encode(a), asgard_rns::encode(b)));
                                                      }
                                                      __attribute__((always_inline)) inline void evolve_mask(uint32_t k) noexcept {
                                                      
                                                          uint64_t delta = ((static_cast<uint64_t>(k) * 0x6a09e667f3bcc908ULL) ^ 0x0000000000001337ULL);
                                                          uint64_t old_mask = reg_mask;
                                                          uint64_t new_mask = ((reg_mask ^ delta) + 0x0000000000005877ULL);
                                                          for (size_t i = 0x0000000000000000ULL; i < 0x0000000000000020ULL; ++i) {
                                                          
                                                              gprs[i] = ((gprs[i] ^ old_mask) ^ new_mask);
                                                          }
                                                          reg_mask = new_mask;
                                                      }
                                                      __attribute__((always_inline)) inline void rotate_registers_epoch(uint32_t from_ep, uint32_t to_ep) noexcept {
                                                      
                                                          uint32_t tr = (((from_ep & 3) << 2) | (to_ep & 3));
                                                          switch (tr) {
                                                          
                                                            case 1: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(1)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(1)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(10)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(14)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(3)]);
                                                                break;
                                                            }
                                                            case 2: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(10)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(9)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(9)], slot_masks[reg_phys_idx(14)]);
                                                                break;
                                                            }
                                                            case 3: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(14)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(6)], gprs[reg_phys_idx(8)]);
                                                                std::swap(slot_masks[reg_phys_idx(6)], slot_masks[reg_phys_idx(8)]);
                                                                std::swap(gprs[reg_phys_idx(6)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(6)], slot_masks[reg_phys_idx(10)]);
                                                                break;
                                                            }
                                                            case 4: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(14)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(10)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(1)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(1)]);
                                                                break;
                                                            }
                                                            case 6: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(10)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(1)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(1)]);
                                                                break;
                                                            }
                                                            case 7: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(14)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(1)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(1)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(8)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(8)], slot_masks[reg_phys_idx(10)]);
                                                                break;
                                                            }
                                                            case 8: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(10)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(9)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(9)], slot_masks[reg_phys_idx(14)]);
                                                                break;
                                                            }
                                                            case 9: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(1)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(1)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(10)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(12)]);
                                                                break;
                                                            }
                                                            case 11: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(14)]);
                                                                std::swap(gprs[reg_phys_idx(8)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(8)], slot_masks[reg_phys_idx(10)]);
                                                                std::swap(gprs[reg_phys_idx(8)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(8)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(8)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(8)], slot_masks[reg_phys_idx(15)]);
                                                                break;
                                                            }
                                                            case 12: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(14)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(6)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(6)], slot_masks[reg_phys_idx(10)]);
                                                                std::swap(gprs[reg_phys_idx(6)], gprs[reg_phys_idx(8)]);
                                                                std::swap(slot_masks[reg_phys_idx(6)], slot_masks[reg_phys_idx(8)]);
                                                                break;
                                                            }
                                                            case 13: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(1)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(1)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(14)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(8)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(8)], slot_masks[reg_phys_idx(10)]);
                                                                break;
                                                            }
                                                            case 14: {
                                                            
                                                                std::swap(gprs[reg_phys_idx(0)], gprs[reg_phys_idx(13)]);
                                                                std::swap(slot_masks[reg_phys_idx(0)], slot_masks[reg_phys_idx(13)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(14)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(14)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(7)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(7)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(3)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(3)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(9)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(9)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(6)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(6)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(5)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(5)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(4)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(4)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(2)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(2)]);
                                                                std::swap(gprs[reg_phys_idx(1)], gprs[reg_phys_idx(12)]);
                                                                std::swap(slot_masks[reg_phys_idx(1)], slot_masks[reg_phys_idx(12)]);
                                                                std::swap(gprs[reg_phys_idx(8)], gprs[reg_phys_idx(15)]);
                                                                std::swap(slot_masks[reg_phys_idx(8)], slot_masks[reg_phys_idx(15)]);
                                                                std::swap(gprs[reg_phys_idx(8)], gprs[reg_phys_idx(11)]);
                                                                std::swap(slot_masks[reg_phys_idx(8)], slot_masks[reg_phys_idx(11)]);
                                                                std::swap(gprs[reg_phys_idx(8)], gprs[reg_phys_idx(10)]);
                                                                std::swap(slot_masks[reg_phys_idx(8)], slot_masks[reg_phys_idx(10)]);
                                                                break;
                                                            }
                                                            default: {
                                                            
                                                                break;
                                                            }
                                                          }
                                                      }
                                                      static inline constexpr size_t STACK_SIZE = 512;
                                                      static inline constexpr size_t STACK_STRIDE = 113;
                                                      static inline constexpr size_t STACK_OFFSET = 48;
                                                      __attribute__((always_inline)) inline size_t scramble_stack_idx(size_t index) const noexcept {
                                                      
                                                          return static_cast<size_t>((((index * STACK_STRIDE) + STACK_OFFSET) & (STACK_SIZE - 1)));
                                                      }
                                                      __attribute__((always_inline)) inline void push(uint64_t v) noexcept {
                                                      
                                                          if (!verify_canaries()) {
                                                          
                                                              reg_mask ^= poison_penalty;
                                                              trapped = true;
                                                          }
                                                          if (sp < STACK_SIZE) {
                                                          
                                                              size_t phys_idx = scramble_stack_idx(sp);
                                                              uint64_t enc_mask = ((static_cast<uint64_t>(sp) * 0x9e3779b97f4a7c15ULL) ^ 0xa5a5a5a55a5a5a5aULL);
                                                              stack[phys_idx] = (v ^ enc_mask);
                                                              sp += 1;
                                                          }
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t pop() noexcept {
                                                      
                                                          if (!verify_canaries()) {
                                                          
                                                              reg_mask ^= poison_penalty;
                                                              trapped = true;
                                                          }
                                                          if (sp > 0) {
                                                          
                                                              sp -= 1;
                                                              size_t phys_idx = scramble_stack_idx(sp);
                                                              uint64_t enc_mask = ((static_cast<uint64_t>(sp) * 0x9e3779b97f4a7c15ULL) ^ 0xa5a5a5a55a5a5a5aULL);
                                                              uint64_t val = (stack[phys_idx] ^ enc_mask);
                                                              stack[phys_idx] = (0xdeadbeefcafe1337ULL ^ enc_mask);
                                                              return val;
                                                          }
                                                          return 0x0000000000000000ULL;
                                                      }
                                                      __attribute__((always_inline)) inline void oblivious_frame_store(size_t logical_idx, uint64_t v) noexcept {
                                                      
                                                          
                                                          #if defined(ASGARD_OBLIVIOUS_MEM)
                                                          size_t p_idx = asgard::oblivious_mem::logical_to_physical_slot((logical_idx & 63), 37, 17, 64);
                                                          uint64_t mask = asgard::oblivious_mem::slot_tweak_mask(running_key, (logical_idx & 63));
                                                          oblivious_frame[p_idx] = (v ^ mask);
                                                          decoy_sink = (v ^ 0x5877cafe1337beefULL);
                                                          #else
                                                          oblivious_frame[(logical_idx & 63)] = v;
                                                          #endif
                                                          
                                                      }
                                                      __attribute__((always_inline)) inline uint64_t oblivious_frame_load(size_t logical_idx) const noexcept {
                                                      
                                                          
                                                          #if defined(ASGARD_OBLIVIOUS_MEM)
                                                          size_t p_idx = asgard::oblivious_mem::logical_to_physical_slot((logical_idx & 63), 37, 17, 64);
                                                          size_t quad_base_idx = (p_idx & (~(static_cast<size_t>(3))));
                                                          size_t target_slot = (p_idx & 3);
                                                          uint64_t raw_val = asgard::oblivious_mem::oblivious_read_quad((&oblivious_frame[quad_base_idx]), target_slot);
                                                          uint64_t mask = asgard::oblivious_mem::slot_tweak_mask(running_key, (logical_idx & 63));
                                                          return (raw_val ^ mask);
                                                          #else
                                                          return oblivious_frame[(logical_idx & 63)];
                                                          #endif
                                                          
                                                      }
                                                      uint64_t trace_digest = 0x53b7d9f7a1b4283eULL;
                                                      uint64_t bridge_state[16];
                                                          inline void morph_math_to_flow(uint64_t target_digest = 0) noexcept {
#if defined(ASGARD_MULTI_VM_ENABLED)
        uint64_t dig = target_digest ? target_digest : trace_digest;
        uint64_t regs[16];
        for (int i = 0; i < 16; ++i) regs[i] = get_reg(i);
        in_place_morph_math_to_flow(regs, bridge_state, dig);
        trace_digest = bridge_rol64(dig, 13) ^ 0x5877CAFEULL;
#else
        (void)target_digest;
#endif
    }
                                                          inline void morph_flow_to_math(uint64_t target_digest = 0) noexcept {
#if defined(ASGARD_MULTI_VM_ENABLED)
        uint64_t dig = target_digest ? target_digest : (bridge_rol64(trace_digest, 51) ^ 0x5877CAFEULL);
        uint64_t regs[16];
        for (int i = 0; i < 16; ++i) regs[i] = get_reg(i);
        in_place_morph_flow_to_math(bridge_state, regs, dig);
        trace_digest = dig;
#else
        (void)target_digest;
#endif
    }
                                                      
                                };
                                
                                // Flag Evaluation and Condition Check Helpers
                                
                                __attribute__((always_inline)) inline static bool eval_condition(const VMContext& ctx, uint8_t cond) noexcept {
                                
                                    switch (cond) {
                                                     case 0: {
                                                                  return ctx.zf;
                                                     }
                                                     case 1: {
                                                                  return (!ctx.zf);
                                                     }
                                                     case 2: {
                                                                  return ctx.cf;
                                                     }
                                                     case 3: {
                                                                  return (!ctx.cf);
                                                     }
                                                     case 4: {
                                                                  return (ctx.cf || ctx.zf);
                                                     }
                                                     case 5: {
                                                                  return ((!ctx.cf) && (!ctx.zf));
                                                     }
                                                     case 6: {
                                                                  return ctx.sf;
                                                     }
                                                     case 7: {
                                                                  return (!ctx.sf);
                                                     }
                                                     case 8: {
                                                                  return (ctx.sf != ctx.of);
                                                     }
                                                     case 9: {
                                                                  return (ctx.sf == ctx.of);
                                                     }
                                                     case 10: {
                                                                   return (ctx.zf || (ctx.sf != ctx.of));
                                                     }
                                                     case 11: {
                                                                   return ((!ctx.zf) && (ctx.sf == ctx.of));
                                                     }
                                                     case 12: {
                                                                   return ctx.of;
                                                     }
                                                     case 13: {
                                                                   return (!ctx.of);
                                                     }
                                                     case 14: {
                                                                   return true;
                                                     }
                                                     case 15: {
                                                                   return ctx.pf;
                                                     }
                                                     default: {
                                                                   return true;
                                                     }
                                    }
                                }
                                
                                __attribute__((always_inline)) inline static void compute_sub_flags(VMContext& ctx, uint64_t a, uint64_t b, uint32_t bits) noexcept {
                                
                                    if ((bits == 0) || (bits >= 64)) {
                                    
                                        uint64_t res = (a - b);
                                        ctx.zf = (res == 0x0000000000000000ULL);
                                        ctx.sf = (static_cast<int64_t>(res) < 0LL);
                                        ctx.cf = (a < b);
                                        ctx.of = ((((a ^ b) & (a ^ res)) >> 0x000000000000003fULL) != 0x0000000000000000ULL);
                                    } else {
                                                uint64_t mask = ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL);
                                                uint64_t sign_bit = (0x0000000000000001ULL << (bits - 1));
                                                uint64_t a_val = (a & mask);
                                                uint64_t b_val = (b & mask);
                                                uint64_t res = ((a_val - b_val) & mask);
                                                ctx.zf = (res == 0x0000000000000000ULL);
                                                ctx.sf = ((res & sign_bit) != 0x0000000000000000ULL);
                                                ctx.cf = (a_val < b_val);
                                                ctx.of = ((((a_val ^ b_val) & (a_val ^ res)) & sign_bit) != 0x0000000000000000ULL);
                                    }
                                }
                                
                                __attribute__((always_inline)) inline static void compute_add_flags(VMContext& ctx, uint64_t a, uint64_t b, uint32_t bits) noexcept {
                                
                                    if ((bits == 0) || (bits >= 64)) {
                                    
                                        uint64_t res = (a + b);
                                        ctx.zf = (res == 0x0000000000000000ULL);
                                        ctx.sf = (static_cast<int64_t>(res) < 0LL);
                                        ctx.cf = (res < a);
                                        ctx.of = ((((~((a ^ b))) & (a ^ res)) >> 0x000000000000003fULL) != 0x0000000000000000ULL);
                                    } else {
                                                uint64_t mask = ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL);
                                                uint64_t sign_bit = (0x0000000000000001ULL << (bits - 1));
                                                uint64_t a_val = (a & mask);
                                                uint64_t b_val = (b & mask);
                                                uint64_t res = ((a_val + b_val) & mask);
                                                ctx.zf = (res == 0x0000000000000000ULL);
                                                ctx.sf = ((res & sign_bit) != 0x0000000000000000ULL);
                                                ctx.cf = (res < a_val);
                                                ctx.of = ((((~((a_val ^ b_val))) & (a_val ^ res)) & sign_bit) != 0x0000000000000000ULL);
                                    }
                                }
                                
                                static inline bool execute_threaded(VMContext& ctx, const uint64_t* bytecode, size_t count, uint32_t seed = asgard_wbox_derive_seed() /* seed = 0x5BA91936U */, bool scrub_source = false) {
                                
                                    if (ctx.reg_mask == 0x0000000000000000ULL) {
                                    
                                        ctx.init(seed);
                                    }
                                    uint64_t full_hash = 0x9757d113496d6877ULL;
                                    for (size_t i = 0x0000000000000000ULL; i < count; ++i) {
                                    
                                        full_hash = (((full_hash ^ bytecode[i]) * 0x5c0dafb08793c9ddULL) + ((uint64_t)(i)));
                                    }
                                    uint64_t hash_diff = (full_hash ^ 0xbada86e55c2e0636ULL);
                                    ctx.running_key ^= hash_diff;
                                    ctx.reg_mask ^= (hash_diff * 0x00005877cafebeefULL);
                                    if (hash_diff != 0x0000000000000000ULL) {
                                    
                                        ctx.trapped = true;
                                        return false;
                                    }
                                    #if defined(__APPLE__)
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc kinfo = {};
    size_t ksize = sizeof(kinfo);
    if (false && sysctl(mib, 4, &kinfo, &ksize, (void*)0, 0) == 0 && (kinfo.kp_proc.p_flag & P_TRACED)) {
        ctx.reg_mask ^= 0xCAFEBABE13375877ULL;
        ctx.trapped = true;
        return false;
    }
#endif
                                    uint64_t stack_buf[256];
                                    uint64_t* heap_work_bc = ((count <= 0x0000000000000100ULL) ? nullptr : ((uint64_t*)(malloc((count * sizeof(uint64_t))))));
                                    uint64_t* work_bc = ((count <= 0x0000000000000100ULL) ? stack_buf : heap_work_bc);
                                    if (__builtin_expect((!work_bc), 0)) {
                                    
                                        ctx.trapped = true;
                                        return false;
                                    }
                                    for (size_t i = 0x0000000000000000ULL; i < count; ++i) {
                                    
                                        work_bc[i] = (0x5877cafe1337beefULL ^ (((uint64_t)(seed)) + ((uint64_t)(i))));
                                    }
                                    size_t vIP_idx = 0x0000000000000000ULL;
                                        /* ASG_VM_TRACE: semantic handler classes, stable across builds. */
    static const char* ASG_TRC_NAMES[134] = { "H_ADC_RI", "H_ADC_RR", "H_ADD_RI", "H_ADD_RR", "H_ADD_RR_A1", "H_ADD_RR_A2", "H_AND_RI", "H_AND_RR", "H_AND_RR_A1", "H_ATOMIC_ADD", "H_ATOMIC_CAS", "H_ATOMIC_LOAD", "H_ATOMIC_STORE", "H_ATOMIC_SWP", "H_BRIDGE_TO_FLOW", "H_BRIDGE_TO_MATH", "H_BSWAP_RR", "H_CALL", "H_CALL_EXTERN", "H_CCMN_RI", "H_CCMN_RR", "H_CCMP_RI", "H_CCMP_RR", "H_CLZ_RR", "H_CMOV", "H_CMP_RI", "H_CMP_RI_A1", "H_CMP_RI_A2", "H_CMP_RR", "H_CMP_RR_A1", "H_CTZ_RR", "H_DECOY", "H_DIV_RR", "H_EXIT", "H_FADD_DD", "H_FCMP_DD", "H_FCSEL_VV", "H_FCVT", "H_FCVTZS", "H_FCVTZU", "H_FDIV_DD", "H_FENCE", "H_FMUL_DD", "H_FSQRT_D", "H_FSUB_DD", "H_FUSED_ADD_IMUL_RRI", "H_FUSED_ADD_XOR_RRI", "H_FUSED_AND_OR_RRI", "H_FUSED_CMP_CMOV", "H_FUSED_MOV_ADD_RRI", "H_FUSED_SHL_ADD_RRI", "H_FUSED_SUB_XOR_RRI", "H_FUSED_XOR_ADD_RRI", "H_GET_FLAGS_R", "H_ICALL_R", "H_IDIV_RR", "H_IJMP_R", "H_IMULH_RR", "H_IMUL_RI", "H_IMUL_RR", "H_JCC", "H_JCC_A1", "H_JMP", "H_JMP_A1", "H_JMP_A2", "H_LOAD_16", "H_LOAD_32", "H_LOAD_64", "H_LOAD_8", "H_LOAD_S16", "H_LOAD_S32", "H_LOAD_S8", "H_MOV_HIGH", "H_MOV_RI", "H_MOV_RI_A1", "H_MOV_RI_A2", "H_MOV_RR", "H_MOV_RR_A1", "H_MOV_RR_A2", "H_MOV_RV", "H_MOV_VR", "H_MULH_RR", "H_NEG_RR", "H_NOP", "H_NOT_RR", "H_OR_RI", "H_OR_RR", "H_OR_RR_A1", "H_PMOVMSKB", "H_POPCNT_RR", "H_POP_R", "H_PUSH_R", "H_RBIT_RR", "H_RESOLVE_SYM", "H_RET", "H_ROL_RI", "H_ROL_RR", "H_ROR_RI", "H_ROR_RR", "H_SAR_RI", "H_SAR_RR", "H_SBB_RI", "H_SBB_RR", "H_SCVTF", "H_SETCC", "H_SET_FLAGS_R", "H_SHL_RI", "H_SHL_RR", "H_SHR_RI", "H_SHR_RR", "H_STORE_16", "H_STORE_32", "H_STORE_64", "H_STORE_8", "H_SUB_RI", "H_SUB_RR", "H_SUB_RR_A1", "H_UCVTF", "H_VADD_VV", "H_VEC_BINOP", "H_VEC_CLEAR_UPPER", "H_VEC_EXT", "H_VEC_IMM", "H_VEC_LOAD", "H_VEC_MOV", "H_VEC_SPLAT", "H_VEC_STORE", "H_VEC_ZERO_UPPER", "H_VMUL_VV", "H_VSUB_VV", "H_VXOR_VV", "H_XOR_RI", "H_XOR_RR", "H_XOR_RR_A1" };
    static const uint8_t ASG_TRC_CLASS[4][256] = {
    { /* domain 0 */ 31, 105, 59, 33, 31, 69, 31, 8, 39, 60, 31, 31, 78, 31, 31, 31, 73, 31, 110, 34, 31, 31, 31, 132, 104, 99, 31, 89, 18, 46, 63, 106, 15, 31, 4, 31, 31, 47, 31, 20, 86, 31, 125, 77, 36, 31, 31, 65, 97, 51, 31, 31, 41, 131, 31, 122, 31, 5, 24, 9, 31, 31, 120, 55, 114, 109, 31, 61, 108, 35, 115, 31, 31, 31, 82, 133, 101, 42, 112, 94, 31, 91, 76, 31, 29, 31, 31, 31, 31, 52, 22, 19, 31, 3, 16, 96, 84, 31, 31, 31, 0, 31, 31, 79, 31, 31, 87, 31, 31, 58, 128, 107, 31, 31, 31, 31, 10, 62, 31, 124, 40, 31, 31, 32, 11, 80, 31, 31, 31, 31, 123, 130, 31, 57, 37, 93, 54, 31, 31, 31, 102, 111, 31, 31, 13, 28, 31, 12, 1, 31, 31, 31, 31, 31, 85, 2, 30, 31, 95, 27, 31, 31, 31, 31, 31, 31, 25, 31, 66, 31, 50, 64, 31, 53, 31, 31, 31, 31, 31, 116, 31, 103, 17, 92, 21, 31, 31, 14, 74, 119, 81, 49, 71, 90, 31, 31, 31, 31, 31, 31, 31, 75, 127, 113, 31, 72, 43, 31, 7, 31, 31, 31, 31, 31, 68, 31, 31, 48, 126, 31, 31, 31, 117, 31, 88, 31, 31, 31, 26, 31, 31, 56, 129, 118, 6, 31, 31, 45, 100, 31, 31, 121, 31, 31, 31, 31, 31, 23, 31, 38, 67, 44, 31, 83, 70, 98 },
    { /* domain 1 */ 31, 31, 11, 80, 31, 32, 40, 31, 31, 124, 10, 62, 31, 31, 31, 31, 128, 107, 31, 58, 87, 31, 31, 31, 31, 79, 0, 31, 31, 31, 84, 31, 16, 96, 31, 3, 22, 19, 31, 52, 31, 31, 29, 31, 76, 31, 31, 91, 112, 94, 101, 42, 82, 133, 31, 31, 115, 31, 108, 35, 31, 61, 114, 109, 120, 55, 31, 31, 24, 9, 31, 5, 31, 122, 41, 131, 31, 31, 97, 51, 31, 65, 36, 31, 125, 77, 86, 31, 31, 20, 31, 47, 4, 31, 15, 31, 63, 106, 18, 46, 31, 89, 104, 99, 31, 132, 31, 31, 110, 34, 73, 31, 31, 31, 78, 31, 31, 31, 39, 60, 31, 8, 31, 69, 59, 33, 31, 105, 70, 98, 31, 83, 67, 44, 31, 38, 31, 23, 31, 31, 31, 31, 31, 121, 100, 31, 31, 45, 6, 31, 129, 118, 31, 56, 26, 31, 31, 31, 88, 31, 117, 31, 31, 31, 126, 31, 31, 48, 68, 31, 31, 31, 31, 31, 7, 31, 43, 31, 31, 72, 127, 113, 31, 75, 31, 31, 31, 31, 31, 31, 71, 90, 81, 49, 74, 119, 31, 14, 21, 31, 17, 92, 31, 103, 31, 116, 31, 31, 31, 31, 31, 53, 50, 64, 66, 31, 25, 31, 31, 31, 31, 31, 31, 31, 95, 27, 30, 31, 85, 2, 31, 31, 31, 31, 1, 31, 31, 12, 13, 28, 31, 31, 102, 111, 31, 31, 54, 31, 37, 93, 31, 57, 123, 130, 31, 31 },
    { /* domain 2 */ 31, 31, 31, 116, 31, 103, 17, 92, 21, 31, 31, 14, 74, 119, 81, 49, 31, 31, 31, 31, 31, 31, 25, 31, 66, 31, 50, 64, 31, 53, 31, 31, 13, 28, 31, 12, 1, 31, 31, 31, 31, 31, 85, 2, 30, 31, 95, 27, 31, 31, 123, 130, 31, 57, 37, 93, 54, 31, 31, 31, 102, 111, 31, 31, 31, 121, 31, 31, 31, 31, 31, 23, 31, 38, 67, 44, 31, 83, 70, 98, 88, 31, 31, 31, 26, 31, 31, 56, 129, 118, 6, 31, 31, 45, 100, 31, 7, 31, 31, 31, 31, 31, 68, 31, 31, 48, 126, 31, 31, 31, 117, 31, 71, 90, 31, 31, 31, 31, 31, 31, 31, 75, 127, 113, 31, 72, 43, 31, 97, 51, 31, 31, 41, 131, 31, 122, 31, 5, 24, 9, 31, 31, 120, 55, 15, 31, 4, 31, 31, 47, 31, 20, 86, 31, 125, 77, 36, 31, 31, 65, 73, 31, 110, 34, 31, 31, 31, 132, 104, 99, 31, 89, 18, 46, 63, 106, 31, 105, 59, 33, 31, 69, 31, 8, 39, 60, 31, 31, 78, 31, 31, 31, 31, 31, 31, 31, 10, 62, 31, 124, 40, 31, 31, 32, 11, 80, 31, 31, 84, 31, 31, 31, 0, 31, 31, 79, 31, 31, 87, 31, 31, 58, 128, 107, 31, 91, 76, 31, 29, 31, 31, 31, 31, 52, 22, 19, 31, 3, 16, 96, 114, 109, 31, 61, 108, 35, 115, 31, 31, 31, 82, 133, 101, 42, 112, 94 },
    { /* domain 3 */ 87, 31, 31, 31, 128, 107, 31, 58, 31, 31, 84, 31, 31, 79, 0, 31, 31, 32, 40, 31, 31, 31, 11, 80, 31, 31, 31, 31, 31, 124, 10, 62, 82, 133, 31, 31, 112, 94, 101, 42, 31, 61, 114, 109, 115, 31, 108, 35, 22, 19, 31, 52, 16, 96, 31, 3, 76, 31, 31, 91, 31, 31, 29, 31, 125, 77, 86, 31, 31, 65, 36, 31, 4, 31, 15, 31, 31, 20, 31, 47, 24, 9, 31, 5, 120, 55, 31, 31, 31, 31, 97, 51, 31, 122, 41, 131, 31, 31, 39, 60, 31, 31, 78, 31, 59, 33, 31, 105, 31, 8, 31, 69, 31, 89, 104, 99, 63, 106, 18, 46, 110, 34, 73, 31, 31, 132, 31, 31, 6, 31, 129, 118, 100, 31, 31, 45, 31, 31, 88, 31, 31, 56, 26, 31, 67, 44, 31, 38, 70, 98, 31, 83, 31, 31, 31, 121, 31, 23, 31, 31, 127, 113, 31, 75, 43, 31, 31, 72, 31, 31, 71, 90, 31, 31, 31, 31, 126, 31, 31, 48, 117, 31, 31, 31, 31, 31, 7, 31, 68, 31, 31, 31, 50, 64, 66, 31, 31, 31, 31, 53, 31, 31, 31, 31, 25, 31, 31, 31, 31, 14, 21, 31, 81, 49, 74, 119, 31, 116, 31, 31, 17, 92, 31, 103, 31, 31, 54, 31, 31, 31, 102, 111, 123, 130, 31, 31, 37, 93, 31, 57, 85, 2, 31, 31, 95, 27, 30, 31, 31, 12, 13, 28, 31, 31, 1, 31 },
    };
    /* Function-local static: legal at this (function) scope, initialized once. */
    static const bool asg_vm_trace_on = (getenv("ASG_VM_TRACE") != nullptr);
                                    static const uint8_t domain_salt[4] = { 0x00, 0x7E, 0xB0, 0x6A };
                                    static uintptr_t all_dispatch_domains[4][256];
    static bool dispatch_domains_ready = false;
    if (__builtin_expect(!dispatch_domains_ready, 0)) {
#if !defined(_MSC_VER) || defined(__clang__)
                                    static void* raw_domain0[256] = {
                                        &&H_DECOY_9,
                                        &&H_SET_FLAGS_R,
                                        &&H_IMUL_RR,
                                        &&H_EXIT,
                                        &&H_DECOY_3,
                                        &&H_LOAD_S16,
                                        &&H_DECOY_8,
                                        &&H_AND_RR_A1,
                                        &&H_FCVTZU,
                                        &&H_JCC,
                                        &&H_DECOY_9,
                                        &&H_DECOY_15,
                                        &&H_MOV_RR_A2,
                                        &&H_DECOY_0,
                                        &&H_DECOY_6,
                                        &&H_DECOY_2,
                                        &&H_MOV_RI,
                                        &&H_DECOY_5,
                                        &&H_STORE_16,
                                        &&H_FADD_DD,
                                        &&H_DECOY_2,
                                        &&H_DECOY_3,
                                        &&H_DECOY_13,
                                        &&H_XOR_RR,
                                        &&H_SETCC,
                                        &&H_SAR_RI,
                                        &&H_DECOY_15,
                                        &&H_POPCNT_RR,
                                        &&H_CALL_EXTERN,
                                        &&H_FUSED_ADD_XOR_RRI,
                                        &&H_JMP_A1,
                                        &&H_SHL_RI,
                                        &&H_BRIDGE_TO_MATH,
                                        &&H_DECOY_13,
                                        &&H_ADD_RR_A1,
                                        &&H_DECOY_12,
                                        &&H_DECOY_5,
                                        &&H_FUSED_AND_OR_RRI,
                                        &&H_DECOY_10,
                                        &&H_CCMN_RR,
                                        &&H_OR_RR,
                                        &&H_DECOY_9,
                                        &&H_VEC_SPLAT,
                                        &&H_MOV_RR_A1,
                                        &&H_FCSEL_VV,
                                        &&H_DECOY_6,
                                        &&H_DECOY_12,
                                        &&H_LOAD_16,
                                        &&H_ROR_RI,
                                        &&H_FUSED_SUB_XOR_RRI,
                                        &&H_DECOY_7,
                                        &&H_DECOY_5,
                                        &&H_FENCE,
                                        &&H_XOR_RI,
                                        &&H_DECOY_2,
                                        &&H_VEC_IMM,
                                        &&H_DECOY_0,
                                        &&H_ADD_RR_A2,
                                        &&H_CMOV,
                                        &&H_ATOMIC_ADD,
                                        &&H_DECOY_0,
                                        &&H_DECOY_15,
                                        &&H_VEC_CLEAR_UPPER,
                                        &&H_IDIV_RR,
                                        &&H_SUB_RI,
                                        &&H_SHR_RR,
                                        &&H_DECOY_8,
                                        &&H_JCC_A1,
                                        &&H_SHR_RI,
                                        &&H_FCMP_DD,
                                        &&H_SUB_RR,
                                        &&H_DECOY_2,
                                        &&H_DECOY_11,
                                        &&H_DECOY_11,
                                        &&H_NEG_RR,
                                        &&H_XOR_RR_A1,
                                        &&H_SBB_RI,
                                        &&H_FMUL_DD,
                                        &&H_STORE_64,
                                        &&H_RET,
                                        &&H_DECOY_8,
                                        &&H_PUSH_R,
                                        &&H_MOV_RR,
                                        &&H_DECOY_12,
                                        &&H_CMP_RR_A1,
                                        &&H_DECOY_5,
                                        &&H_DECOY_11,
                                        &&H_DECOY_9,
                                        &&H_DECOY_0,
                                        &&H_FUSED_XOR_ADD_RRI,
                                        &&H_CCMP_RR,
                                        &&H_CCMN_RI,
                                        &&H_DECOY_0,
                                        &&H_ADD_RR,
                                        &&H_BSWAP_RR,
                                        &&H_ROL_RR,
                                        &&H_NOT_RR,
                                        &&H_DECOY_6,
                                        &&H_DECOY_6,
                                        &&H_DECOY_0,
                                        &&H_ADC_RI,
                                        &&H_DECOY_8,
                                        &&H_DECOY_11,
                                        &&H_MOV_RV,
                                        &&H_DECOY_3,
                                        &&H_DECOY_5,
                                        &&H_OR_RR_A1,
                                        &&H_DECOY_1,
                                        &&H_DECOY_15,
                                        &&H_IMUL_RI,
                                        &&H_VMUL_VV,
                                        &&H_SHL_RR,
                                        &&H_DECOY_10,
                                        &&H_DECOY_11,
                                        &&H_DECOY_14,
                                        &&H_DECOY_8,
                                        &&H_ATOMIC_CAS,
                                        &&H_JMP,
                                        &&H_DECOY_0,
                                        &&H_VEC_MOV,
                                        &&H_FDIV_DD,
                                        &&H_DECOY_4,
                                        &&H_DECOY_0,
                                        &&H_DIV_RR,
                                        &&H_ATOMIC_LOAD,
                                        &&H_MOV_VR,
                                        &&H_DECOY_12,
                                        &&H_DECOY_12,
                                        &&H_DECOY_13,
                                        &&H_DECOY_0,
                                        &&H_VEC_LOAD,
                                        &&H_VXOR_VV,
                                        &&H_DECOY_1,
                                        &&H_IMULH_RR,
                                        &&H_FCVT,
                                        &&H_RESOLVE_SYM,
                                        &&H_ICALL_R,
                                        &&H_DECOY_6,
                                        &&H_DECOY_3,
                                        &&H_DECOY_8,
                                        &&H_SBB_RR,
                                        &&H_STORE_32,
                                        &&H_DECOY_4,
                                        &&H_DECOY_14,
                                        &&H_ATOMIC_SWP,
                                        &&H_CMP_RR,
                                        &&H_DECOY_14,
                                        &&H_ATOMIC_STORE,
                                        &&H_ADC_RR,
                                        &&H_DECOY_3,
                                        &&H_DECOY_1,
                                        &&H_DECOY_4,
                                        &&H_DECOY_13,
                                        &&H_DECOY_8,
                                        &&H_OR_RI,
                                        &&H_ADD_RI,
                                        &&H_CTZ_RR,
                                        &&H_DECOY_14,
                                        &&H_ROL_RI,
                                        &&H_CMP_RI_A2,
                                        &&H_DECOY_0,
                                        &&H_DECOY_8,
                                        &&H_DECOY_9,
                                        &&H_DECOY_8,
                                        &&H_DECOY_0,
                                        &&H_DECOY_3,
                                        &&H_CMP_RI,
                                        &&H_DECOY_11,
                                        &&H_LOAD_32,
                                        &&H_DECOY_9,
                                        &&H_FUSED_SHL_ADD_RRI,
                                        &&H_JMP_A2,
                                        &&H_DECOY_2,
                                        &&H_GET_FLAGS_R,
                                        &&H_DECOY_6,
                                        &&H_DECOY_2,
                                        &&H_DECOY_2,
                                        &&H_DECOY_13,
                                        &&H_DECOY_7,
                                        &&H_SUB_RR_A1,
                                        &&H_DECOY_5,
                                        &&H_SCVTF,
                                        &&H_CALL,
                                        &&H_RBIT_RR,
                                        &&H_CCMP_RI,
                                        &&H_DECOY_8,
                                        &&H_DECOY_13,
                                        &&H_BRIDGE_TO_FLOW,
                                        &&H_MOV_RI_A1,
                                        &&H_VEC_BINOP,
                                        &&H_MULH_RR,
                                        &&H_FUSED_MOV_ADD_RRI,
                                        &&H_LOAD_S8,
                                        &&H_POP_R,
                                        &&H_DECOY_12,
                                        &&H_DECOY_6,
                                        &&H_DECOY_9,
                                        &&H_DECOY_13,
                                        &&H_DECOY_13,
                                        &&H_DECOY_12,
                                        &&H_DECOY_8,
                                        &&H_MOV_RI_A2,
                                        &&H_VEC_ZERO_UPPER,
                                        &&H_STORE_8,
                                        &&H_DECOY_9,
                                        &&H_MOV_HIGH,
                                        &&H_FSQRT_D,
                                        &&H_DECOY_2,
                                        &&H_AND_RR,
                                        &&H_DECOY_4,
                                        &&H_DECOY_8,
                                        &&H_DECOY_13,
                                        &&H_DECOY_6,
                                        &&H_DECOY_5,
                                        &&H_LOAD_8,
                                        &&H_DECOY_1,
                                        &&H_DECOY_2,
                                        &&H_FUSED_CMP_CMOV,
                                        &&H_VEC_STORE,
                                        &&H_DECOY_7,
                                        &&H_DECOY_10,
                                        &&H_DECOY_4,
                                        &&H_UCVTF,
                                        &&H_DECOY_4,
                                        &&H_PMOVMSKB,
                                        &&H_DECOY_14,
                                        &&H_DECOY_13,
                                        &&H_DECOY_12,
                                        &&H_CMP_RI_A1,
                                        &&H_DECOY_13,
                                        &&H_DECOY_12,
                                        &&H_IJMP_R,
                                        &&H_VSUB_VV,
                                        &&H_VADD_VV,
                                        &&H_AND_RI,
                                        &&H_DECOY_8,
                                        &&H_DECOY_3,
                                        &&H_FUSED_ADD_IMUL_RRI,
                                        &&H_SAR_RR,
                                        &&H_DECOY_14,
                                        &&H_DECOY_3,
                                        &&H_VEC_EXT,
                                        &&H_DECOY_4,
                                        &&H_DECOY_5,
                                        &&H_DECOY_8,
                                        &&H_DECOY_3,
                                        &&H_DECOY_2,
                                        &&H_CLZ_RR,
                                        &&H_DECOY_3,
                                        &&H_FCVTZS,
                                        &&H_LOAD_64,
                                        &&H_FSUB_DD,
                                        &&H_DECOY_5,
                                        &&H_NOP,
                                        &&H_LOAD_S32,
                                        &&H_ROR_RR
                                    };
                                    static void* raw_domain1[256] = {
                                        &&H_DECOY_9,
                                        &&H_DECOY_9,
                                        &&H_ATOMIC_LOAD_D1,
                                        &&H_MOV_VR_D1,
                                        &&H_DECOY_5,
                                        &&H_DIV_RR_D1,
                                        &&H_FDIV_DD_D1,
                                        &&H_DECOY_5,
                                        &&H_DECOY_13,
                                        &&H_VEC_MOV_D1,
                                        &&H_ATOMIC_CAS_D1,
                                        &&H_JMP_D1,
                                        &&H_DECOY_3,
                                        &&H_DECOY_13,
                                        &&H_DECOY_11,
                                        &&H_DECOY_12,
                                        &&H_VMUL_VV_D1,
                                        &&H_SHL_RR_D1,
                                        &&H_DECOY_8,
                                        &&H_IMUL_RI_D1,
                                        &&H_OR_RR_A1_D1,
                                        &&H_DECOY_6,
                                        &&H_DECOY_4,
                                        &&H_DECOY_6,
                                        &&H_DECOY_8,
                                        &&H_MOV_RV_D1,
                                        &&H_ADC_RI_D1,
                                        &&H_DECOY_1,
                                        &&H_DECOY_11,
                                        &&H_DECOY_5,
                                        &&H_NOT_RR_D1,
                                        &&H_DECOY_7,
                                        &&H_BSWAP_RR_D1,
                                        &&H_ROL_RR_D1,
                                        &&H_DECOY_9,
                                        &&H_ADD_RR_D1,
                                        &&H_CCMP_RR_D1,
                                        &&H_CCMN_RI_D1,
                                        &&H_DECOY_1,
                                        &&H_FUSED_XOR_ADD_RRI_D1,
                                        &&H_DECOY_8,
                                        &&H_DECOY_6,
                                        &&H_CMP_RR_A1_D1,
                                        &&H_DECOY_14,
                                        &&H_MOV_RR_D1,
                                        &&H_DECOY_1,
                                        &&H_DECOY_9,
                                        &&H_PUSH_R_D1,
                                        &&H_STORE_64_D1,
                                        &&H_RET_D1,
                                        &&H_SBB_RI_D1,
                                        &&H_FMUL_DD_D1,
                                        &&H_NEG_RR_D1,
                                        &&H_XOR_RR_A1_D1,
                                        &&H_DECOY_12,
                                        &&H_DECOY_12,
                                        &&H_SUB_RR_D1,
                                        &&H_DECOY_15,
                                        &&H_SHR_RI_D1,
                                        &&H_FCMP_DD_D1,
                                        &&H_DECOY_13,
                                        &&H_JCC_A1_D1,
                                        &&H_SUB_RI_D1,
                                        &&H_SHR_RR_D1,
                                        &&H_VEC_CLEAR_UPPER_D1,
                                        &&H_IDIV_RR_D1,
                                        &&H_DECOY_9,
                                        &&H_DECOY_8,
                                        &&H_CMOV_D1,
                                        &&H_ATOMIC_ADD_D1,
                                        &&H_DECOY_1,
                                        &&H_ADD_RR_A2_D1,
                                        &&H_DECOY_15,
                                        &&H_VEC_IMM_D1,
                                        &&H_FENCE_D1,
                                        &&H_XOR_RI_D1,
                                        &&H_DECOY_12,
                                        &&H_DECOY_10,
                                        &&H_ROR_RI_D1,
                                        &&H_FUSED_SUB_XOR_RRI_D1,
                                        &&H_DECOY_9,
                                        &&H_LOAD_16_D1,
                                        &&H_FCSEL_VV_D1,
                                        &&H_DECOY_15,
                                        &&H_VEC_SPLAT_D1,
                                        &&H_MOV_RR_A1_D1,
                                        &&H_OR_RR_D1,
                                        &&H_DECOY_10,
                                        &&H_DECOY_7,
                                        &&H_CCMN_RR_D1,
                                        &&H_DECOY_14,
                                        &&H_FUSED_AND_OR_RRI_D1,
                                        &&H_ADD_RR_A1_D1,
                                        &&H_DECOY_1,
                                        &&H_BRIDGE_TO_MATH_D1,
                                        &&H_DECOY_14,
                                        &&H_JMP_A1_D1,
                                        &&H_SHL_RI_D1,
                                        &&H_CALL_EXTERN_D1,
                                        &&H_FUSED_ADD_XOR_RRI_D1,
                                        &&H_DECOY_4,
                                        &&H_POPCNT_RR_D1,
                                        &&H_SETCC_D1,
                                        &&H_SAR_RI_D1,
                                        &&H_DECOY_10,
                                        &&H_XOR_RR_D1,
                                        &&H_DECOY_11,
                                        &&H_DECOY_12,
                                        &&H_STORE_16_D1,
                                        &&H_FADD_DD_D1,
                                        &&H_MOV_RI_D1,
                                        &&H_DECOY_6,
                                        &&H_DECOY_3,
                                        &&H_DECOY_15,
                                        &&H_MOV_RR_A2_D1,
                                        &&H_DECOY_9,
                                        &&H_DECOY_14,
                                        &&H_DECOY_4,
                                        &&H_FCVTZU_D1,
                                        &&H_JCC_D1,
                                        &&H_DECOY_5,
                                        &&H_AND_RR_A1_D1,
                                        &&H_DECOY_12,
                                        &&H_LOAD_S16_D1,
                                        &&H_IMUL_RR_D1,
                                        &&H_EXIT_D1,
                                        &&H_DECOY_10,
                                        &&H_SET_FLAGS_R_D1,
                                        &&H_LOAD_S32_D1,
                                        &&H_ROR_RR_D1,
                                        &&H_DECOY_14,
                                        &&H_NOP_D1,
                                        &&H_LOAD_64_D1,
                                        &&H_FSUB_DD_D1,
                                        &&H_DECOY_4,
                                        &&H_FCVTZS_D1,
                                        &&H_DECOY_15,
                                        &&H_CLZ_RR_D1,
                                        &&H_DECOY_1,
                                        &&H_DECOY_12,
                                        &&H_DECOY_9,
                                        &&H_DECOY_10,
                                        &&H_DECOY_4,
                                        &&H_VEC_EXT_D1,
                                        &&H_SAR_RR_D1,
                                        &&H_DECOY_11,
                                        &&H_DECOY_12,
                                        &&H_FUSED_ADD_IMUL_RRI_D1,
                                        &&H_AND_RI_D1,
                                        &&H_DECOY_13,
                                        &&H_VSUB_VV_D1,
                                        &&H_VADD_VV_D1,
                                        &&H_DECOY_9,
                                        &&H_IJMP_R_D1,
                                        &&H_CMP_RI_A1_D1,
                                        &&H_DECOY_6,
                                        &&H_DECOY_2,
                                        &&H_DECOY_1,
                                        &&H_PMOVMSKB_D1,
                                        &&H_DECOY_15,
                                        &&H_UCVTF_D1,
                                        &&H_DECOY_1,
                                        &&H_DECOY_3,
                                        &&H_DECOY_13,
                                        &&H_VEC_STORE_D1,
                                        &&H_DECOY_12,
                                        &&H_DECOY_3,
                                        &&H_FUSED_CMP_CMOV_D1,
                                        &&H_LOAD_8_D1,
                                        &&H_DECOY_14,
                                        &&H_DECOY_15,
                                        &&H_DECOY_14,
                                        &&H_DECOY_13,
                                        &&H_DECOY_2,
                                        &&H_AND_RR_D1,
                                        &&H_DECOY_5,
                                        &&H_FSQRT_D_D1,
                                        &&H_DECOY_15,
                                        &&H_DECOY_2,
                                        &&H_MOV_HIGH_D1,
                                        &&H_VEC_ZERO_UPPER_D1,
                                        &&H_STORE_8_D1,
                                        &&H_DECOY_9,
                                        &&H_MOV_RI_A2_D1,
                                        &&H_DECOY_10,
                                        &&H_DECOY_9,
                                        &&H_DECOY_2,
                                        &&H_DECOY_6,
                                        &&H_DECOY_1,
                                        &&H_DECOY_11,
                                        &&H_LOAD_S8_D1,
                                        &&H_POP_R_D1,
                                        &&H_MULH_RR_D1,
                                        &&H_FUSED_MOV_ADD_RRI_D1,
                                        &&H_MOV_RI_A1_D1,
                                        &&H_VEC_BINOP_D1,
                                        &&H_DECOY_2,
                                        &&H_BRIDGE_TO_FLOW_D1,
                                        &&H_CCMP_RI_D1,
                                        &&H_DECOY_9,
                                        &&H_CALL_D1,
                                        &&H_RBIT_RR_D1,
                                        &&H_DECOY_14,
                                        &&H_SCVTF_D1,
                                        &&H_DECOY_12,
                                        &&H_SUB_RR_A1_D1,
                                        &&H_DECOY_3,
                                        &&H_DECOY_14,
                                        &&H_DECOY_3,
                                        &&H_DECOY_15,
                                        &&H_DECOY_11,
                                        &&H_GET_FLAGS_R_D1,
                                        &&H_FUSED_SHL_ADD_RRI_D1,
                                        &&H_JMP_A2_D1,
                                        &&H_LOAD_32_D1,
                                        &&H_DECOY_10,
                                        &&H_CMP_RI_D1,
                                        &&H_DECOY_8,
                                        &&H_DECOY_9,
                                        &&H_DECOY_12,
                                        &&H_DECOY_14,
                                        &&H_DECOY_13,
                                        &&H_DECOY_1,
                                        &&H_DECOY_9,
                                        &&H_ROL_RI_D1,
                                        &&H_CMP_RI_A2_D1,
                                        &&H_CTZ_RR_D1,
                                        &&H_DECOY_7,
                                        &&H_OR_RI_D1,
                                        &&H_ADD_RI_D1,
                                        &&H_DECOY_14,
                                        &&H_DECOY_9,
                                        &&H_DECOY_14,
                                        &&H_DECOY_1,
                                        &&H_ADC_RR_D1,
                                        &&H_DECOY_12,
                                        &&H_DECOY_3,
                                        &&H_ATOMIC_STORE_D1,
                                        &&H_ATOMIC_SWP_D1,
                                        &&H_CMP_RR_D1,
                                        &&H_DECOY_1,
                                        &&H_DECOY_11,
                                        &&H_SBB_RR_D1,
                                        &&H_STORE_32_D1,
                                        &&H_DECOY_8,
                                        &&H_DECOY_13,
                                        &&H_ICALL_R_D1,
                                        &&H_DECOY_7,
                                        &&H_FCVT_D1,
                                        &&H_RESOLVE_SYM_D1,
                                        &&H_DECOY_10,
                                        &&H_IMULH_RR_D1,
                                        &&H_VEC_LOAD_D1,
                                        &&H_VXOR_VV_D1,
                                        &&H_DECOY_14,
                                        &&H_DECOY_1
                                    };
                                    static void* raw_domain2[256] = {
                                        &&H_DECOY_0,
                                        &&H_DECOY_11,
                                        &&H_DECOY_5,
                                        &&H_SUB_RR_A1_D2,
                                        &&H_DECOY_3,
                                        &&H_SCVTF_D2,
                                        &&H_CALL_D2,
                                        &&H_RBIT_RR_D2,
                                        &&H_CCMP_RI_D2,
                                        &&H_DECOY_6,
                                        &&H_DECOY_11,
                                        &&H_BRIDGE_TO_FLOW_D2,
                                        &&H_MOV_RI_A1_D2,
                                        &&H_VEC_BINOP_D2,
                                        &&H_MULH_RR_D2,
                                        &&H_FUSED_MOV_ADD_RRI_D2,
                                        &&H_DECOY_14,
                                        &&H_DECOY_6,
                                        &&H_DECOY_7,
                                        &&H_DECOY_6,
                                        &&H_DECOY_14,
                                        &&H_DECOY_1,
                                        &&H_CMP_RI_D2,
                                        &&H_DECOY_9,
                                        &&H_LOAD_32_D2,
                                        &&H_DECOY_7,
                                        &&H_FUSED_SHL_ADD_RRI_D2,
                                        &&H_JMP_A2_D2,
                                        &&H_DECOY_0,
                                        &&H_GET_FLAGS_R_D2,
                                        &&H_DECOY_4,
                                        &&H_DECOY_0,
                                        &&H_ATOMIC_SWP_D2,
                                        &&H_CMP_RR_D2,
                                        &&H_DECOY_12,
                                        &&H_ATOMIC_STORE_D2,
                                        &&H_ADC_RR_D2,
                                        &&H_DECOY_1,
                                        &&H_DECOY_15,
                                        &&H_DECOY_2,
                                        &&H_DECOY_11,
                                        &&H_DECOY_6,
                                        &&H_OR_RI_D2,
                                        &&H_ADD_RI_D2,
                                        &&H_CTZ_RR_D2,
                                        &&H_DECOY_12,
                                        &&H_ROL_RI_D2,
                                        &&H_CMP_RI_A2_D2,
                                        &&H_DECOY_11,
                                        &&H_DECOY_14,
                                        &&H_VEC_LOAD_D2,
                                        &&H_VXOR_VV_D2,
                                        &&H_DECOY_15,
                                        &&H_IMULH_RR_D2,
                                        &&H_FCVT_D2,
                                        &&H_RESOLVE_SYM_D2,
                                        &&H_ICALL_R_D2,
                                        &&H_DECOY_4,
                                        &&H_DECOY_1,
                                        &&H_DECOY_6,
                                        &&H_SBB_RR_D2,
                                        &&H_STORE_32_D2,
                                        &&H_DECOY_2,
                                        &&H_DECOY_12,
                                        &&H_DECOY_1,
                                        &&H_VEC_EXT_D2,
                                        &&H_DECOY_2,
                                        &&H_DECOY_3,
                                        &&H_DECOY_6,
                                        &&H_DECOY_1,
                                        &&H_DECOY_0,
                                        &&H_CLZ_RR_D2,
                                        &&H_DECOY_1,
                                        &&H_FCVTZS_D2,
                                        &&H_LOAD_64_D2,
                                        &&H_FSUB_DD_D2,
                                        &&H_DECOY_3,
                                        &&H_NOP_D2,
                                        &&H_LOAD_S32_D2,
                                        &&H_ROR_RR_D2,
                                        &&H_PMOVMSKB_D2,
                                        &&H_DECOY_12,
                                        &&H_DECOY_11,
                                        &&H_DECOY_10,
                                        &&H_CMP_RI_A1_D2,
                                        &&H_DECOY_11,
                                        &&H_DECOY_10,
                                        &&H_IJMP_R_D2,
                                        &&H_VSUB_VV_D2,
                                        &&H_VADD_VV_D2,
                                        &&H_AND_RI_D2,
                                        &&H_DECOY_6,
                                        &&H_DECOY_1,
                                        &&H_FUSED_ADD_IMUL_RRI_D2,
                                        &&H_SAR_RR_D2,
                                        &&H_DECOY_12,
                                        &&H_AND_RR_D2,
                                        &&H_DECOY_2,
                                        &&H_DECOY_6,
                                        &&H_DECOY_11,
                                        &&H_DECOY_4,
                                        &&H_DECOY_3,
                                        &&H_LOAD_8_D2,
                                        &&H_DECOY_15,
                                        &&H_DECOY_0,
                                        &&H_FUSED_CMP_CMOV_D2,
                                        &&H_VEC_STORE_D2,
                                        &&H_DECOY_5,
                                        &&H_DECOY_8,
                                        &&H_DECOY_2,
                                        &&H_UCVTF_D2,
                                        &&H_DECOY_2,
                                        &&H_LOAD_S8_D2,
                                        &&H_POP_R_D2,
                                        &&H_DECOY_10,
                                        &&H_DECOY_4,
                                        &&H_DECOY_7,
                                        &&H_DECOY_11,
                                        &&H_DECOY_11,
                                        &&H_DECOY_10,
                                        &&H_DECOY_6,
                                        &&H_MOV_RI_A2_D2,
                                        &&H_VEC_ZERO_UPPER_D2,
                                        &&H_STORE_8_D2,
                                        &&H_DECOY_7,
                                        &&H_MOV_HIGH_D2,
                                        &&H_FSQRT_D_D2,
                                        &&H_DECOY_0,
                                        &&H_ROR_RI_D2,
                                        &&H_FUSED_SUB_XOR_RRI_D2,
                                        &&H_DECOY_5,
                                        &&H_DECOY_3,
                                        &&H_FENCE_D2,
                                        &&H_XOR_RI_D2,
                                        &&H_DECOY_0,
                                        &&H_VEC_IMM_D2,
                                        &&H_DECOY_14,
                                        &&H_ADD_RR_A2_D2,
                                        &&H_CMOV_D2,
                                        &&H_ATOMIC_ADD_D2,
                                        &&H_DECOY_14,
                                        &&H_DECOY_13,
                                        &&H_VEC_CLEAR_UPPER_D2,
                                        &&H_IDIV_RR_D2,
                                        &&H_BRIDGE_TO_MATH_D2,
                                        &&H_DECOY_11,
                                        &&H_ADD_RR_A1_D2,
                                        &&H_DECOY_10,
                                        &&H_DECOY_3,
                                        &&H_FUSED_AND_OR_RRI_D2,
                                        &&H_DECOY_8,
                                        &&H_CCMN_RR_D2,
                                        &&H_OR_RR_D2,
                                        &&H_DECOY_7,
                                        &&H_VEC_SPLAT_D2,
                                        &&H_MOV_RR_A1_D2,
                                        &&H_FCSEL_VV_D2,
                                        &&H_DECOY_4,
                                        &&H_DECOY_10,
                                        &&H_LOAD_16_D2,
                                        &&H_MOV_RI_D2,
                                        &&H_DECOY_3,
                                        &&H_STORE_16_D2,
                                        &&H_FADD_DD_D2,
                                        &&H_DECOY_0,
                                        &&H_DECOY_1,
                                        &&H_DECOY_11,
                                        &&H_XOR_RR_D2,
                                        &&H_SETCC_D2,
                                        &&H_SAR_RI_D2,
                                        &&H_DECOY_13,
                                        &&H_POPCNT_RR_D2,
                                        &&H_CALL_EXTERN_D2,
                                        &&H_FUSED_ADD_XOR_RRI_D2,
                                        &&H_JMP_A1_D2,
                                        &&H_SHL_RI_D2,
                                        &&H_DECOY_7,
                                        &&H_SET_FLAGS_R_D2,
                                        &&H_IMUL_RR_D2,
                                        &&H_EXIT_D2,
                                        &&H_DECOY_1,
                                        &&H_LOAD_S16_D2,
                                        &&H_DECOY_6,
                                        &&H_AND_RR_A1_D2,
                                        &&H_FCVTZU_D2,
                                        &&H_JCC_D2,
                                        &&H_DECOY_7,
                                        &&H_DECOY_13,
                                        &&H_MOV_RR_A2_D2,
                                        &&H_DECOY_14,
                                        &&H_DECOY_4,
                                        &&H_DECOY_0,
                                        &&H_DECOY_8,
                                        &&H_DECOY_9,
                                        &&H_DECOY_12,
                                        &&H_DECOY_6,
                                        &&H_ATOMIC_CAS_D2,
                                        &&H_JMP_D2,
                                        &&H_DECOY_14,
                                        &&H_VEC_MOV_D2,
                                        &&H_FDIV_DD_D2,
                                        &&H_DECOY_2,
                                        &&H_DECOY_14,
                                        &&H_DIV_RR_D2,
                                        &&H_ATOMIC_LOAD_D2,
                                        &&H_MOV_VR_D2,
                                        &&H_DECOY_10,
                                        &&H_DECOY_10,
                                        &&H_NOT_RR_D2,
                                        &&H_DECOY_4,
                                        &&H_DECOY_4,
                                        &&H_DECOY_14,
                                        &&H_ADC_RI_D2,
                                        &&H_DECOY_6,
                                        &&H_DECOY_9,
                                        &&H_MOV_RV_D2,
                                        &&H_DECOY_1,
                                        &&H_DECOY_3,
                                        &&H_OR_RR_A1_D2,
                                        &&H_DECOY_15,
                                        &&H_DECOY_13,
                                        &&H_IMUL_RI_D2,
                                        &&H_VMUL_VV_D2,
                                        &&H_SHL_RR_D2,
                                        &&H_DECOY_6,
                                        &&H_PUSH_R_D2,
                                        &&H_MOV_RR_D2,
                                        &&H_DECOY_10,
                                        &&H_CMP_RR_A1_D2,
                                        &&H_DECOY_3,
                                        &&H_DECOY_9,
                                        &&H_DECOY_7,
                                        &&H_DECOY_14,
                                        &&H_FUSED_XOR_ADD_RRI_D2,
                                        &&H_CCMP_RR_D2,
                                        &&H_CCMN_RI_D2,
                                        &&H_DECOY_14,
                                        &&H_ADD_RR_D2,
                                        &&H_BSWAP_RR_D2,
                                        &&H_ROL_RR_D2,
                                        &&H_SUB_RI_D2,
                                        &&H_SHR_RR_D2,
                                        &&H_DECOY_6,
                                        &&H_JCC_A1_D2,
                                        &&H_SHR_RI_D2,
                                        &&H_FCMP_DD_D2,
                                        &&H_SUB_RR_D2,
                                        &&H_DECOY_0,
                                        &&H_DECOY_9,
                                        &&H_DECOY_9,
                                        &&H_NEG_RR_D2,
                                        &&H_XOR_RR_A1_D2,
                                        &&H_SBB_RI_D2,
                                        &&H_FMUL_DD_D2,
                                        &&H_STORE_64_D2,
                                        &&H_RET_D2
                                    };
                                    static void* raw_domain3[256] = {
                                        &&H_OR_RR_A1_D3,
                                        &&H_DECOY_8,
                                        &&H_DECOY_6,
                                        &&H_DECOY_8,
                                        &&H_VMUL_VV_D3,
                                        &&H_SHL_RR_D3,
                                        &&H_DECOY_2,
                                        &&H_IMUL_RI_D3,
                                        &&H_DECOY_13,
                                        &&H_DECOY_7,
                                        &&H_NOT_RR_D3,
                                        &&H_DECOY_9,
                                        &&H_DECOY_2,
                                        &&H_MOV_RV_D3,
                                        &&H_ADC_RI_D3,
                                        &&H_DECOY_11,
                                        &&H_DECOY_7,
                                        &&H_DIV_RR_D3,
                                        &&H_FDIV_DD_D3,
                                        &&H_DECOY_7,
                                        &&H_DECOY_3,
                                        &&H_DECOY_3,
                                        &&H_ATOMIC_LOAD_D3,
                                        &&H_MOV_VR_D3,
                                        &&H_DECOY_5,
                                        &&H_DECOY_15,
                                        &&H_DECOY_13,
                                        &&H_DECOY_14,
                                        &&H_DECOY_7,
                                        &&H_VEC_MOV_D3,
                                        &&H_ATOMIC_CAS_D3,
                                        &&H_JMP_D3,
                                        &&H_NEG_RR_D3,
                                        &&H_XOR_RR_A1_D3,
                                        &&H_DECOY_14,
                                        &&H_DECOY_14,
                                        &&H_STORE_64_D3,
                                        &&H_RET_D3,
                                        &&H_SBB_RI_D3,
                                        &&H_FMUL_DD_D3,
                                        &&H_DECOY_15,
                                        &&H_JCC_A1_D3,
                                        &&H_SUB_RI_D3,
                                        &&H_SHR_RR_D3,
                                        &&H_SUB_RR_D3,
                                        &&H_DECOY_9,
                                        &&H_SHR_RI_D3,
                                        &&H_FCMP_DD_D3,
                                        &&H_CCMP_RR_D3,
                                        &&H_CCMN_RI_D3,
                                        &&H_DECOY_3,
                                        &&H_FUSED_XOR_ADD_RRI_D3,
                                        &&H_BSWAP_RR_D3,
                                        &&H_ROL_RR_D3,
                                        &&H_DECOY_3,
                                        &&H_ADD_RR_D3,
                                        &&H_MOV_RR_D3,
                                        &&H_DECOY_3,
                                        &&H_DECOY_11,
                                        &&H_PUSH_R_D3,
                                        &&H_DECOY_2,
                                        &&H_DECOY_0,
                                        &&H_CMP_RR_A1_D3,
                                        &&H_DECOY_8,
                                        &&H_VEC_SPLAT_D3,
                                        &&H_MOV_RR_A1_D3,
                                        &&H_OR_RR_D3,
                                        &&H_DECOY_12,
                                        &&H_DECOY_3,
                                        &&H_LOAD_16_D3,
                                        &&H_FCSEL_VV_D3,
                                        &&H_DECOY_9,
                                        &&H_ADD_RR_A1_D3,
                                        &&H_DECOY_3,
                                        &&H_BRIDGE_TO_MATH_D3,
                                        &&H_DECOY_0,
                                        &&H_DECOY_1,
                                        &&H_CCMN_RR_D3,
                                        &&H_DECOY_8,
                                        &&H_FUSED_AND_OR_RRI_D3,
                                        &&H_CMOV_D3,
                                        &&H_ATOMIC_ADD_D3,
                                        &&H_DECOY_3,
                                        &&H_ADD_RR_A2_D3,
                                        &&H_VEC_CLEAR_UPPER_D3,
                                        &&H_IDIV_RR_D3,
                                        &&H_DECOY_3,
                                        &&H_DECOY_2,
                                        &&H_DECOY_14,
                                        &&H_DECOY_12,
                                        &&H_ROR_RI_D3,
                                        &&H_FUSED_SUB_XOR_RRI_D3,
                                        &&H_DECOY_9,
                                        &&H_VEC_IMM_D3,
                                        &&H_FENCE_D3,
                                        &&H_XOR_RI_D3,
                                        &&H_DECOY_0,
                                        &&H_DECOY_6,
                                        &&H_FCVTZU_D3,
                                        &&H_JCC_D3,
                                        &&H_DECOY_13,
                                        &&H_DECOY_9,
                                        &&H_MOV_RR_A2_D3,
                                        &&H_DECOY_3,
                                        &&H_IMUL_RR_D3,
                                        &&H_EXIT_D3,
                                        &&H_DECOY_12,
                                        &&H_SET_FLAGS_R_D3,
                                        &&H_DECOY_15,
                                        &&H_AND_RR_A1_D3,
                                        &&H_DECOY_6,
                                        &&H_LOAD_S16_D3,
                                        &&H_DECOY_6,
                                        &&H_POPCNT_RR_D3,
                                        &&H_SETCC_D3,
                                        &&H_SAR_RI_D3,
                                        &&H_JMP_A1_D3,
                                        &&H_SHL_RI_D3,
                                        &&H_CALL_EXTERN_D3,
                                        &&H_FUSED_ADD_XOR_RRI_D3,
                                        &&H_STORE_16_D3,
                                        &&H_FADD_DD_D3,
                                        &&H_MOV_RI_D3,
                                        &&H_DECOY_8,
                                        &&H_DECOY_4,
                                        &&H_XOR_RR_D3,
                                        &&H_DECOY_5,
                                        &&H_DECOY_6,
                                        &&H_AND_RI_D3,
                                        &&H_DECOY_15,
                                        &&H_VSUB_VV_D3,
                                        &&H_VADD_VV_D3,
                                        &&H_SAR_RR_D3,
                                        &&H_DECOY_5,
                                        &&H_DECOY_6,
                                        &&H_FUSED_ADD_IMUL_RRI_D3,
                                        &&H_DECOY_4,
                                        &&H_DECOY_3,
                                        &&H_PMOVMSKB_D3,
                                        &&H_DECOY_1,
                                        &&H_DECOY_3,
                                        &&H_IJMP_R_D3,
                                        &&H_CMP_RI_A1_D3,
                                        &&H_DECOY_0,
                                        &&H_LOAD_64_D3,
                                        &&H_FSUB_DD_D3,
                                        &&H_DECOY_6,
                                        &&H_FCVTZS_D3,
                                        &&H_LOAD_S32_D3,
                                        &&H_ROR_RR_D3,
                                        &&H_DECOY_8,
                                        &&H_NOP_D3,
                                        &&H_DECOY_11,
                                        &&H_DECOY_12,
                                        &&H_DECOY_6,
                                        &&H_VEC_EXT_D3,
                                        &&H_DECOY_9,
                                        &&H_CLZ_RR_D3,
                                        &&H_DECOY_11,
                                        &&H_DECOY_6,
                                        &&H_VEC_ZERO_UPPER_D3,
                                        &&H_STORE_8_D3,
                                        &&H_DECOY_11,
                                        &&H_MOV_RI_A2_D3,
                                        &&H_FSQRT_D_D3,
                                        &&H_DECOY_9,
                                        &&H_DECOY_12,
                                        &&H_MOV_HIGH_D3,
                                        &&H_DECOY_3,
                                        &&H_DECOY_13,
                                        &&H_LOAD_S8_D3,
                                        &&H_POP_R_D3,
                                        &&H_DECOY_4,
                                        &&H_DECOY_3,
                                        &&H_DECOY_12,
                                        &&H_DECOY_0,
                                        &&H_VEC_STORE_D3,
                                        &&H_DECOY_14,
                                        &&H_DECOY_5,
                                        &&H_FUSED_CMP_CMOV_D3,
                                        &&H_UCVTF_D3,
                                        &&H_DECOY_11,
                                        &&H_DECOY_13,
                                        &&H_DECOY_7,
                                        &&H_DECOY_15,
                                        &&H_DECOY_4,
                                        &&H_AND_RR_D3,
                                        &&H_DECOY_7,
                                        &&H_LOAD_8_D3,
                                        &&H_DECOY_8,
                                        &&H_DECOY_9,
                                        &&H_DECOY_8,
                                        &&H_FUSED_SHL_ADD_RRI_D3,
                                        &&H_JMP_A2_D3,
                                        &&H_LOAD_32_D3,
                                        &&H_DECOY_12,
                                        &&H_DECOY_13,
                                        &&H_DECOY_9,
                                        &&H_DECOY_5,
                                        &&H_GET_FLAGS_R_D3,
                                        &&H_DECOY_0,
                                        &&H_DECOY_15,
                                        &&H_DECOY_3,
                                        &&H_DECOY_11,
                                        &&H_CMP_RI_D3,
                                        &&H_DECOY_2,
                                        &&H_DECOY_3,
                                        &&H_DECOY_6,
                                        &&H_DECOY_4,
                                        &&H_BRIDGE_TO_FLOW_D3,
                                        &&H_CCMP_RI_D3,
                                        &&H_DECOY_11,
                                        &&H_MULH_RR_D3,
                                        &&H_FUSED_MOV_ADD_RRI_D3,
                                        &&H_MOV_RI_A1_D3,
                                        &&H_VEC_BINOP_D3,
                                        &&H_DECOY_14,
                                        &&H_SUB_RR_A1_D3,
                                        &&H_DECOY_5,
                                        &&H_DECOY_0,
                                        &&H_CALL_D3,
                                        &&H_RBIT_RR_D3,
                                        &&H_DECOY_8,
                                        &&H_SCVTF_D3,
                                        &&H_DECOY_10,
                                        &&H_DECOY_15,
                                        &&H_ICALL_R_D3,
                                        &&H_DECOY_9,
                                        &&H_DECOY_11,
                                        &&H_DECOY_5,
                                        &&H_SBB_RR_D3,
                                        &&H_STORE_32_D3,
                                        &&H_VEC_LOAD_D3,
                                        &&H_VXOR_VV_D3,
                                        &&H_DECOY_0,
                                        &&H_DECOY_3,
                                        &&H_FCVT_D3,
                                        &&H_RESOLVE_SYM_D3,
                                        &&H_DECOY_4,
                                        &&H_IMULH_RR_D3,
                                        &&H_OR_RI_D3,
                                        &&H_ADD_RI_D3,
                                        &&H_DECOY_0,
                                        &&H_DECOY_11,
                                        &&H_ROL_RI_D3,
                                        &&H_CMP_RI_A2_D3,
                                        &&H_CTZ_RR_D3,
                                        &&H_DECOY_1,
                                        &&H_DECOY_5,
                                        &&H_ATOMIC_STORE_D3,
                                        &&H_ATOMIC_SWP_D3,
                                        &&H_CMP_RR_D3,
                                        &&H_DECOY_8,
                                        &&H_DECOY_11,
                                        &&H_ADC_RR_D3,
                                        &&H_DECOY_6
                                    };
                                    static void** raw_all_domains[4] = { raw_domain0, raw_domain1, raw_domain2, raw_domain3 };
                                            for (size_t d = 0; d < 4; ++d) {
            for (size_t o = 0; o < 256; ++o) {
                uintptr_t k_slot = ((uintptr_t)seed * 0x517CC1B727220A95ULL) ^ (((uintptr_t)d * 256ULL + (uintptr_t)o) * 0x6A09E667F3BCC908ULL);
                all_dispatch_domains[d][o] = (uintptr_t)raw_all_domains[d][o] ^ k_slot;
                *(reinterpret_cast<volatile uintptr_t*>(&raw_all_domains[d][o])) = k_slot ^ 0xDEADBEEF5A5A5A5AULL;
            }
        }
#else
        for (size_t d = 0; d < 4; ++d) {
            for (size_t o = 0; o < 256; ++o) {
                uintptr_t k_slot = ((uintptr_t)seed * 0x517CC1B727220A95ULL) ^ (((uintptr_t)d * 256ULL + (uintptr_t)o) * 0x6A09E667F3BCC908ULL);
                all_dispatch_domains[d][o] = ((uintptr_t)(d * 256 + o) + 0x1337) ^ k_slot;
            }
        }
#endif
        dispatch_domains_ready = true;
    }
                                    uint64_t g_handlers_hash = compute_handlers_hash(((const uintptr_t*)(all_dispatch_domains)), 4);
                                        uint64_t word = 0;
    uint64_t k_dyn = 0;
    uint8_t op = 0;
    uint8_t dst = 0;
    uint8_t src = 0;
    int64_t imm = 0;
    size_t next_canary_step = 47 + ((uint64_t)seed & 0x3FULL);

#if defined(_MSC_VER) && !defined(__clang__)
    #define DISPATCH_OPCODE() do { \
        goto DISPATCH_MSVC; \
    } while(0)
#else
    #define DISPATCH_OPCODE() do { \
        uint8_t domain_idx = (uint8_t)((k_dyn >> 32) % 4); \
        uint8_t permuted_slot = (uint8_t)(op ^ domain_salt[domain_idx]); \
        uintptr_t k_slot = ((uintptr_t)seed * 0x517CC1B727220A95ULL) ^ (((uintptr_t)domain_idx * 256ULL + (uintptr_t)permuted_slot) * 0x6A09E667F3BCC908ULL); \
        void* target = (void*)(all_dispatch_domains[domain_idx][permuted_slot] ^ k_slot); \
        goto *target; \
    } while(0)
#endif

    #define FETCH_NEXT() do { \
        if (__builtin_expect(vIP_idx >= count, 0)) goto EXIT_VM; \
        if (__builtin_expect(ctx.executed_instructions > (count * 10000ULL + 1000000ULL), 0)) { \
            ctx.trapped = true; \
            goto EXIT_VM; \
        } \
        uint64_t k_pos = key64_for_offset(seed, vIP_idx); \
        k_dyn = k_pos ^ ctx.running_key; \
        if (__builtin_expect(ctx.executed_instructions >= next_canary_step, 0)) { \
            if (__builtin_expect(!ctx.verify_canaries(), 0)) { \
                ctx.reg_mask ^= (0xCAFEBABE13375877ULL ^ (k_dyn * 0x9E3779B97F4A7C15ULL)) | 1ULL; \
            } \
            next_canary_step = ctx.executed_instructions + 47 + ((k_dyn >> 21) & 0x7FULL); \
        } \
        work_bc[vIP_idx] = bytecode[vIP_idx]; \
        word = work_bc[vIP_idx] ^ k_dyn; \
        SCRUB_WORD(&work_bc[vIP_idx], (k_dyn * 0x6A09E667F3BCC908ULL) ^ 0x5877CAFE1337BEEFULL); \
        vIP_idx++; \
        op = (uint8_t)((((word >> 0) + 0xFFULL) - ((word >> 0) | 0xFFULL))); \
        dst = (uint8_t)((((word >> 8) + 0x1FULL) - ((word >> 8) | 0x1FULL))); \
        src = (uint8_t)((((word >> 13) + 0x1FULL) - ((word >> 13) | 0x1FULL))); \
        imm = (int64_t)((int32_t)((((word >> 18) + 0xFFFFFFFFULL) - ((word >> 18) | 0xFFFFFFFFULL)))); \
        ctx.evolve_mask((uint32_t)k_dyn); \
        ctx.evolve_slot_mask(dst, (uint32_t)k_dyn); \
        ctx.advance_running_key(op, dst, imm); \
        if (__builtin_expect(asg_vm_trace_on, 0)) { uint8_t t_dom = (uint8_t)((k_dyn >> 32) % 4); fprintf(stderr, "%u\n", (unsigned)ASG_TRC_CLASS[t_dom][(uint8_t)(op ^ domain_salt[t_dom])]); } \
        DISPATCH_OPCODE(); \
    } while(0)
                                    ctx.reanchor_running_key(0x0000000000000000ULL);
                                    #if defined(_MSC_VER) && !defined(__clang__)
    goto START_VM_MSVC;
    DISPATCH_MSVC: {
        uint8_t d_idx = (uint8_t)((k_dyn >> 32) % 4);
        uint8_t permuted_slot = (uint8_t)(op ^ domain_salt[d_idx]);
        if (__builtin_expect(asg_vm_trace_on, 0)) { fprintf(stderr, "%u\n", (unsigned)ASG_TRC_CLASS[d_idx][permuted_slot]); }
        switch ((uint32_t)d_idx * 256U + (uint32_t)permuted_slot) {
        case (0 * 256 + 0): goto H_DECOY_9;
        case (0 * 256 + 1): goto H_SET_FLAGS_R;
        case (0 * 256 + 2): goto H_IMUL_RR;
        case (0 * 256 + 3): goto H_EXIT;
        case (0 * 256 + 4): goto H_DECOY_3;
        case (0 * 256 + 5): goto H_LOAD_S16;
        case (0 * 256 + 6): goto H_DECOY_8;
        case (0 * 256 + 7): goto H_AND_RR_A1;
        case (0 * 256 + 8): goto H_FCVTZU;
        case (0 * 256 + 9): goto H_JCC;
        case (0 * 256 + 10): goto H_DECOY_9;
        case (0 * 256 + 11): goto H_DECOY_15;
        case (0 * 256 + 12): goto H_MOV_RR_A2;
        case (0 * 256 + 13): goto H_DECOY_0;
        case (0 * 256 + 14): goto H_DECOY_6;
        case (0 * 256 + 15): goto H_DECOY_2;
        case (0 * 256 + 16): goto H_MOV_RI;
        case (0 * 256 + 17): goto H_DECOY_5;
        case (0 * 256 + 18): goto H_STORE_16;
        case (0 * 256 + 19): goto H_FADD_DD;
        case (0 * 256 + 20): goto H_DECOY_2;
        case (0 * 256 + 21): goto H_DECOY_3;
        case (0 * 256 + 22): goto H_DECOY_13;
        case (0 * 256 + 23): goto H_XOR_RR;
        case (0 * 256 + 24): goto H_SETCC;
        case (0 * 256 + 25): goto H_SAR_RI;
        case (0 * 256 + 26): goto H_DECOY_15;
        case (0 * 256 + 27): goto H_POPCNT_RR;
        case (0 * 256 + 28): goto H_CALL_EXTERN;
        case (0 * 256 + 29): goto H_FUSED_ADD_XOR_RRI;
        case (0 * 256 + 30): goto H_JMP_A1;
        case (0 * 256 + 31): goto H_SHL_RI;
        case (0 * 256 + 32): goto H_BRIDGE_TO_MATH;
        case (0 * 256 + 33): goto H_DECOY_13;
        case (0 * 256 + 34): goto H_ADD_RR_A1;
        case (0 * 256 + 35): goto H_DECOY_12;
        case (0 * 256 + 36): goto H_DECOY_5;
        case (0 * 256 + 37): goto H_FUSED_AND_OR_RRI;
        case (0 * 256 + 38): goto H_DECOY_10;
        case (0 * 256 + 39): goto H_CCMN_RR;
        case (0 * 256 + 40): goto H_OR_RR;
        case (0 * 256 + 41): goto H_DECOY_9;
        case (0 * 256 + 42): goto H_VEC_SPLAT;
        case (0 * 256 + 43): goto H_MOV_RR_A1;
        case (0 * 256 + 44): goto H_FCSEL_VV;
        case (0 * 256 + 45): goto H_DECOY_6;
        case (0 * 256 + 46): goto H_DECOY_12;
        case (0 * 256 + 47): goto H_LOAD_16;
        case (0 * 256 + 48): goto H_ROR_RI;
        case (0 * 256 + 49): goto H_FUSED_SUB_XOR_RRI;
        case (0 * 256 + 50): goto H_DECOY_7;
        case (0 * 256 + 51): goto H_DECOY_5;
        case (0 * 256 + 52): goto H_FENCE;
        case (0 * 256 + 53): goto H_XOR_RI;
        case (0 * 256 + 54): goto H_DECOY_2;
        case (0 * 256 + 55): goto H_VEC_IMM;
        case (0 * 256 + 56): goto H_DECOY_0;
        case (0 * 256 + 57): goto H_ADD_RR_A2;
        case (0 * 256 + 58): goto H_CMOV;
        case (0 * 256 + 59): goto H_ATOMIC_ADD;
        case (0 * 256 + 60): goto H_DECOY_0;
        case (0 * 256 + 61): goto H_DECOY_15;
        case (0 * 256 + 62): goto H_VEC_CLEAR_UPPER;
        case (0 * 256 + 63): goto H_IDIV_RR;
        case (0 * 256 + 64): goto H_SUB_RI;
        case (0 * 256 + 65): goto H_SHR_RR;
        case (0 * 256 + 66): goto H_DECOY_8;
        case (0 * 256 + 67): goto H_JCC_A1;
        case (0 * 256 + 68): goto H_SHR_RI;
        case (0 * 256 + 69): goto H_FCMP_DD;
        case (0 * 256 + 70): goto H_SUB_RR;
        case (0 * 256 + 71): goto H_DECOY_2;
        case (0 * 256 + 72): goto H_DECOY_11;
        case (0 * 256 + 73): goto H_DECOY_11;
        case (0 * 256 + 74): goto H_NEG_RR;
        case (0 * 256 + 75): goto H_XOR_RR_A1;
        case (0 * 256 + 76): goto H_SBB_RI;
        case (0 * 256 + 77): goto H_FMUL_DD;
        case (0 * 256 + 78): goto H_STORE_64;
        case (0 * 256 + 79): goto H_RET;
        case (0 * 256 + 80): goto H_DECOY_8;
        case (0 * 256 + 81): goto H_PUSH_R;
        case (0 * 256 + 82): goto H_MOV_RR;
        case (0 * 256 + 83): goto H_DECOY_12;
        case (0 * 256 + 84): goto H_CMP_RR_A1;
        case (0 * 256 + 85): goto H_DECOY_5;
        case (0 * 256 + 86): goto H_DECOY_11;
        case (0 * 256 + 87): goto H_DECOY_9;
        case (0 * 256 + 88): goto H_DECOY_0;
        case (0 * 256 + 89): goto H_FUSED_XOR_ADD_RRI;
        case (0 * 256 + 90): goto H_CCMP_RR;
        case (0 * 256 + 91): goto H_CCMN_RI;
        case (0 * 256 + 92): goto H_DECOY_0;
        case (0 * 256 + 93): goto H_ADD_RR;
        case (0 * 256 + 94): goto H_BSWAP_RR;
        case (0 * 256 + 95): goto H_ROL_RR;
        case (0 * 256 + 96): goto H_NOT_RR;
        case (0 * 256 + 97): goto H_DECOY_6;
        case (0 * 256 + 98): goto H_DECOY_6;
        case (0 * 256 + 99): goto H_DECOY_0;
        case (0 * 256 + 100): goto H_ADC_RI;
        case (0 * 256 + 101): goto H_DECOY_8;
        case (0 * 256 + 102): goto H_DECOY_11;
        case (0 * 256 + 103): goto H_MOV_RV;
        case (0 * 256 + 104): goto H_DECOY_3;
        case (0 * 256 + 105): goto H_DECOY_5;
        case (0 * 256 + 106): goto H_OR_RR_A1;
        case (0 * 256 + 107): goto H_DECOY_1;
        case (0 * 256 + 108): goto H_DECOY_15;
        case (0 * 256 + 109): goto H_IMUL_RI;
        case (0 * 256 + 110): goto H_VMUL_VV;
        case (0 * 256 + 111): goto H_SHL_RR;
        case (0 * 256 + 112): goto H_DECOY_10;
        case (0 * 256 + 113): goto H_DECOY_11;
        case (0 * 256 + 114): goto H_DECOY_14;
        case (0 * 256 + 115): goto H_DECOY_8;
        case (0 * 256 + 116): goto H_ATOMIC_CAS;
        case (0 * 256 + 117): goto H_JMP;
        case (0 * 256 + 118): goto H_DECOY_0;
        case (0 * 256 + 119): goto H_VEC_MOV;
        case (0 * 256 + 120): goto H_FDIV_DD;
        case (0 * 256 + 121): goto H_DECOY_4;
        case (0 * 256 + 122): goto H_DECOY_0;
        case (0 * 256 + 123): goto H_DIV_RR;
        case (0 * 256 + 124): goto H_ATOMIC_LOAD;
        case (0 * 256 + 125): goto H_MOV_VR;
        case (0 * 256 + 126): goto H_DECOY_12;
        case (0 * 256 + 127): goto H_DECOY_12;
        case (0 * 256 + 128): goto H_DECOY_13;
        case (0 * 256 + 129): goto H_DECOY_0;
        case (0 * 256 + 130): goto H_VEC_LOAD;
        case (0 * 256 + 131): goto H_VXOR_VV;
        case (0 * 256 + 132): goto H_DECOY_1;
        case (0 * 256 + 133): goto H_IMULH_RR;
        case (0 * 256 + 134): goto H_FCVT;
        case (0 * 256 + 135): goto H_RESOLVE_SYM;
        case (0 * 256 + 136): goto H_ICALL_R;
        case (0 * 256 + 137): goto H_DECOY_6;
        case (0 * 256 + 138): goto H_DECOY_3;
        case (0 * 256 + 139): goto H_DECOY_8;
        case (0 * 256 + 140): goto H_SBB_RR;
        case (0 * 256 + 141): goto H_STORE_32;
        case (0 * 256 + 142): goto H_DECOY_4;
        case (0 * 256 + 143): goto H_DECOY_14;
        case (0 * 256 + 144): goto H_ATOMIC_SWP;
        case (0 * 256 + 145): goto H_CMP_RR;
        case (0 * 256 + 146): goto H_DECOY_14;
        case (0 * 256 + 147): goto H_ATOMIC_STORE;
        case (0 * 256 + 148): goto H_ADC_RR;
        case (0 * 256 + 149): goto H_DECOY_3;
        case (0 * 256 + 150): goto H_DECOY_1;
        case (0 * 256 + 151): goto H_DECOY_4;
        case (0 * 256 + 152): goto H_DECOY_13;
        case (0 * 256 + 153): goto H_DECOY_8;
        case (0 * 256 + 154): goto H_OR_RI;
        case (0 * 256 + 155): goto H_ADD_RI;
        case (0 * 256 + 156): goto H_CTZ_RR;
        case (0 * 256 + 157): goto H_DECOY_14;
        case (0 * 256 + 158): goto H_ROL_RI;
        case (0 * 256 + 159): goto H_CMP_RI_A2;
        case (0 * 256 + 160): goto H_DECOY_0;
        case (0 * 256 + 161): goto H_DECOY_8;
        case (0 * 256 + 162): goto H_DECOY_9;
        case (0 * 256 + 163): goto H_DECOY_8;
        case (0 * 256 + 164): goto H_DECOY_0;
        case (0 * 256 + 165): goto H_DECOY_3;
        case (0 * 256 + 166): goto H_CMP_RI;
        case (0 * 256 + 167): goto H_DECOY_11;
        case (0 * 256 + 168): goto H_LOAD_32;
        case (0 * 256 + 169): goto H_DECOY_9;
        case (0 * 256 + 170): goto H_FUSED_SHL_ADD_RRI;
        case (0 * 256 + 171): goto H_JMP_A2;
        case (0 * 256 + 172): goto H_DECOY_2;
        case (0 * 256 + 173): goto H_GET_FLAGS_R;
        case (0 * 256 + 174): goto H_DECOY_6;
        case (0 * 256 + 175): goto H_DECOY_2;
        case (0 * 256 + 176): goto H_DECOY_2;
        case (0 * 256 + 177): goto H_DECOY_13;
        case (0 * 256 + 178): goto H_DECOY_7;
        case (0 * 256 + 179): goto H_SUB_RR_A1;
        case (0 * 256 + 180): goto H_DECOY_5;
        case (0 * 256 + 181): goto H_SCVTF;
        case (0 * 256 + 182): goto H_CALL;
        case (0 * 256 + 183): goto H_RBIT_RR;
        case (0 * 256 + 184): goto H_CCMP_RI;
        case (0 * 256 + 185): goto H_DECOY_8;
        case (0 * 256 + 186): goto H_DECOY_13;
        case (0 * 256 + 187): goto H_BRIDGE_TO_FLOW;
        case (0 * 256 + 188): goto H_MOV_RI_A1;
        case (0 * 256 + 189): goto H_VEC_BINOP;
        case (0 * 256 + 190): goto H_MULH_RR;
        case (0 * 256 + 191): goto H_FUSED_MOV_ADD_RRI;
        case (0 * 256 + 192): goto H_LOAD_S8;
        case (0 * 256 + 193): goto H_POP_R;
        case (0 * 256 + 194): goto H_DECOY_12;
        case (0 * 256 + 195): goto H_DECOY_6;
        case (0 * 256 + 196): goto H_DECOY_9;
        case (0 * 256 + 197): goto H_DECOY_13;
        case (0 * 256 + 198): goto H_DECOY_13;
        case (0 * 256 + 199): goto H_DECOY_12;
        case (0 * 256 + 200): goto H_DECOY_8;
        case (0 * 256 + 201): goto H_MOV_RI_A2;
        case (0 * 256 + 202): goto H_VEC_ZERO_UPPER;
        case (0 * 256 + 203): goto H_STORE_8;
        case (0 * 256 + 204): goto H_DECOY_9;
        case (0 * 256 + 205): goto H_MOV_HIGH;
        case (0 * 256 + 206): goto H_FSQRT_D;
        case (0 * 256 + 207): goto H_DECOY_2;
        case (0 * 256 + 208): goto H_AND_RR;
        case (0 * 256 + 209): goto H_DECOY_4;
        case (0 * 256 + 210): goto H_DECOY_8;
        case (0 * 256 + 211): goto H_DECOY_13;
        case (0 * 256 + 212): goto H_DECOY_6;
        case (0 * 256 + 213): goto H_DECOY_5;
        case (0 * 256 + 214): goto H_LOAD_8;
        case (0 * 256 + 215): goto H_DECOY_1;
        case (0 * 256 + 216): goto H_DECOY_2;
        case (0 * 256 + 217): goto H_FUSED_CMP_CMOV;
        case (0 * 256 + 218): goto H_VEC_STORE;
        case (0 * 256 + 219): goto H_DECOY_7;
        case (0 * 256 + 220): goto H_DECOY_10;
        case (0 * 256 + 221): goto H_DECOY_4;
        case (0 * 256 + 222): goto H_UCVTF;
        case (0 * 256 + 223): goto H_DECOY_4;
        case (0 * 256 + 224): goto H_PMOVMSKB;
        case (0 * 256 + 225): goto H_DECOY_14;
        case (0 * 256 + 226): goto H_DECOY_13;
        case (0 * 256 + 227): goto H_DECOY_12;
        case (0 * 256 + 228): goto H_CMP_RI_A1;
        case (0 * 256 + 229): goto H_DECOY_13;
        case (0 * 256 + 230): goto H_DECOY_12;
        case (0 * 256 + 231): goto H_IJMP_R;
        case (0 * 256 + 232): goto H_VSUB_VV;
        case (0 * 256 + 233): goto H_VADD_VV;
        case (0 * 256 + 234): goto H_AND_RI;
        case (0 * 256 + 235): goto H_DECOY_8;
        case (0 * 256 + 236): goto H_DECOY_3;
        case (0 * 256 + 237): goto H_FUSED_ADD_IMUL_RRI;
        case (0 * 256 + 238): goto H_SAR_RR;
        case (0 * 256 + 239): goto H_DECOY_14;
        case (0 * 256 + 240): goto H_DECOY_3;
        case (0 * 256 + 241): goto H_VEC_EXT;
        case (0 * 256 + 242): goto H_DECOY_4;
        case (0 * 256 + 243): goto H_DECOY_5;
        case (0 * 256 + 244): goto H_DECOY_8;
        case (0 * 256 + 245): goto H_DECOY_3;
        case (0 * 256 + 246): goto H_DECOY_2;
        case (0 * 256 + 247): goto H_CLZ_RR;
        case (0 * 256 + 248): goto H_DECOY_3;
        case (0 * 256 + 249): goto H_FCVTZS;
        case (0 * 256 + 250): goto H_LOAD_64;
        case (0 * 256 + 251): goto H_FSUB_DD;
        case (0 * 256 + 252): goto H_DECOY_5;
        case (0 * 256 + 253): goto H_NOP;
        case (0 * 256 + 254): goto H_LOAD_S32;
        case (0 * 256 + 255): goto H_ROR_RR;
        case (1 * 256 + 0): goto H_DECOY_9;
        case (1 * 256 + 1): goto H_DECOY_9;
        case (1 * 256 + 2): goto H_ATOMIC_LOAD_D1;
        case (1 * 256 + 3): goto H_MOV_VR_D1;
        case (1 * 256 + 4): goto H_DECOY_5;
        case (1 * 256 + 5): goto H_DIV_RR_D1;
        case (1 * 256 + 6): goto H_FDIV_DD_D1;
        case (1 * 256 + 7): goto H_DECOY_5;
        case (1 * 256 + 8): goto H_DECOY_13;
        case (1 * 256 + 9): goto H_VEC_MOV_D1;
        case (1 * 256 + 10): goto H_ATOMIC_CAS_D1;
        case (1 * 256 + 11): goto H_JMP_D1;
        case (1 * 256 + 12): goto H_DECOY_3;
        case (1 * 256 + 13): goto H_DECOY_13;
        case (1 * 256 + 14): goto H_DECOY_11;
        case (1 * 256 + 15): goto H_DECOY_12;
        case (1 * 256 + 16): goto H_VMUL_VV_D1;
        case (1 * 256 + 17): goto H_SHL_RR_D1;
        case (1 * 256 + 18): goto H_DECOY_8;
        case (1 * 256 + 19): goto H_IMUL_RI_D1;
        case (1 * 256 + 20): goto H_OR_RR_A1_D1;
        case (1 * 256 + 21): goto H_DECOY_6;
        case (1 * 256 + 22): goto H_DECOY_4;
        case (1 * 256 + 23): goto H_DECOY_6;
        case (1 * 256 + 24): goto H_DECOY_8;
        case (1 * 256 + 25): goto H_MOV_RV_D1;
        case (1 * 256 + 26): goto H_ADC_RI_D1;
        case (1 * 256 + 27): goto H_DECOY_1;
        case (1 * 256 + 28): goto H_DECOY_11;
        case (1 * 256 + 29): goto H_DECOY_5;
        case (1 * 256 + 30): goto H_NOT_RR_D1;
        case (1 * 256 + 31): goto H_DECOY_7;
        case (1 * 256 + 32): goto H_BSWAP_RR_D1;
        case (1 * 256 + 33): goto H_ROL_RR_D1;
        case (1 * 256 + 34): goto H_DECOY_9;
        case (1 * 256 + 35): goto H_ADD_RR_D1;
        case (1 * 256 + 36): goto H_CCMP_RR_D1;
        case (1 * 256 + 37): goto H_CCMN_RI_D1;
        case (1 * 256 + 38): goto H_DECOY_1;
        case (1 * 256 + 39): goto H_FUSED_XOR_ADD_RRI_D1;
        case (1 * 256 + 40): goto H_DECOY_8;
        case (1 * 256 + 41): goto H_DECOY_6;
        case (1 * 256 + 42): goto H_CMP_RR_A1_D1;
        case (1 * 256 + 43): goto H_DECOY_14;
        case (1 * 256 + 44): goto H_MOV_RR_D1;
        case (1 * 256 + 45): goto H_DECOY_1;
        case (1 * 256 + 46): goto H_DECOY_9;
        case (1 * 256 + 47): goto H_PUSH_R_D1;
        case (1 * 256 + 48): goto H_STORE_64_D1;
        case (1 * 256 + 49): goto H_RET_D1;
        case (1 * 256 + 50): goto H_SBB_RI_D1;
        case (1 * 256 + 51): goto H_FMUL_DD_D1;
        case (1 * 256 + 52): goto H_NEG_RR_D1;
        case (1 * 256 + 53): goto H_XOR_RR_A1_D1;
        case (1 * 256 + 54): goto H_DECOY_12;
        case (1 * 256 + 55): goto H_DECOY_12;
        case (1 * 256 + 56): goto H_SUB_RR_D1;
        case (1 * 256 + 57): goto H_DECOY_15;
        case (1 * 256 + 58): goto H_SHR_RI_D1;
        case (1 * 256 + 59): goto H_FCMP_DD_D1;
        case (1 * 256 + 60): goto H_DECOY_13;
        case (1 * 256 + 61): goto H_JCC_A1_D1;
        case (1 * 256 + 62): goto H_SUB_RI_D1;
        case (1 * 256 + 63): goto H_SHR_RR_D1;
        case (1 * 256 + 64): goto H_VEC_CLEAR_UPPER_D1;
        case (1 * 256 + 65): goto H_IDIV_RR_D1;
        case (1 * 256 + 66): goto H_DECOY_9;
        case (1 * 256 + 67): goto H_DECOY_8;
        case (1 * 256 + 68): goto H_CMOV_D1;
        case (1 * 256 + 69): goto H_ATOMIC_ADD_D1;
        case (1 * 256 + 70): goto H_DECOY_1;
        case (1 * 256 + 71): goto H_ADD_RR_A2_D1;
        case (1 * 256 + 72): goto H_DECOY_15;
        case (1 * 256 + 73): goto H_VEC_IMM_D1;
        case (1 * 256 + 74): goto H_FENCE_D1;
        case (1 * 256 + 75): goto H_XOR_RI_D1;
        case (1 * 256 + 76): goto H_DECOY_12;
        case (1 * 256 + 77): goto H_DECOY_10;
        case (1 * 256 + 78): goto H_ROR_RI_D1;
        case (1 * 256 + 79): goto H_FUSED_SUB_XOR_RRI_D1;
        case (1 * 256 + 80): goto H_DECOY_9;
        case (1 * 256 + 81): goto H_LOAD_16_D1;
        case (1 * 256 + 82): goto H_FCSEL_VV_D1;
        case (1 * 256 + 83): goto H_DECOY_15;
        case (1 * 256 + 84): goto H_VEC_SPLAT_D1;
        case (1 * 256 + 85): goto H_MOV_RR_A1_D1;
        case (1 * 256 + 86): goto H_OR_RR_D1;
        case (1 * 256 + 87): goto H_DECOY_10;
        case (1 * 256 + 88): goto H_DECOY_7;
        case (1 * 256 + 89): goto H_CCMN_RR_D1;
        case (1 * 256 + 90): goto H_DECOY_14;
        case (1 * 256 + 91): goto H_FUSED_AND_OR_RRI_D1;
        case (1 * 256 + 92): goto H_ADD_RR_A1_D1;
        case (1 * 256 + 93): goto H_DECOY_1;
        case (1 * 256 + 94): goto H_BRIDGE_TO_MATH_D1;
        case (1 * 256 + 95): goto H_DECOY_14;
        case (1 * 256 + 96): goto H_JMP_A1_D1;
        case (1 * 256 + 97): goto H_SHL_RI_D1;
        case (1 * 256 + 98): goto H_CALL_EXTERN_D1;
        case (1 * 256 + 99): goto H_FUSED_ADD_XOR_RRI_D1;
        case (1 * 256 + 100): goto H_DECOY_4;
        case (1 * 256 + 101): goto H_POPCNT_RR_D1;
        case (1 * 256 + 102): goto H_SETCC_D1;
        case (1 * 256 + 103): goto H_SAR_RI_D1;
        case (1 * 256 + 104): goto H_DECOY_10;
        case (1 * 256 + 105): goto H_XOR_RR_D1;
        case (1 * 256 + 106): goto H_DECOY_11;
        case (1 * 256 + 107): goto H_DECOY_12;
        case (1 * 256 + 108): goto H_STORE_16_D1;
        case (1 * 256 + 109): goto H_FADD_DD_D1;
        case (1 * 256 + 110): goto H_MOV_RI_D1;
        case (1 * 256 + 111): goto H_DECOY_6;
        case (1 * 256 + 112): goto H_DECOY_3;
        case (1 * 256 + 113): goto H_DECOY_15;
        case (1 * 256 + 114): goto H_MOV_RR_A2_D1;
        case (1 * 256 + 115): goto H_DECOY_9;
        case (1 * 256 + 116): goto H_DECOY_14;
        case (1 * 256 + 117): goto H_DECOY_4;
        case (1 * 256 + 118): goto H_FCVTZU_D1;
        case (1 * 256 + 119): goto H_JCC_D1;
        case (1 * 256 + 120): goto H_DECOY_5;
        case (1 * 256 + 121): goto H_AND_RR_A1_D1;
        case (1 * 256 + 122): goto H_DECOY_12;
        case (1 * 256 + 123): goto H_LOAD_S16_D1;
        case (1 * 256 + 124): goto H_IMUL_RR_D1;
        case (1 * 256 + 125): goto H_EXIT_D1;
        case (1 * 256 + 126): goto H_DECOY_10;
        case (1 * 256 + 127): goto H_SET_FLAGS_R_D1;
        case (1 * 256 + 128): goto H_LOAD_S32_D1;
        case (1 * 256 + 129): goto H_ROR_RR_D1;
        case (1 * 256 + 130): goto H_DECOY_14;
        case (1 * 256 + 131): goto H_NOP_D1;
        case (1 * 256 + 132): goto H_LOAD_64_D1;
        case (1 * 256 + 133): goto H_FSUB_DD_D1;
        case (1 * 256 + 134): goto H_DECOY_4;
        case (1 * 256 + 135): goto H_FCVTZS_D1;
        case (1 * 256 + 136): goto H_DECOY_15;
        case (1 * 256 + 137): goto H_CLZ_RR_D1;
        case (1 * 256 + 138): goto H_DECOY_1;
        case (1 * 256 + 139): goto H_DECOY_12;
        case (1 * 256 + 140): goto H_DECOY_9;
        case (1 * 256 + 141): goto H_DECOY_10;
        case (1 * 256 + 142): goto H_DECOY_4;
        case (1 * 256 + 143): goto H_VEC_EXT_D1;
        case (1 * 256 + 144): goto H_SAR_RR_D1;
        case (1 * 256 + 145): goto H_DECOY_11;
        case (1 * 256 + 146): goto H_DECOY_12;
        case (1 * 256 + 147): goto H_FUSED_ADD_IMUL_RRI_D1;
        case (1 * 256 + 148): goto H_AND_RI_D1;
        case (1 * 256 + 149): goto H_DECOY_13;
        case (1 * 256 + 150): goto H_VSUB_VV_D1;
        case (1 * 256 + 151): goto H_VADD_VV_D1;
        case (1 * 256 + 152): goto H_DECOY_9;
        case (1 * 256 + 153): goto H_IJMP_R_D1;
        case (1 * 256 + 154): goto H_CMP_RI_A1_D1;
        case (1 * 256 + 155): goto H_DECOY_6;
        case (1 * 256 + 156): goto H_DECOY_2;
        case (1 * 256 + 157): goto H_DECOY_1;
        case (1 * 256 + 158): goto H_PMOVMSKB_D1;
        case (1 * 256 + 159): goto H_DECOY_15;
        case (1 * 256 + 160): goto H_UCVTF_D1;
        case (1 * 256 + 161): goto H_DECOY_1;
        case (1 * 256 + 162): goto H_DECOY_3;
        case (1 * 256 + 163): goto H_DECOY_13;
        case (1 * 256 + 164): goto H_VEC_STORE_D1;
        case (1 * 256 + 165): goto H_DECOY_12;
        case (1 * 256 + 166): goto H_DECOY_3;
        case (1 * 256 + 167): goto H_FUSED_CMP_CMOV_D1;
        case (1 * 256 + 168): goto H_LOAD_8_D1;
        case (1 * 256 + 169): goto H_DECOY_14;
        case (1 * 256 + 170): goto H_DECOY_15;
        case (1 * 256 + 171): goto H_DECOY_14;
        case (1 * 256 + 172): goto H_DECOY_13;
        case (1 * 256 + 173): goto H_DECOY_2;
        case (1 * 256 + 174): goto H_AND_RR_D1;
        case (1 * 256 + 175): goto H_DECOY_5;
        case (1 * 256 + 176): goto H_FSQRT_D_D1;
        case (1 * 256 + 177): goto H_DECOY_15;
        case (1 * 256 + 178): goto H_DECOY_2;
        case (1 * 256 + 179): goto H_MOV_HIGH_D1;
        case (1 * 256 + 180): goto H_VEC_ZERO_UPPER_D1;
        case (1 * 256 + 181): goto H_STORE_8_D1;
        case (1 * 256 + 182): goto H_DECOY_9;
        case (1 * 256 + 183): goto H_MOV_RI_A2_D1;
        case (1 * 256 + 184): goto H_DECOY_10;
        case (1 * 256 + 185): goto H_DECOY_9;
        case (1 * 256 + 186): goto H_DECOY_2;
        case (1 * 256 + 187): goto H_DECOY_6;
        case (1 * 256 + 188): goto H_DECOY_1;
        case (1 * 256 + 189): goto H_DECOY_11;
        case (1 * 256 + 190): goto H_LOAD_S8_D1;
        case (1 * 256 + 191): goto H_POP_R_D1;
        case (1 * 256 + 192): goto H_MULH_RR_D1;
        case (1 * 256 + 193): goto H_FUSED_MOV_ADD_RRI_D1;
        case (1 * 256 + 194): goto H_MOV_RI_A1_D1;
        case (1 * 256 + 195): goto H_VEC_BINOP_D1;
        case (1 * 256 + 196): goto H_DECOY_2;
        case (1 * 256 + 197): goto H_BRIDGE_TO_FLOW_D1;
        case (1 * 256 + 198): goto H_CCMP_RI_D1;
        case (1 * 256 + 199): goto H_DECOY_9;
        case (1 * 256 + 200): goto H_CALL_D1;
        case (1 * 256 + 201): goto H_RBIT_RR_D1;
        case (1 * 256 + 202): goto H_DECOY_14;
        case (1 * 256 + 203): goto H_SCVTF_D1;
        case (1 * 256 + 204): goto H_DECOY_12;
        case (1 * 256 + 205): goto H_SUB_RR_A1_D1;
        case (1 * 256 + 206): goto H_DECOY_3;
        case (1 * 256 + 207): goto H_DECOY_14;
        case (1 * 256 + 208): goto H_DECOY_3;
        case (1 * 256 + 209): goto H_DECOY_15;
        case (1 * 256 + 210): goto H_DECOY_11;
        case (1 * 256 + 211): goto H_GET_FLAGS_R_D1;
        case (1 * 256 + 212): goto H_FUSED_SHL_ADD_RRI_D1;
        case (1 * 256 + 213): goto H_JMP_A2_D1;
        case (1 * 256 + 214): goto H_LOAD_32_D1;
        case (1 * 256 + 215): goto H_DECOY_10;
        case (1 * 256 + 216): goto H_CMP_RI_D1;
        case (1 * 256 + 217): goto H_DECOY_8;
        case (1 * 256 + 218): goto H_DECOY_9;
        case (1 * 256 + 219): goto H_DECOY_12;
        case (1 * 256 + 220): goto H_DECOY_14;
        case (1 * 256 + 221): goto H_DECOY_13;
        case (1 * 256 + 222): goto H_DECOY_1;
        case (1 * 256 + 223): goto H_DECOY_9;
        case (1 * 256 + 224): goto H_ROL_RI_D1;
        case (1 * 256 + 225): goto H_CMP_RI_A2_D1;
        case (1 * 256 + 226): goto H_CTZ_RR_D1;
        case (1 * 256 + 227): goto H_DECOY_7;
        case (1 * 256 + 228): goto H_OR_RI_D1;
        case (1 * 256 + 229): goto H_ADD_RI_D1;
        case (1 * 256 + 230): goto H_DECOY_14;
        case (1 * 256 + 231): goto H_DECOY_9;
        case (1 * 256 + 232): goto H_DECOY_14;
        case (1 * 256 + 233): goto H_DECOY_1;
        case (1 * 256 + 234): goto H_ADC_RR_D1;
        case (1 * 256 + 235): goto H_DECOY_12;
        case (1 * 256 + 236): goto H_DECOY_3;
        case (1 * 256 + 237): goto H_ATOMIC_STORE_D1;
        case (1 * 256 + 238): goto H_ATOMIC_SWP_D1;
        case (1 * 256 + 239): goto H_CMP_RR_D1;
        case (1 * 256 + 240): goto H_DECOY_1;
        case (1 * 256 + 241): goto H_DECOY_11;
        case (1 * 256 + 242): goto H_SBB_RR_D1;
        case (1 * 256 + 243): goto H_STORE_32_D1;
        case (1 * 256 + 244): goto H_DECOY_8;
        case (1 * 256 + 245): goto H_DECOY_13;
        case (1 * 256 + 246): goto H_ICALL_R_D1;
        case (1 * 256 + 247): goto H_DECOY_7;
        case (1 * 256 + 248): goto H_FCVT_D1;
        case (1 * 256 + 249): goto H_RESOLVE_SYM_D1;
        case (1 * 256 + 250): goto H_DECOY_10;
        case (1 * 256 + 251): goto H_IMULH_RR_D1;
        case (1 * 256 + 252): goto H_VEC_LOAD_D1;
        case (1 * 256 + 253): goto H_VXOR_VV_D1;
        case (1 * 256 + 254): goto H_DECOY_14;
        case (1 * 256 + 255): goto H_DECOY_1;
        case (2 * 256 + 0): goto H_DECOY_0;
        case (2 * 256 + 1): goto H_DECOY_11;
        case (2 * 256 + 2): goto H_DECOY_5;
        case (2 * 256 + 3): goto H_SUB_RR_A1_D2;
        case (2 * 256 + 4): goto H_DECOY_3;
        case (2 * 256 + 5): goto H_SCVTF_D2;
        case (2 * 256 + 6): goto H_CALL_D2;
        case (2 * 256 + 7): goto H_RBIT_RR_D2;
        case (2 * 256 + 8): goto H_CCMP_RI_D2;
        case (2 * 256 + 9): goto H_DECOY_6;
        case (2 * 256 + 10): goto H_DECOY_11;
        case (2 * 256 + 11): goto H_BRIDGE_TO_FLOW_D2;
        case (2 * 256 + 12): goto H_MOV_RI_A1_D2;
        case (2 * 256 + 13): goto H_VEC_BINOP_D2;
        case (2 * 256 + 14): goto H_MULH_RR_D2;
        case (2 * 256 + 15): goto H_FUSED_MOV_ADD_RRI_D2;
        case (2 * 256 + 16): goto H_DECOY_14;
        case (2 * 256 + 17): goto H_DECOY_6;
        case (2 * 256 + 18): goto H_DECOY_7;
        case (2 * 256 + 19): goto H_DECOY_6;
        case (2 * 256 + 20): goto H_DECOY_14;
        case (2 * 256 + 21): goto H_DECOY_1;
        case (2 * 256 + 22): goto H_CMP_RI_D2;
        case (2 * 256 + 23): goto H_DECOY_9;
        case (2 * 256 + 24): goto H_LOAD_32_D2;
        case (2 * 256 + 25): goto H_DECOY_7;
        case (2 * 256 + 26): goto H_FUSED_SHL_ADD_RRI_D2;
        case (2 * 256 + 27): goto H_JMP_A2_D2;
        case (2 * 256 + 28): goto H_DECOY_0;
        case (2 * 256 + 29): goto H_GET_FLAGS_R_D2;
        case (2 * 256 + 30): goto H_DECOY_4;
        case (2 * 256 + 31): goto H_DECOY_0;
        case (2 * 256 + 32): goto H_ATOMIC_SWP_D2;
        case (2 * 256 + 33): goto H_CMP_RR_D2;
        case (2 * 256 + 34): goto H_DECOY_12;
        case (2 * 256 + 35): goto H_ATOMIC_STORE_D2;
        case (2 * 256 + 36): goto H_ADC_RR_D2;
        case (2 * 256 + 37): goto H_DECOY_1;
        case (2 * 256 + 38): goto H_DECOY_15;
        case (2 * 256 + 39): goto H_DECOY_2;
        case (2 * 256 + 40): goto H_DECOY_11;
        case (2 * 256 + 41): goto H_DECOY_6;
        case (2 * 256 + 42): goto H_OR_RI_D2;
        case (2 * 256 + 43): goto H_ADD_RI_D2;
        case (2 * 256 + 44): goto H_CTZ_RR_D2;
        case (2 * 256 + 45): goto H_DECOY_12;
        case (2 * 256 + 46): goto H_ROL_RI_D2;
        case (2 * 256 + 47): goto H_CMP_RI_A2_D2;
        case (2 * 256 + 48): goto H_DECOY_11;
        case (2 * 256 + 49): goto H_DECOY_14;
        case (2 * 256 + 50): goto H_VEC_LOAD_D2;
        case (2 * 256 + 51): goto H_VXOR_VV_D2;
        case (2 * 256 + 52): goto H_DECOY_15;
        case (2 * 256 + 53): goto H_IMULH_RR_D2;
        case (2 * 256 + 54): goto H_FCVT_D2;
        case (2 * 256 + 55): goto H_RESOLVE_SYM_D2;
        case (2 * 256 + 56): goto H_ICALL_R_D2;
        case (2 * 256 + 57): goto H_DECOY_4;
        case (2 * 256 + 58): goto H_DECOY_1;
        case (2 * 256 + 59): goto H_DECOY_6;
        case (2 * 256 + 60): goto H_SBB_RR_D2;
        case (2 * 256 + 61): goto H_STORE_32_D2;
        case (2 * 256 + 62): goto H_DECOY_2;
        case (2 * 256 + 63): goto H_DECOY_12;
        case (2 * 256 + 64): goto H_DECOY_1;
        case (2 * 256 + 65): goto H_VEC_EXT_D2;
        case (2 * 256 + 66): goto H_DECOY_2;
        case (2 * 256 + 67): goto H_DECOY_3;
        case (2 * 256 + 68): goto H_DECOY_6;
        case (2 * 256 + 69): goto H_DECOY_1;
        case (2 * 256 + 70): goto H_DECOY_0;
        case (2 * 256 + 71): goto H_CLZ_RR_D2;
        case (2 * 256 + 72): goto H_DECOY_1;
        case (2 * 256 + 73): goto H_FCVTZS_D2;
        case (2 * 256 + 74): goto H_LOAD_64_D2;
        case (2 * 256 + 75): goto H_FSUB_DD_D2;
        case (2 * 256 + 76): goto H_DECOY_3;
        case (2 * 256 + 77): goto H_NOP_D2;
        case (2 * 256 + 78): goto H_LOAD_S32_D2;
        case (2 * 256 + 79): goto H_ROR_RR_D2;
        case (2 * 256 + 80): goto H_PMOVMSKB_D2;
        case (2 * 256 + 81): goto H_DECOY_12;
        case (2 * 256 + 82): goto H_DECOY_11;
        case (2 * 256 + 83): goto H_DECOY_10;
        case (2 * 256 + 84): goto H_CMP_RI_A1_D2;
        case (2 * 256 + 85): goto H_DECOY_11;
        case (2 * 256 + 86): goto H_DECOY_10;
        case (2 * 256 + 87): goto H_IJMP_R_D2;
        case (2 * 256 + 88): goto H_VSUB_VV_D2;
        case (2 * 256 + 89): goto H_VADD_VV_D2;
        case (2 * 256 + 90): goto H_AND_RI_D2;
        case (2 * 256 + 91): goto H_DECOY_6;
        case (2 * 256 + 92): goto H_DECOY_1;
        case (2 * 256 + 93): goto H_FUSED_ADD_IMUL_RRI_D2;
        case (2 * 256 + 94): goto H_SAR_RR_D2;
        case (2 * 256 + 95): goto H_DECOY_12;
        case (2 * 256 + 96): goto H_AND_RR_D2;
        case (2 * 256 + 97): goto H_DECOY_2;
        case (2 * 256 + 98): goto H_DECOY_6;
        case (2 * 256 + 99): goto H_DECOY_11;
        case (2 * 256 + 100): goto H_DECOY_4;
        case (2 * 256 + 101): goto H_DECOY_3;
        case (2 * 256 + 102): goto H_LOAD_8_D2;
        case (2 * 256 + 103): goto H_DECOY_15;
        case (2 * 256 + 104): goto H_DECOY_0;
        case (2 * 256 + 105): goto H_FUSED_CMP_CMOV_D2;
        case (2 * 256 + 106): goto H_VEC_STORE_D2;
        case (2 * 256 + 107): goto H_DECOY_5;
        case (2 * 256 + 108): goto H_DECOY_8;
        case (2 * 256 + 109): goto H_DECOY_2;
        case (2 * 256 + 110): goto H_UCVTF_D2;
        case (2 * 256 + 111): goto H_DECOY_2;
        case (2 * 256 + 112): goto H_LOAD_S8_D2;
        case (2 * 256 + 113): goto H_POP_R_D2;
        case (2 * 256 + 114): goto H_DECOY_10;
        case (2 * 256 + 115): goto H_DECOY_4;
        case (2 * 256 + 116): goto H_DECOY_7;
        case (2 * 256 + 117): goto H_DECOY_11;
        case (2 * 256 + 118): goto H_DECOY_11;
        case (2 * 256 + 119): goto H_DECOY_10;
        case (2 * 256 + 120): goto H_DECOY_6;
        case (2 * 256 + 121): goto H_MOV_RI_A2_D2;
        case (2 * 256 + 122): goto H_VEC_ZERO_UPPER_D2;
        case (2 * 256 + 123): goto H_STORE_8_D2;
        case (2 * 256 + 124): goto H_DECOY_7;
        case (2 * 256 + 125): goto H_MOV_HIGH_D2;
        case (2 * 256 + 126): goto H_FSQRT_D_D2;
        case (2 * 256 + 127): goto H_DECOY_0;
        case (2 * 256 + 128): goto H_ROR_RI_D2;
        case (2 * 256 + 129): goto H_FUSED_SUB_XOR_RRI_D2;
        case (2 * 256 + 130): goto H_DECOY_5;
        case (2 * 256 + 131): goto H_DECOY_3;
        case (2 * 256 + 132): goto H_FENCE_D2;
        case (2 * 256 + 133): goto H_XOR_RI_D2;
        case (2 * 256 + 134): goto H_DECOY_0;
        case (2 * 256 + 135): goto H_VEC_IMM_D2;
        case (2 * 256 + 136): goto H_DECOY_14;
        case (2 * 256 + 137): goto H_ADD_RR_A2_D2;
        case (2 * 256 + 138): goto H_CMOV_D2;
        case (2 * 256 + 139): goto H_ATOMIC_ADD_D2;
        case (2 * 256 + 140): goto H_DECOY_14;
        case (2 * 256 + 141): goto H_DECOY_13;
        case (2 * 256 + 142): goto H_VEC_CLEAR_UPPER_D2;
        case (2 * 256 + 143): goto H_IDIV_RR_D2;
        case (2 * 256 + 144): goto H_BRIDGE_TO_MATH_D2;
        case (2 * 256 + 145): goto H_DECOY_11;
        case (2 * 256 + 146): goto H_ADD_RR_A1_D2;
        case (2 * 256 + 147): goto H_DECOY_10;
        case (2 * 256 + 148): goto H_DECOY_3;
        case (2 * 256 + 149): goto H_FUSED_AND_OR_RRI_D2;
        case (2 * 256 + 150): goto H_DECOY_8;
        case (2 * 256 + 151): goto H_CCMN_RR_D2;
        case (2 * 256 + 152): goto H_OR_RR_D2;
        case (2 * 256 + 153): goto H_DECOY_7;
        case (2 * 256 + 154): goto H_VEC_SPLAT_D2;
        case (2 * 256 + 155): goto H_MOV_RR_A1_D2;
        case (2 * 256 + 156): goto H_FCSEL_VV_D2;
        case (2 * 256 + 157): goto H_DECOY_4;
        case (2 * 256 + 158): goto H_DECOY_10;
        case (2 * 256 + 159): goto H_LOAD_16_D2;
        case (2 * 256 + 160): goto H_MOV_RI_D2;
        case (2 * 256 + 161): goto H_DECOY_3;
        case (2 * 256 + 162): goto H_STORE_16_D2;
        case (2 * 256 + 163): goto H_FADD_DD_D2;
        case (2 * 256 + 164): goto H_DECOY_0;
        case (2 * 256 + 165): goto H_DECOY_1;
        case (2 * 256 + 166): goto H_DECOY_11;
        case (2 * 256 + 167): goto H_XOR_RR_D2;
        case (2 * 256 + 168): goto H_SETCC_D2;
        case (2 * 256 + 169): goto H_SAR_RI_D2;
        case (2 * 256 + 170): goto H_DECOY_13;
        case (2 * 256 + 171): goto H_POPCNT_RR_D2;
        case (2 * 256 + 172): goto H_CALL_EXTERN_D2;
        case (2 * 256 + 173): goto H_FUSED_ADD_XOR_RRI_D2;
        case (2 * 256 + 174): goto H_JMP_A1_D2;
        case (2 * 256 + 175): goto H_SHL_RI_D2;
        case (2 * 256 + 176): goto H_DECOY_7;
        case (2 * 256 + 177): goto H_SET_FLAGS_R_D2;
        case (2 * 256 + 178): goto H_IMUL_RR_D2;
        case (2 * 256 + 179): goto H_EXIT_D2;
        case (2 * 256 + 180): goto H_DECOY_1;
        case (2 * 256 + 181): goto H_LOAD_S16_D2;
        case (2 * 256 + 182): goto H_DECOY_6;
        case (2 * 256 + 183): goto H_AND_RR_A1_D2;
        case (2 * 256 + 184): goto H_FCVTZU_D2;
        case (2 * 256 + 185): goto H_JCC_D2;
        case (2 * 256 + 186): goto H_DECOY_7;
        case (2 * 256 + 187): goto H_DECOY_13;
        case (2 * 256 + 188): goto H_MOV_RR_A2_D2;
        case (2 * 256 + 189): goto H_DECOY_14;
        case (2 * 256 + 190): goto H_DECOY_4;
        case (2 * 256 + 191): goto H_DECOY_0;
        case (2 * 256 + 192): goto H_DECOY_8;
        case (2 * 256 + 193): goto H_DECOY_9;
        case (2 * 256 + 194): goto H_DECOY_12;
        case (2 * 256 + 195): goto H_DECOY_6;
        case (2 * 256 + 196): goto H_ATOMIC_CAS_D2;
        case (2 * 256 + 197): goto H_JMP_D2;
        case (2 * 256 + 198): goto H_DECOY_14;
        case (2 * 256 + 199): goto H_VEC_MOV_D2;
        case (2 * 256 + 200): goto H_FDIV_DD_D2;
        case (2 * 256 + 201): goto H_DECOY_2;
        case (2 * 256 + 202): goto H_DECOY_14;
        case (2 * 256 + 203): goto H_DIV_RR_D2;
        case (2 * 256 + 204): goto H_ATOMIC_LOAD_D2;
        case (2 * 256 + 205): goto H_MOV_VR_D2;
        case (2 * 256 + 206): goto H_DECOY_10;
        case (2 * 256 + 207): goto H_DECOY_10;
        case (2 * 256 + 208): goto H_NOT_RR_D2;
        case (2 * 256 + 209): goto H_DECOY_4;
        case (2 * 256 + 210): goto H_DECOY_4;
        case (2 * 256 + 211): goto H_DECOY_14;
        case (2 * 256 + 212): goto H_ADC_RI_D2;
        case (2 * 256 + 213): goto H_DECOY_6;
        case (2 * 256 + 214): goto H_DECOY_9;
        case (2 * 256 + 215): goto H_MOV_RV_D2;
        case (2 * 256 + 216): goto H_DECOY_1;
        case (2 * 256 + 217): goto H_DECOY_3;
        case (2 * 256 + 218): goto H_OR_RR_A1_D2;
        case (2 * 256 + 219): goto H_DECOY_15;
        case (2 * 256 + 220): goto H_DECOY_13;
        case (2 * 256 + 221): goto H_IMUL_RI_D2;
        case (2 * 256 + 222): goto H_VMUL_VV_D2;
        case (2 * 256 + 223): goto H_SHL_RR_D2;
        case (2 * 256 + 224): goto H_DECOY_6;
        case (2 * 256 + 225): goto H_PUSH_R_D2;
        case (2 * 256 + 226): goto H_MOV_RR_D2;
        case (2 * 256 + 227): goto H_DECOY_10;
        case (2 * 256 + 228): goto H_CMP_RR_A1_D2;
        case (2 * 256 + 229): goto H_DECOY_3;
        case (2 * 256 + 230): goto H_DECOY_9;
        case (2 * 256 + 231): goto H_DECOY_7;
        case (2 * 256 + 232): goto H_DECOY_14;
        case (2 * 256 + 233): goto H_FUSED_XOR_ADD_RRI_D2;
        case (2 * 256 + 234): goto H_CCMP_RR_D2;
        case (2 * 256 + 235): goto H_CCMN_RI_D2;
        case (2 * 256 + 236): goto H_DECOY_14;
        case (2 * 256 + 237): goto H_ADD_RR_D2;
        case (2 * 256 + 238): goto H_BSWAP_RR_D2;
        case (2 * 256 + 239): goto H_ROL_RR_D2;
        case (2 * 256 + 240): goto H_SUB_RI_D2;
        case (2 * 256 + 241): goto H_SHR_RR_D2;
        case (2 * 256 + 242): goto H_DECOY_6;
        case (2 * 256 + 243): goto H_JCC_A1_D2;
        case (2 * 256 + 244): goto H_SHR_RI_D2;
        case (2 * 256 + 245): goto H_FCMP_DD_D2;
        case (2 * 256 + 246): goto H_SUB_RR_D2;
        case (2 * 256 + 247): goto H_DECOY_0;
        case (2 * 256 + 248): goto H_DECOY_9;
        case (2 * 256 + 249): goto H_DECOY_9;
        case (2 * 256 + 250): goto H_NEG_RR_D2;
        case (2 * 256 + 251): goto H_XOR_RR_A1_D2;
        case (2 * 256 + 252): goto H_SBB_RI_D2;
        case (2 * 256 + 253): goto H_FMUL_DD_D2;
        case (2 * 256 + 254): goto H_STORE_64_D2;
        case (2 * 256 + 255): goto H_RET_D2;
        case (3 * 256 + 0): goto H_OR_RR_A1_D3;
        case (3 * 256 + 1): goto H_DECOY_8;
        case (3 * 256 + 2): goto H_DECOY_6;
        case (3 * 256 + 3): goto H_DECOY_8;
        case (3 * 256 + 4): goto H_VMUL_VV_D3;
        case (3 * 256 + 5): goto H_SHL_RR_D3;
        case (3 * 256 + 6): goto H_DECOY_2;
        case (3 * 256 + 7): goto H_IMUL_RI_D3;
        case (3 * 256 + 8): goto H_DECOY_13;
        case (3 * 256 + 9): goto H_DECOY_7;
        case (3 * 256 + 10): goto H_NOT_RR_D3;
        case (3 * 256 + 11): goto H_DECOY_9;
        case (3 * 256 + 12): goto H_DECOY_2;
        case (3 * 256 + 13): goto H_MOV_RV_D3;
        case (3 * 256 + 14): goto H_ADC_RI_D3;
        case (3 * 256 + 15): goto H_DECOY_11;
        case (3 * 256 + 16): goto H_DECOY_7;
        case (3 * 256 + 17): goto H_DIV_RR_D3;
        case (3 * 256 + 18): goto H_FDIV_DD_D3;
        case (3 * 256 + 19): goto H_DECOY_7;
        case (3 * 256 + 20): goto H_DECOY_3;
        case (3 * 256 + 21): goto H_DECOY_3;
        case (3 * 256 + 22): goto H_ATOMIC_LOAD_D3;
        case (3 * 256 + 23): goto H_MOV_VR_D3;
        case (3 * 256 + 24): goto H_DECOY_5;
        case (3 * 256 + 25): goto H_DECOY_15;
        case (3 * 256 + 26): goto H_DECOY_13;
        case (3 * 256 + 27): goto H_DECOY_14;
        case (3 * 256 + 28): goto H_DECOY_7;
        case (3 * 256 + 29): goto H_VEC_MOV_D3;
        case (3 * 256 + 30): goto H_ATOMIC_CAS_D3;
        case (3 * 256 + 31): goto H_JMP_D3;
        case (3 * 256 + 32): goto H_NEG_RR_D3;
        case (3 * 256 + 33): goto H_XOR_RR_A1_D3;
        case (3 * 256 + 34): goto H_DECOY_14;
        case (3 * 256 + 35): goto H_DECOY_14;
        case (3 * 256 + 36): goto H_STORE_64_D3;
        case (3 * 256 + 37): goto H_RET_D3;
        case (3 * 256 + 38): goto H_SBB_RI_D3;
        case (3 * 256 + 39): goto H_FMUL_DD_D3;
        case (3 * 256 + 40): goto H_DECOY_15;
        case (3 * 256 + 41): goto H_JCC_A1_D3;
        case (3 * 256 + 42): goto H_SUB_RI_D3;
        case (3 * 256 + 43): goto H_SHR_RR_D3;
        case (3 * 256 + 44): goto H_SUB_RR_D3;
        case (3 * 256 + 45): goto H_DECOY_9;
        case (3 * 256 + 46): goto H_SHR_RI_D3;
        case (3 * 256 + 47): goto H_FCMP_DD_D3;
        case (3 * 256 + 48): goto H_CCMP_RR_D3;
        case (3 * 256 + 49): goto H_CCMN_RI_D3;
        case (3 * 256 + 50): goto H_DECOY_3;
        case (3 * 256 + 51): goto H_FUSED_XOR_ADD_RRI_D3;
        case (3 * 256 + 52): goto H_BSWAP_RR_D3;
        case (3 * 256 + 53): goto H_ROL_RR_D3;
        case (3 * 256 + 54): goto H_DECOY_3;
        case (3 * 256 + 55): goto H_ADD_RR_D3;
        case (3 * 256 + 56): goto H_MOV_RR_D3;
        case (3 * 256 + 57): goto H_DECOY_3;
        case (3 * 256 + 58): goto H_DECOY_11;
        case (3 * 256 + 59): goto H_PUSH_R_D3;
        case (3 * 256 + 60): goto H_DECOY_2;
        case (3 * 256 + 61): goto H_DECOY_0;
        case (3 * 256 + 62): goto H_CMP_RR_A1_D3;
        case (3 * 256 + 63): goto H_DECOY_8;
        case (3 * 256 + 64): goto H_VEC_SPLAT_D3;
        case (3 * 256 + 65): goto H_MOV_RR_A1_D3;
        case (3 * 256 + 66): goto H_OR_RR_D3;
        case (3 * 256 + 67): goto H_DECOY_12;
        case (3 * 256 + 68): goto H_DECOY_3;
        case (3 * 256 + 69): goto H_LOAD_16_D3;
        case (3 * 256 + 70): goto H_FCSEL_VV_D3;
        case (3 * 256 + 71): goto H_DECOY_9;
        case (3 * 256 + 72): goto H_ADD_RR_A1_D3;
        case (3 * 256 + 73): goto H_DECOY_3;
        case (3 * 256 + 74): goto H_BRIDGE_TO_MATH_D3;
        case (3 * 256 + 75): goto H_DECOY_0;
        case (3 * 256 + 76): goto H_DECOY_1;
        case (3 * 256 + 77): goto H_CCMN_RR_D3;
        case (3 * 256 + 78): goto H_DECOY_8;
        case (3 * 256 + 79): goto H_FUSED_AND_OR_RRI_D3;
        case (3 * 256 + 80): goto H_CMOV_D3;
        case (3 * 256 + 81): goto H_ATOMIC_ADD_D3;
        case (3 * 256 + 82): goto H_DECOY_3;
        case (3 * 256 + 83): goto H_ADD_RR_A2_D3;
        case (3 * 256 + 84): goto H_VEC_CLEAR_UPPER_D3;
        case (3 * 256 + 85): goto H_IDIV_RR_D3;
        case (3 * 256 + 86): goto H_DECOY_3;
        case (3 * 256 + 87): goto H_DECOY_2;
        case (3 * 256 + 88): goto H_DECOY_14;
        case (3 * 256 + 89): goto H_DECOY_12;
        case (3 * 256 + 90): goto H_ROR_RI_D3;
        case (3 * 256 + 91): goto H_FUSED_SUB_XOR_RRI_D3;
        case (3 * 256 + 92): goto H_DECOY_9;
        case (3 * 256 + 93): goto H_VEC_IMM_D3;
        case (3 * 256 + 94): goto H_FENCE_D3;
        case (3 * 256 + 95): goto H_XOR_RI_D3;
        case (3 * 256 + 96): goto H_DECOY_0;
        case (3 * 256 + 97): goto H_DECOY_6;
        case (3 * 256 + 98): goto H_FCVTZU_D3;
        case (3 * 256 + 99): goto H_JCC_D3;
        case (3 * 256 + 100): goto H_DECOY_13;
        case (3 * 256 + 101): goto H_DECOY_9;
        case (3 * 256 + 102): goto H_MOV_RR_A2_D3;
        case (3 * 256 + 103): goto H_DECOY_3;
        case (3 * 256 + 104): goto H_IMUL_RR_D3;
        case (3 * 256 + 105): goto H_EXIT_D3;
        case (3 * 256 + 106): goto H_DECOY_12;
        case (3 * 256 + 107): goto H_SET_FLAGS_R_D3;
        case (3 * 256 + 108): goto H_DECOY_15;
        case (3 * 256 + 109): goto H_AND_RR_A1_D3;
        case (3 * 256 + 110): goto H_DECOY_6;
        case (3 * 256 + 111): goto H_LOAD_S16_D3;
        case (3 * 256 + 112): goto H_DECOY_6;
        case (3 * 256 + 113): goto H_POPCNT_RR_D3;
        case (3 * 256 + 114): goto H_SETCC_D3;
        case (3 * 256 + 115): goto H_SAR_RI_D3;
        case (3 * 256 + 116): goto H_JMP_A1_D3;
        case (3 * 256 + 117): goto H_SHL_RI_D3;
        case (3 * 256 + 118): goto H_CALL_EXTERN_D3;
        case (3 * 256 + 119): goto H_FUSED_ADD_XOR_RRI_D3;
        case (3 * 256 + 120): goto H_STORE_16_D3;
        case (3 * 256 + 121): goto H_FADD_DD_D3;
        case (3 * 256 + 122): goto H_MOV_RI_D3;
        case (3 * 256 + 123): goto H_DECOY_8;
        case (3 * 256 + 124): goto H_DECOY_4;
        case (3 * 256 + 125): goto H_XOR_RR_D3;
        case (3 * 256 + 126): goto H_DECOY_5;
        case (3 * 256 + 127): goto H_DECOY_6;
        case (3 * 256 + 128): goto H_AND_RI_D3;
        case (3 * 256 + 129): goto H_DECOY_15;
        case (3 * 256 + 130): goto H_VSUB_VV_D3;
        case (3 * 256 + 131): goto H_VADD_VV_D3;
        case (3 * 256 + 132): goto H_SAR_RR_D3;
        case (3 * 256 + 133): goto H_DECOY_5;
        case (3 * 256 + 134): goto H_DECOY_6;
        case (3 * 256 + 135): goto H_FUSED_ADD_IMUL_RRI_D3;
        case (3 * 256 + 136): goto H_DECOY_4;
        case (3 * 256 + 137): goto H_DECOY_3;
        case (3 * 256 + 138): goto H_PMOVMSKB_D3;
        case (3 * 256 + 139): goto H_DECOY_1;
        case (3 * 256 + 140): goto H_DECOY_3;
        case (3 * 256 + 141): goto H_IJMP_R_D3;
        case (3 * 256 + 142): goto H_CMP_RI_A1_D3;
        case (3 * 256 + 143): goto H_DECOY_0;
        case (3 * 256 + 144): goto H_LOAD_64_D3;
        case (3 * 256 + 145): goto H_FSUB_DD_D3;
        case (3 * 256 + 146): goto H_DECOY_6;
        case (3 * 256 + 147): goto H_FCVTZS_D3;
        case (3 * 256 + 148): goto H_LOAD_S32_D3;
        case (3 * 256 + 149): goto H_ROR_RR_D3;
        case (3 * 256 + 150): goto H_DECOY_8;
        case (3 * 256 + 151): goto H_NOP_D3;
        case (3 * 256 + 152): goto H_DECOY_11;
        case (3 * 256 + 153): goto H_DECOY_12;
        case (3 * 256 + 154): goto H_DECOY_6;
        case (3 * 256 + 155): goto H_VEC_EXT_D3;
        case (3 * 256 + 156): goto H_DECOY_9;
        case (3 * 256 + 157): goto H_CLZ_RR_D3;
        case (3 * 256 + 158): goto H_DECOY_11;
        case (3 * 256 + 159): goto H_DECOY_6;
        case (3 * 256 + 160): goto H_VEC_ZERO_UPPER_D3;
        case (3 * 256 + 161): goto H_STORE_8_D3;
        case (3 * 256 + 162): goto H_DECOY_11;
        case (3 * 256 + 163): goto H_MOV_RI_A2_D3;
        case (3 * 256 + 164): goto H_FSQRT_D_D3;
        case (3 * 256 + 165): goto H_DECOY_9;
        case (3 * 256 + 166): goto H_DECOY_12;
        case (3 * 256 + 167): goto H_MOV_HIGH_D3;
        case (3 * 256 + 168): goto H_DECOY_3;
        case (3 * 256 + 169): goto H_DECOY_13;
        case (3 * 256 + 170): goto H_LOAD_S8_D3;
        case (3 * 256 + 171): goto H_POP_R_D3;
        case (3 * 256 + 172): goto H_DECOY_4;
        case (3 * 256 + 173): goto H_DECOY_3;
        case (3 * 256 + 174): goto H_DECOY_12;
        case (3 * 256 + 175): goto H_DECOY_0;
        case (3 * 256 + 176): goto H_VEC_STORE_D3;
        case (3 * 256 + 177): goto H_DECOY_14;
        case (3 * 256 + 178): goto H_DECOY_5;
        case (3 * 256 + 179): goto H_FUSED_CMP_CMOV_D3;
        case (3 * 256 + 180): goto H_UCVTF_D3;
        case (3 * 256 + 181): goto H_DECOY_11;
        case (3 * 256 + 182): goto H_DECOY_13;
        case (3 * 256 + 183): goto H_DECOY_7;
        case (3 * 256 + 184): goto H_DECOY_15;
        case (3 * 256 + 185): goto H_DECOY_4;
        case (3 * 256 + 186): goto H_AND_RR_D3;
        case (3 * 256 + 187): goto H_DECOY_7;
        case (3 * 256 + 188): goto H_LOAD_8_D3;
        case (3 * 256 + 189): goto H_DECOY_8;
        case (3 * 256 + 190): goto H_DECOY_9;
        case (3 * 256 + 191): goto H_DECOY_8;
        case (3 * 256 + 192): goto H_FUSED_SHL_ADD_RRI_D3;
        case (3 * 256 + 193): goto H_JMP_A2_D3;
        case (3 * 256 + 194): goto H_LOAD_32_D3;
        case (3 * 256 + 195): goto H_DECOY_12;
        case (3 * 256 + 196): goto H_DECOY_13;
        case (3 * 256 + 197): goto H_DECOY_9;
        case (3 * 256 + 198): goto H_DECOY_5;
        case (3 * 256 + 199): goto H_GET_FLAGS_R_D3;
        case (3 * 256 + 200): goto H_DECOY_0;
        case (3 * 256 + 201): goto H_DECOY_15;
        case (3 * 256 + 202): goto H_DECOY_3;
        case (3 * 256 + 203): goto H_DECOY_11;
        case (3 * 256 + 204): goto H_CMP_RI_D3;
        case (3 * 256 + 205): goto H_DECOY_2;
        case (3 * 256 + 206): goto H_DECOY_3;
        case (3 * 256 + 207): goto H_DECOY_6;
        case (3 * 256 + 208): goto H_DECOY_4;
        case (3 * 256 + 209): goto H_BRIDGE_TO_FLOW_D3;
        case (3 * 256 + 210): goto H_CCMP_RI_D3;
        case (3 * 256 + 211): goto H_DECOY_11;
        case (3 * 256 + 212): goto H_MULH_RR_D3;
        case (3 * 256 + 213): goto H_FUSED_MOV_ADD_RRI_D3;
        case (3 * 256 + 214): goto H_MOV_RI_A1_D3;
        case (3 * 256 + 215): goto H_VEC_BINOP_D3;
        case (3 * 256 + 216): goto H_DECOY_14;
        case (3 * 256 + 217): goto H_SUB_RR_A1_D3;
        case (3 * 256 + 218): goto H_DECOY_5;
        case (3 * 256 + 219): goto H_DECOY_0;
        case (3 * 256 + 220): goto H_CALL_D3;
        case (3 * 256 + 221): goto H_RBIT_RR_D3;
        case (3 * 256 + 222): goto H_DECOY_8;
        case (3 * 256 + 223): goto H_SCVTF_D3;
        case (3 * 256 + 224): goto H_DECOY_10;
        case (3 * 256 + 225): goto H_DECOY_15;
        case (3 * 256 + 226): goto H_ICALL_R_D3;
        case (3 * 256 + 227): goto H_DECOY_9;
        case (3 * 256 + 228): goto H_DECOY_11;
        case (3 * 256 + 229): goto H_DECOY_5;
        case (3 * 256 + 230): goto H_SBB_RR_D3;
        case (3 * 256 + 231): goto H_STORE_32_D3;
        case (3 * 256 + 232): goto H_VEC_LOAD_D3;
        case (3 * 256 + 233): goto H_VXOR_VV_D3;
        case (3 * 256 + 234): goto H_DECOY_0;
        case (3 * 256 + 235): goto H_DECOY_3;
        case (3 * 256 + 236): goto H_FCVT_D3;
        case (3 * 256 + 237): goto H_RESOLVE_SYM_D3;
        case (3 * 256 + 238): goto H_DECOY_4;
        case (3 * 256 + 239): goto H_IMULH_RR_D3;
        case (3 * 256 + 240): goto H_OR_RI_D3;
        case (3 * 256 + 241): goto H_ADD_RI_D3;
        case (3 * 256 + 242): goto H_DECOY_0;
        case (3 * 256 + 243): goto H_DECOY_11;
        case (3 * 256 + 244): goto H_ROL_RI_D3;
        case (3 * 256 + 245): goto H_CMP_RI_A2_D3;
        case (3 * 256 + 246): goto H_CTZ_RR_D3;
        case (3 * 256 + 247): goto H_DECOY_1;
        case (3 * 256 + 248): goto H_DECOY_5;
        case (3 * 256 + 249): goto H_ATOMIC_STORE_D3;
        case (3 * 256 + 250): goto H_ATOMIC_SWP_D3;
        case (3 * 256 + 251): goto H_CMP_RR_D3;
        case (3 * 256 + 252): goto H_DECOY_8;
        case (3 * 256 + 253): goto H_DECOY_11;
        case (3 * 256 + 254): goto H_ADC_RR_D3;
        case (3 * 256 + 255): goto H_DECOY_6;

        default: goto EXIT_VM;
        }
    }
    START_VM_MSVC:
#endif
                                    if (__builtin_expect(asg_vm_trace_on, 0)) { fputs("# B\n", stderr); }
                                    FETCH_NEXT();
                                        #define PROBE_START() do {} while(0)
    #define PROBE_CHECK() do {} while(0)

    H_NOP: { ctx.executed_instructions += 1; FETCH_NEXT(); }
    H_MOV_RR: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x0000000000000002ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_s ^ 0x2643beaed856e0edULL) ^ 0x2643beaed856e0edULL) : ((_s + 0xc1ab5d8ac3da7af8ULL) - 0xc1ab5d8ac3da7af8ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x0000000000000014ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_imm ^ 0x657ca4452b43e521ULL) ^ 0x657ca4452b43e521ULL) : ((_imm + 0xcc53264e4acf3ce8ULL) - 0xcc53264e4acf3ce8ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_A1: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x000000000000000eULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_s + 0x0000000013375877ULL) - 0x0000000013375877ULL) : ((_s ^ 0x4edb898495500e83ULL) ^ 0x4edb898495500e83ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_A2: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x0000000000000013ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~((~_s))) : (_s ^ 0x0000000000000000ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_A1: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x000000000000001fULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_imm ^ 0x651a2a228022e492ULL) ^ 0x651a2a228022e492ULL) : ((_imm + 0x0000000058771337ULL) - 0x0000000058771337ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_A2: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x000000000000000bULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~((~_imm))) : ((_imm + 0x00000000deadbeefULL) - 0x00000000deadbeefULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_HIGH: {
        uint64_t _d = ctx.get_reg(dst);
        uint64_t _hi = (static_cast<uint64_t>(static_cast<uint32_t>(imm)) << 32);
        ctx.set_reg(dst, ((_d & 0x00000000ffffffffULL) ^ _hi));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_NEG_RR: { PROBE_START(); uint64_t _v = ctx.get_reg(dst); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000015ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((~_v) + 0x0000000000000001ULL) : (0x0000000000000000ULL - _v))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_NOT_RR: { PROBE_START(); uint64_t _v = ctx.get_reg(dst); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000013ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~_v) : (_v ^ (~0x0000000000000000ULL)))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_BSWAP_RR: {
        uint32_t bits = static_cast<uint32_t>(imm);
        if (bits == 16) {
                     ctx.set_reg(dst, static_cast<uint64_t>(__builtin_bswap16(static_cast<uint16_t>(ctx.get_reg(src)))));
} else {
            if (bits == 32) {
                                 ctx.set_reg(dst, static_cast<uint64_t>(__builtin_bswap32(static_cast<uint32_t>(ctx.get_reg(src)))));
            } else {
                        ctx.set_reg(dst, __builtin_bswap64(ctx.get_reg(src)));
            }
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CLZ_RR: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (val & mask);
        uint64_t _clz = ((bits <= 32) ? ((static_cast<uint32_t>(mval) == 0) ? static_cast<uint64_t>(bits) : static_cast<uint64_t>((__builtin_clz(static_cast<uint32_t>(mval)) - (32 - bits)))) : ((mval == 0x0000000000000000ULL) ? 0x0000000000000040ULL : static_cast<uint64_t>(__builtin_clzll(mval))));
        ctx.set_reg(dst, _clz);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CTZ_RR: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (val & mask);
        uint64_t _ctz = ((bits <= 32) ? ((static_cast<uint32_t>(mval) == 0) ? static_cast<uint64_t>(bits) : static_cast<uint64_t>(__builtin_ctz(static_cast<uint32_t>(mval)))) : ((mval == 0x0000000000000000ULL) ? 0x0000000000000040ULL : static_cast<uint64_t>(__builtin_ctzll(mval))));
        ctx.set_reg(dst, _ctz);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_POPCNT_RR: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (val & mask);
        uint64_t res = ((bits <= 32) ? static_cast<uint64_t>(__builtin_popcount(static_cast<uint32_t>(mval))) : static_cast<uint64_t>(__builtin_popcountll(mval)));
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RBIT_RR: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t res = 0x0000000000000000ULL;
        for (size_t i = 0; i < bits; ++i) {
                                       if (((val >> i) & 0x0000000000000001ULL) != 0x0000000000000000ULL) {
                                       
                                           res |= (0x0000000000000001ULL << ((bits - 1) - i));
                                       }
}
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADD_RR: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000000ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))))) + (((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) + (ctx.get_reg(src) & 0x5555555555555555ULL)) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) ^ ((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))))) + (((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) + (ctx.get_reg(src) & 0x5555555555555555ULL)) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x71d690ac9bf64a55ULL) << 0x0000000000000021ULL)) ^ (((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))))) + (((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) + (ctx.get_reg(src) & 0x5555555555555555ULL)) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) ^ ((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))))) + (((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (((ctx.get_reg(src) & 0x5555555555555555ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(src) & 0x5555555555555555ULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) + (ctx.get_reg(src) & 0x5555555555555555ULL)) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) + 0x0000000000000003ULL))))))))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x71d690ac9bf64a55ULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x71d690ac9bf64a55ULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RI: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000006ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) + static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & static_cast<uint64_t>(imm)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RR_A1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000009ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) : ((0x0000000000000002ULL * (ctx.get_reg(dst) | ctx.get_reg(src))) - (ctx.get_reg(dst) ^ ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RR_A2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000009ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RR: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001aULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((0x0000000000000002ULL * ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) | ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) - ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) + ((((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) | ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL)))) + ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) - (ctx.get_reg(dst) - ctx.get_reg(src)))) ^ ((((((0x0000000000000002ULL * ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) | ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) - ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) + ((((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) | ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL)))) + ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) - (ctx.get_reg(dst) - ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x55dcf4194893e261ULL) << 0x0000000000000021ULL)) ^ (((((((0x0000000000000002ULL * ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) | ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) - ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) + ((((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) | ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL)))) + ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) - (ctx.get_reg(dst) - ctx.get_reg(src)))) ^ ((((((0x0000000000000002ULL * ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) | ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) - ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) + ((((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) | ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL)))) + ((((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~0x5555555555555555ULL))) + ((ctx.get_reg(dst) ^ 0x5555555555555555ULL) - ((ctx.get_reg(dst) | 0x5555555555555555ULL) - (ctx.get_reg(dst) & 0x5555555555555555ULL)))) - ((ctx.get_reg(src) + 0x5555555555555555ULL) - (ctx.get_reg(src) | 0x5555555555555555ULL))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & 0xffffffff00000000ULL)) - (((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL) & 0xff00ff00ff00ff00ULL))))) - (ctx.get_reg(dst) - ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x55dcf4194893e261ULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x55dcf4194893e261ULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RR_A1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) - (ctx.get_reg(dst) ^ ctx.get_reg(src))) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RI: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) - static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & static_cast<uint64_t>(imm)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_IMUL_RR: { PROBE_START(); uint64_t a = ctx.get_reg(dst); uint64_t b = ctx.get_reg(src); uint64_t res = ((((k_dyn >> 0x000000000000000cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (a * b) : (((a & b) * (a | b)) + ((a & (~b)) * ((~a) & b)))); ctx.set_reg(dst, res); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_IMUL_RI: { PROBE_START(); uint64_t a = ctx.get_reg(dst); uint64_t b = static_cast<uint64_t>(imm); uint64_t res = ((((k_dyn >> 0x0000000000000018ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (a * b) : (((a & b) * (a | b)) + ((a & (~b)) * ((~a) & b)))); ctx.set_reg(dst, res); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RR: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000013ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((((((ctx.get_reg(dst) + ctx.get_reg(src)) & (~((0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))) - ((~((ctx.get_reg(dst) + ctx.get_reg(src)))) & (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))) + (((ctx.get_reg(dst) + ctx.get_reg(src)) ^ (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - (((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - ((ctx.get_reg(dst) + ctx.get_reg(src)) & (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))))) ^ (((((((ctx.get_reg(dst) + ctx.get_reg(src)) & (~((0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))) - ((~((ctx.get_reg(dst) + ctx.get_reg(src)))) & (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))) + (((ctx.get_reg(dst) + ctx.get_reg(src)) ^ (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - (((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - ((ctx.get_reg(dst) + ctx.get_reg(src)) & (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))))) & 0x000000007fffffffULL) * 0x3c02176c365d2385ULL) << 0x0000000000000021ULL)) ^ ((((((((ctx.get_reg(dst) + ctx.get_reg(src)) & (~((0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))) - ((~((ctx.get_reg(dst) + ctx.get_reg(src)))) & (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))) + (((ctx.get_reg(dst) + ctx.get_reg(src)) ^ (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - (((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - ((ctx.get_reg(dst) + ctx.get_reg(src)) & (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))))) ^ (((((((ctx.get_reg(dst) + ctx.get_reg(src)) & (~((0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))) - ((~((ctx.get_reg(dst) + ctx.get_reg(src)))) & (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))) + (((ctx.get_reg(dst) + ctx.get_reg(src)) ^ (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - (((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - ((ctx.get_reg(dst) + ctx.get_reg(src)) & (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))))) & 0x000000007fffffffULL) * 0x3c02176c365d2385ULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x3c02176c365d2385ULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RR_A1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000017ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RI: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000012ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) | static_cast<uint64_t>(imm)) - (ctx.get_reg(dst) & static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RR: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000010ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((((ctx.get_reg(dst) ^ (ctx.get_reg(dst) & (~ctx.get_reg(src)))) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) & (~ctx.get_reg(src))) * ((ctx.get_reg(dst) & (~ctx.get_reg(src))) + 0x0000000000000001ULL)))) + ((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) ^ ((0x0000000000000002ULL * ((ctx.get_reg(dst) | ctx.get_reg(src)) & (~((ctx.get_reg(dst) & ctx.get_reg(src)))))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) ^ (ctx.get_reg(dst) & ctx.get_reg(src))))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) ^ ctx.get_reg(src)))) & ((0x0000000000000002ULL * ((ctx.get_reg(dst) | ctx.get_reg(src)) & (~((ctx.get_reg(dst) & ctx.get_reg(src)))))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) ^ (ctx.get_reg(dst) & ctx.get_reg(src))))))) + (0x8000000000000000ULL * (((0x0000000000000002ULL * ((ctx.get_reg(dst) | ctx.get_reg(src)) & (~((ctx.get_reg(dst) & ctx.get_reg(src)))))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) ^ (ctx.get_reg(dst) & ctx.get_reg(src)))) * (((0x0000000000000002ULL * ((ctx.get_reg(dst) | ctx.get_reg(src)) & (~((ctx.get_reg(dst) & ctx.get_reg(src)))))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) ^ (ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL))))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) | ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RR_A1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001eULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) | ctx.get_reg(src))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) ^ ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RI: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000000ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) & static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) + static_cast<uint64_t>(imm)) - (ctx.get_reg(dst) | static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RR: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000003ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))))) + (((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) ^ ((((((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))))) + (((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x577d5d9ef2825195ULL) << 0x0000000000000021ULL)) ^ (((((((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))))) + (((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) ^ ((((((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))))) + (((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) & 0xff00ff00ff00ff00ULL)) | (((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0x00000000ffffffffULL) + ((ctx.get_reg(src) & 0xffffffff00000000ULL) & 0xffffffff00000000ULL)))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0x5555555555555555ULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL) | ((ctx.get_reg(src) & 0x00000000ffffffffULL) & 0xaaaaaaaaaaaaaaaaULL))) & ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x577d5d9ef2825195ULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x577d5d9ef2825195ULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RR_A1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RI: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001fULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) | static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) + (ctx.get_reg(dst) & static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ROL_RI: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, ((v << s) | (v >> ((64 - s) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROR_RI: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, ((val >> shift) | (val << ((64 - shift) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHL_RI: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, (val << shift));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHR_RI: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, (val >> shift));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SAR_RI: {
        int64_t sval = static_cast<int64_t>(ctx.get_reg(dst));
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, static_cast<uint64_t>((sval >> shift)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROL_RR: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, ((val << shift) | (val >> ((64 - shift) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROR_RR: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, ((v >> s) | (v << ((64 - s) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHL_RR: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, (val << shift));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHR_RR: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, (v >> s));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SAR_RR: {
        uint64_t _res = static_cast<uint64_t>((static_cast<int64_t>(ctx.get_reg(dst)) >> static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL))));
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_DIV_RR: {
        uint64_t b = ctx.get_reg(src);
        if (__builtin_expect((!b), 0) != 0) {
                                         ctx.trapped = true;
                                         goto EXIT_VM;
}
        ctx.set_reg(dst, (ctx.get_reg(dst) / b));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IDIV_RR: {
        int64_t a = static_cast<int64_t>(ctx.get_reg(dst));
        int64_t b = static_cast<int64_t>(ctx.get_reg(src));
        if ((b == 0) || ((b == -1) && (a == INT64_MIN))) {
                                                      ctx.trapped = true;
                                                      goto EXIT_VM;
}
        int64_t q = ((b == -1) ? static_cast<int64_t>((0x0000000000000000ULL - static_cast<uint64_t>(a))) : (a / b));
        ctx.set_reg(dst, static_cast<uint64_t>(q));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_MULH_RR: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        
#if defined(__SIZEOF_INT128__)
uint64_t res = static_cast<uint64_t>(((((unsigned __int128)(a)) * ((unsigned __int128)(b))) >> 64));
ctx.set_reg(dst, res);
#else
uint64_t a_lo = static_cast<uint32_t>(a);
uint64_t a_hi = (a >> 32);
uint64_t b_lo = static_cast<uint32_t>(b);
uint64_t b_hi = (b >> 32);
uint64_t p0 = (a_lo * b_lo);
uint64_t p1 = (a_lo * b_hi);
uint64_t p2 = (a_hi * b_lo);
uint64_t p3 = (a_hi * b_hi);
uint64_t cy = ((((p0 >> 32) + static_cast<uint32_t>(p1)) + static_cast<uint32_t>(p2)) >> 32);
uint64_t res = (((p3 + (p1 >> 32)) + (p2 >> 32)) + cy);
ctx.set_reg(dst, res);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IMULH_RR: {
        
#if defined(__SIZEOF_INT128__)
uint64_t res = static_cast<uint64_t>(((((signed __int128)(static_cast<int64_t>(ctx.get_reg(dst)))) * ((signed __int128)(static_cast<int64_t>(ctx.get_reg(src))))) >> 64));
ctx.set_reg(dst, res);
#else
int64_t a = static_cast<int64_t>(ctx.get_reg(dst));
int64_t b = static_cast<int64_t>(ctx.get_reg(src));
uint64_t ua = static_cast<uint64_t>(a);
uint64_t ub = static_cast<uint64_t>(b);
uint64_t a_lo = static_cast<uint32_t>(ua);
uint64_t a_hi = (ua >> 32);
uint64_t b_lo = static_cast<uint32_t>(ub);
uint64_t b_hi = (ub >> 32);
uint64_t cy = (((((a_lo * b_lo) >> 32) + static_cast<uint32_t>((a_lo * b_hi))) + static_cast<uint32_t>((a_hi * b_lo))) >> 32);
uint64_t res = ((((a_hi * b_hi) + ((a_lo * b_hi) >> 32)) + ((a_hi * b_lo) >> 32)) + cy);
if (a < 0) {
                res -= ub;
}
if (b < 0) {
                res -= ua;
}
ctx.set_reg(dst, res);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        uint64_t _imm = static_cast<uint64_t>(imm);
        compute_sub_flags(ctx, ctx.get_reg(dst), _imm, bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RR: {
        PROBE_START();
        uint64_t _a = ctx.get_reg(dst);
        uint64_t _b = ctx.get_reg(src);
        compute_sub_flags(ctx, _a, _b, static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_A1: {
        PROBE_START();
        uint64_t _d = ctx.get_reg(dst);
        compute_sub_flags(ctx, _d, static_cast<uint64_t>(imm), static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_A2: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        uint64_t _imm = static_cast<uint64_t>(imm);
        compute_sub_flags(ctx, ctx.get_reg(dst), _imm, bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RR_A1: {
        PROBE_START();
        uint64_t _a = ctx.get_reg(dst);
        uint64_t _b = ctx.get_reg(src);
        compute_sub_flags(ctx, _a, _b, static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_PUSH_R: {
        uint64_t val = ctx.get_reg(dst);
        ctx.push(val);
        uint64_t cur_sp = ctx.get_reg(REG_RSP);
        if ((cur_sp >= 0x0000000000010008ULL) && (cur_sp <= 0x00007fffffffffffULL)) {

    uint64_t sp_val = (cur_sp - 0x0000000000000008ULL);
    ctx.set_reg(REG_RSP, sp_val);
    (*(reinterpret_cast<uint64_t*>(sp_val))) = val;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_POP_R: {
        uint64_t cur_sp = ctx.get_reg(REG_RSP);
        uint64_t val = 0x0000000000000000ULL;
        if ((cur_sp >= 0x0000000000010000ULL) && (cur_sp <= 0x00007fffffffffffULL)) {

    std::memcpy((&val), reinterpret_cast<const void*>(cur_sp), sizeof(uint64_t));
    ctx.set_reg(REG_RSP, (cur_sp + 0x0000000000000008ULL));
    ctx.pop();} else {
                          val = ctx.pop();
}
        ctx.set_reg(dst, val);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADC_RR: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint64_t c = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a + b) + c);
        ctx.cf = ((res < a) || ((c != 0x0000000000000000ULL) && (res == a)));
        ctx.of = ((((a ^ res) & (b ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADC_RI: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint64_t c = static_cast<uint64_t>(ctx.cf);
        uint64_t res = ((a + b) + c);
        ctx.cf = ((res < a) || ((c != 0x0000000000000000ULL) && (res == a)));
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = ((res >> 63) != 0x0000000000000000ULL);
        ctx.of = ((((a ^ res) & (b ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SBB_RR: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint64_t borrow = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a - b) - borrow);
        ctx.cf = ((a < b) || ((borrow != 0x0000000000000000ULL) && (a == b)));
        ctx.of = ((((a ^ b) & (a ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SBB_RI: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint64_t borrow = static_cast<uint64_t>(ctx.cf);
        uint64_t res = ((a - b) - borrow);
        ctx.cf = ((a < b) || ((borrow != 0x0000000000000000ULL) && (a == b)));
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = ((res >> 63) != 0x0000000000000000ULL);
        ctx.of = ((((a ^ b) & (a ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMP_RR: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (!eval_condition(ctx, cond)) {
                                     ctx.sf = ((nzcv & 8) != 0);
                                     ctx.zf = ((nzcv & 4) != 0);
                                     ctx.cf = ((nzcv & 2) != 0);
                                     ctx.of = ((nzcv & 1) != 0);
} else {
            uint64_t a = ctx.get_reg(dst);
            uint64_t b = ctx.get_reg(src);
            compute_sub_flags(ctx, a, b, bits);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMP_RI: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint64_t b = static_cast<uint64_t>((((word >> 26) + 0x000000000000001fULL) - ((word >> 26) | 0x000000000000001fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (!eval_condition(ctx, cond)) {
                                     ctx.sf = ((nzcv & 8) != 0);
                                     ctx.zf = ((nzcv & 4) != 0);
                                     ctx.cf = ((nzcv & 2) != 0);
                                     ctx.of = ((nzcv & 1) != 0);
} else {
            uint64_t a = ctx.get_reg(dst);
            compute_sub_flags(ctx, a, b, bits);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMN_RR: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (!eval_condition(ctx, cond)) {
                                     ctx.sf = ((nzcv & 8) != 0);
                                     ctx.zf = ((nzcv & 4) != 0);
                                     ctx.cf = ((nzcv & 2) != 0);
                                     ctx.of = ((nzcv & 1) != 0);
} else {
            uint64_t a = ctx.get_reg(dst);
            uint64_t b = ctx.get_reg(src);
            compute_add_flags(ctx, a, b, bits);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMN_RI: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint64_t b = static_cast<uint64_t>((((word >> 26) + 0x000000000000001fULL) - ((word >> 26) | 0x000000000000001fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (eval_condition(ctx, cond)) {
                                    uint64_t a = ctx.get_reg(dst);
                                    compute_add_flags(ctx, a, b, bits);
} else {
            ctx.sf = ((nzcv & 8) != 0);
            ctx.zf = ((nzcv & 4) != 0);
            ctx.cf = ((nzcv & 2) != 0);
            ctx.of = ((nzcv & 1) != 0);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_GET_FLAGS_R: {
        uint64_t f = ((((0x0000000000000002ULL | (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL)) | (ctx.zf ? 0x0000000000000040ULL : 0x0000000000000000ULL)) | (ctx.sf ? 0x0000000000000080ULL : 0x0000000000000000ULL)) | (ctx.of ? 0x0000000000000800ULL : 0x0000000000000000ULL));
        ctx.set_reg(dst, f);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SET_FLAGS_R: {
        uint64_t f = ctx.get_reg(src);
        ctx.cf = ((f & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.zf = ((f & 0x0000000000000040ULL) != 0x0000000000000000ULL);
        ctx.sf = ((f & 0x0000000000000080ULL) != 0x0000000000000000ULL);
        ctx.of = ((f & 0x0000000000000800ULL) != 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP: {
        size_t _target = static_cast<size_t>(imm);
        vIP_idx = _target;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_A1: {
        size_t _target = static_cast<size_t>(imm);
        vIP_idx = _target;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_A2: {
        vIP_idx = static_cast<size_t>(((static_cast<uint64_t>(imm) ^ 0x0000000000005877ULL) ^ 0x0000000000005877ULL));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JCC: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t base_vip = static_cast<uint64_t>(((word >> 0x0000000000000016ULL) & 0x00000000001fffffULL));
        uint64_t enc_delta = static_cast<uint64_t>(((word >> 0x000000000000002bULL) & 0x00000000001fffffULL));
        uint64_t salt = (((static_cast<uint64_t>(cond) * 0x0000000000005877ULL) ^ 0x000000001337beefULL) & 0x00000000001fffffULL);
        uint64_t delta = (enc_delta ^ salt);
        uint64_t t_true = (base_vip ^ delta);
        uint64_t t_false = base_vip;
        uint64_t c = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        vIP_idx = static_cast<size_t>(((c * t_true) + ((0x0000000000000001ULL - c) * t_false)));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JCC_A1: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t base_vip = static_cast<uint64_t>(((word >> 0x0000000000000016ULL) & 0x00000000001fffffULL));
        uint64_t enc_delta = static_cast<uint64_t>(((word >> 0x000000000000002bULL) & 0x00000000001fffffULL));
        uint64_t salt = (((static_cast<uint64_t>(cond) * 0x0000000000005877ULL) ^ 0x000000001337beefULL) & 0x00000000001fffffULL);
        uint64_t delta = (enc_delta ^ salt);
        uint64_t t_true = (base_vip ^ delta);
        uint64_t t_false = base_vip;
        uint64_t c = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        vIP_idx = static_cast<size_t>(((c * t_true) + ((0x0000000000000001ULL - c) * t_false)));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMOV: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        if (eval_condition(ctx, cond)) {
                                    ctx.set_reg(dst, ctx.get_reg(src));
}
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SETCC: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t val = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        ctx.set_reg(dst, val);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CALL: {
        ctx.push(static_cast<uint64_t>(vIP_idx));
        size_t _target_vip = static_cast<size_t>(imm);
        vIP_idx = _target_vip;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IJMP_R: {
        uint64_t target = ctx.get_reg(dst);
        size_t _t_idx = static_cast<size_t>(target);
        if (_t_idx < count) {
                         vIP_idx = _t_idx;
} else {
            if (target != 0x0000000000000000ULL) {
                                                      #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                                      uint64_t a1 = ctx.get_reg(REG_RCX);
                                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                                      uint64_t a3 = ctx.get_reg(REG_RBX);
                                                      uint64_t a4 = ctx.get_reg(REG_RSI);
                                                      uint64_t a5 = ctx.get_reg(REG_RDI);
                                                      #elif defined(ASGARD_GUEST_RISCV64)
                                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                                      uint64_t a1 = ctx.get_reg(REG_RDX);
                                                      uint64_t a2 = ctx.get_reg(REG_RCX);
                                                      uint64_t a3 = ctx.get_reg(REG_RSI);
                                                      uint64_t a4 = ctx.get_reg(REG_RDI);
                                                      uint64_t a5 = ctx.get_reg(REG_R8);
                                                      #else
                                                      uint64_t a0 = ctx.get_reg(REG_RDI);
                                                      uint64_t a1 = ctx.get_reg(REG_RSI);
                                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                                      uint64_t a3 = ctx.get_reg(REG_RCX);
                                                      uint64_t a4 = ctx.get_reg(REG_R8);
                                                      uint64_t a5 = ctx.get_reg(REG_R9);
                                                      #endif
                                                      typedef uint64_t (*indirect_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                      indirect_fn_t fn = reinterpret_cast<indirect_fn_t>(target);
                                                      uint64_t ret_val = fn(a0, a1, a2, a3, a4, a5);
                                                      ctx.set_reg(REG_RAX, ret_val);
                                                      goto EXIT_VM;
            }
}
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ICALL_R: {
        uint64_t target_ptr = ctx.get_reg(dst);
        if (__builtin_expect((target_ptr < count), 1)) {
                                                    uint64_t _ret = static_cast<uint64_t>(vIP_idx);
                                                    ctx.push(_ret);
                                                    vIP_idx = static_cast<size_t>(target_ptr);
} else {
            if (target_ptr != 0) {
                                      #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                      uint64_t a1 = ctx.get_reg(REG_RCX);
                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                      uint64_t a3 = ctx.get_reg(REG_RBX);
                                      uint64_t a4 = ctx.get_reg(REG_RSI);
                                      uint64_t a5 = ctx.get_reg(REG_RDI);
                                      #elif defined(ASGARD_GUEST_RISCV64)
                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                      uint64_t a1 = ctx.get_reg(REG_RDX);
                                      uint64_t a2 = ctx.get_reg(REG_RCX);
                                      uint64_t a3 = ctx.get_reg(REG_RSI);
                                      uint64_t a4 = ctx.get_reg(REG_RDI);
                                      uint64_t a5 = ctx.get_reg(REG_R8);
                                      #else
                                      uint64_t a0 = ctx.get_reg(REG_RDI);
                                      uint64_t a1 = ctx.get_reg(REG_RSI);
                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                      uint64_t a3 = ctx.get_reg(REG_RCX);
                                      uint64_t a4 = ctx.get_reg(REG_R8);
                                      uint64_t a5 = ctx.get_reg(REG_R9);
                                      #endif
                                      typedef uint64_t (*indirect_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                      indirect_fn_t fn = reinterpret_cast<indirect_fn_t>(target_ptr);
                                      uint64_t ret_val = fn(a0, a1, a2, a3, a4, a5);
                                      ctx.set_reg(REG_RAX, ret_val);
            }
}
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RET: case_ret: { if (!ctx.verify_canaries()) {
                                 ctx.trapped = true;
} ctx.executed_instructions++; goto EXIT_VM; }
    H_EXIT: { if (!ctx.verify_canaries()) {
                                 ctx.trapped = true;
} ctx.executed_instructions++; goto EXIT_VM; }

    H_BRIDGE_TO_FLOW: {
        ctx.morph_math_to_flow(static_cast<uint64_t>(imm));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_BRIDGE_TO_MATH: {
        ctx.morph_flow_to_math(static_cast<uint64_t>((imm & 0xffffffffffffffffULL)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FUSED_MOV_ADD_RRI: {
        ctx.set_reg(dst, (ctx.get_reg(src) + static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_ADD_IMUL_RRI: {
        uint64_t _sum = (ctx.get_reg(dst) + ctx.get_reg(src));
        ctx.set_reg(dst, (_sum * static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_ADD_XOR_RRI: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) + ctx.get_reg(src)) ^ static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_SUB_XOR_RRI: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) - ctx.get_reg(src)) ^ static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_XOR_ADD_RRI: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_CMP_CMOV: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint8_t cond = static_cast<uint8_t>(((word >> 0x0000000000000032ULL) & 0x000000000000000fULL));
        uint32_t bits = static_cast<uint32_t>(((word >> 0x0000000000000036ULL) & 0x000000000000007fULL));
        compute_sub_flags(ctx, a, b, bits);
        if (eval_condition(ctx, cond)) {
                                    ctx.set_reg(dst, ctx.get_reg(src));
}
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_AND_OR_RRI: {
        uint64_t _imm = static_cast<uint64_t>(imm);
        uint64_t _a = (ctx.get_reg(dst) & ctx.get_reg(src));
        ctx.set_reg(dst, ((_a + _imm) - (_a & _imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_SHL_ADD_RRI: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) << (static_cast<uint64_t>(imm) & 0x000000000000003fULL)) + ctx.get_reg(src)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_VADD_VV: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        uint64_t _res0 = (d0 + s0);
        uint64_t _res1 = (d1 + s1);
        ctx.set_vreg(dst, _res0, _res1);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VSUB_VV: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vr = vsubq_u64(vcombine_u64(vcreate_u64(d0), vcreate_u64(d1)), vcombine_u64(vcreate_u64(s0), vcreate_u64(s1)));
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vr = _mm_sub_epi64(_mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0)), _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0)));
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
uint64_t _r0 = (d0 - s0);
uint64_t _r1 = (d1 - s1);
ctx.set_vreg(dst, _r0, _r1);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VMUL_VV: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        ctx.set_vreg(dst, static_cast<uint64_t>((d0 * s0)), static_cast<uint64_t>((d1 * s1)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VXOR_VV: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vr = veorq_u64(vcombine_u64(vcreate_u64(d0), vcreate_u64(d1)), vcombine_u64(vcreate_u64(s0), vcreate_u64(s1)));
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vr = _mm_xor_si128(_mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0)), _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0)));
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
uint64_t _r0 = (d0 ^ s0);
uint64_t _r1 = (d1 ^ s1);
ctx.set_vreg(dst, _r0, _r1);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_MOV: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x00000000000003ffULL));
        size_t i = 0;
        while (i < ((bits + 63) / 64)) {
                                    ctx.set_vreg_lane(dst, i, ctx.get_vreg_lane(src, i));
                                    i += 1;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_BINOP: {
        uint32_t src2 = static_cast<uint32_t>((imm & 0x000000000000001fULL));
        uint32_t bits = static_cast<uint32_t>(((imm >> 5) & 0x00000000000003ffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 15) & 0x00000000000000ffULL));
        if (lane_bits == 0) {
                         lane_bits = 64;
}
        uint32_t vop = static_cast<uint32_t>(((imm >> 23) & 0x000000000000001fULL));
        uint32_t elem = static_cast<uint32_t>(((imm >> 28) & 0x0000000000000003ULL));
        uint64_t mask = ((lane_bits == 8) ? 0x00000000000000ffULL : ((lane_bits == 16) ? 0x000000000000ffffULL : ((lane_bits == 32) ? 0x00000000ffffffffULL : 0xffffffffffffffffULL)));
        size_t bit = 0;
        while (bit < bits) {
                        size_t chunk = (bit / 64);
                        uint32_t shift = static_cast<uint32_t>((bit % 64));
                        uint64_t a = ((ctx.get_vreg_lane(src, chunk) >> shift) & mask);
                        uint64_t b = ((ctx.get_vreg_lane(src2, chunk) >> shift) & mask);
                        uint64_t value = 0x0000000000000000ULL;
                        if ((elem == 1) && (vop <= 2)) {
                                                            float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                                            float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                                            float fr = ((vop == 0) ? (fa + fb) : ((vop == 1) ? (fa - fb) : (fa * fb)));
                                                            value = std::bit_cast<uint32_t>(fr);
                        } else {
                                    if ((elem == 1) && (vop == 11)) {
                                    
                                        float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                        float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                        value = std::bit_cast<uint32_t>(std::fmin(fa, fb));
                                    } else {
                                                if ((elem == 1) && (vop == 12)) {
                                                
                                                    float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                                    float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                                    value = std::bit_cast<uint32_t>(std::fmax(fa, fb));
                                                } else {
                                                            if ((elem == 2) && (vop <= 2)) {
                                                            
                                                                double fa = std::bit_cast<double>(a);
                                                                double fb = std::bit_cast<double>(b);
                                                                double fr = ((vop == 0) ? (fa + fb) : ((vop == 1) ? (fa - fb) : (fa * fb)));
                                                                value = std::bit_cast<uint64_t>(fr);
                                                            } else {
                                                                    if ((elem == 2) && (vop == 11)) {
                                                                    
                                                                    double fa = std::bit_cast<double>(a);
                                                                    double fb = std::bit_cast<double>(b);
                                                                    value = std::bit_cast<uint64_t>(std::fmin(fa, fb));
                                                                    } else {
                                                                    
                                                                    if ((elem == 2) && (vop == 12)) {
                                                                    
                                                                    double fa = std::bit_cast<double>(a);
                                                                    double fb = std::bit_cast<double>(b);
                                                                    value = std::bit_cast<uint64_t>(std::fmax(fa, fb));
                                                                    } else {
                                                                    
                                                                    int64_t sa = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(a))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(a))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(a))) : static_cast<int64_t>(a))));
                                                                    int64_t sb = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(b))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(b))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(b))) : static_cast<int64_t>(b))));
                                                                    switch (vop) {
                                                                    
                                                                    case 0: {
                                                                    
                                                                    value = (a + b);
                                                                    break;
                                                                    }
                                                                    case 1: {
                                                                    
                                                                    value = (a - b);
                                                                    break;
                                                                    }
                                                                    case 2: {
                                                                    
                                                                    value = (a * b);
                                                                    break;
                                                                    }
                                                                    case 3: {
                                                                    
                                                                    value = (a & b);
                                                                    break;
                                                                    }
                                                                    case 4: {
                                                                    
                                                                    value = (a | b);
                                                                    break;
                                                                    }
                                                                    case 5: {
                                                                    
                                                                    value = (a ^ b);
                                                                    break;
                                                                    }
                                                                    case 6: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a << cnt));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 7: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a >> cnt));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 8: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? ((sa < 0) ? mask : 0x0000000000000000ULL) : (static_cast<uint64_t>((sa >> cnt)) & mask));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 9: {
                                                                    
                                                                    value = ((a == b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 10: {
                                                                    
                                                                    value = ((sa > sb) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 11: {
                                                                    
                                                                    value = ((sa < sb) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 12: {
                                                                    
                                                                    value = ((sa > sb) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 13: {
                                                                    
                                                                    value = ((a < b) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 14: {
                                                                    
                                                                    value = ((a > b) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 15: {
                                                                    
                                                                    value = (static_cast<uint64_t>(((sa < 0) ? (-sa) : sa)) & mask);
                                                                    break;
                                                                    }
                                                                    case 16: {
                                                                    
                                                                    value = ((~a) & b);
                                                                    break;
                                                                    }
                                                                    case 17: {
                                                                    
                                                                    {
                                                                    size_t block_lane = ((bit / lane_bits) % (128 / lane_bits));
                                                                    size_t half_idx = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (half_idx * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 18: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_idx = ((num_lanes / 2) + (block_lane / 2));
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (half_idx * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 21: {
                                                                    
                                                                    {
                                                                    uint8_t ctrl = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if ((ctrl & 128) != 0) {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    } else {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + ((ctrl & 15) * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 23: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_len = (num_lanes / 2);
                                                                    size_t src_reg = ((block_lane < half_len) ? src : src2);
                                                                    size_t sel_elem = ((block_lane < half_len) ? (block_lane * 2) : ((block_lane - half_len) * 2));
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 24: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_len = (num_lanes / 2);
                                                                    size_t src_reg = ((block_lane < half_len) ? src : src2);
                                                                    size_t sel_elem = ((block_lane < half_len) ? ((block_lane * 2) + 1) : (((block_lane - half_len) * 2) + 1));
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 25: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t k = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t sel_elem = (k * 2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 26: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t k = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t sel_elem = ((k * 2) + 1);
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 28: {
                                                                    
                                                                    {
                                                                    uint8_t idx = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if (idx < 16) {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + (idx * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    } else {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 29: {
                                                                    
                                                                    {
                                                                    uint8_t idx = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if (idx < 16) {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + (idx * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    } else {
                                                                    
                                                                    value = ((ctx.get_vreg_lane(dst, chunk) >> shift) & 0x00000000000000ffULL);
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 30: {
                                                                    
                                                                    {
                                                                    int64_t min_val = ((lane_bits == 64) ? static_cast<int64_t>(0x8000000000000000ULL) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(0x0000000080000000ULL))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(32768))) : static_cast<int64_t>(((int8_t)(128))))));
                                                                    if (sb == 0) {
                                                                    
                                                                    value = 0xffffffffffffffffULL;
                                                                    } else {
                                                                    
                                                                    if ((sb == -1) && (sa == min_val)) {
                                                                    
                                                                    value = static_cast<uint64_t>(sa);
                                                                    } else {
                                                                    
                                                                    value = static_cast<uint64_t>((sa / sb));
                                                                    }
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 31: {
                                                                    
                                                                    value = ((b != 0) ? (a / b) : mask);
                                                                    break;
                                                                    }
                                                                    case 32: {
                                                                    
                                                                    {
                                                                    int64_t min_val = ((lane_bits == 64) ? static_cast<int64_t>(0x8000000000000000ULL) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(0x0000000080000000ULL))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(32768))) : static_cast<int64_t>(((int8_t)(128))))));
                                                                    if (sb == 0) {
                                                                    
                                                                    value = a;
                                                                    } else {
                                                                    
                                                                    if ((sb == -1) && (sa == min_val)) {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    } else {
                                                                    
                                                                    value = static_cast<uint64_t>((sa % sb));
                                                                    }
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 33: {
                                                                    
                                                                    value = ((b != 0) ? (a % b) : a);
                                                                    break;
                                                                    }
                                                                    case 34: {
                                                                    
                                                                    value = ((a != b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 35: {
                                                                    
                                                                    value = ((sa <= sb) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 36: {
                                                                    
                                                                    value = ((a < b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 37: {
                                                                    
                                                                    value = ((a <= b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    default: {
                                                                    
                                                                    value = (a ^ b);
                                                                    break;
                                                                    }
                                                                    }
                                                                    }
                                                                    }
                                                            }
                                                }
                                    }
                        }
                        uint64_t old_value = ctx.get_vreg_lane(dst, chunk);
                        uint64_t packed_mask = (mask << shift);
                        ctx.set_vreg_lane(dst, chunk, ((old_value & (~packed_mask)) | ((value & mask) << shift)));
                        bit += lane_bits;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_IMM: {
        uint64_t imm_val = (imm & 0x00000000000000ffULL);
        uint32_t bits = static_cast<uint32_t>(((imm >> 8) & 0x00000000000003ffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 18) & 0x00000000000000ffULL));
        if (lane_bits == 0) {
                         lane_bits = 64;
}
        uint32_t vop = static_cast<uint32_t>(((imm >> 26) & 0x000000000000001fULL));
        uint64_t mask = ((lane_bits == 8) ? 0x00000000000000ffULL : ((lane_bits == 16) ? 0x000000000000ffffULL : ((lane_bits == 32) ? 0x00000000ffffffffULL : 0xffffffffffffffffULL)));
        size_t bit = 0;
        while (bit < bits) {
                        size_t chunk = (bit / 64);
                        uint32_t shift = static_cast<uint32_t>((bit % 64));
                        uint64_t a = ((ctx.get_vreg_lane(src, chunk) >> shift) & mask);
                        int64_t sa = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(a))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(a))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(a))) : static_cast<int64_t>(a))));
                        uint64_t value = 0x0000000000000000ULL;
                        switch (vop) {
                                        case 6: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a << cnt));
                                                          break;
                                                     }
                                        }
                                        case 7: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a >> cnt));
                                                          break;
                                                     }
                                        }
                                        case 8: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? ((sa < 0) ? mask : 0x0000000000000000ULL) : (static_cast<uint64_t>((sa >> cnt)) & mask));
                                                          break;
                                                     }
                                        }
                                        case 21: {
                                                      {
                                                           size_t lane_in_128 = ((bit / 32) % 4);
                                                           size_t sel = ((imm_val >> (lane_in_128 * 2)) & 0x0000000000000003ULL);
                                                           size_t src_bit = (((bit / 128) * 128) + (sel * 32));
                                                           value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000ffffffffULL);
                                                           break;
                                                      }
                                        }
                                        case 22: {
                                                      {
                                                           size_t lane_idx = (bit / lane_bits);
                                                           size_t sel = ((imm_val >> (lane_idx % 8)) & 0x0000000000000001ULL);
                                                           value = ((sel == 0) ? a : ((ctx.get_vreg_lane(dst, chunk) >> shift) & mask));
                                                           break;
                                                      }
                                        }
                                        default: {
                                                      value = a;
                                                      break;
                                        }
                        }
                        uint64_t old_value = ctx.get_vreg_lane(dst, chunk);
                        uint64_t packed_mask = (mask << shift);
                        ctx.set_vreg_lane(dst, chunk, ((old_value & (~packed_mask)) | ((value & mask) << shift)));
                        bit += lane_bits;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_CLEAR_UPPER: {
        ctx.set_vreg_lane(dst, 2, 0x0000000000000000ULL);
        ctx.set_vreg_lane(dst, 3, 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_ZERO_UPPER: {
        for (size_t i = 0; i < 16; ++i) {
                                     ctx.set_vreg_lane(i, 2, 0x0000000000000000ULL);
                                     ctx.set_vreg_lane(i, 3, 0x0000000000000000ULL);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_PMOVMSKB: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x00000000000003ffULL));
        uint32_t num_bytes = (bits / 8);
        uint64_t mask = 0x0000000000000000ULL;
        for (size_t b_idx = 0; b_idx < num_bytes; ++b_idx) {
                                                        uint64_t byte_val = ((ctx.get_vreg_lane(src, (b_idx / 8)) >> ((b_idx % 8) * 8)) & 0x00000000000000ffULL);
                                                        if ((byte_val & 0x0000000000000080ULL) != 0x0000000000000000ULL) {
                                                        
                                                            mask |= (0x0000000000000001ULL << b_idx);
                                                        }
}
        ctx.set_reg(dst, mask);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_LOAD: {
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x00000000000003ffULL));
        uint64_t address = (ctx.get_reg(src) + static_cast<uint64_t>(imm));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     uint64_t value = 0x0000000000000000ULL;
                                                     std::memcpy((&value), reinterpret_cast<const void*>((address + (i * 8))), sizeof(value));
                                                     ctx.set_vreg_lane(dst, i, value);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_STORE: {
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x00000000000003ffULL));
        uint64_t address = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     std::memcpy(reinterpret_cast<void*>((address + (i * 8))), (&ctx.vregs[(src & 31)][(i & 7)]), sizeof(uint64_t));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_SPLAT: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x000000000000ffffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 16) & 0x000000000000ffffULL));
        uint64_t val = ctx.get_reg(src);
        uint64_t mask = ((lane_bits >= 64) ? 0xffffffffffffffffULL : ((0x0000000000000001ULL << lane_bits) - 0x0000000000000001ULL));
        uint64_t val_masked = (val & mask);
        uint32_t num_lanes = ((lane_bits > 0) ? (bits / lane_bits) : 0);
        for (size_t l = 0; l < num_lanes; ++l) {
                                            uint32_t pos = (l * lane_bits);
                                            uint32_t chunk = (pos / 64);
                                            uint32_t shift = (pos % 64);
                                            uint64_t packed_mask = ((lane_bits >= 64) ? 0xffffffffffffffffULL : (mask << shift));
                                            uint64_t cur = ctx.get_vreg_lane(dst, chunk);
                                            cur = ((cur & (~packed_mask)) | (val_masked << shift));
                                            ctx.set_vreg_lane(dst, chunk, cur);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_EXT: {
        uint32_t src2 = static_cast<uint32_t>((imm & 0x000000000000001fULL));
        uint32_t shift_bytes = static_cast<uint32_t>(((imm >> 5) & 0x000000000000000fULL));
        uint32_t bits = static_cast<uint32_t>(((imm >> 9) & 0x00000000000003ffULL));
        if (bits == 0) {
                    bits = 128;
}
        for (size_t byte_idx = 0; byte_idx < (bits / 8); ++byte_idx) {
                                                                  size_t total_idx = ((byte_idx % 16) + shift_bytes);
                                                                  uint64_t val = 0x0000000000000000ULL;
                                                                  if (total_idx < 16) {
                                                                  
                                                                    size_t bit_pos = (((byte_idx / 16) * 128) + (total_idx * 8));
                                                                    val = ((ctx.get_vreg_lane(src, (bit_pos / 64)) >> (bit_pos % 64)) & 0x00000000000000ffULL);
                                                                  } else {
                                                                  
                                                                    size_t m_idx = (total_idx - 16);
                                                                    size_t bit_pos = (((byte_idx / 16) * 128) + (m_idx * 8));
                                                                    val = ((ctx.get_vreg_lane(src2, (bit_pos / 64)) >> (bit_pos % 64)) & 0x00000000000000ffULL);
                                                                  }
                                                                  size_t chunk = ((byte_idx * 8) / 64);
                                                                  uint32_t shift = static_cast<uint32_t>(((byte_idx * 8) % 64));
                                                                  uint64_t old_v = ctx.get_vreg_lane(dst, chunk);
                                                                  uint64_t clr = (old_v & (~((0x00000000000000ffULL << shift))));
                                                                  ctx.set_vreg_lane(dst, chunk, (clr | (val << shift)));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CALL_EXTERN: {
        size_t sym_idx = ((size_t)(imm));
        void* sym_ptr = asgard_resolve_sym_idx(((int32_t)(sym_idx)));
        if (sym_ptr) {
                  uint32_t sym_h = g_external_symbols[sym_idx].hash;
                  uint32_t sym_ah = g_external_symbols[sym_idx].alt_hash;
                  
                  #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                  uint64_t a0 = ctx.get_reg(REG_RAX);
                  uint64_t a1 = ctx.get_reg(REG_RCX);
                  uint64_t a2 = ctx.get_reg(REG_RDX);
                  uint64_t a3 = ctx.get_reg(REG_RBX);
                  uint64_t a4 = ctx.get_reg(REG_RSI);
                  uint64_t a5 = ctx.get_reg(REG_RDI);
                  uint64_t a6 = ctx.get_reg(REG_R8);
                  uint64_t a7 = ctx.get_reg(REG_R9);
                  #elif defined(ASGARD_GUEST_RISCV64)
                  uint64_t a0 = ctx.get_reg(REG_RAX);
                  uint64_t a1 = ctx.get_reg(REG_RDX);
                  uint64_t a2 = ctx.get_reg(REG_RCX);
                  uint64_t a3 = ctx.get_reg(REG_RSI);
                  uint64_t a4 = ctx.get_reg(REG_RDI);
                  uint64_t a5 = ctx.get_reg(REG_R8);
                  uint64_t a6 = ctx.get_reg(REG_R9);
                  uint64_t a7 = ctx.get_reg(REG_R12);
                  #else
                  uint64_t a0 = (ctx.get_reg(REG_RDI) ? ctx.get_reg(REG_RDI) : ctx.get_reg(REG_RAX));
                  uint64_t a1 = ctx.get_reg(REG_RSI);
                  uint64_t a2 = ctx.get_reg(REG_RDX);
                  uint64_t a3 = ctx.get_reg(REG_RCX);
                  uint64_t a4 = ctx.get_reg(REG_R8);
                  uint64_t a5 = ctx.get_reg(REG_R9);
                  uint64_t a6 = ctx.get_reg(REG_RAX);
                  uint64_t a7 = ctx.get_reg(REG_RBX);
                  #endif
                  
                  const uint64_t* stk = reinterpret_cast<const uint64_t*>(ctx.get_reg(REG_RSP));
                  uint64_t ret_val = 0x0000000000000000ULL;
                  if ((((((sym_h == 0x42fcf5cfU) || (sym_ah == 0x42fcf5cfU)) || (sym_h == 0x07554acdU)) || (sym_ah == 0x07554acdU)) || (sym_h == 0xe76fb4aaU)) || (sym_ah == 0xe76fb4aaU)) {
                  
                      typedef int (*printf_fn_t)(const char*, ...);
                      printf_fn_t pfn = reinterpret_cast<printf_fn_t>(sym_ptr);
                      
                      #if defined(__APPLE__) && defined(__aarch64__)
                      ret_val = ((uint64_t)(pfn(((const char*)(a0)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                      #else
                      ret_val = ((uint64_t)(pfn(((const char*)(a0)), a1, a2, a3, a4, a5, a6, a7)));
                      #endif
                      
                  } else {
                              if ((((((((((((((((sym_h == 0xfcb512e2U) || (sym_ah == 0xfcb512e2U)) || (sym_h == 0x4b3c5330U)) || (sym_ah == 0x4b3c5330U)) || (sym_h == 0x937d1ef6U)) || (sym_ah == 0x937d1ef6U)) || (sym_h == 0xcb76d42bU)) || (sym_ah == 0xcb76d42bU)) || (sym_h == 0xd54ce817U)) || (sym_ah == 0xd54ce817U)) || (sym_h == 0xbbed3905U)) || (sym_ah == 0xbbed3905U)) || (sym_h == 0x42c07c7cU)) || (sym_ah == 0x42c07c7cU)) || (sym_h == 0x24559dbdU)) || (sym_ah == 0x24559dbdU)) {
                              
                                  typedef int (*fprintf_fn_t)(void*, const char*, ...);
                                  fprintf_fn_t fpfn = reinterpret_cast<fprintf_fn_t>(sym_ptr);
                                  
                                  #if defined(__APPLE__) && defined(__aarch64__)
                                  ret_val = ((uint64_t)(fpfn(((void*)(a0)), ((const char*)(a1)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                  #else
                                  ret_val = ((uint64_t)(fpfn(((void*)(a0)), ((const char*)(a1)), a2, a3, a4, a5, a6, a7)));
                                  #endif
                                  
                              } else {
                                          if ((((((((sym_h == 0x7fe32b00U) || (sym_ah == 0x7fe32b00U)) || (sym_h == 0xbcbf60eeU)) || (sym_ah == 0xbcbf60eeU)) || (sym_h == 0x70e2d349U)) || (sym_ah == 0x70e2d349U)) || (sym_h == 0x44fa3468U)) || (sym_ah == 0x44fa3468U)) {
                                          
                                              typedef int (*sprintf_fn_t)(char*, const char*, ...);
                                              sprintf_fn_t spfn = reinterpret_cast<sprintf_fn_t>(sym_ptr);
                                              
                                              #if defined(__APPLE__) && defined(__aarch64__)
                                              ret_val = ((uint64_t)(spfn(((char*)(a0)), ((const char*)(a1)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                              #else
                                              ret_val = ((uint64_t)(spfn(((char*)(a0)), ((const char*)(a1)), a2, a3, a4, a5, a6, a7)));
                                              #endif
                                              
                                          } else {
                                                      if ((((((((sym_h == 0x54ee11faU) || (sym_ah == 0x54ee11faU)) || (sym_h == 0x933075f4U)) || (sym_ah == 0x933075f4U)) || (sym_h == 0x3fd5eb6fU)) || (sym_ah == 0x3fd5eb6fU)) || (sym_h == 0x5b3553b4U)) || (sym_ah == 0x5b3553b4U)) {
                                                      
                                                          typedef int (*snprintf_fn_t)(char*, size_t, const char*, ...);
                                                          snprintf_fn_t snpfn = reinterpret_cast<snprintf_fn_t>(sym_ptr);
                                                          
                                                          #if defined(__APPLE__) && defined(__aarch64__)
                                                          ret_val = ((uint64_t)(snpfn(((char*)(a0)), ((size_t)(a1)), ((const char*)(a2)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                                          #else
                                                          ret_val = ((uint64_t)(snpfn(((char*)(a0)), ((size_t)(a1)), ((const char*)(a2)), a3, a4, a5, a6, a7)));
                                                          #endif
                                                          
                                                      } else {
                                                                  typedef uint64_t (*extern_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                                  extern_fn_t fn = reinterpret_cast<extern_fn_t>(sym_ptr);
                                                                  ret_val = fn(a0, a1, a2, a3, a4, a5, a6, a7);
                                                      }
                                          }
                              }
                  }
                  ctx.set_reg(REG_RAX, ret_val);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_64: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, asgard::oblivious_mem::oblivious_load_u64(static_cast<uintptr_t>(addr)));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint64_t _v = 0x0000000000000000ULL;
std::memcpy((&_v), reinterpret_cast<const void*>(_ptr), sizeof(uint64_t));
ctx.set_reg(dst, _v);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_32: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(asgard::oblivious_mem::oblivious_load_u32(static_cast<uintptr_t>(addr)))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint32_t _v32 = 0x00000000U;
std::memcpy((&_v32), reinterpret_cast<const void*>(_ptr), sizeof(uint32_t));
ctx.set_reg(dst, ((uint64_t)(_v32)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_16: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(asgard::oblivious_mem::oblivious_load_u16(static_cast<uintptr_t>(addr)))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint16_t _v16 = ((uint16_t)(0x00000000U));
std::memcpy((&_v16), reinterpret_cast<const void*>(_ptr), sizeof(uint16_t));
ctx.set_reg(dst, ((uint64_t)(_v16)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_8: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(asgard::oblivious_mem::oblivious_load_u8(static_cast<uintptr_t>(addr)))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint8_t _v8 = 0x00;
std::memcpy((&_v8), reinterpret_cast<const void*>(_ptr), sizeof(uint8_t));
ctx.set_reg(dst, ((uint64_t)(_v8)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S32: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
int32_t _s32 = ((int32_t)(asgard::oblivious_mem::oblivious_load_u32(_addr)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(_s32)))));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int32_t*>(addr))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S16: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(((int16_t)(asgard::oblivious_mem::oblivious_load_u16(static_cast<uintptr_t>(addr)))))))));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int16_t*>(addr))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S8: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(((int8_t)(asgard::oblivious_mem::oblivious_load_u8(static_cast<uintptr_t>(addr)))))))));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int8_t*>(addr))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_64: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
asgard::oblivious_mem::oblivious_store_u64(_ptr, ctx.get_reg(src), (&ctx.decoy_sink));
#else
char* _target = (reinterpret_cast<char*>(ctx.get_reg(dst)) + imm);
(*(reinterpret_cast<uint64_t*>(_target))) = ctx.get_reg(src);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_32: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
asgard::oblivious_mem::oblivious_store_u32(_ptr, ((uint32_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
uint32_t _v32 = ((uint32_t)(ctx.get_reg(src)));
std::memcpy(reinterpret_cast<void*>(_ptr), (&_v32), sizeof(uint32_t));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_16: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
asgard::oblivious_mem::oblivious_store_u16(_ptr, ((uint16_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
(*(reinterpret_cast<uint16_t*>(addr))) = ((uint16_t)(ctx.get_reg(src)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_8: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
asgard::oblivious_mem::oblivious_store_u8(static_cast<uintptr_t>(addr), ((uint8_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
char* _target = (reinterpret_cast<char*>(ctx.get_reg(dst)) + imm);
(*(reinterpret_cast<uint8_t*>(_target))) = ((uint8_t)(ctx.get_reg(src)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RESOLVE_SYM: {
        size_t sym_idx = ((size_t)(imm));
        void* sym_ptr = asgard_resolve_sym_idx(((int32_t)(sym_idx)));
        ctx.set_reg(dst, ((uint64_t)(sym_ptr)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FADD_DD: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((std::bit_cast<double>(_s) + std::bit_cast<double>(_i))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FSUB_DD: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        double _b = std::bit_cast<double>(ctx.get_vreg_lane(static_cast<uint8_t>(imm), 0));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((_a - _b)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FMUL_DD: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((std::bit_cast<double>(_s) * std::bit_cast<double>(_i))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FDIV_DD: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        double a = std::bit_cast<double>(_s);
        double b = std::bit_cast<double>(_i);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((b != 0.0) ? (a / b) : 0.0)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FSQRT_D: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        double a = std::bit_cast<double>(_s);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((a >= 0.0) ? std::sqrt(a) : 0.0)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCMP_DD: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        double _b = std::bit_cast<double>(ctx.get_vreg_lane(static_cast<uint8_t>(imm), 0));
        bool _nan = (std::isnan(_a) || std::isnan(_b));
        ctx.of = false;
        ctx.sf = false;
        ctx.cf = (_nan || (_a < _b));
        ctx.zf = (_nan || (_a == _b));
        ctx.pf = _nan;
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVTZS: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        double a = std::bit_cast<double>(a_raw);
        ctx.set_reg(dst, ((uint64_t)(((int64_t)(a)))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SCVTF: {
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(((int64_t)(ctx.get_reg(src)))))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVTZU: {
        double a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        if (a < 0.0) {
                  ctx.set_reg(dst, 0x0000000000000000ULL);
} else {
            ctx.set_reg(dst, ((uint64_t)(a)));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_UCVTF: {
        double _d = static_cast<double>(ctx.get_reg(src));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(_d), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVT: {
        if (static_cast<uint32_t>(imm) == 1) {
                                          double _d = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
                                          float _f = static_cast<float>(_d);
                                          uint32_t _u = std::bit_cast<uint32_t>(_f);
                                          uint64_t _prev = ctx.get_vreg_lane(dst, 0);
                                          ctx.set_vreg(dst, ((_prev & 0xffffffff00000000ULL) | static_cast<uint64_t>(_u)), 0x0000000000000000ULL);
} else {
            uint32_t _raw32 = static_cast<uint32_t>(ctx.get_vreg_lane(src, 0));
            float _f = std::bit_cast<float>(_raw32);
            double _d = static_cast<double>(_f);
            ctx.set_vreg(dst, std::bit_cast<uint64_t>(_d), 0x0000000000000000ULL);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_LOAD: {
        uint64_t _addr = (ctx.get_reg(src) + static_cast<uint64_t>(imm));
        uint64_t _val = __atomic_load_n(reinterpret_cast<uint64_t*>(_addr), __ATOMIC_SEQ_CST);
        ctx.set_reg(dst, _val);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_STORE: {
        uint64_t _addr = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        __atomic_store_n(reinterpret_cast<uint64_t*>(_addr), ctx.get_reg(src), __ATOMIC_SEQ_CST);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_CAS: {
        uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
        std::atomic<uint64_t>* ptr = reinterpret_cast<std::atomic<uint64_t>*>(addr);
        uint64_t expected = ctx.get_reg(src);
        uint64_t desired = ctx.get_reg(REG_RAX);
        ptr->compare_exchange_strong(expected, desired, std::memory_order_seq_cst);
        ctx.set_reg(src, expected);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_ADD: {
        uint64_t* ptr = reinterpret_cast<uint64_t*>((ctx.get_reg(dst) + ((uint64_t)(imm))));
        uint64_t old = __atomic_load_n(ptr, __ATOMIC_RELAXED);
        uint64_t add_val = ctx.get_reg(src);
        while (!__atomic_compare_exchange_n(ptr, (&old), (old + add_val), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {

    
}
        ctx.set_reg(src, old);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_SWP: {
        uint64_t* ptr = reinterpret_cast<uint64_t*>((ctx.get_reg(dst) + ((uint64_t)(imm))));
        uint64_t old = __atomic_load_n(ptr, __ATOMIC_RELAXED);
        uint64_t new_val = ctx.get_reg(src);
        while (!__atomic_compare_exchange_n(ptr, (&old), new_val, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {

    
}
        ctx.set_reg(src, old);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FENCE: { std::atomic_thread_fence(std::memory_order_seq_cst); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_VR: { ctx.set_vreg_lane(dst, 0, ctx.get_reg(src)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RV: { ctx.set_reg(dst, ctx.get_vreg_lane(src, 0)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_FCSEL_VV: {
        uint8_t cond = ((uint8_t)((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL))));
        if (eval_condition(ctx, cond)) {
                                    ctx.set_vreg_lane(dst, 0, ctx.get_vreg_lane(src, 0));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_DECOY_0: { ctx.reg_mask ^= (((k_dyn * 0x6a09e667f3bcc908ULL) + 0x0000000000005877ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (ctx.get_reg(dst) ^ (0x0000000000005877ULL + static_cast<uint64_t>(imm)))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_1: { uint64_t _d = ctx.get_reg(dst); ctx.reg_mask ^= ((static_cast<uint64_t>(op) * 0x0000000000005877ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (_d + static_cast<uint64_t>(imm))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_2: { uint64_t _d = ctx.get_reg(dst); ctx.reg_mask ^= ((k_dyn * 0x0000000000009e37ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, ((_d * 0x0000000000009e37ULL) ^ ctx.reg_mask)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_3: { uint64_t _l = (ctx.get_reg(dst) << 3); uint64_t _r = (ctx.get_reg(dst) >> 61); ctx.reg_mask ^= ((k_dyn * 0x517cc1b727220a95ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (_l | _r)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_4: { ctx.reg_mask ^= ((k_dyn + static_cast<uint64_t>(src)) | 0x0000000000000001ULL); ctx.set_reg(dst, ((ctx.get_reg(src) | static_cast<uint64_t>(imm)) - (ctx.get_reg(src) & static_cast<uint64_t>(imm)))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_5: { ctx.reg_mask ^= ((k_dyn * 0x0000000000005877ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (ctx.get_reg(dst) & (~ctx.get_reg(src)))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_6: { ctx.reg_mask ^= ((k_dyn ^ 0x00000000cafebabeULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (ctx.get_reg(dst) | 0x00000000cafebabeULL)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_7: { ctx.reg_mask ^= ((k_dyn * 0x94d049bb133111ebULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (((ctx.get_reg(dst) >> 5) | static_cast<uint64_t>(imm)) - ((ctx.get_reg(dst) >> 5) & static_cast<uint64_t>(imm)))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_8: { uint64_t _d = ctx.get_reg(dst); ctx.reg_mask ^= ((static_cast<uint64_t>(op) - 0x0000000000001337ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (_d - 0x0000000000001337ULL)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_9: { ctx.reg_mask ^= (((k_dyn + 0x0000000000000001ULL) * 0x0000000000005877ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (ctx.get_reg(dst) ^ (ctx.get_reg(src) + 0x0000000000000001ULL))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_10: { ctx.reg_mask ^= ((k_dyn * 0x5851f42d4c957f2dULL) | 0x0000000000000001ULL); ctx.set_reg(dst, ((ctx.get_reg(dst) * 0x5851f42d4c957f2dULL) + 0x0000000000000001ULL)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_11: { ctx.reg_mask ^= ((k_dyn << 7) | 0x0000000000000001ULL); ctx.set_reg(dst, ((ctx.get_reg(dst) << 7) ^ static_cast<uint64_t>(imm))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_12: { ctx.reg_mask ^= ((k_dyn + 0x00000000deadbeefULL) | 0x0000000000000001ULL); ctx.set_reg(dst, ((~ctx.get_reg(dst)) ^ (~0x00000000deadbeefULL))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_13: { ctx.reg_mask ^= ((k_dyn ^ static_cast<uint64_t>(dst)) | 0x0000000000000001ULL); ctx.set_reg(dst, ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src))))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_14: { ctx.reg_mask ^= ((k_dyn * 0x0000000000000003ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, ((ctx.get_reg(dst) | (static_cast<uint64_t>(imm) * 0x0000000000000003ULL)) - (ctx.get_reg(dst) & (static_cast<uint64_t>(imm) * 0x0000000000000003ULL)))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY_15: { ctx.reg_mask ^= ((k_dyn * 0xbf58476d1ce4e5b9ULL) | 0x0000000000000001ULL); ctx.set_reg(dst, (ctx.get_reg(dst) ^ (~0x0000000000000000ULL))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_DECOY: { uint64_t _p = (((static_cast<uint64_t>(op) * 0xbf58476d1ce4e5b9ULL) ^ (k_dyn * 0x6a09e667f3bcc908ULL)) ^ 0xcafebabe13375877ULL); ctx.reg_mask ^= (_p | 0x0000000000000001ULL); ctx.set_reg(dst, ((ctx.get_reg(dst) ^ ctx.reg_mask) + static_cast<uint64_t>(imm))); ctx.executed_instructions++; FETCH_NEXT(); }
    H_NOP_D1: { ((void)(dst)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_D1: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x0000000000000015ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_s ^ 0xff65f1672481e4faULL) ^ 0xff65f1672481e4faULL) : ((_s + 0xbe1f43ff8a531cefULL) - 0xbe1f43ff8a531cefULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_D1: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x0000000000000000ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_imm ^ 0x863c5f9f7e56dc38ULL) ^ 0x863c5f9f7e56dc38ULL) : ((_imm + 0xd9074448dbfe00f8ULL) - 0xd9074448dbfe00f8ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_A1_D1: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x000000000000001aULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_s + 0x0000000013375877ULL) - 0x0000000013375877ULL) : ((_s ^ 0xa8b4d4aefce12f10ULL) ^ 0xa8b4d4aefce12f10ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_A2_D1: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x0000000000000001ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~((~_s))) : (_s ^ 0x0000000000000000ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_A1_D1: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x0000000000000005ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_imm ^ 0xf44eb9d59de14601ULL) ^ 0xf44eb9d59de14601ULL) : ((_imm + 0x0000000058771337ULL) - 0x0000000058771337ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_A2_D1: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x000000000000000eULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~((~_imm))) : ((_imm + 0x00000000deadbeefULL) - 0x00000000deadbeefULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_HIGH_D1: {
        uint32_t _low32 = static_cast<uint32_t>(ctx.get_reg(dst));
        ctx.set_reg(dst, ((static_cast<uint64_t>(static_cast<uint32_t>(imm)) << 32) | static_cast<uint64_t>(_low32)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_NEG_RR_D1: { PROBE_START(); uint64_t _v = ctx.get_reg(dst); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000019ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((~_v) + 0x0000000000000001ULL) : (0x0000000000000000ULL - _v))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_NOT_RR_D1: { PROBE_START(); uint64_t _v = ctx.get_reg(dst); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001fULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~_v) : (_v ^ (~0x0000000000000000ULL)))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_BSWAP_RR_D1: {
        uint64_t _val = ctx.get_reg(src);
        uint32_t _b = static_cast<uint32_t>(imm);
        uint64_t _r = ((_b == 16) ? static_cast<uint64_t>(__builtin_bswap16(static_cast<uint16_t>(_val))) : ((_b == 32) ? static_cast<uint64_t>(__builtin_bswap32(static_cast<uint32_t>(_val))) : __builtin_bswap64(_val)));
        ctx.set_reg(dst, _r);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CLZ_RR_D1: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (val & mask);
        uint64_t _clz = ((bits <= 32) ? ((static_cast<uint32_t>(mval) == 0) ? static_cast<uint64_t>(bits) : static_cast<uint64_t>((__builtin_clz(static_cast<uint32_t>(mval)) - (32 - bits)))) : ((mval == 0x0000000000000000ULL) ? 0x0000000000000040ULL : static_cast<uint64_t>(__builtin_clzll(mval))));
        ctx.set_reg(dst, _clz);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CTZ_RR_D1: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (val & mask);
        uint64_t res;
        if (bits <= 32) {
                     uint32_t v32 = static_cast<uint32_t>(mval);
                     res = ((v32 == 0) ? static_cast<uint64_t>(bits) : static_cast<uint64_t>(__builtin_ctz(v32)));
} else {
            res = ((mval == 0x0000000000000000ULL) ? 0x0000000000000040ULL : static_cast<uint64_t>(__builtin_ctzll(mval)));
}
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_POPCNT_RR_D1: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (val & mask);
        uint64_t res = ((bits <= 32) ? static_cast<uint64_t>(__builtin_popcount(static_cast<uint32_t>(mval))) : static_cast<uint64_t>(__builtin_popcountll(mval)));
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RBIT_RR_D1: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t res = 0x0000000000000000ULL;
        for (size_t i = 0; i < bits; ++i) {
                                       if (((val >> i) & 0x0000000000000001ULL) != 0x0000000000000000ULL) {
                                       
                                           res |= (0x0000000000000001ULL << ((bits - 1) - i));
                                       }
}
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADD_RR_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000019ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((0x0000000000000002ULL * ((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) - ((ctx.get_reg(dst) + ctx.get_reg(src)) ^ (0x2000000000000000ULL * (ctx.get_reg(src) * (((((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))) * ((ctx.get_reg(src) + 0x0000000000000001ULL) + ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) + (((ctx.get_reg(src) + 0x0000000000000001ULL) & (~(((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) * ((~((ctx.get_reg(src) + 0x0000000000000001ULL))) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) - (((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))) * ((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) + ((((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))) + ((ctx.get_reg(dst) + ctx.get_reg(src)) & (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) ^ ((((((0x0000000000000002ULL * ((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) - ((ctx.get_reg(dst) + ctx.get_reg(src)) ^ (0x2000000000000000ULL * (ctx.get_reg(src) * (((((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))) * ((ctx.get_reg(src) + 0x0000000000000001ULL) + ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) + (((ctx.get_reg(src) + 0x0000000000000001ULL) & (~(((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) * ((~((ctx.get_reg(src) + 0x0000000000000001ULL))) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) - (((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))) * ((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) + ((((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))) + ((ctx.get_reg(dst) + ctx.get_reg(src)) & (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x165d74b3a308514bULL) << 0x0000000000000021ULL)) ^ (((((((0x0000000000000002ULL * ((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) - ((ctx.get_reg(dst) + ctx.get_reg(src)) ^ (0x2000000000000000ULL * (ctx.get_reg(src) * (((((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))) * ((ctx.get_reg(src) + 0x0000000000000001ULL) + ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) + (((ctx.get_reg(src) + 0x0000000000000001ULL) & (~(((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) * ((~((ctx.get_reg(src) + 0x0000000000000001ULL))) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) - (((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))) * ((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) + ((((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))) + ((ctx.get_reg(dst) + ctx.get_reg(src)) & (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) ^ ((((((0x0000000000000002ULL * ((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) - ((ctx.get_reg(dst) + ctx.get_reg(src)) ^ (0x2000000000000000ULL * (ctx.get_reg(src) * (((((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))) * ((ctx.get_reg(src) + 0x0000000000000001ULL) + ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) + (((ctx.get_reg(src) + 0x0000000000000001ULL) & (~(((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) * ((~((ctx.get_reg(src) + 0x0000000000000001ULL))) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) - (((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))) * ((ctx.get_reg(src) + 0x0000000000000001ULL) & ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) + ((((ctx.get_reg(dst) + ctx.get_reg(src)) | (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))) + ((ctx.get_reg(dst) + ctx.get_reg(src)) & (0x2000000000000000ULL * ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) + ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) - ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x165d74b3a308514bULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x165d74b3a308514bULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RI_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000019ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) + static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & static_cast<uint64_t>(imm)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RR_A1_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000000ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) : ((0x0000000000000002ULL * (ctx.get_reg(dst) | ctx.get_reg(src))) - (ctx.get_reg(dst) ^ ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RR_A2_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000005ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RR_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000fULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((0x0000000000000002ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) | ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) - ((ctx.get_reg(dst) - ctx.get_reg(src)) ^ ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) + ((((ctx.get_reg(dst) - ctx.get_reg(src)) | ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL))))) + ((ctx.get_reg(dst) - ctx.get_reg(src)) & ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) - (ctx.get_reg(dst) - ctx.get_reg(src)))) ^ ((((((0x0000000000000002ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) | ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) - ((ctx.get_reg(dst) - ctx.get_reg(src)) ^ ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) + ((((ctx.get_reg(dst) - ctx.get_reg(src)) | ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL))))) + ((ctx.get_reg(dst) - ctx.get_reg(src)) & ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) - (ctx.get_reg(dst) - ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x53ede1e998b4968dULL) << 0x0000000000000021ULL)) ^ (((((((0x0000000000000002ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) | ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) - ((ctx.get_reg(dst) - ctx.get_reg(src)) ^ ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) + ((((ctx.get_reg(dst) - ctx.get_reg(src)) | ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL))))) + ((ctx.get_reg(dst) - ctx.get_reg(src)) & ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) - (ctx.get_reg(dst) - ctx.get_reg(src)))) ^ ((((((0x0000000000000002ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) | ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) - ((ctx.get_reg(dst) - ctx.get_reg(src)) ^ ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) + ((((ctx.get_reg(dst) - ctx.get_reg(src)) | ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL))))) + ((ctx.get_reg(dst) - ctx.get_reg(src)) & ((((ctx.get_reg(dst) - ctx.get_reg(src)) ^ (ctx.get_reg(dst) - ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) - ctx.get_reg(src)))) & (ctx.get_reg(dst) - ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) - ctx.get_reg(src)) * ((ctx.get_reg(dst) - ctx.get_reg(src)) + 0x0000000000000001ULL)))))) - (ctx.get_reg(dst) - ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x53ede1e998b4968dULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x53ede1e998b4968dULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RR_A1_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000007ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) - (ctx.get_reg(dst) ^ ctx.get_reg(src))) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RI_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001bULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) - static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & static_cast<uint64_t>(imm)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_IMUL_RR_D1: { PROBE_START(); uint64_t a = ctx.get_reg(dst); uint64_t b = ctx.get_reg(src); uint64_t res = ((((k_dyn >> 0x000000000000001eULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (a * b) : (((a & b) * (a | b)) + ((a & (~b)) * ((~a) & b)))); ctx.set_reg(dst, res); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_IMUL_RI_D1: { PROBE_START(); uint64_t a = ctx.get_reg(dst); uint64_t b = static_cast<uint64_t>(imm); uint64_t res = ((((k_dyn >> 0x0000000000000009ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (a * b) : (((a & b) * (a | b)) + ((a & (~b)) * ((~a) & b)))); ctx.set_reg(dst, res); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RR_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) + (ctx.get_reg(dst) & ctx.get_reg(src))) & (~((ctx.get_reg(dst) + ctx.get_reg(src))))) - ((~(((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))) & (ctx.get_reg(dst) + ctx.get_reg(src)))) + ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) + (ctx.get_reg(dst) & ctx.get_reg(src))) ^ (ctx.get_reg(dst) + ctx.get_reg(src))) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) | (ctx.get_reg(dst) + ctx.get_reg(src))) - (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) & (ctx.get_reg(dst) + ctx.get_reg(src))))))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RR_A1_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000009ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RI_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001aULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) | static_cast<uint64_t>(imm)) - (ctx.get_reg(dst) & static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RR_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000011ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((ctx.get_reg(dst) ^ (~(((~ctx.get_reg(dst)) | (~((~ctx.get_reg(src)))))))) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) + (0x8000000000000000ULL * ((~(((~ctx.get_reg(dst)) | (~((~ctx.get_reg(src))))))) * ((ctx.get_reg(dst) & (~ctx.get_reg(src))) + 0x0000000000000001ULL)))) | (((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) | ctx.get_reg(src)) ^ (ctx.get_reg(dst) & ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) | ctx.get_reg(src)))) & (ctx.get_reg(dst) & ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) & ctx.get_reg(src)) * ((ctx.get_reg(dst) & ctx.get_reg(src)) + 0x0000000000000001ULL))))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) ^ ctx.get_reg(src)))) & ((((ctx.get_reg(dst) | ctx.get_reg(src)) ^ (ctx.get_reg(dst) & ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) | ctx.get_reg(src)))) & (ctx.get_reg(dst) & ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) & ctx.get_reg(src)) * ((ctx.get_reg(dst) & ctx.get_reg(src)) + 0x0000000000000001ULL)))))))) + ((((ctx.get_reg(dst) ^ (~(((~ctx.get_reg(dst)) | (~((~ctx.get_reg(src)))))))) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) + (0x8000000000000000ULL * ((~(((~ctx.get_reg(dst)) | (~((~ctx.get_reg(src))))))) * ((ctx.get_reg(dst) & (~ctx.get_reg(src))) + 0x0000000000000001ULL)))) & (((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) ^ ((((ctx.get_reg(dst) | ctx.get_reg(src)) ^ (ctx.get_reg(dst) & ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) | ctx.get_reg(src)))) & (ctx.get_reg(dst) & ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) & ctx.get_reg(src)) * ((ctx.get_reg(dst) & ctx.get_reg(src)) + 0x0000000000000001ULL))))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) ^ ctx.get_reg(src)))) & ((((ctx.get_reg(dst) | ctx.get_reg(src)) ^ (ctx.get_reg(dst) & ctx.get_reg(src))) - (0x0000000000000002ULL * ((~((ctx.get_reg(dst) | ctx.get_reg(src)))) & (ctx.get_reg(dst) & ctx.get_reg(src))))) + (0x8000000000000000ULL * ((ctx.get_reg(dst) & ctx.get_reg(src)) * ((ctx.get_reg(dst) & ctx.get_reg(src)) + 0x0000000000000001ULL))))))))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) | ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RR_A1_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) | ctx.get_reg(src))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) ^ ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RI_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001bULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) & static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) + static_cast<uint64_t>(imm)) - (ctx.get_reg(dst) | static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RR_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001aULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) | ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) - (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) ^ ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) + (((((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) | ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL)))))) + (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) & ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) ^ ((((((0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) | ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) - (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) ^ ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) + (((((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) | ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL)))))) + (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) & ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x08f94eb960c83129ULL) << 0x0000000000000021ULL)) ^ (((((((0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) | ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) - (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) ^ ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) + (((((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) | ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL)))))) + (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) & ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) ^ ((((((0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) | ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) - (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) ^ ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) + (((((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) | ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL)))))) + (((ctx.get_reg(dst) & 0x00ff00ff00ff00ffULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x00ff00ff00ff00ffULL))) + ((ctx.get_reg(src) ^ 0x00ff00ff00ff00ffULL) - ((ctx.get_reg(src) | 0x00ff00ff00ff00ffULL) - (ctx.get_reg(src) & 0x00ff00ff00ff00ffULL))))) & ((((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & 0xff00ff00ff00ff00ULL) & 0xaaaaaaaaaaaaaaaaULL)) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0xff00ff00ff00ff00ULL))) + ((ctx.get_reg(src) ^ 0xff00ff00ff00ff00ULL) - ((ctx.get_reg(src) | 0xff00ff00ff00ff00ULL) - (ctx.get_reg(src) & 0xff00ff00ff00ff00ULL))))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x08f94eb960c83129ULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x08f94eb960c83129ULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RR_A1_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RI_D1: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000012ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) | static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) + (ctx.get_reg(dst) & static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ROL_RI_D1: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, ((val << shift) | (val >> ((64 - shift) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROR_RI_D1: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, ((val >> shift) | (val << ((64 - shift) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHL_RI_D1: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, (v << s));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHR_RI_D1: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, (v >> s));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SAR_RI_D1: {
        int64_t sval = static_cast<int64_t>(ctx.get_reg(dst));
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, static_cast<uint64_t>((sval >> shift)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROL_RR_D1: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, ((v << s) | (v >> ((64 - s) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROR_RR_D1: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, ((val >> shift) | (val << ((64 - shift) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHL_RR_D1: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, (val << shift));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHR_RR_D1: {
        uint64_t _res = (ctx.get_reg(dst) >> static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL)));
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SAR_RR_D1: {
        int64_t sval = static_cast<int64_t>(ctx.get_reg(dst));
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, static_cast<uint64_t>((sval >> shift)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_DIV_RR_D1: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        if (b == 0x0000000000000000ULL) {
                                     ctx.trapped = true;
                                     goto EXIT_VM;
}
        ctx.set_reg(dst, (a / b));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IDIV_RR_D1: {
        int64_t _d = static_cast<int64_t>(ctx.get_reg(dst));
        int64_t _s = static_cast<int64_t>(ctx.get_reg(src));
        if ((_s == 0) || ((_s == -1) && (_d == INT64_MIN))) {
                                                         ctx.trapped = true;
                                                         goto EXIT_VM;
}
        int64_t _quot = ((_s == -1) ? (-_d) : (_d / _s));
        ctx.set_reg(dst, static_cast<uint64_t>(_quot));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_MULH_RR_D1: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        
#if defined(__SIZEOF_INT128__)
uint64_t res = static_cast<uint64_t>(((((unsigned __int128)(a)) * ((unsigned __int128)(b))) >> 64));
ctx.set_reg(dst, res);
#else
uint64_t a_lo = static_cast<uint32_t>(a);
uint64_t a_hi = (a >> 32);
uint64_t b_lo = static_cast<uint32_t>(b);
uint64_t b_hi = (b >> 32);
uint64_t p0 = (a_lo * b_lo);
uint64_t p1 = (a_lo * b_hi);
uint64_t p2 = (a_hi * b_lo);
uint64_t p3 = (a_hi * b_hi);
uint64_t cy = ((((p0 >> 32) + static_cast<uint32_t>(p1)) + static_cast<uint32_t>(p2)) >> 32);
uint64_t res = (((p3 + (p1 >> 32)) + (p2 >> 32)) + cy);
ctx.set_reg(dst, res);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IMULH_RR_D1: {
        int64_t a = static_cast<int64_t>(ctx.get_reg(dst));
        int64_t b = static_cast<int64_t>(ctx.get_reg(src));
        
#if defined(__SIZEOF_INT128__)
signed __int128 _prod = (((signed __int128)(a)) * ((signed __int128)(b)));
uint64_t res = static_cast<uint64_t>((_prod >> 64));
ctx.set_reg(dst, res);
#else
uint64_t ua = static_cast<uint64_t>(a);
uint64_t ub = static_cast<uint64_t>(b);
uint64_t a_lo = static_cast<uint32_t>(ua);
uint64_t a_hi = (ua >> 32);
uint64_t b_lo = static_cast<uint32_t>(ub);
uint64_t b_hi = (ub >> 32);
uint64_t p0 = (a_lo * b_lo);
uint64_t p1 = (a_lo * b_hi);
uint64_t p2 = (a_hi * b_lo);
uint64_t p3 = (a_hi * b_hi);
uint64_t cy = ((((p0 >> 32) + static_cast<uint32_t>(p1)) + static_cast<uint32_t>(p2)) >> 32);
uint64_t res = (((p3 + (p1 >> 32)) + (p2 >> 32)) + cy);
if (a < 0) {
                res -= ub;
}
if (b < 0) {
                res -= ua;
}
ctx.set_reg(dst, res);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_D1: {
        PROBE_START();
        uint64_t _d = ctx.get_reg(dst);
        compute_sub_flags(ctx, _d, static_cast<uint64_t>(imm), static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RR_D1: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        compute_sub_flags(ctx, ctx.get_reg(dst), ctx.get_reg(src), bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_A1_D1: {
        PROBE_START();
        uint64_t _d = ctx.get_reg(dst);
        compute_sub_flags(ctx, _d, static_cast<uint64_t>(imm), static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_A2_D1: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        uint64_t _imm = static_cast<uint64_t>(imm);
        compute_sub_flags(ctx, ctx.get_reg(dst), _imm, bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RR_A1_D1: {
        PROBE_START();
        uint64_t _a = ctx.get_reg(dst);
        uint64_t _b = ctx.get_reg(src);
        compute_sub_flags(ctx, _a, _b, static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_PUSH_R_D1: {
        uint64_t val = ctx.get_reg(dst);
        ctx.push(val);
        uint64_t cur_sp = ctx.get_reg(REG_RSP);
        if ((cur_sp >= 0x0000000000010008ULL) && (cur_sp <= 0x00007fffffffffffULL)) {

    uint64_t* sp_ptr = reinterpret_cast<uint64_t*>((cur_sp - 0x0000000000000008ULL));
    ctx.set_reg(REG_RSP, reinterpret_cast<uint64_t>(sp_ptr));
    (*sp_ptr) = val;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_POP_R_D1: {
        uint64_t cur_sp = ctx.get_reg(REG_RSP);
        uint64_t val = 0x0000000000000000ULL;
        if ((cur_sp >= 0x0000000000010000ULL) && (cur_sp <= 0x00007fffffffffffULL)) {

    std::memcpy((&val), reinterpret_cast<const void*>(cur_sp), sizeof(uint64_t));
    ctx.set_reg(REG_RSP, (cur_sp + 0x0000000000000008ULL));
    ctx.pop();} else {
                          val = ctx.pop();
}
        ctx.set_reg(dst, val);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADC_RR_D1: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint64_t c = static_cast<uint64_t>(ctx.cf);
        uint64_t res = ((a + b) + c);
        ctx.cf = ((res < a) || ((c != 0x0000000000000000ULL) && (res == a)));
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = ((res >> 63) != 0x0000000000000000ULL);
        ctx.of = ((((a ^ res) & (b ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADC_RI_D1: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint64_t c = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a + b) + c);
        ctx.cf = ((res < a) || ((c != 0x0000000000000000ULL) && (res == a)));
        ctx.of = ((((a ^ res) & (b ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SBB_RR_D1: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint64_t borrow = static_cast<uint64_t>(ctx.cf);
        uint64_t res = ((a - b) - borrow);
        ctx.cf = ((a < b) || ((borrow != 0x0000000000000000ULL) && (a == b)));
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = ((res >> 63) != 0x0000000000000000ULL);
        ctx.of = ((((a ^ b) & (a ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SBB_RI_D1: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint64_t borrow = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a - b) - borrow);
        ctx.cf = ((a < b) || ((borrow != 0x0000000000000000ULL) && (a == b)));
        ctx.of = ((((a ^ b) & (a ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMP_RR_D1: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (eval_condition(ctx, cond)) {
                                    uint64_t a = ctx.get_reg(dst);
                                    uint64_t b = ctx.get_reg(src);
                                    compute_sub_flags(ctx, a, b, bits);
} else {
            ctx.sf = ((nzcv & 8) != 0);
            ctx.zf = ((nzcv & 4) != 0);
            ctx.cf = ((nzcv & 2) != 0);
            ctx.of = ((nzcv & 1) != 0);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMP_RI_D1: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint64_t b = static_cast<uint64_t>((((word >> 26) + 0x000000000000001fULL) - ((word >> 26) | 0x000000000000001fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (eval_condition(ctx, cond)) {
                                    uint64_t a = ctx.get_reg(dst);
                                    compute_sub_flags(ctx, a, b, bits);
} else {
            ctx.sf = ((nzcv & 8) != 0);
            ctx.zf = ((nzcv & 4) != 0);
            ctx.cf = ((nzcv & 2) != 0);
            ctx.of = ((nzcv & 1) != 0);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMN_RR_D1: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (!eval_condition(ctx, cond)) {
                                     ctx.sf = ((nzcv & 8) != 0);
                                     ctx.zf = ((nzcv & 4) != 0);
                                     ctx.cf = ((nzcv & 2) != 0);
                                     ctx.of = ((nzcv & 1) != 0);
} else {
            uint64_t a = ctx.get_reg(dst);
            uint64_t b = ctx.get_reg(src);
            compute_add_flags(ctx, a, b, bits);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMN_RI_D1: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint64_t b = static_cast<uint64_t>((((word >> 26) + 0x000000000000001fULL) - ((word >> 26) | 0x000000000000001fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (eval_condition(ctx, cond)) {
                                    uint64_t a = ctx.get_reg(dst);
                                    compute_add_flags(ctx, a, b, bits);
} else {
            ctx.sf = ((nzcv & 8) != 0);
            ctx.zf = ((nzcv & 4) != 0);
            ctx.cf = ((nzcv & 2) != 0);
            ctx.of = ((nzcv & 1) != 0);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_GET_FLAGS_R_D1: {
        uint64_t f = 0x0000000000000002ULL;
        f |= static_cast<uint64_t>(ctx.cf);
        f |= (static_cast<uint64_t>(ctx.zf) << 6);
        f |= (static_cast<uint64_t>(ctx.sf) << 7);
        f |= (static_cast<uint64_t>(ctx.of) << 11);
        ctx.set_reg(dst, f);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SET_FLAGS_R_D1: {
        uint64_t mask = ctx.get_reg(src);
        ctx.cf = (((mask >> 0) & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.zf = (((mask >> 6) & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.sf = (((mask >> 7) & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.of = (((mask >> 11) & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_D1: {
        vIP_idx = static_cast<size_t>(imm);
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_A1_D1: {
        size_t _target = static_cast<size_t>(imm);
        vIP_idx = _target;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_A2_D1: {
        vIP_idx = static_cast<size_t>(((static_cast<uint64_t>(imm) ^ 0x0000000000005877ULL) ^ 0x0000000000005877ULL));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JCC_D1: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t base_vip = static_cast<uint64_t>(((word >> 0x0000000000000016ULL) & 0x00000000001fffffULL));
        uint64_t enc_delta = static_cast<uint64_t>(((word >> 0x000000000000002bULL) & 0x00000000001fffffULL));
        uint64_t salt = (((static_cast<uint64_t>(cond) * 0x0000000000005877ULL) ^ 0x000000001337beefULL) & 0x00000000001fffffULL);
        uint64_t delta = (enc_delta ^ salt);
        uint64_t t_true = (base_vip ^ delta);
        uint64_t t_false = base_vip;
        uint64_t c = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        vIP_idx = static_cast<size_t>(asgard::branchless_vip::select_vip(c, t_true, t_false));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JCC_A1_D1: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t base_vip = static_cast<uint64_t>(((word >> 0x0000000000000016ULL) & 0x00000000001fffffULL));
        uint64_t enc_delta = static_cast<uint64_t>(((word >> 0x000000000000002bULL) & 0x00000000001fffffULL));
        uint64_t salt = (((static_cast<uint64_t>(cond) * 0x0000000000005877ULL) ^ 0x000000001337beefULL) & 0x00000000001fffffULL);
        uint64_t delta = (enc_delta ^ salt);
        uint64_t t_true = (base_vip ^ delta);
        uint64_t t_false = base_vip;
        uint64_t c = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        vIP_idx = static_cast<size_t>(asgard::branchless_vip::select_vip(c, t_true, t_false));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMOV_D1: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t _m = (eval_condition(ctx, cond) ? (~0x0000000000000000ULL) : 0x0000000000000000ULL);
        ctx.set_reg(dst, ((ctx.get_reg(src) & _m) | (ctx.get_reg(dst) & (~_m))));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SETCC_D1: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t val = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        ctx.set_reg(dst, val);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CALL_D1: {
        ctx.push(static_cast<uint64_t>(vIP_idx));
        uint64_t _imm_target = static_cast<uint64_t>(imm);
        vIP_idx = static_cast<size_t>(_imm_target);
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IJMP_R_D1: {
        uint64_t target = ctx.get_reg(dst);
        size_t _t_idx = static_cast<size_t>(target);
        if (_t_idx < count) {
                         vIP_idx = _t_idx;
} else {
            if (target != 0x0000000000000000ULL) {
                                                      #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                                      uint64_t a1 = ctx.get_reg(REG_RCX);
                                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                                      uint64_t a3 = ctx.get_reg(REG_RBX);
                                                      uint64_t a4 = ctx.get_reg(REG_RSI);
                                                      uint64_t a5 = ctx.get_reg(REG_RDI);
                                                      #elif defined(ASGARD_GUEST_RISCV64)
                                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                                      uint64_t a1 = ctx.get_reg(REG_RDX);
                                                      uint64_t a2 = ctx.get_reg(REG_RCX);
                                                      uint64_t a3 = ctx.get_reg(REG_RSI);
                                                      uint64_t a4 = ctx.get_reg(REG_RDI);
                                                      uint64_t a5 = ctx.get_reg(REG_R8);
                                                      #else
                                                      uint64_t a0 = ctx.get_reg(REG_RDI);
                                                      uint64_t a1 = ctx.get_reg(REG_RSI);
                                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                                      uint64_t a3 = ctx.get_reg(REG_RCX);
                                                      uint64_t a4 = ctx.get_reg(REG_R8);
                                                      uint64_t a5 = ctx.get_reg(REG_R9);
                                                      #endif
                                                      typedef uint64_t (*indirect_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                      indirect_fn_t fn = reinterpret_cast<indirect_fn_t>(target);
                                                      uint64_t ret_val = fn(a0, a1, a2, a3, a4, a5);
                                                      ctx.set_reg(REG_RAX, ret_val);
                                                      goto EXIT_VM;
            }
}
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ICALL_R_D1: {
        uint64_t target_ptr = ctx.get_reg(dst);
        if (target_ptr < count) {
                             ctx.push(static_cast<uint64_t>(vIP_idx));
                             vIP_idx = static_cast<size_t>(target_ptr);
} else {
            if (target_ptr != 0x0000000000000000ULL) {
                                                          #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                                                          uint64_t a0 = ctx.get_reg(REG_RAX);
                                                          uint64_t a1 = ctx.get_reg(REG_RCX);
                                                          uint64_t a2 = ctx.get_reg(REG_RDX);
                                                          uint64_t a3 = ctx.get_reg(REG_RBX);
                                                          uint64_t a4 = ctx.get_reg(REG_RSI);
                                                          uint64_t a5 = ctx.get_reg(REG_RDI);
                                                          #elif defined(ASGARD_GUEST_RISCV64)
                                                          uint64_t a0 = ctx.get_reg(REG_RAX);
                                                          uint64_t a1 = ctx.get_reg(REG_RDX);
                                                          uint64_t a2 = ctx.get_reg(REG_RCX);
                                                          uint64_t a3 = ctx.get_reg(REG_RSI);
                                                          uint64_t a4 = ctx.get_reg(REG_RDI);
                                                          uint64_t a5 = ctx.get_reg(REG_R8);
                                                          #else
                                                          uint64_t a0 = ctx.get_reg(REG_RDI);
                                                          uint64_t a1 = ctx.get_reg(REG_RSI);
                                                          uint64_t a2 = ctx.get_reg(REG_RDX);
                                                          uint64_t a3 = ctx.get_reg(REG_RCX);
                                                          uint64_t a4 = ctx.get_reg(REG_R8);
                                                          uint64_t a5 = ctx.get_reg(REG_R9);
                                                          #endif
                                                          typedef uint64_t (*indirect_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                          indirect_fn_t fn = reinterpret_cast<indirect_fn_t>(target_ptr);
                                                          uint64_t ret_val = fn(a0, a1, a2, a3, a4, a5);
                                                          ctx.set_reg(REG_RAX, ret_val);
            }
}
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RET_D1: { if (!ctx.verify_canaries()) {
                                 ctx.trapped = true;
} ctx.executed_instructions++; goto EXIT_VM; }
    H_EXIT_D1: { if (!ctx.verify_canaries()) {
                                 ctx.trapped = true;
} ctx.executed_instructions++; goto EXIT_VM; }

    H_BRIDGE_TO_FLOW_D1: {
        uint64_t _imm_flow = static_cast<uint64_t>(imm);
        ctx.morph_math_to_flow(_imm_flow);
        ctx.executed_instructions += 1;
        FETCH_NEXT();
    }
    H_BRIDGE_TO_MATH_D1: {
        uint64_t _imm_math = static_cast<uint64_t>(imm);
        ctx.morph_flow_to_math(_imm_math);
        ctx.executed_instructions += 1;
        FETCH_NEXT();
    }
    H_FUSED_MOV_ADD_RRI_D1: {
        uint64_t _base = ctx.get_reg(src);
        ctx.set_reg(dst, (_base + static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_ADD_IMUL_RRI_D1: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) + ctx.get_reg(src)) * static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_ADD_XOR_RRI_D1: {
        uint64_t _sum = (ctx.get_reg(dst) + ctx.get_reg(src));
        uint64_t _imm = static_cast<uint64_t>(imm);
        ctx.set_reg(dst, ((_sum + _imm) - (0x0000000000000002ULL * (_sum & _imm))));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_SUB_XOR_RRI_D1: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) - ctx.get_reg(src)) ^ static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_XOR_ADD_RRI_D1: {
        uint64_t _a = ctx.get_reg(dst);
        uint64_t _b = ctx.get_reg(src);
        uint64_t _x = ((_a | _b) - (_a & _b));
        uint64_t _i = static_cast<uint64_t>(imm);
        ctx.set_reg(dst, ((_x | _i) + (_x & _i)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_CMP_CMOV_D1: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint8_t cond = static_cast<uint8_t>(((word >> 0x0000000000000032ULL) & 0x000000000000000fULL));
        uint32_t bits = static_cast<uint32_t>(((word >> 0x0000000000000036ULL) & 0x000000000000007fULL));
        compute_sub_flags(ctx, a, b, bits);
        if (eval_condition(ctx, cond)) {
                                    ctx.set_reg(dst, ctx.get_reg(src));
}
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_AND_OR_RRI_D1: {
        uint64_t _imm = static_cast<uint64_t>(imm);
        uint64_t _a = (ctx.get_reg(dst) & ctx.get_reg(src));
        ctx.set_reg(dst, ((_a + _imm) - (_a & _imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_SHL_ADD_RRI_D1: {
        uint64_t _shl = (ctx.get_reg(dst) << (static_cast<uint64_t>(imm) & 0x000000000000003fULL));
        uint64_t _s = ctx.get_reg(src);
        ctx.set_reg(dst, ((_shl ^ _s) + (0x0000000000000002ULL * (_shl & _s))));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_VADD_VV_D1: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vd = vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
uint64x2_t vs = vcombine_u64(vcreate_u64(s0), vcreate_u64(s1));
uint64x2_t vr = vaddq_u64(vd, vs);
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vd = _mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0));
__m128i vs = _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0));
__m128i vr = _mm_add_epi64(vd, vs);
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
ctx.set_vreg(dst, (d0 + s0), (d1 + s1));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VSUB_VV_D1: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vd = vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
uint64x2_t vs = vcombine_u64(vcreate_u64(s0), vcreate_u64(s1));
uint64x2_t vr = vsubq_u64(vd, vs);
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vd = _mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0));
__m128i vs = _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0));
__m128i vr = _mm_sub_epi64(vd, vs);
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
ctx.set_vreg(dst, (d0 - s0), (d1 - s1));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VMUL_VV_D1: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        uint64_t _m0 = (d0 * s0);
        uint64_t _m1 = (d1 * s1);
        ctx.set_vreg(dst, _m0, _m1);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VXOR_VV_D1: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vd = vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
uint64x2_t vs = vcombine_u64(vcreate_u64(s0), vcreate_u64(s1));
uint64x2_t vr = veorq_u64(vd, vs);
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vd = _mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0));
__m128i vs = _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0));
__m128i vr = _mm_xor_si128(vd, vs);
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
ctx.set_vreg(dst, (d0 ^ s0), (d1 ^ s1));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_MOV_D1: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x00000000000003ffULL));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     ctx.set_vreg_lane(dst, i, ctx.get_vreg_lane(src, i));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_BINOP_D1: {
        uint32_t src2 = static_cast<uint32_t>((imm & 0x000000000000001fULL));
        uint32_t bits = static_cast<uint32_t>(((imm >> 5) & 0x00000000000003ffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 15) & 0x00000000000000ffULL));
        if (lane_bits == 0) {
                         lane_bits = 64;
}
        uint32_t vop = static_cast<uint32_t>(((imm >> 23) & 0x000000000000001fULL));
        uint32_t elem = static_cast<uint32_t>(((imm >> 28) & 0x0000000000000003ULL));
        uint64_t mask = ((lane_bits == 8) ? 0x00000000000000ffULL : ((lane_bits == 16) ? 0x000000000000ffffULL : ((lane_bits == 32) ? 0x00000000ffffffffULL : 0xffffffffffffffffULL)));
        size_t bit = 0;
        while (bit < bits) {
                        size_t chunk = (bit / 64);
                        uint32_t shift = static_cast<uint32_t>((bit % 64));
                        uint64_t a = ((ctx.get_vreg_lane(src, chunk) >> shift) & mask);
                        uint64_t b = ((ctx.get_vreg_lane(src2, chunk) >> shift) & mask);
                        uint64_t value = 0x0000000000000000ULL;
                        if ((elem == 1) && (vop <= 2)) {
                                                            float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                                            float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                                            float fr = ((vop == 0) ? (fa + fb) : ((vop == 1) ? (fa - fb) : (fa * fb)));
                                                            value = std::bit_cast<uint32_t>(fr);
                        } else {
                                    if ((elem == 1) && (vop == 11)) {
                                    
                                        float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                        float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                        value = std::bit_cast<uint32_t>(std::fmin(fa, fb));
                                    } else {
                                                if ((elem == 1) && (vop == 12)) {
                                                
                                                    float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                                    float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                                    value = std::bit_cast<uint32_t>(std::fmax(fa, fb));
                                                } else {
                                                            if ((elem == 2) && (vop <= 2)) {
                                                            
                                                                double fa = std::bit_cast<double>(a);
                                                                double fb = std::bit_cast<double>(b);
                                                                double fr = ((vop == 0) ? (fa + fb) : ((vop == 1) ? (fa - fb) : (fa * fb)));
                                                                value = std::bit_cast<uint64_t>(fr);
                                                            } else {
                                                                    if ((elem == 2) && (vop == 11)) {
                                                                    
                                                                    double fa = std::bit_cast<double>(a);
                                                                    double fb = std::bit_cast<double>(b);
                                                                    value = std::bit_cast<uint64_t>(std::fmin(fa, fb));
                                                                    } else {
                                                                    
                                                                    if ((elem == 2) && (vop == 12)) {
                                                                    
                                                                    double fa = std::bit_cast<double>(a);
                                                                    double fb = std::bit_cast<double>(b);
                                                                    value = std::bit_cast<uint64_t>(std::fmax(fa, fb));
                                                                    } else {
                                                                    
                                                                    int64_t sa = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(a))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(a))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(a))) : static_cast<int64_t>(a))));
                                                                    int64_t sb = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(b))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(b))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(b))) : static_cast<int64_t>(b))));
                                                                    switch (vop) {
                                                                    
                                                                    case 0: {
                                                                    
                                                                    value = (a + b);
                                                                    break;
                                                                    }
                                                                    case 1: {
                                                                    
                                                                    value = (a - b);
                                                                    break;
                                                                    }
                                                                    case 2: {
                                                                    
                                                                    value = (a * b);
                                                                    break;
                                                                    }
                                                                    case 3: {
                                                                    
                                                                    value = (a & b);
                                                                    break;
                                                                    }
                                                                    case 4: {
                                                                    
                                                                    value = (a | b);
                                                                    break;
                                                                    }
                                                                    case 5: {
                                                                    
                                                                    value = (a ^ b);
                                                                    break;
                                                                    }
                                                                    case 6: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a << cnt));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 7: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a >> cnt));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 8: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? ((sa < 0) ? mask : 0x0000000000000000ULL) : (static_cast<uint64_t>((sa >> cnt)) & mask));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 9: {
                                                                    
                                                                    value = ((a == b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 10: {
                                                                    
                                                                    value = ((sa > sb) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 11: {
                                                                    
                                                                    value = ((sa < sb) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 12: {
                                                                    
                                                                    value = ((sa > sb) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 13: {
                                                                    
                                                                    value = ((a < b) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 14: {
                                                                    
                                                                    value = ((a > b) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 15: {
                                                                    
                                                                    value = (static_cast<uint64_t>(((sa < 0) ? (-sa) : sa)) & mask);
                                                                    break;
                                                                    }
                                                                    case 16: {
                                                                    
                                                                    value = ((~a) & b);
                                                                    break;
                                                                    }
                                                                    case 17: {
                                                                    
                                                                    {
                                                                    size_t block_lane = ((bit / lane_bits) % (128 / lane_bits));
                                                                    size_t half_idx = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (half_idx * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 18: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_idx = ((num_lanes / 2) + (block_lane / 2));
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (half_idx * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 21: {
                                                                    
                                                                    {
                                                                    uint8_t ctrl = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if ((ctrl & 128) != 0) {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    } else {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + ((ctrl & 15) * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 23: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_len = (num_lanes / 2);
                                                                    size_t src_reg = ((block_lane < half_len) ? src : src2);
                                                                    size_t sel_elem = ((block_lane < half_len) ? (block_lane * 2) : ((block_lane - half_len) * 2));
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 24: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_len = (num_lanes / 2);
                                                                    size_t src_reg = ((block_lane < half_len) ? src : src2);
                                                                    size_t sel_elem = ((block_lane < half_len) ? ((block_lane * 2) + 1) : (((block_lane - half_len) * 2) + 1));
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 25: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t k = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t sel_elem = (k * 2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 26: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t k = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t sel_elem = ((k * 2) + 1);
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 28: {
                                                                    
                                                                    {
                                                                    uint8_t idx = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if (idx < 16) {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + (idx * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    } else {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 29: {
                                                                    
                                                                    {
                                                                    uint8_t idx = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if (idx < 16) {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + (idx * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    } else {
                                                                    
                                                                    value = ((ctx.get_vreg_lane(dst, chunk) >> shift) & 0x00000000000000ffULL);
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 30: {
                                                                    
                                                                    {
                                                                    int64_t min_val = ((lane_bits == 64) ? static_cast<int64_t>(0x8000000000000000ULL) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(0x0000000080000000ULL))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(32768))) : static_cast<int64_t>(((int8_t)(128))))));
                                                                    if (sb == 0) {
                                                                    
                                                                    value = 0xffffffffffffffffULL;
                                                                    } else {
                                                                    
                                                                    if ((sb == -1) && (sa == min_val)) {
                                                                    
                                                                    value = static_cast<uint64_t>(sa);
                                                                    } else {
                                                                    
                                                                    value = static_cast<uint64_t>((sa / sb));
                                                                    }
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 31: {
                                                                    
                                                                    value = ((b != 0) ? (a / b) : mask);
                                                                    break;
                                                                    }
                                                                    case 32: {
                                                                    
                                                                    {
                                                                    int64_t min_val = ((lane_bits == 64) ? static_cast<int64_t>(0x8000000000000000ULL) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(0x0000000080000000ULL))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(32768))) : static_cast<int64_t>(((int8_t)(128))))));
                                                                    if (sb == 0) {
                                                                    
                                                                    value = a;
                                                                    } else {
                                                                    
                                                                    if ((sb == -1) && (sa == min_val)) {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    } else {
                                                                    
                                                                    value = static_cast<uint64_t>((sa % sb));
                                                                    }
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 33: {
                                                                    
                                                                    value = ((b != 0) ? (a % b) : a);
                                                                    break;
                                                                    }
                                                                    case 34: {
                                                                    
                                                                    value = ((a != b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 35: {
                                                                    
                                                                    value = ((sa <= sb) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 36: {
                                                                    
                                                                    value = ((a < b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 37: {
                                                                    
                                                                    value = ((a <= b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    default: {
                                                                    
                                                                    value = (a ^ b);
                                                                    break;
                                                                    }
                                                                    }
                                                                    }
                                                                    }
                                                            }
                                                }
                                    }
                        }
                        uint64_t old_value = ctx.get_vreg_lane(dst, chunk);
                        uint64_t packed_mask = (mask << shift);
                        ctx.set_vreg_lane(dst, chunk, ((old_value & (~packed_mask)) | ((value & mask) << shift)));
                        bit += lane_bits;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_IMM_D1: {
        uint64_t imm_val = (imm & 0x00000000000000ffULL);
        uint32_t bits = static_cast<uint32_t>(((imm >> 8) & 0x00000000000003ffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 18) & 0x00000000000000ffULL));
        if (lane_bits == 0) {
                         lane_bits = 64;
}
        uint32_t vop = static_cast<uint32_t>(((imm >> 26) & 0x000000000000001fULL));
        uint64_t mask = ((lane_bits == 8) ? 0x00000000000000ffULL : ((lane_bits == 16) ? 0x000000000000ffffULL : ((lane_bits == 32) ? 0x00000000ffffffffULL : 0xffffffffffffffffULL)));
        size_t bit = 0;
        while (bit < bits) {
                        size_t chunk = (bit / 64);
                        uint32_t shift = static_cast<uint32_t>((bit % 64));
                        uint64_t a = ((ctx.get_vreg_lane(src, chunk) >> shift) & mask);
                        int64_t sa = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(a))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(a))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(a))) : static_cast<int64_t>(a))));
                        uint64_t value = 0x0000000000000000ULL;
                        switch (vop) {
                                        case 6: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a << cnt));
                                                          break;
                                                     }
                                        }
                                        case 7: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a >> cnt));
                                                          break;
                                                     }
                                        }
                                        case 8: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? ((sa < 0) ? mask : 0x0000000000000000ULL) : (static_cast<uint64_t>((sa >> cnt)) & mask));
                                                          break;
                                                     }
                                        }
                                        case 21: {
                                                      {
                                                           size_t lane_in_128 = ((bit / 32) % 4);
                                                           size_t sel = ((imm_val >> (lane_in_128 * 2)) & 0x0000000000000003ULL);
                                                           size_t src_bit = (((bit / 128) * 128) + (sel * 32));
                                                           value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000ffffffffULL);
                                                           break;
                                                      }
                                        }
                                        case 22: {
                                                      {
                                                           size_t lane_idx = (bit / lane_bits);
                                                           size_t sel = ((imm_val >> (lane_idx % 8)) & 0x0000000000000001ULL);
                                                           value = ((sel == 0) ? a : ((ctx.get_vreg_lane(dst, chunk) >> shift) & mask));
                                                           break;
                                                      }
                                        }
                                        default: {
                                                      value = a;
                                                      break;
                                        }
                        }
                        uint64_t old_value = ctx.get_vreg_lane(dst, chunk);
                        uint64_t packed_mask = (mask << shift);
                        ctx.set_vreg_lane(dst, chunk, ((old_value & (~packed_mask)) | ((value & mask) << shift)));
                        bit += lane_bits;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_CLEAR_UPPER_D1: {
        ctx.set_vreg_lane(dst, 2, 0x0000000000000000ULL);
        ctx.set_vreg_lane(dst, 3, 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_ZERO_UPPER_D1: {
        for (size_t i = 0; i < 16; ++i) {
                                     ctx.set_vreg_lane(i, 2, 0x0000000000000000ULL);
                                     ctx.set_vreg_lane(i, 3, 0x0000000000000000ULL);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_PMOVMSKB_D1: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x00000000000003ffULL));
        uint32_t num_bytes = (bits / 8);
        uint64_t mask = 0x0000000000000000ULL;
        for (size_t b_idx = 0; b_idx < num_bytes; ++b_idx) {
                                                        uint64_t byte_val = ((ctx.get_vreg_lane(src, (b_idx / 8)) >> ((b_idx % 8) * 8)) & 0x00000000000000ffULL);
                                                        if ((byte_val & 0x0000000000000080ULL) != 0x0000000000000000ULL) {
                                                        
                                                            mask |= (0x0000000000000001ULL << b_idx);
                                                        }
}
        ctx.set_reg(dst, mask);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_LOAD_D1: {
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x00000000000003ffULL));
        uint64_t address = (ctx.get_reg(src) + static_cast<uint64_t>(imm));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     uint64_t value = 0x0000000000000000ULL;
                                                     std::memcpy((&value), reinterpret_cast<const void*>((address + (i * 8))), sizeof(value));
                                                     ctx.set_vreg_lane(dst, i, value);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_STORE_D1: {
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x00000000000003ffULL));
        uint64_t address = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     std::memcpy(reinterpret_cast<void*>((address + (i * 8))), (&ctx.vregs[(src & 31)][(i & 7)]), sizeof(uint64_t));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_SPLAT_D1: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x000000000000ffffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 16) & 0x000000000000ffffULL));
        uint64_t val = ctx.get_reg(src);
        uint64_t mask = ((lane_bits >= 64) ? 0xffffffffffffffffULL : ((0x0000000000000001ULL << lane_bits) - 0x0000000000000001ULL));
        uint64_t val_masked = (val & mask);
        uint32_t num_lanes = ((lane_bits > 0) ? (bits / lane_bits) : 0);
        for (size_t l = 0; l < num_lanes; ++l) {
                                            uint32_t pos = (l * lane_bits);
                                            uint32_t chunk = (pos / 64);
                                            uint32_t shift = (pos % 64);
                                            uint64_t packed_mask = ((lane_bits >= 64) ? 0xffffffffffffffffULL : (mask << shift));
                                            uint64_t cur = ctx.get_vreg_lane(dst, chunk);
                                            cur = ((cur & (~packed_mask)) | (val_masked << shift));
                                            ctx.set_vreg_lane(dst, chunk, cur);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_EXT_D1: {
        uint32_t src2 = static_cast<uint32_t>((imm & 0x000000000000001fULL));
        uint32_t shift_bytes = static_cast<uint32_t>(((imm >> 5) & 0x000000000000000fULL));
        uint32_t bits = static_cast<uint32_t>(((imm >> 9) & 0x00000000000003ffULL));
        if (bits == 0) {
                    bits = 128;
}
        for (size_t byte_idx = 0; byte_idx < (bits / 8); ++byte_idx) {
                                                                  size_t total_idx = ((byte_idx % 16) + shift_bytes);
                                                                  uint64_t val = 0x0000000000000000ULL;
                                                                  if (total_idx < 16) {
                                                                  
                                                                    size_t bit_pos = (((byte_idx / 16) * 128) + (total_idx * 8));
                                                                    val = ((ctx.get_vreg_lane(src, (bit_pos / 64)) >> (bit_pos % 64)) & 0x00000000000000ffULL);
                                                                  } else {
                                                                  
                                                                    size_t m_idx = (total_idx - 16);
                                                                    size_t bit_pos = (((byte_idx / 16) * 128) + (m_idx * 8));
                                                                    val = ((ctx.get_vreg_lane(src2, (bit_pos / 64)) >> (bit_pos % 64)) & 0x00000000000000ffULL);
                                                                  }
                                                                  size_t chunk = ((byte_idx * 8) / 64);
                                                                  uint32_t shift = static_cast<uint32_t>(((byte_idx * 8) % 64));
                                                                  uint64_t old_v = ctx.get_vreg_lane(dst, chunk);
                                                                  uint64_t clr = (old_v & (~((0x00000000000000ffULL << shift))));
                                                                  ctx.set_vreg_lane(dst, chunk, (clr | (val << shift)));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CALL_EXTERN_D1: {
        size_t sym_idx = ((size_t)(imm));
        void* sym_ptr = asgard_resolve_sym_idx(((int32_t)(sym_idx)));
        if (sym_ptr) {
                  uint32_t sym_h = g_external_symbols[sym_idx].hash;
                  uint32_t sym_ah = g_external_symbols[sym_idx].alt_hash;
                  
                  #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                  uint64_t a0 = ctx.get_reg(REG_RAX);
                  uint64_t a1 = ctx.get_reg(REG_RCX);
                  uint64_t a2 = ctx.get_reg(REG_RDX);
                  uint64_t a3 = ctx.get_reg(REG_RBX);
                  uint64_t a4 = ctx.get_reg(REG_RSI);
                  uint64_t a5 = ctx.get_reg(REG_RDI);
                  uint64_t a6 = ctx.get_reg(REG_R8);
                  uint64_t a7 = ctx.get_reg(REG_R9);
                  #elif defined(ASGARD_GUEST_RISCV64)
                  uint64_t a0 = ctx.get_reg(REG_RAX);
                  uint64_t a1 = ctx.get_reg(REG_RDX);
                  uint64_t a2 = ctx.get_reg(REG_RCX);
                  uint64_t a3 = ctx.get_reg(REG_RSI);
                  uint64_t a4 = ctx.get_reg(REG_RDI);
                  uint64_t a5 = ctx.get_reg(REG_R8);
                  uint64_t a6 = ctx.get_reg(REG_R9);
                  uint64_t a7 = ctx.get_reg(REG_R12);
                  #else
                  uint64_t a0 = (ctx.get_reg(REG_RDI) ? ctx.get_reg(REG_RDI) : ctx.get_reg(REG_RAX));
                  uint64_t a1 = ctx.get_reg(REG_RSI);
                  uint64_t a2 = ctx.get_reg(REG_RDX);
                  uint64_t a3 = ctx.get_reg(REG_RCX);
                  uint64_t a4 = ctx.get_reg(REG_R8);
                  uint64_t a5 = ctx.get_reg(REG_R9);
                  uint64_t a6 = ctx.get_reg(REG_RAX);
                  uint64_t a7 = ctx.get_reg(REG_RBX);
                  #endif
                  
                  const uint64_t* stk = reinterpret_cast<const uint64_t*>(ctx.get_reg(REG_RSP));
                  uint64_t ret_val = 0x0000000000000000ULL;
                  if ((((((sym_h == 0x42fcf5cfU) || (sym_ah == 0x42fcf5cfU)) || (sym_h == 0x07554acdU)) || (sym_ah == 0x07554acdU)) || (sym_h == 0xe76fb4aaU)) || (sym_ah == 0xe76fb4aaU)) {
                  
                      typedef int (*printf_fn_t)(const char*, ...);
                      printf_fn_t pfn = reinterpret_cast<printf_fn_t>(sym_ptr);
                      
                      #if defined(__APPLE__) && defined(__aarch64__)
                      ret_val = ((uint64_t)(pfn(((const char*)(a0)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                      #else
                      ret_val = ((uint64_t)(pfn(((const char*)(a0)), a1, a2, a3, a4, a5, a6, a7)));
                      #endif
                      
                  } else {
                              if ((((((((((((((((sym_h == 0xfcb512e2U) || (sym_ah == 0xfcb512e2U)) || (sym_h == 0x4b3c5330U)) || (sym_ah == 0x4b3c5330U)) || (sym_h == 0x937d1ef6U)) || (sym_ah == 0x937d1ef6U)) || (sym_h == 0xcb76d42bU)) || (sym_ah == 0xcb76d42bU)) || (sym_h == 0xd54ce817U)) || (sym_ah == 0xd54ce817U)) || (sym_h == 0xbbed3905U)) || (sym_ah == 0xbbed3905U)) || (sym_h == 0x42c07c7cU)) || (sym_ah == 0x42c07c7cU)) || (sym_h == 0x24559dbdU)) || (sym_ah == 0x24559dbdU)) {
                              
                                  typedef int (*fprintf_fn_t)(void*, const char*, ...);
                                  fprintf_fn_t fpfn = reinterpret_cast<fprintf_fn_t>(sym_ptr);
                                  
                                  #if defined(__APPLE__) && defined(__aarch64__)
                                  ret_val = ((uint64_t)(fpfn(((void*)(a0)), ((const char*)(a1)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                  #else
                                  ret_val = ((uint64_t)(fpfn(((void*)(a0)), ((const char*)(a1)), a2, a3, a4, a5, a6, a7)));
                                  #endif
                                  
                              } else {
                                          if ((((((((sym_h == 0x7fe32b00U) || (sym_ah == 0x7fe32b00U)) || (sym_h == 0xbcbf60eeU)) || (sym_ah == 0xbcbf60eeU)) || (sym_h == 0x70e2d349U)) || (sym_ah == 0x70e2d349U)) || (sym_h == 0x44fa3468U)) || (sym_ah == 0x44fa3468U)) {
                                          
                                              typedef int (*sprintf_fn_t)(char*, const char*, ...);
                                              sprintf_fn_t spfn = reinterpret_cast<sprintf_fn_t>(sym_ptr);
                                              
                                              #if defined(__APPLE__) && defined(__aarch64__)
                                              ret_val = ((uint64_t)(spfn(((char*)(a0)), ((const char*)(a1)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                              #else
                                              ret_val = ((uint64_t)(spfn(((char*)(a0)), ((const char*)(a1)), a2, a3, a4, a5, a6, a7)));
                                              #endif
                                              
                                          } else {
                                                      if ((((((((sym_h == 0x54ee11faU) || (sym_ah == 0x54ee11faU)) || (sym_h == 0x933075f4U)) || (sym_ah == 0x933075f4U)) || (sym_h == 0x3fd5eb6fU)) || (sym_ah == 0x3fd5eb6fU)) || (sym_h == 0x5b3553b4U)) || (sym_ah == 0x5b3553b4U)) {
                                                      
                                                          typedef int (*snprintf_fn_t)(char*, size_t, const char*, ...);
                                                          snprintf_fn_t snpfn = reinterpret_cast<snprintf_fn_t>(sym_ptr);
                                                          
                                                          #if defined(__APPLE__) && defined(__aarch64__)
                                                          ret_val = ((uint64_t)(snpfn(((char*)(a0)), ((size_t)(a1)), ((const char*)(a2)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                                          #else
                                                          ret_val = ((uint64_t)(snpfn(((char*)(a0)), ((size_t)(a1)), ((const char*)(a2)), a3, a4, a5, a6, a7)));
                                                          #endif
                                                          
                                                      } else {
                                                                  typedef uint64_t (*extern_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                                  extern_fn_t fn = reinterpret_cast<extern_fn_t>(sym_ptr);
                                                                  ret_val = fn(a0, a1, a2, a3, a4, a5, a6, a7);
                                                      }
                                          }
                              }
                  }
                  ctx.set_reg(REG_RAX, ret_val);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_64_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint64_t _val = asgard::oblivious_mem::oblivious_load_u64(_addr);
ctx.set_reg(dst, _val);
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint64_t _v = 0x0000000000000000ULL;
std::memcpy((&_v), reinterpret_cast<const void*>(_ptr), sizeof(uint64_t));
ctx.set_reg(dst, _v);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_32_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(asgard::oblivious_mem::oblivious_load_u32(static_cast<uintptr_t>(addr)))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint32_t _v32 = 0x00000000U;
std::memcpy((&_v32), reinterpret_cast<const void*>(_ptr), sizeof(uint32_t));
ctx.set_reg(dst, ((uint64_t)(_v32)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_16_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(asgard::oblivious_mem::oblivious_load_u16(static_cast<uintptr_t>(addr)))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint16_t _v16 = ((uint16_t)(0x00000000U));
std::memcpy((&_v16), reinterpret_cast<const void*>(_ptr), sizeof(uint16_t));
ctx.set_reg(dst, ((uint64_t)(_v16)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_8_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint8_t _v8 = asgard::oblivious_mem::oblivious_load_u8(_addr);
ctx.set_reg(dst, ((uint64_t)(_v8)));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)((*(reinterpret_cast<const uint8_t*>(addr))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S32_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(((int32_t)(asgard::oblivious_mem::oblivious_load_u32(static_cast<uintptr_t>(addr)))))))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
int32_t _s32 = 0;
std::memcpy((&_s32), reinterpret_cast<const void*>(_ptr), sizeof(int32_t));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(_s32)))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S16_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
int16_t _s16 = ((int16_t)(asgard::oblivious_mem::oblivious_load_u16(_addr)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(_s16)))));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int16_t*>(addr))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S8_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
int8_t _s8 = ((int8_t)(asgard::oblivious_mem::oblivious_load_u8(_addr)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(_s8)))));
#else
const char* _base = reinterpret_cast<const char*>(ctx.get_reg(src));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int8_t*>((_base + imm)))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_64_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
asgard::oblivious_mem::oblivious_store_u64(_ptr, ctx.get_reg(src), (&ctx.decoy_sink));
#else
char* _target = (reinterpret_cast<char*>(ctx.get_reg(dst)) + imm);
(*(reinterpret_cast<uint64_t*>(_target))) = ctx.get_reg(src);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_32_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
asgard::oblivious_mem::oblivious_store_u32(static_cast<uintptr_t>(addr), ((uint32_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
(*(reinterpret_cast<uint32_t*>(addr))) = ((uint32_t)(ctx.get_reg(src)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_16_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
asgard::oblivious_mem::oblivious_store_u16(static_cast<uintptr_t>(addr), ((uint16_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
uint16_t _v16 = ((uint16_t)(ctx.get_reg(src)));
std::memcpy(reinterpret_cast<void*>(_ptr), (&_v16), sizeof(uint16_t));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_8_D1: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
asgard::oblivious_mem::oblivious_store_u8(static_cast<uintptr_t>(addr), ((uint8_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
(*(reinterpret_cast<uint8_t*>(addr))) = ((uint8_t)(ctx.get_reg(src)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RESOLVE_SYM_D1: {
        size_t sym_idx = ((size_t)(imm));
        void* sym_ptr = asgard_resolve_sym_idx(((int32_t)(sym_idx)));
        ctx.set_reg(dst, ((uint64_t)(sym_ptr)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FADD_DD_D1: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((std::bit_cast<double>(_s) + std::bit_cast<double>(_i))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FSUB_DD_D1: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        uint64_t b_raw = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        double a = std::bit_cast<double>(a_raw);
        double b = std::bit_cast<double>(b_raw);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((a - b)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FMUL_DD_D1: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        double _b = std::bit_cast<double>(ctx.get_vreg_lane(static_cast<uint8_t>(imm), 0));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((_a * _b)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FDIV_DD_D1: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        double _b = std::bit_cast<double>(ctx.get_vreg_lane(static_cast<uint8_t>(imm), 0));
        double _q = ((_b == 0.0) ? ((_a == 0.0) ? NAN : ((std::signbit(_a) ^ std::signbit(_b)) ? (-INFINITY) : INFINITY)) : (_a / _b));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(_q), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FSQRT_D_D1: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        double _root = ((_a < 0.0) ? NAN : std::sqrt(_a));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(_root), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCMP_DD_D1: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        uint64_t b_raw = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        double a = std::bit_cast<double>(a_raw);
        double b = std::bit_cast<double>(b_raw);
        bool is_nan = (std::isnan(a) || std::isnan(b));
        ctx.zf = (is_nan || (a == b));
        ctx.cf = (is_nan || (a < b));
        ctx.pf = is_nan;
        ctx.sf = false;
        ctx.of = false;
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVTZS_D1: {
        ctx.set_reg(dst, ((uint64_t)(((int64_t)(std::bit_cast<double>(ctx.get_vreg_lane(src, 0)))))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SCVTF_D1: {
        int64_t v = ((int64_t)(ctx.get_reg(src)));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(v))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVTZU_D1: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        uint64_t _u64 = ((_a < 0.0) ? 0x0000000000000000ULL : static_cast<uint64_t>(_a));
        ctx.set_reg(dst, _u64);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_UCVTF_D1: {
        uint64_t _v = ctx.get_reg(src);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(_v))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVT_D1: {
        if (((uint32_t)(imm)) == 1) {
                                 double d64 = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
                                 float f32 = ((float)(d64));
                                 uint32_t u32 = std::bit_cast<uint32_t>(f32);
                                 ctx.set_vreg(dst, ((ctx.get_vreg_lane(dst, 0) & 0xffffffff00000000ULL) | ((uint64_t)(u32))), 0x0000000000000000ULL);
} else {
            float f32 = std::bit_cast<float>(((uint32_t)(ctx.get_vreg_lane(src, 0))));
            ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(f32))), 0x0000000000000000ULL);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_LOAD_D1: {
        uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
        std::atomic<uint64_t>* ptr = reinterpret_cast<std::atomic<uint64_t>*>(addr);
        ctx.set_reg(dst, ptr->load(std::memory_order_seq_cst));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_STORE_D1: {
        uint64_t _addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
        ((void)(__atomic_exchange_n(reinterpret_cast<uint64_t*>(_addr), ctx.get_reg(src), __ATOMIC_SEQ_CST)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_CAS_D1: {
        uint64_t _addr = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        uint64_t _exp = ctx.get_reg(src);
        uint64_t _des = ctx.get_reg(REG_RAX);
        __atomic_compare_exchange_n(reinterpret_cast<uint64_t*>(_addr), (&_exp), _des, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        ctx.set_reg(src, _exp);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_ADD_D1: {
        uint64_t* ptr = reinterpret_cast<uint64_t*>((ctx.get_reg(dst) + ((uint64_t)(imm))));
        uint64_t old = __atomic_load_n(ptr, __ATOMIC_RELAXED);
        uint64_t add_val = ctx.get_reg(src);
        while (!__atomic_compare_exchange_n(ptr, (&old), (old + add_val), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {

    
}
        ctx.set_reg(src, old);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_SWP_D1: {
        uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
        std::atomic<uint64_t>* ptr = reinterpret_cast<std::atomic<uint64_t>*>(addr);
        uint64_t old = ptr->exchange(ctx.get_reg(src), std::memory_order_seq_cst);
        ctx.set_reg(src, old);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FENCE_D1: { std::atomic_thread_fence(std::memory_order_seq_cst); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_VR_D1: {
        uint64_t _val = (ctx.get_reg(src) ^ 0xa5a5a5a55a5a5a5aULL);
        ctx.set_vreg_lane(dst, 0, (_val ^ 0xa5a5a5a55a5a5a5aULL));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_MOV_RV_D1: { ctx.set_reg(dst, ctx.get_vreg_lane(src, 0)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_FCSEL_VV_D1: {
        uint8_t cond = ((uint8_t)((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL))));
        if (eval_condition(ctx, cond)) {
                                    ctx.set_vreg_lane(dst, 0, ctx.get_vreg_lane(src, 0));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }

    H_NOP_D2: { ctx.executed_instructions += 1; FETCH_NEXT(); }
    H_MOV_RR_D2: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x000000000000000eULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_s ^ 0x4e440e24b3fb3f57ULL) ^ 0x4e440e24b3fb3f57ULL) : ((_s + 0x8102d7d02bda470bULL) - 0x8102d7d02bda470bULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_D2: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x0000000000000017ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_imm ^ 0x09ca47795073e050ULL) ^ 0x09ca47795073e050ULL) : ((_imm + 0x366e67510f3fb8daULL) - 0x366e67510f3fb8daULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_A1_D2: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x000000000000000aULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_s + 0x0000000013375877ULL) - 0x0000000013375877ULL) : ((_s ^ 0xc765577d3da7813fULL) ^ 0xc765577d3da7813fULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_A2_D2: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x000000000000001cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~((~_s))) : (_s ^ 0x0000000000000000ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_A1_D2: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x0000000000000010ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_imm ^ 0x7e08a2b0530b6904ULL) ^ 0x7e08a2b0530b6904ULL) : ((_imm + 0x0000000058771337ULL) - 0x0000000058771337ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_A2_D2: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x0000000000000015ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~((~_imm))) : ((_imm + 0x00000000deadbeefULL) - 0x00000000deadbeefULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_HIGH_D2: {
        uint64_t high_val = (static_cast<uint64_t>(static_cast<uint32_t>(imm)) << 32);
        ctx.set_reg(dst, ((ctx.get_reg(dst) & 0x00000000ffffffffULL) | high_val));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_NEG_RR_D2: { PROBE_START(); uint64_t _v = ctx.get_reg(dst); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000009ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((~_v) + 0x0000000000000001ULL) : (0x0000000000000000ULL - _v))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_NOT_RR_D2: { PROBE_START(); uint64_t _v = ctx.get_reg(dst); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000014ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~_v) : (_v ^ (~0x0000000000000000ULL)))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_BSWAP_RR_D2: {
        uint32_t bits = static_cast<uint32_t>(imm);
        if (bits == 16) {
                     ctx.set_reg(dst, static_cast<uint64_t>(__builtin_bswap16(static_cast<uint16_t>(ctx.get_reg(src)))));
} else {
            if (bits == 32) {
                                 ctx.set_reg(dst, static_cast<uint64_t>(__builtin_bswap32(static_cast<uint32_t>(ctx.get_reg(src)))));
            } else {
                        ctx.set_reg(dst, __builtin_bswap64(ctx.get_reg(src)));
            }
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CLZ_RR_D2: {
        uint64_t _s = ctx.get_reg(src);
        uint32_t _bits = static_cast<uint32_t>(imm);
        uint64_t _mask = ((_bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << _bits) - 0x0000000000000001ULL));
        uint64_t _ms = (_s & _mask);
        if (_bits <= 32) {
                      uint32_t _v32 = static_cast<uint32_t>(_ms);
                      ctx.set_reg(dst, ((_v32 == 0) ? static_cast<uint64_t>(_bits) : static_cast<uint64_t>((__builtin_clz(_v32) - (32 - _bits)))));
} else {
            ctx.set_reg(dst, ((_ms == 0x0000000000000000ULL) ? 0x0000000000000040ULL : static_cast<uint64_t>(__builtin_clzll(_ms))));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CTZ_RR_D2: {
        uint64_t _s = ctx.get_reg(src);
        uint32_t _bits = static_cast<uint32_t>(imm);
        uint64_t _mask = ((_bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << _bits) - 0x0000000000000001ULL));
        uint64_t _ms = (_s & _mask);
        if (_bits <= 32) {
                      uint32_t _v32 = static_cast<uint32_t>(_ms);
                      ctx.set_reg(dst, ((_v32 == 0) ? static_cast<uint64_t>(_bits) : static_cast<uint64_t>(__builtin_ctz(_v32))));
} else {
            ctx.set_reg(dst, ((_ms == 0x0000000000000000ULL) ? 0x0000000000000040ULL : static_cast<uint64_t>(__builtin_ctzll(_ms))));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_POPCNT_RR_D2: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (val & mask);
        uint64_t res = ((bits <= 32) ? static_cast<uint64_t>(__builtin_popcount(static_cast<uint32_t>(mval))) : static_cast<uint64_t>(__builtin_popcountll(mval)));
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RBIT_RR_D2: {
        uint64_t _val = ctx.get_reg(src);
        uint32_t _bits = static_cast<uint32_t>(imm);
        uint64_t _res = 0x0000000000000000ULL;
        uint32_t _i = 0;
        while (_i < _bits) {
                        if (((_val >> _i) & 0x0000000000000001ULL) != 0x0000000000000000ULL) {
                        
                            _res |= (0x0000000000000001ULL << ((_bits - 1) - _i));
                        }
                        _i += 1;
}
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADD_RR_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001aULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((((ctx.get_reg(dst) + ctx.get_reg(src)) + (((0x2000000000000000ULL & ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))) * (0x2000000000000000ULL | ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))) + ((0x2000000000000000ULL & (~(((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) * ((~0x2000000000000000ULL) & ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))))) ^ (((((ctx.get_reg(dst) + ctx.get_reg(src)) + (((0x2000000000000000ULL & ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))) * (0x2000000000000000ULL | ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))) + ((0x2000000000000000ULL & (~(((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) * ((~0x2000000000000000ULL) & ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))))) & 0x000000007fffffffULL) * 0x04f9872b4de904b1ULL) << 0x0000000000000021ULL)) ^ ((((((ctx.get_reg(dst) + ctx.get_reg(src)) + (((0x2000000000000000ULL & ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))) * (0x2000000000000000ULL | ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))) + ((0x2000000000000000ULL & (~(((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) * ((~0x2000000000000000ULL) & ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))))) ^ (((((ctx.get_reg(dst) + ctx.get_reg(src)) + (((0x2000000000000000ULL & ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))) * (0x2000000000000000ULL | ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))) + ((0x2000000000000000ULL & (~(((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))))))) * ((~0x2000000000000000ULL) & ((((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) ^ ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL))))) + ((ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))) * (ctx.get_reg(src) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) + ((ctx.get_reg(src) & (~(((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))) * ((~ctx.get_reg(src)) & ((ctx.get_reg(src) + 0x0000000000000001ULL) * ((ctx.get_reg(src) + 0x0000000000000002ULL) * (ctx.get_reg(src) + 0x0000000000000003ULL)))))))))) & 0x000000007fffffffULL) * 0x04f9872b4de904b1ULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x04f9872b4de904b1ULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RI_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000017ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) + static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & static_cast<uint64_t>(imm)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RR_A1_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000004ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) : ((0x0000000000000002ULL * (ctx.get_reg(dst) | ctx.get_reg(src))) - (ctx.get_reg(dst) ^ ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RR_A2_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000017ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RR_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001eULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((((((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & (~((((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))))) - ((~((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) | (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))) - (((ctx.get_reg(dst) & ctx.get_reg(src)) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))))) + (((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) ^ (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) | (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))) - (((ctx.get_reg(dst) & ctx.get_reg(src)) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) - (((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) | (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) - ((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))))))) ^ (((((((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & (~((((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))))) - ((~((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) | (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))) - (((ctx.get_reg(dst) & ctx.get_reg(src)) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))))) + (((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) ^ (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) | (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))) - (((ctx.get_reg(dst) & ctx.get_reg(src)) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) - (((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) | (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) - ((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))))))) & 0x000000007fffffffULL) * 0x0965dd1b958cf75bULL) << 0x0000000000000021ULL)) ^ ((((((((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & (~((((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))))) - ((~((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) | (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))) - (((ctx.get_reg(dst) & ctx.get_reg(src)) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))))) + (((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) ^ (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) | (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))) - (((ctx.get_reg(dst) & ctx.get_reg(src)) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) - (((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) | (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) - ((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))))))) ^ (((((((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & (~((((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))))) - ((~((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) | (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))) - (((ctx.get_reg(dst) & ctx.get_reg(src)) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))))) + (((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) ^ (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) | (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) | (ctx.get_reg(src) & 0xffffffff00000000ULL))) - (((ctx.get_reg(dst) & ctx.get_reg(src)) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) - (((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) | (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) - ((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))))))) & 0x000000007fffffffULL) * 0x0965dd1b958cf75bULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x0965dd1b958cf75bULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RR_A1_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000017ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) - (ctx.get_reg(dst) ^ ctx.get_reg(src))) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RI_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000fULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) - static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & static_cast<uint64_t>(imm)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_IMUL_RR_D2: { PROBE_START(); uint64_t a = ctx.get_reg(dst); uint64_t b = ctx.get_reg(src); uint64_t res = ((((k_dyn >> 0x0000000000000005ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (a * b) : (((a & b) * (a | b)) + ((a & (~b)) * ((~a) & b)))); ctx.set_reg(dst, res); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_IMUL_RI_D2: { PROBE_START(); uint64_t a = ctx.get_reg(dst); uint64_t b = static_cast<uint64_t>(imm); uint64_t res = ((((k_dyn >> 0x0000000000000008ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (a * b) : (((a & b) * (a | b)) + ((a & (~b)) * ((~a) & b)))); ctx.set_reg(dst, res); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RR_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000fULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((((ctx.get_reg(dst) ^ ctx.get_reg(src)) & 0x5555555555555555ULL) + (((((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) + (((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) & 0x5555555555555555ULL)) + (((ctx.get_reg(dst) ^ ctx.get_reg(src)) & 0xaaaaaaaaaaaaaaaaULL) + (((((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) + (((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) - (ctx.get_reg(dst) + ctx.get_reg(src))))) & 0xaaaaaaaaaaaaaaaaULL))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RR_A1_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000018ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RI_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000011ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) | static_cast<uint64_t>(imm)) - (ctx.get_reg(dst) & static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RR_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000015ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((((ctx.get_reg(dst) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0xaaaaaaaaaaaaaaaaULL))) | ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) - ((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))))) + ((((ctx.get_reg(dst) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0xaaaaaaaaaaaaaaaaULL))) & ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) - ((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src)))))) ^ ((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0xaaaaaaaaaaaaaaaaULL))) | ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) - ((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))))) + ((((ctx.get_reg(dst) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0xaaaaaaaaaaaaaaaaULL))) & ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) - ((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src)))))) & 0x000000007fffffffULL) * 0x6424f8a2dd83ed6fULL) << 0x0000000000000021ULL)) ^ (((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0xaaaaaaaaaaaaaaaaULL))) | ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) - ((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))))) + ((((ctx.get_reg(dst) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0xaaaaaaaaaaaaaaaaULL))) & ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) - ((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src)))))) ^ ((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0xaaaaaaaaaaaaaaaaULL))) | ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) - ((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))))) + ((((ctx.get_reg(dst) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00000000ffffffffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xffffffff00000000ULL)) & 0xaaaaaaaaaaaaaaaaULL))) & ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src))) + (((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) - (ctx.get_reg(dst) + ctx.get_reg(src)))) - ((((ctx.get_reg(dst) & 0x5555555555555555ULL) | (ctx.get_reg(src) & 0x5555555555555555ULL)) + ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) - (ctx.get_reg(dst) & ctx.get_reg(src)))))) & 0x000000007fffffffULL) * 0x6424f8a2dd83ed6fULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x6424f8a2dd83ed6fULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) | ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RR_A1_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001fULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) | ctx.get_reg(src))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) ^ ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RI_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000008ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) & static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) + static_cast<uint64_t>(imm)) - (ctx.get_reg(dst) | static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RR_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000012ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((((((ctx.get_reg(dst) & 0x5555555555555555ULL) + ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x5555555555555555ULL))) + ((ctx.get_reg(src) ^ 0x5555555555555555ULL) - ((ctx.get_reg(src) | 0x5555555555555555ULL) - (ctx.get_reg(src) & 0x5555555555555555ULL))))) - ((ctx.get_reg(dst) & 0x5555555555555555ULL) & ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x5555555555555555ULL))) + ((ctx.get_reg(src) ^ 0x5555555555555555ULL) - ((ctx.get_reg(src) | 0x5555555555555555ULL) - (ctx.get_reg(src) & 0x5555555555555555ULL)))))) ^ ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) + (0x0000000000000002ULL * (((ctx.get_reg(dst) & 0x5555555555555555ULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x5555555555555555ULL))) + ((ctx.get_reg(src) ^ 0x5555555555555555ULL) - ((ctx.get_reg(src) | 0x5555555555555555ULL) - (ctx.get_reg(src) & 0x5555555555555555ULL))))) & ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))) + (((((ctx.get_reg(dst) & 0x5555555555555555ULL) | ((ctx.get_reg(src) - (ctx.get_reg(src) & (~0x5555555555555555ULL))) + ((ctx.get_reg(src) ^ 0x5555555555555555ULL) - ((ctx.get_reg(src) | 0x5555555555555555ULL) - (ctx.get_reg(src) & 0x5555555555555555ULL))))) ^ ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))) + (0x0000000000000002ULL * ((((ctx.get_reg(dst) & 0x5555555555555555ULL) + (ctx.get_reg(src) & 0x5555555555555555ULL)) - ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL))) & ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) | (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))) - (ctx.get_reg(dst) | ctx.get_reg(src)))) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RR_A1_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000007ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RI_D2: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000014ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) | static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) + (ctx.get_reg(dst) & static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ROL_RI_D2: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        uint64_t _res = ((val << shift) | (val >> ((64 - shift) & 63)));
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROR_RI_D2: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        uint64_t _res = ((val >> shift) | (val << ((64 - shift) & 63)));
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHL_RI_D2: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, (v << s));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHR_RI_D2: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, (v >> s));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SAR_RI_D2: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, static_cast<uint64_t>((static_cast<int64_t>(val) >> shift)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROL_RR_D2: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        uint64_t _res = ((val << shift) | (val >> ((64 - shift) & 63)));
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROR_RR_D2: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, ((v >> s) | (v << ((64 - s) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHL_RR_D2: {
        uint64_t _res = (ctx.get_reg(dst) << static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL)));
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHR_RR_D2: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, (val >> shift));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SAR_RR_D2: {
        int64_t sval = static_cast<int64_t>(ctx.get_reg(dst));
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, static_cast<uint64_t>((sval >> shift)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_DIV_RR_D2: {
        uint64_t _divisor = ctx.get_reg(src);
        if (_divisor == 0x0000000000000000ULL) {
                                            ctx.trapped = true;
                                            goto EXIT_VM;
}
        uint64_t _dividend = ctx.get_reg(dst);
        ctx.set_reg(dst, (_dividend / _divisor));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IDIV_RR_D2: {
        int64_t _d = static_cast<int64_t>(ctx.get_reg(dst));
        int64_t _s = static_cast<int64_t>(ctx.get_reg(src));
        if ((_s == 0) || ((_s == -1) && (_d == INT64_MIN))) {
                                                         ctx.trapped = true;
                                                         goto EXIT_VM;
}
        int64_t _quot = ((_s == -1) ? (-_d) : (_d / _s));
        ctx.set_reg(dst, static_cast<uint64_t>(_quot));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_MULH_RR_D2: {
        
#if defined(__SIZEOF_INT128__)
uint64_t res = static_cast<uint64_t>(((((unsigned __int128)(ctx.get_reg(dst))) * ((unsigned __int128)(ctx.get_reg(src)))) >> 64));
ctx.set_reg(dst, res);
#else
uint64_t a = ctx.get_reg(dst);
uint64_t b = ctx.get_reg(src);
uint64_t a_lo = static_cast<uint32_t>(a);
uint64_t a_hi = (a >> 32);
uint64_t b_lo = static_cast<uint32_t>(b);
uint64_t b_hi = (b >> 32);
uint64_t cy = (((((a_lo * b_lo) >> 32) + static_cast<uint32_t>((a_lo * b_hi))) + static_cast<uint32_t>((a_hi * b_lo))) >> 32);
uint64_t res = ((((a_hi * b_hi) + ((a_lo * b_hi) >> 32)) + ((a_hi * b_lo) >> 32)) + cy);
ctx.set_reg(dst, res);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IMULH_RR_D2: {
        int64_t a = static_cast<int64_t>(ctx.get_reg(dst));
        int64_t b = static_cast<int64_t>(ctx.get_reg(src));
        
#if defined(__SIZEOF_INT128__)
signed __int128 _prod = (((signed __int128)(a)) * ((signed __int128)(b)));
uint64_t res = static_cast<uint64_t>((_prod >> 64));
ctx.set_reg(dst, res);
#else
uint64_t ua = static_cast<uint64_t>(a);
uint64_t ub = static_cast<uint64_t>(b);
uint64_t a_lo = static_cast<uint32_t>(ua);
uint64_t a_hi = (ua >> 32);
uint64_t b_lo = static_cast<uint32_t>(ub);
uint64_t b_hi = (ub >> 32);
uint64_t p0 = (a_lo * b_lo);
uint64_t p1 = (a_lo * b_hi);
uint64_t p2 = (a_hi * b_lo);
uint64_t p3 = (a_hi * b_hi);
uint64_t cy = ((((p0 >> 32) + static_cast<uint32_t>(p1)) + static_cast<uint32_t>(p2)) >> 32);
uint64_t res = (((p3 + (p1 >> 32)) + (p2 >> 32)) + cy);
if (a < 0) {
                res -= ub;
}
if (b < 0) {
                res -= ua;
}
ctx.set_reg(dst, res);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_D2: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        uint64_t _imm = static_cast<uint64_t>(imm);
        compute_sub_flags(ctx, ctx.get_reg(dst), _imm, bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RR_D2: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        compute_sub_flags(ctx, ctx.get_reg(dst), ctx.get_reg(src), bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_A1_D2: {
        PROBE_START();
        uint64_t _d = ctx.get_reg(dst);
        compute_sub_flags(ctx, _d, static_cast<uint64_t>(imm), static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_A2_D2: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        uint64_t _imm = static_cast<uint64_t>(imm);
        compute_sub_flags(ctx, ctx.get_reg(dst), _imm, bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RR_A1_D2: {
        PROBE_START();
        uint64_t _a = ctx.get_reg(dst);
        uint64_t _b = ctx.get_reg(src);
        compute_sub_flags(ctx, _a, _b, static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_PUSH_R_D2: {
        uint64_t val = ctx.get_reg(dst);
        ctx.push(val);
        uint64_t cur_sp = ctx.get_reg(REG_RSP);
        if ((cur_sp >= 0x0000000000010008ULL) && (cur_sp <= 0x00007fffffffffffULL)) {

    uint64_t* sp_ptr = reinterpret_cast<uint64_t*>((cur_sp - 0x0000000000000008ULL));
    ctx.set_reg(REG_RSP, reinterpret_cast<uint64_t>(sp_ptr));
    (*sp_ptr) = val;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_POP_R_D2: {
        uint64_t cur_sp = ctx.get_reg(REG_RSP);
        uint64_t val = 0x0000000000000000ULL;
        if ((cur_sp >= 0x0000000000010000ULL) && (cur_sp <= 0x00007fffffffffffULL)) {

    std::memcpy((&val), reinterpret_cast<const void*>(cur_sp), sizeof(uint64_t));
    ctx.set_reg(REG_RSP, (cur_sp + 0x0000000000000008ULL));
    ctx.pop();} else {
                          val = ctx.pop();
}
        ctx.set_reg(dst, val);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADC_RR_D2: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint64_t c = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a + b) + c);
        ctx.cf = ((res < a) || ((c != 0x0000000000000000ULL) && (res == a)));
        ctx.of = ((((a ^ res) & (b ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADC_RI_D2: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint64_t c = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t ab = (a + b);
        uint64_t res = (ab + c);
        ctx.cf = ((ab < a) || (res < ab));
        ctx.of = ((((a ^ res) & (b ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SBB_RR_D2: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint64_t borrow = static_cast<uint64_t>(ctx.cf);
        uint64_t res = ((a - b) - borrow);
        ctx.cf = ((a < b) || ((borrow != 0x0000000000000000ULL) && (a == b)));
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = ((res >> 63) != 0x0000000000000000ULL);
        ctx.of = ((((a ^ b) & (a ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SBB_RI_D2: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint64_t borrow = static_cast<uint64_t>(ctx.cf);
        uint64_t res = ((a - b) - borrow);
        ctx.cf = ((a < b) || ((borrow != 0x0000000000000000ULL) && (a == b)));
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = ((res >> 63) != 0x0000000000000000ULL);
        ctx.of = ((((a ^ b) & (a ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMP_RR_D2: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (!eval_condition(ctx, cond)) {
                                     ctx.sf = ((nzcv & 8) != 0);
                                     ctx.zf = ((nzcv & 4) != 0);
                                     ctx.cf = ((nzcv & 2) != 0);
                                     ctx.of = ((nzcv & 1) != 0);
} else {
            uint64_t a = ctx.get_reg(dst);
            uint64_t b = ctx.get_reg(src);
            compute_sub_flags(ctx, a, b, bits);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMP_RI_D2: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint64_t b = static_cast<uint64_t>((((word >> 26) + 0x000000000000001fULL) - ((word >> 26) | 0x000000000000001fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (eval_condition(ctx, cond)) {
                                    uint64_t a = ctx.get_reg(dst);
                                    compute_sub_flags(ctx, a, b, bits);
} else {
            ctx.sf = ((nzcv & 8) != 0);
            ctx.zf = ((nzcv & 4) != 0);
            ctx.cf = ((nzcv & 2) != 0);
            ctx.of = ((nzcv & 1) != 0);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMN_RR_D2: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (!eval_condition(ctx, cond)) {
                                     ctx.sf = ((nzcv & 8) != 0);
                                     ctx.zf = ((nzcv & 4) != 0);
                                     ctx.cf = ((nzcv & 2) != 0);
                                     ctx.of = ((nzcv & 1) != 0);
} else {
            uint64_t a = ctx.get_reg(dst);
            uint64_t b = ctx.get_reg(src);
            compute_add_flags(ctx, a, b, bits);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMN_RI_D2: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint64_t b = static_cast<uint64_t>((((word >> 26) + 0x000000000000001fULL) - ((word >> 26) | 0x000000000000001fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (eval_condition(ctx, cond)) {
                                    uint64_t a = ctx.get_reg(dst);
                                    compute_add_flags(ctx, a, b, bits);
} else {
            ctx.sf = ((nzcv & 8) != 0);
            ctx.zf = ((nzcv & 4) != 0);
            ctx.cf = ((nzcv & 2) != 0);
            ctx.of = ((nzcv & 1) != 0);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_GET_FLAGS_R_D2: {
        uint64_t f = 0x0000000000000002ULL;
        if (ctx.cf) {
                 f |= 0x0000000000000001ULL;
}
        if (ctx.zf) {
                 f |= 0x0000000000000040ULL;
}
        if (ctx.sf) {
                 f |= 0x0000000000000080ULL;
}
        if (ctx.of) {
                 f |= 0x0000000000000800ULL;
}
        ctx.set_reg(dst, f);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SET_FLAGS_R_D2: {
        uint64_t f = ctx.get_reg(src);
        ctx.cf = ((f & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.zf = ((f & 0x0000000000000040ULL) != 0x0000000000000000ULL);
        ctx.sf = ((f & 0x0000000000000080ULL) != 0x0000000000000000ULL);
        ctx.of = ((f & 0x0000000000000800ULL) != 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_D2: {
        size_t _target = static_cast<size_t>(imm);
        vIP_idx = _target;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_A1_D2: {
        size_t _target = static_cast<size_t>(imm);
        vIP_idx = _target;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_A2_D2: {
        vIP_idx = static_cast<size_t>(((static_cast<uint64_t>(imm) ^ 0x0000000000005877ULL) ^ 0x0000000000005877ULL));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JCC_D2: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t base_vip = static_cast<uint64_t>(((word >> 0x0000000000000016ULL) & 0x00000000001fffffULL));
        uint64_t enc_delta = static_cast<uint64_t>(((word >> 0x000000000000002bULL) & 0x00000000001fffffULL));
        uint64_t salt = (((static_cast<uint64_t>(cond) * 0x0000000000005877ULL) ^ 0x000000001337beefULL) & 0x00000000001fffffULL);
        uint64_t delta = (enc_delta ^ salt);
        uint64_t t_true = (base_vip ^ delta);
        uint64_t t_false = base_vip;
        uint64_t c = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        vIP_idx = static_cast<size_t>(asgard::branchless_vip::select_vip(c, t_true, t_false));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JCC_A1_D2: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t base_vip = static_cast<uint64_t>(((word >> 0x0000000000000016ULL) & 0x00000000001fffffULL));
        uint64_t enc_delta = static_cast<uint64_t>(((word >> 0x000000000000002bULL) & 0x00000000001fffffULL));
        uint64_t salt = (((static_cast<uint64_t>(cond) * 0x0000000000005877ULL) ^ 0x000000001337beefULL) & 0x00000000001fffffULL);
        uint64_t delta = (enc_delta ^ salt);
        uint64_t t_true = (base_vip ^ delta);
        uint64_t t_false = base_vip;
        uint64_t c = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        vIP_idx = static_cast<size_t>(asgard::branchless_vip::select_vip(c, t_true, t_false));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMOV_D2: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t _s = ctx.get_reg(src);
        uint64_t _d = ctx.get_reg(dst);
        ctx.set_reg(dst, (eval_condition(ctx, cond) ? _s : _d));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SETCC_D2: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t val = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        ctx.set_reg(dst, val);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CALL_D2: {
        ctx.push(static_cast<uint64_t>(vIP_idx));
        uint64_t _imm_target = static_cast<uint64_t>(imm);
        vIP_idx = static_cast<size_t>(_imm_target);
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IJMP_R_D2: {
        uint64_t target = ctx.get_reg(dst);
        size_t _t_idx = static_cast<size_t>(target);
        if (_t_idx < count) {
                         vIP_idx = _t_idx;
} else {
            if (target != 0x0000000000000000ULL) {
                                                      #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                                      uint64_t a1 = ctx.get_reg(REG_RCX);
                                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                                      uint64_t a3 = ctx.get_reg(REG_RBX);
                                                      uint64_t a4 = ctx.get_reg(REG_RSI);
                                                      uint64_t a5 = ctx.get_reg(REG_RDI);
                                                      #elif defined(ASGARD_GUEST_RISCV64)
                                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                                      uint64_t a1 = ctx.get_reg(REG_RDX);
                                                      uint64_t a2 = ctx.get_reg(REG_RCX);
                                                      uint64_t a3 = ctx.get_reg(REG_RSI);
                                                      uint64_t a4 = ctx.get_reg(REG_RDI);
                                                      uint64_t a5 = ctx.get_reg(REG_R8);
                                                      #else
                                                      uint64_t a0 = ctx.get_reg(REG_RDI);
                                                      uint64_t a1 = ctx.get_reg(REG_RSI);
                                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                                      uint64_t a3 = ctx.get_reg(REG_RCX);
                                                      uint64_t a4 = ctx.get_reg(REG_R8);
                                                      uint64_t a5 = ctx.get_reg(REG_R9);
                                                      #endif
                                                      typedef uint64_t (*indirect_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                      indirect_fn_t fn = reinterpret_cast<indirect_fn_t>(target);
                                                      uint64_t ret_val = fn(a0, a1, a2, a3, a4, a5);
                                                      ctx.set_reg(REG_RAX, ret_val);
                                                      goto EXIT_VM;
            }
}
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ICALL_R_D2: {
        uint64_t target_ptr = ctx.get_reg(dst);
        if (target_ptr < count) {
                             ctx.push(static_cast<uint64_t>(vIP_idx));
                             vIP_idx = static_cast<size_t>(target_ptr);
} else {
            if (target_ptr != 0x0000000000000000ULL) {
                                                          #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                                                          uint64_t a0 = ctx.get_reg(REG_RAX);
                                                          uint64_t a1 = ctx.get_reg(REG_RCX);
                                                          uint64_t a2 = ctx.get_reg(REG_RDX);
                                                          uint64_t a3 = ctx.get_reg(REG_RBX);
                                                          uint64_t a4 = ctx.get_reg(REG_RSI);
                                                          uint64_t a5 = ctx.get_reg(REG_RDI);
                                                          #elif defined(ASGARD_GUEST_RISCV64)
                                                          uint64_t a0 = ctx.get_reg(REG_RAX);
                                                          uint64_t a1 = ctx.get_reg(REG_RDX);
                                                          uint64_t a2 = ctx.get_reg(REG_RCX);
                                                          uint64_t a3 = ctx.get_reg(REG_RSI);
                                                          uint64_t a4 = ctx.get_reg(REG_RDI);
                                                          uint64_t a5 = ctx.get_reg(REG_R8);
                                                          #else
                                                          uint64_t a0 = ctx.get_reg(REG_RDI);
                                                          uint64_t a1 = ctx.get_reg(REG_RSI);
                                                          uint64_t a2 = ctx.get_reg(REG_RDX);
                                                          uint64_t a3 = ctx.get_reg(REG_RCX);
                                                          uint64_t a4 = ctx.get_reg(REG_R8);
                                                          uint64_t a5 = ctx.get_reg(REG_R9);
                                                          #endif
                                                          typedef uint64_t (*indirect_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                          indirect_fn_t fn = reinterpret_cast<indirect_fn_t>(target_ptr);
                                                          uint64_t ret_val = fn(a0, a1, a2, a3, a4, a5);
                                                          ctx.set_reg(REG_RAX, ret_val);
            }
}
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RET_D2: { if (ctx.sp > 512) {
                       ctx.trapped = true;
} ctx.executed_instructions += 1; goto EXIT_VM; }
    H_EXIT_D2: { if (ctx.sp > 512) {
                       ctx.trapped = true;
} ctx.executed_instructions += 1; goto EXIT_VM; }

    H_BRIDGE_TO_FLOW_D2: {
        ctx.morph_math_to_flow(static_cast<uint64_t>((imm & 0xffffffffffffffffULL)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_BRIDGE_TO_MATH_D2: {
        ctx.morph_flow_to_math(static_cast<uint64_t>(imm));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FUSED_MOV_ADD_RRI_D2: {
        uint64_t _s = ctx.get_reg(src);
        uint64_t _i = static_cast<uint64_t>(imm);
        ctx.set_reg(dst, ((_s ^ _i) + (0x0000000000000002ULL * (_s & _i))));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_ADD_IMUL_RRI_D2: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) + ctx.get_reg(src)) * static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_ADD_XOR_RRI_D2: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) + ctx.get_reg(src)) ^ static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_SUB_XOR_RRI_D2: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) - ctx.get_reg(src)) ^ static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_XOR_ADD_RRI_D2: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_CMP_CMOV_D2: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint8_t cond = static_cast<uint8_t>(((word >> 0x0000000000000032ULL) & 0x000000000000000fULL));
        uint32_t bits = static_cast<uint32_t>(((word >> 0x0000000000000036ULL) & 0x000000000000007fULL));
        compute_sub_flags(ctx, a, b, bits);
        uint64_t _m = (eval_condition(ctx, cond) ? (~0x0000000000000000ULL) : 0x0000000000000000ULL);
        ctx.set_reg(dst, ((ctx.get_reg(src) & _m) | (a & (~_m))));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_AND_OR_RRI_D2: {
        uint64_t _and = (ctx.get_reg(dst) & ctx.get_reg(src));
        ctx.set_reg(dst, (_and | static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_SHL_ADD_RRI_D2: {
        uint64_t _shl = (ctx.get_reg(dst) << (static_cast<uint64_t>(imm) & 0x000000000000003fULL));
        uint64_t _s = ctx.get_reg(src);
        ctx.set_reg(dst, ((_shl ^ _s) + (0x0000000000000002ULL * (_shl & _s))));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_VADD_VV_D2: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vd = vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
uint64x2_t vs = vcombine_u64(vcreate_u64(s0), vcreate_u64(s1));
uint64x2_t vr = vaddq_u64(vd, vs);
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vd = _mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0));
__m128i vs = _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0));
__m128i vr = _mm_add_epi64(vd, vs);
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
ctx.set_vreg(dst, (d0 + s0), (d1 + s1));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VSUB_VV_D2: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vd = vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
uint64x2_t vs = vcombine_u64(vcreate_u64(s0), vcreate_u64(s1));
uint64x2_t vr = vsubq_u64(vd, vs);
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vd = _mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0));
__m128i vs = _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0));
__m128i vr = _mm_sub_epi64(vd, vs);
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
ctx.set_vreg(dst, (d0 - s0), (d1 - s1));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VMUL_VV_D2: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        uint64_t _m0 = (d0 * s0);
        uint64_t _m1 = (d1 * s1);
        ctx.set_vreg(dst, _m0, _m1);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VXOR_VV_D2: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vd = vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
uint64x2_t vs = vcombine_u64(vcreate_u64(s0), vcreate_u64(s1));
uint64x2_t vr = veorq_u64(vd, vs);
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vd = _mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0));
__m128i vs = _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0));
__m128i vr = _mm_xor_si128(vd, vs);
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
ctx.set_vreg(dst, (d0 ^ s0), (d1 ^ s1));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_MOV_D2: {
        size_t _words = static_cast<size_t>(((static_cast<uint32_t>((imm & 0x00000000000003ffULL)) + 63) / 64));
        for (size_t i = 0; i < _words; ++i) {
                                         uint64_t _v = ctx.get_vreg_lane(src, i);
                                         ctx.set_vreg_lane(dst, i, _v);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_BINOP_D2: {
        uint32_t src2 = static_cast<uint32_t>((imm & 0x000000000000001fULL));
        uint32_t bits = static_cast<uint32_t>(((imm >> 5) & 0x00000000000003ffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 15) & 0x00000000000000ffULL));
        if (lane_bits == 0) {
                         lane_bits = 64;
}
        uint32_t vop = static_cast<uint32_t>(((imm >> 23) & 0x000000000000001fULL));
        uint32_t elem = static_cast<uint32_t>(((imm >> 28) & 0x0000000000000003ULL));
        uint64_t mask = ((lane_bits == 8) ? 0x00000000000000ffULL : ((lane_bits == 16) ? 0x000000000000ffffULL : ((lane_bits == 32) ? 0x00000000ffffffffULL : 0xffffffffffffffffULL)));
        size_t bit = 0;
        while (bit < bits) {
                        size_t chunk = (bit / 64);
                        uint32_t shift = static_cast<uint32_t>((bit % 64));
                        uint64_t a = ((ctx.get_vreg_lane(src, chunk) >> shift) & mask);
                        uint64_t b = ((ctx.get_vreg_lane(src2, chunk) >> shift) & mask);
                        uint64_t value = 0x0000000000000000ULL;
                        if ((elem == 1) && (vop <= 2)) {
                                                            float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                                            float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                                            float fr = ((vop == 0) ? (fa + fb) : ((vop == 1) ? (fa - fb) : (fa * fb)));
                                                            value = std::bit_cast<uint32_t>(fr);
                        } else {
                                    if ((elem == 1) && (vop == 11)) {
                                    
                                        float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                        float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                        value = std::bit_cast<uint32_t>(std::fmin(fa, fb));
                                    } else {
                                                if ((elem == 1) && (vop == 12)) {
                                                
                                                    float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                                    float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                                    value = std::bit_cast<uint32_t>(std::fmax(fa, fb));
                                                } else {
                                                            if ((elem == 2) && (vop <= 2)) {
                                                            
                                                                double fa = std::bit_cast<double>(a);
                                                                double fb = std::bit_cast<double>(b);
                                                                double fr = ((vop == 0) ? (fa + fb) : ((vop == 1) ? (fa - fb) : (fa * fb)));
                                                                value = std::bit_cast<uint64_t>(fr);
                                                            } else {
                                                                    if ((elem == 2) && (vop == 11)) {
                                                                    
                                                                    double fa = std::bit_cast<double>(a);
                                                                    double fb = std::bit_cast<double>(b);
                                                                    value = std::bit_cast<uint64_t>(std::fmin(fa, fb));
                                                                    } else {
                                                                    
                                                                    if ((elem == 2) && (vop == 12)) {
                                                                    
                                                                    double fa = std::bit_cast<double>(a);
                                                                    double fb = std::bit_cast<double>(b);
                                                                    value = std::bit_cast<uint64_t>(std::fmax(fa, fb));
                                                                    } else {
                                                                    
                                                                    int64_t sa = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(a))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(a))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(a))) : static_cast<int64_t>(a))));
                                                                    int64_t sb = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(b))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(b))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(b))) : static_cast<int64_t>(b))));
                                                                    switch (vop) {
                                                                    
                                                                    case 0: {
                                                                    
                                                                    value = (a + b);
                                                                    break;
                                                                    }
                                                                    case 1: {
                                                                    
                                                                    value = (a - b);
                                                                    break;
                                                                    }
                                                                    case 2: {
                                                                    
                                                                    value = (a * b);
                                                                    break;
                                                                    }
                                                                    case 3: {
                                                                    
                                                                    value = (a & b);
                                                                    break;
                                                                    }
                                                                    case 4: {
                                                                    
                                                                    value = (a | b);
                                                                    break;
                                                                    }
                                                                    case 5: {
                                                                    
                                                                    value = (a ^ b);
                                                                    break;
                                                                    }
                                                                    case 6: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a << cnt));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 7: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a >> cnt));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 8: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? ((sa < 0) ? mask : 0x0000000000000000ULL) : (static_cast<uint64_t>((sa >> cnt)) & mask));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 9: {
                                                                    
                                                                    value = ((a == b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 10: {
                                                                    
                                                                    value = ((sa > sb) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 11: {
                                                                    
                                                                    value = ((sa < sb) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 12: {
                                                                    
                                                                    value = ((sa > sb) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 13: {
                                                                    
                                                                    value = ((a < b) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 14: {
                                                                    
                                                                    value = ((a > b) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 15: {
                                                                    
                                                                    value = (static_cast<uint64_t>(((sa < 0) ? (-sa) : sa)) & mask);
                                                                    break;
                                                                    }
                                                                    case 16: {
                                                                    
                                                                    value = ((~a) & b);
                                                                    break;
                                                                    }
                                                                    case 17: {
                                                                    
                                                                    {
                                                                    size_t block_lane = ((bit / lane_bits) % (128 / lane_bits));
                                                                    size_t half_idx = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (half_idx * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 18: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_idx = ((num_lanes / 2) + (block_lane / 2));
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (half_idx * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 21: {
                                                                    
                                                                    {
                                                                    uint8_t ctrl = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if ((ctrl & 128) != 0) {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    } else {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + ((ctrl & 15) * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 23: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_len = (num_lanes / 2);
                                                                    size_t src_reg = ((block_lane < half_len) ? src : src2);
                                                                    size_t sel_elem = ((block_lane < half_len) ? (block_lane * 2) : ((block_lane - half_len) * 2));
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 24: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_len = (num_lanes / 2);
                                                                    size_t src_reg = ((block_lane < half_len) ? src : src2);
                                                                    size_t sel_elem = ((block_lane < half_len) ? ((block_lane * 2) + 1) : (((block_lane - half_len) * 2) + 1));
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 25: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t k = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t sel_elem = (k * 2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 26: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t k = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t sel_elem = ((k * 2) + 1);
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 28: {
                                                                    
                                                                    {
                                                                    uint8_t idx = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if (idx < 16) {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + (idx * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    } else {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 29: {
                                                                    
                                                                    {
                                                                    uint8_t idx = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if (idx < 16) {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + (idx * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    } else {
                                                                    
                                                                    value = ((ctx.get_vreg_lane(dst, chunk) >> shift) & 0x00000000000000ffULL);
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 30: {
                                                                    
                                                                    {
                                                                    int64_t min_val = ((lane_bits == 64) ? static_cast<int64_t>(0x8000000000000000ULL) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(0x0000000080000000ULL))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(32768))) : static_cast<int64_t>(((int8_t)(128))))));
                                                                    if (sb == 0) {
                                                                    
                                                                    value = 0xffffffffffffffffULL;
                                                                    } else {
                                                                    
                                                                    if ((sb == -1) && (sa == min_val)) {
                                                                    
                                                                    value = static_cast<uint64_t>(sa);
                                                                    } else {
                                                                    
                                                                    value = static_cast<uint64_t>((sa / sb));
                                                                    }
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 31: {
                                                                    
                                                                    value = ((b != 0) ? (a / b) : mask);
                                                                    break;
                                                                    }
                                                                    case 32: {
                                                                    
                                                                    {
                                                                    int64_t min_val = ((lane_bits == 64) ? static_cast<int64_t>(0x8000000000000000ULL) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(0x0000000080000000ULL))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(32768))) : static_cast<int64_t>(((int8_t)(128))))));
                                                                    if (sb == 0) {
                                                                    
                                                                    value = a;
                                                                    } else {
                                                                    
                                                                    if ((sb == -1) && (sa == min_val)) {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    } else {
                                                                    
                                                                    value = static_cast<uint64_t>((sa % sb));
                                                                    }
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 33: {
                                                                    
                                                                    value = ((b != 0) ? (a % b) : a);
                                                                    break;
                                                                    }
                                                                    case 34: {
                                                                    
                                                                    value = ((a != b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 35: {
                                                                    
                                                                    value = ((sa <= sb) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 36: {
                                                                    
                                                                    value = ((a < b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 37: {
                                                                    
                                                                    value = ((a <= b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    default: {
                                                                    
                                                                    value = (a ^ b);
                                                                    break;
                                                                    }
                                                                    }
                                                                    }
                                                                    }
                                                            }
                                                }
                                    }
                        }
                        uint64_t old_value = ctx.get_vreg_lane(dst, chunk);
                        uint64_t packed_mask = (mask << shift);
                        ctx.set_vreg_lane(dst, chunk, ((old_value & (~packed_mask)) | ((value & mask) << shift)));
                        bit += lane_bits;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_IMM_D2: {
        uint64_t imm_val = (imm & 0x00000000000000ffULL);
        uint32_t bits = static_cast<uint32_t>(((imm >> 8) & 0x00000000000003ffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 18) & 0x00000000000000ffULL));
        if (lane_bits == 0) {
                         lane_bits = 64;
}
        uint32_t vop = static_cast<uint32_t>(((imm >> 26) & 0x000000000000001fULL));
        uint64_t mask = ((lane_bits == 8) ? 0x00000000000000ffULL : ((lane_bits == 16) ? 0x000000000000ffffULL : ((lane_bits == 32) ? 0x00000000ffffffffULL : 0xffffffffffffffffULL)));
        size_t bit = 0;
        while (bit < bits) {
                        size_t chunk = (bit / 64);
                        uint32_t shift = static_cast<uint32_t>((bit % 64));
                        uint64_t a = ((ctx.get_vreg_lane(src, chunk) >> shift) & mask);
                        int64_t sa = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(a))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(a))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(a))) : static_cast<int64_t>(a))));
                        uint64_t value = 0x0000000000000000ULL;
                        switch (vop) {
                                        case 6: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a << cnt));
                                                          break;
                                                     }
                                        }
                                        case 7: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a >> cnt));
                                                          break;
                                                     }
                                        }
                                        case 8: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? ((sa < 0) ? mask : 0x0000000000000000ULL) : (static_cast<uint64_t>((sa >> cnt)) & mask));
                                                          break;
                                                     }
                                        }
                                        case 21: {
                                                      {
                                                           size_t lane_in_128 = ((bit / 32) % 4);
                                                           size_t sel = ((imm_val >> (lane_in_128 * 2)) & 0x0000000000000003ULL);
                                                           size_t src_bit = (((bit / 128) * 128) + (sel * 32));
                                                           value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000ffffffffULL);
                                                           break;
                                                      }
                                        }
                                        case 22: {
                                                      {
                                                           size_t lane_idx = (bit / lane_bits);
                                                           size_t sel = ((imm_val >> (lane_idx % 8)) & 0x0000000000000001ULL);
                                                           value = ((sel == 0) ? a : ((ctx.get_vreg_lane(dst, chunk) >> shift) & mask));
                                                           break;
                                                      }
                                        }
                                        default: {
                                                      value = a;
                                                      break;
                                        }
                        }
                        uint64_t old_value = ctx.get_vreg_lane(dst, chunk);
                        uint64_t packed_mask = (mask << shift);
                        ctx.set_vreg_lane(dst, chunk, ((old_value & (~packed_mask)) | ((value & mask) << shift)));
                        bit += lane_bits;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_CLEAR_UPPER_D2: {
        ctx.set_vreg_lane(dst, 2, 0x0000000000000000ULL);
        ctx.set_vreg_lane(dst, 3, 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_ZERO_UPPER_D2: {
        for (size_t i = 0; i < 16; ++i) {
                                     ctx.set_vreg_lane(i, 2, 0x0000000000000000ULL);
                                     ctx.set_vreg_lane(i, 3, 0x0000000000000000ULL);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_PMOVMSKB_D2: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x00000000000003ffULL));
        uint32_t num_bytes = (bits / 8);
        uint64_t mask = 0x0000000000000000ULL;
        for (size_t b_idx = 0; b_idx < num_bytes; ++b_idx) {
                                                        uint64_t byte_val = ((ctx.get_vreg_lane(src, (b_idx / 8)) >> ((b_idx % 8) * 8)) & 0x00000000000000ffULL);
                                                        if ((byte_val & 0x0000000000000080ULL) != 0x0000000000000000ULL) {
                                                        
                                                            mask |= (0x0000000000000001ULL << b_idx);
                                                        }
}
        ctx.set_reg(dst, mask);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_LOAD_D2: {
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x00000000000003ffULL));
        uint64_t address = (ctx.get_reg(src) + static_cast<uint64_t>(imm));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     uint64_t value = 0x0000000000000000ULL;
                                                     std::memcpy((&value), reinterpret_cast<const void*>((address + (i * 8))), sizeof(value));
                                                     ctx.set_vreg_lane(dst, i, value);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_STORE_D2: {
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x00000000000003ffULL));
        uint64_t address = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     std::memcpy(reinterpret_cast<void*>((address + (i * 8))), (&ctx.vregs[(src & 31)][(i & 7)]), sizeof(uint64_t));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_SPLAT_D2: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x000000000000ffffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 16) & 0x000000000000ffffULL));
        uint64_t val = ctx.get_reg(src);
        uint64_t mask = ((lane_bits >= 64) ? 0xffffffffffffffffULL : ((0x0000000000000001ULL << lane_bits) - 0x0000000000000001ULL));
        uint64_t val_masked = (val & mask);
        uint32_t num_lanes = ((lane_bits > 0) ? (bits / lane_bits) : 0);
        for (size_t l = 0; l < num_lanes; ++l) {
                                            uint32_t pos = (l * lane_bits);
                                            uint32_t chunk = (pos / 64);
                                            uint32_t shift = (pos % 64);
                                            uint64_t packed_mask = ((lane_bits >= 64) ? 0xffffffffffffffffULL : (mask << shift));
                                            uint64_t cur = ctx.get_vreg_lane(dst, chunk);
                                            cur = ((cur & (~packed_mask)) | (val_masked << shift));
                                            ctx.set_vreg_lane(dst, chunk, cur);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_EXT_D2: {
        uint32_t src2 = static_cast<uint32_t>((imm & 0x000000000000001fULL));
        uint32_t shift_bytes = static_cast<uint32_t>(((imm >> 5) & 0x000000000000000fULL));
        uint32_t bits = static_cast<uint32_t>(((imm >> 9) & 0x00000000000003ffULL));
        if (bits == 0) {
                    bits = 128;
}
        for (size_t byte_idx = 0; byte_idx < (bits / 8); ++byte_idx) {
                                                                  size_t total_idx = ((byte_idx % 16) + shift_bytes);
                                                                  uint64_t val = 0x0000000000000000ULL;
                                                                  if (total_idx < 16) {
                                                                  
                                                                    size_t bit_pos = (((byte_idx / 16) * 128) + (total_idx * 8));
                                                                    val = ((ctx.get_vreg_lane(src, (bit_pos / 64)) >> (bit_pos % 64)) & 0x00000000000000ffULL);
                                                                  } else {
                                                                  
                                                                    size_t m_idx = (total_idx - 16);
                                                                    size_t bit_pos = (((byte_idx / 16) * 128) + (m_idx * 8));
                                                                    val = ((ctx.get_vreg_lane(src2, (bit_pos / 64)) >> (bit_pos % 64)) & 0x00000000000000ffULL);
                                                                  }
                                                                  size_t chunk = ((byte_idx * 8) / 64);
                                                                  uint32_t shift = static_cast<uint32_t>(((byte_idx * 8) % 64));
                                                                  uint64_t old_v = ctx.get_vreg_lane(dst, chunk);
                                                                  uint64_t clr = (old_v & (~((0x00000000000000ffULL << shift))));
                                                                  ctx.set_vreg_lane(dst, chunk, (clr | (val << shift)));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CALL_EXTERN_D2: {
        size_t sym_idx = ((size_t)(imm));
        void* sym_ptr = asgard_resolve_sym_idx(((int32_t)(sym_idx)));
        if (sym_ptr) {
                  uint32_t sym_h = g_external_symbols[sym_idx].hash;
                  uint32_t sym_ah = g_external_symbols[sym_idx].alt_hash;
                  
                  #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                  uint64_t a0 = ctx.get_reg(REG_RAX);
                  uint64_t a1 = ctx.get_reg(REG_RCX);
                  uint64_t a2 = ctx.get_reg(REG_RDX);
                  uint64_t a3 = ctx.get_reg(REG_RBX);
                  uint64_t a4 = ctx.get_reg(REG_RSI);
                  uint64_t a5 = ctx.get_reg(REG_RDI);
                  uint64_t a6 = ctx.get_reg(REG_R8);
                  uint64_t a7 = ctx.get_reg(REG_R9);
                  #elif defined(ASGARD_GUEST_RISCV64)
                  uint64_t a0 = ctx.get_reg(REG_RAX);
                  uint64_t a1 = ctx.get_reg(REG_RDX);
                  uint64_t a2 = ctx.get_reg(REG_RCX);
                  uint64_t a3 = ctx.get_reg(REG_RSI);
                  uint64_t a4 = ctx.get_reg(REG_RDI);
                  uint64_t a5 = ctx.get_reg(REG_R8);
                  uint64_t a6 = ctx.get_reg(REG_R9);
                  uint64_t a7 = ctx.get_reg(REG_R12);
                  #else
                  uint64_t a0 = (ctx.get_reg(REG_RDI) ? ctx.get_reg(REG_RDI) : ctx.get_reg(REG_RAX));
                  uint64_t a1 = ctx.get_reg(REG_RSI);
                  uint64_t a2 = ctx.get_reg(REG_RDX);
                  uint64_t a3 = ctx.get_reg(REG_RCX);
                  uint64_t a4 = ctx.get_reg(REG_R8);
                  uint64_t a5 = ctx.get_reg(REG_R9);
                  uint64_t a6 = ctx.get_reg(REG_RAX);
                  uint64_t a7 = ctx.get_reg(REG_RBX);
                  #endif
                  
                  const uint64_t* stk = reinterpret_cast<const uint64_t*>(ctx.get_reg(REG_RSP));
                  uint64_t ret_val = 0x0000000000000000ULL;
                  if ((((((sym_h == 0x42fcf5cfU) || (sym_ah == 0x42fcf5cfU)) || (sym_h == 0x07554acdU)) || (sym_ah == 0x07554acdU)) || (sym_h == 0xe76fb4aaU)) || (sym_ah == 0xe76fb4aaU)) {
                  
                      typedef int (*printf_fn_t)(const char*, ...);
                      printf_fn_t pfn = reinterpret_cast<printf_fn_t>(sym_ptr);
                      
                      #if defined(__APPLE__) && defined(__aarch64__)
                      ret_val = ((uint64_t)(pfn(((const char*)(a0)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                      #else
                      ret_val = ((uint64_t)(pfn(((const char*)(a0)), a1, a2, a3, a4, a5, a6, a7)));
                      #endif
                      
                  } else {
                              if ((((((((((((((((sym_h == 0xfcb512e2U) || (sym_ah == 0xfcb512e2U)) || (sym_h == 0x4b3c5330U)) || (sym_ah == 0x4b3c5330U)) || (sym_h == 0x937d1ef6U)) || (sym_ah == 0x937d1ef6U)) || (sym_h == 0xcb76d42bU)) || (sym_ah == 0xcb76d42bU)) || (sym_h == 0xd54ce817U)) || (sym_ah == 0xd54ce817U)) || (sym_h == 0xbbed3905U)) || (sym_ah == 0xbbed3905U)) || (sym_h == 0x42c07c7cU)) || (sym_ah == 0x42c07c7cU)) || (sym_h == 0x24559dbdU)) || (sym_ah == 0x24559dbdU)) {
                              
                                  typedef int (*fprintf_fn_t)(void*, const char*, ...);
                                  fprintf_fn_t fpfn = reinterpret_cast<fprintf_fn_t>(sym_ptr);
                                  
                                  #if defined(__APPLE__) && defined(__aarch64__)
                                  ret_val = ((uint64_t)(fpfn(((void*)(a0)), ((const char*)(a1)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                  #else
                                  ret_val = ((uint64_t)(fpfn(((void*)(a0)), ((const char*)(a1)), a2, a3, a4, a5, a6, a7)));
                                  #endif
                                  
                              } else {
                                          if ((((((((sym_h == 0x7fe32b00U) || (sym_ah == 0x7fe32b00U)) || (sym_h == 0xbcbf60eeU)) || (sym_ah == 0xbcbf60eeU)) || (sym_h == 0x70e2d349U)) || (sym_ah == 0x70e2d349U)) || (sym_h == 0x44fa3468U)) || (sym_ah == 0x44fa3468U)) {
                                          
                                              typedef int (*sprintf_fn_t)(char*, const char*, ...);
                                              sprintf_fn_t spfn = reinterpret_cast<sprintf_fn_t>(sym_ptr);
                                              
                                              #if defined(__APPLE__) && defined(__aarch64__)
                                              ret_val = ((uint64_t)(spfn(((char*)(a0)), ((const char*)(a1)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                              #else
                                              ret_val = ((uint64_t)(spfn(((char*)(a0)), ((const char*)(a1)), a2, a3, a4, a5, a6, a7)));
                                              #endif
                                              
                                          } else {
                                                      if ((((((((sym_h == 0x54ee11faU) || (sym_ah == 0x54ee11faU)) || (sym_h == 0x933075f4U)) || (sym_ah == 0x933075f4U)) || (sym_h == 0x3fd5eb6fU)) || (sym_ah == 0x3fd5eb6fU)) || (sym_h == 0x5b3553b4U)) || (sym_ah == 0x5b3553b4U)) {
                                                      
                                                          typedef int (*snprintf_fn_t)(char*, size_t, const char*, ...);
                                                          snprintf_fn_t snpfn = reinterpret_cast<snprintf_fn_t>(sym_ptr);
                                                          
                                                          #if defined(__APPLE__) && defined(__aarch64__)
                                                          ret_val = ((uint64_t)(snpfn(((char*)(a0)), ((size_t)(a1)), ((const char*)(a2)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                                          #else
                                                          ret_val = ((uint64_t)(snpfn(((char*)(a0)), ((size_t)(a1)), ((const char*)(a2)), a3, a4, a5, a6, a7)));
                                                          #endif
                                                          
                                                      } else {
                                                                  typedef uint64_t (*extern_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                                  extern_fn_t fn = reinterpret_cast<extern_fn_t>(sym_ptr);
                                                                  ret_val = fn(a0, a1, a2, a3, a4, a5, a6, a7);
                                                      }
                                          }
                              }
                  }
                  ctx.set_reg(REG_RAX, ret_val);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_64_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint64_t _val = asgard::oblivious_mem::oblivious_load_u64(_addr);
ctx.set_reg(dst, _val);
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, (*(reinterpret_cast<const uint64_t*>(addr))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_32_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint32_t _v32 = asgard::oblivious_mem::oblivious_load_u32(_addr);
ctx.set_reg(dst, ((uint64_t)(_v32)));
#else
const char* _base = reinterpret_cast<const char*>(ctx.get_reg(src));
ctx.set_reg(dst, ((uint64_t)((*(reinterpret_cast<const uint32_t*>((_base + imm)))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_16_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint16_t _v16 = asgard::oblivious_mem::oblivious_load_u16(_addr);
ctx.set_reg(dst, ((uint64_t)(_v16)));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)((*(reinterpret_cast<const uint16_t*>(addr))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_8_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint8_t _v8 = asgard::oblivious_mem::oblivious_load_u8(_addr);
ctx.set_reg(dst, ((uint64_t)(_v8)));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint8_t _v8 = 0x00;
std::memcpy((&_v8), reinterpret_cast<const void*>(_ptr), sizeof(uint8_t));
ctx.set_reg(dst, ((uint64_t)(_v8)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S32_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
int32_t _s32 = ((int32_t)(asgard::oblivious_mem::oblivious_load_u32(_addr)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(_s32)))));
#else
const char* _base = reinterpret_cast<const char*>(ctx.get_reg(src));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int32_t*>((_base + imm)))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S16_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(((int16_t)(asgard::oblivious_mem::oblivious_load_u16(static_cast<uintptr_t>(addr)))))))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
int16_t _s16 = ((int16_t)(0));
std::memcpy((&_s16), reinterpret_cast<const void*>(_ptr), sizeof(int16_t));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(_s16)))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S8_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(((int8_t)(asgard::oblivious_mem::oblivious_load_u8(static_cast<uintptr_t>(addr)))))))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
int8_t _s8 = ((int8_t)(0));
std::memcpy((&_s8), reinterpret_cast<const void*>(_ptr), sizeof(int8_t));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(_s8)))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_64_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
asgard::oblivious_mem::oblivious_store_u64(_ptr, ctx.get_reg(src), (&ctx.decoy_sink));
#else
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
(*(reinterpret_cast<uint64_t*>(addr))) = ctx.get_reg(src);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_32_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
asgard::oblivious_mem::oblivious_store_u32(_ptr, ((uint32_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
uint32_t _v32 = ((uint32_t)(ctx.get_reg(src)));
std::memcpy(reinterpret_cast<void*>(_ptr), (&_v32), sizeof(uint32_t));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_16_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
asgard::oblivious_mem::oblivious_store_u16(static_cast<uintptr_t>(addr), ((uint16_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
uint16_t _v16 = ((uint16_t)(ctx.get_reg(src)));
std::memcpy(reinterpret_cast<void*>(_ptr), (&_v16), sizeof(uint16_t));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_8_D2: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
asgard::oblivious_mem::oblivious_store_u8(_ptr, ((uint8_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
char* _target = (reinterpret_cast<char*>(ctx.get_reg(dst)) + imm);
(*(reinterpret_cast<uint8_t*>(_target))) = ((uint8_t)(ctx.get_reg(src)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RESOLVE_SYM_D2: {
        size_t sym_idx = ((size_t)(imm));
        void* sym_ptr = asgard_resolve_sym_idx(((int32_t)(sym_idx)));
        ctx.set_reg(dst, ((uint64_t)(sym_ptr)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FADD_DD_D2: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        uint64_t b_raw = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        double a = std::bit_cast<double>(a_raw);
        double b = std::bit_cast<double>(b_raw);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((a + b)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FSUB_DD_D2: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        double _b = std::bit_cast<double>(ctx.get_vreg_lane(static_cast<uint8_t>(imm), 0));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((_a - _b)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FMUL_DD_D2: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((std::bit_cast<double>(_s) * std::bit_cast<double>(_i))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FDIV_DD_D2: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        double _b = std::bit_cast<double>(ctx.get_vreg_lane(static_cast<uint8_t>(imm), 0));
        double _q = ((_b == 0.0) ? ((_a == 0.0) ? NAN : ((std::signbit(_a) ^ std::signbit(_b)) ? (-INFINITY) : INFINITY)) : (_a / _b));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(_q), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FSQRT_D_D2: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        double a = std::bit_cast<double>(a_raw);
        double r = std::sqrt(a);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(r), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCMP_DD_D2: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        double a = std::bit_cast<double>(_s);
        double b = std::bit_cast<double>(_i);
        bool _nan = (std::isnan(a) || std::isnan(b));
        bool _eq = (a == b);
        bool _lt = (a < b);
        ctx.zf = (_nan || _eq);
        ctx.cf = (_nan || _lt);
        ctx.pf = _nan;
        ctx.sf = false;
        ctx.of = false;
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVTZS_D2: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        double a = std::bit_cast<double>(a_raw);
        ctx.set_reg(dst, ((uint64_t)(((int64_t)(a)))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SCVTF_D2: {
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(((int64_t)(ctx.get_reg(src)))))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVTZU_D2: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        double a = std::bit_cast<double>(a_raw);
        ctx.set_reg(dst, ((a < 0.0) ? 0x0000000000000000ULL : ((uint64_t)(a))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_UCVTF_D2: {
        uint64_t v = ctx.get_reg(src);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(v))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVT_D2: {
        if (((uint32_t)(imm)) == 1) {
                                 double d64 = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
                                 float f32 = ((float)(d64));
                                 uint32_t u32 = std::bit_cast<uint32_t>(f32);
                                 ctx.set_vreg(dst, ((ctx.get_vreg_lane(dst, 0) & 0xffffffff00000000ULL) | ((uint64_t)(u32))), 0x0000000000000000ULL);
} else {
            float f32 = std::bit_cast<float>(((uint32_t)(ctx.get_vreg_lane(src, 0))));
            ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(f32))), 0x0000000000000000ULL);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_LOAD_D2: {
        uint64_t _addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
        std::atomic_thread_fence(std::memory_order_seq_cst);
        uint64_t _loaded = (*(reinterpret_cast<volatile uint64_t*>(_addr)));
        std::atomic_thread_fence(std::memory_order_seq_cst);
        ctx.set_reg(dst, _loaded);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_STORE_D2: {
        uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
        std::atomic<uint64_t>* ptr = reinterpret_cast<std::atomic<uint64_t>*>(addr);
        ptr->store(ctx.get_reg(src), std::memory_order_seq_cst);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_CAS_D2: {
        uint64_t _addr = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        uint64_t _exp = ctx.get_reg(src);
        uint64_t _des = ctx.get_reg(REG_RAX);
        __atomic_compare_exchange_n(reinterpret_cast<uint64_t*>(_addr), (&_exp), _des, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        ctx.set_reg(src, _exp);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_ADD_D2: {
        uint64_t _addr = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        uint64_t _old = __atomic_fetch_add(reinterpret_cast<uint64_t*>(_addr), ctx.get_reg(src), __ATOMIC_SEQ_CST);
        ctx.set_reg(src, _old);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_SWP_D2: {
        uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
        std::atomic<uint64_t>* ptr = reinterpret_cast<std::atomic<uint64_t>*>(addr);
        uint64_t old = ptr->exchange(ctx.get_reg(src), std::memory_order_seq_cst);
        ctx.set_reg(src, old);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FENCE_D2: { std::atomic_thread_fence(std::memory_order_seq_cst); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_VR_D2: {
        uint64_t _val = ctx.get_reg(src);
        uint64_t _buf[1];
        std::memcpy(_buf, (&_val), sizeof(uint64_t));
        ctx.set_vreg_lane(dst, 0, _buf[0]);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_MOV_RV_D2: { ctx.set_reg(dst, ctx.get_vreg_lane(src, 0)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_FCSEL_VV_D2: {
        if (eval_condition(ctx, static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL))))) {

    uint64_t _v = ctx.get_vreg_lane(src, 0);
    ctx.set_vreg_lane(dst, 0, _v);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }

    H_NOP_D3: { ctx.executed_instructions += 1; FETCH_NEXT(); }
    H_MOV_RR_D3: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x0000000000000002ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_s ^ 0x2ed0136e708d8fb7ULL) ^ 0x2ed0136e708d8fb7ULL) : ((_s + 0x6666ba1c44cb1120ULL) - 0x6666ba1c44cb1120ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_D3: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x0000000000000002ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_imm ^ 0xc3e6e0a8791f7016ULL) ^ 0xc3e6e0a8791f7016ULL) : ((_imm + 0xc3774f5004eadf5bULL) - 0xc3774f5004eadf5bULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_A1_D3: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x0000000000000007ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_s + 0x0000000013375877ULL) - 0x0000000013375877ULL) : ((_s ^ 0x3d3771fc3faa3d1bULL) ^ 0x3d3771fc3faa3d1bULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RR_A2_D3: { uint64_t _s = ctx.get_reg(src); uint64_t _v = ((((k_dyn >> 0x0000000000000011ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~((~_s))) : (_s ^ 0x0000000000000000ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_A1_D3: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x0000000000000008ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((_imm ^ 0xddeebf94509fff5aULL) ^ 0xddeebf94509fff5aULL) : ((_imm + 0x0000000058771337ULL) - 0x0000000058771337ULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RI_A2_D3: { uint64_t _imm = static_cast<uint64_t>(static_cast<uint32_t>(imm)); uint64_t _v = ((((k_dyn >> 0x000000000000000dULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~((~_imm))) : ((_imm + 0x00000000deadbeefULL) - 0x00000000deadbeefULL)); ctx.set_reg(dst, _v); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_HIGH_D3: {
        uint64_t _d = ctx.get_reg(dst);
        uint64_t _hi = (static_cast<uint64_t>(static_cast<uint32_t>(imm)) << 32);
        ctx.set_reg(dst, ((_d & 0x00000000ffffffffULL) ^ _hi));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_NEG_RR_D3: { PROBE_START(); uint64_t _v = ctx.get_reg(dst); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000003ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((~_v) + 0x0000000000000001ULL) : (0x0000000000000000ULL - _v))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_NOT_RR_D3: { PROBE_START(); uint64_t _v = ctx.get_reg(dst); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001aULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (~_v) : (_v ^ (~0x0000000000000000ULL)))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_BSWAP_RR_D3: {
        uint64_t _val = ctx.get_reg(src);
        uint32_t _b = static_cast<uint32_t>(imm);
        uint64_t _r = ((_b == 16) ? static_cast<uint64_t>(__builtin_bswap16(static_cast<uint16_t>(_val))) : ((_b == 32) ? static_cast<uint64_t>(__builtin_bswap32(static_cast<uint32_t>(_val))) : __builtin_bswap64(_val)));
        ctx.set_reg(dst, _r);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CLZ_RR_D3: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (val & mask);
        uint64_t res;
        if (bits <= 32) {
                     uint32_t v32 = static_cast<uint32_t>(mval);
                     res = ((v32 == 0) ? static_cast<uint64_t>(bits) : static_cast<uint64_t>((__builtin_clz(v32) - (32 - bits))));
} else {
            res = ((mval == 0x0000000000000000ULL) ? 0x0000000000000040ULL : static_cast<uint64_t>(__builtin_clzll(mval)));
}
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CTZ_RR_D3: {
        uint64_t _s = ctx.get_reg(src);
        uint32_t _bits = static_cast<uint32_t>(imm);
        uint64_t _mask = ((_bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << _bits) - 0x0000000000000001ULL));
        uint64_t _ms = (_s & _mask);
        if (_bits <= 32) {
                      uint32_t _v32 = static_cast<uint32_t>(_ms);
                      ctx.set_reg(dst, ((_v32 == 0) ? static_cast<uint64_t>(_bits) : static_cast<uint64_t>(__builtin_ctz(_v32))));
} else {
            ctx.set_reg(dst, ((_ms == 0x0000000000000000ULL) ? 0x0000000000000040ULL : static_cast<uint64_t>(__builtin_ctzll(_ms))));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_POPCNT_RR_D3: {
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t mask = ((bits >= 64) ? (~0x0000000000000000ULL) : ((0x0000000000000001ULL << bits) - 0x0000000000000001ULL));
        uint64_t mval = (ctx.get_reg(src) & mask);
        if (bits <= 32) {
                     ctx.set_reg(dst, static_cast<uint64_t>(__builtin_popcount(static_cast<uint32_t>(mval))));
} else {
            ctx.set_reg(dst, static_cast<uint64_t>(__builtin_popcountll(mval)));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RBIT_RR_D3: {
        uint64_t val = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(imm);
        uint64_t res = 0x0000000000000000ULL;
        for (size_t i = 0; i < bits; ++i) {
                                       if (((val >> i) & 0x0000000000000001ULL) != 0x0000000000000000ULL) {
                                       
                                           res |= (0x0000000000000001ULL << ((bits - 1) - i));
                                       }
}
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADD_RR_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000013ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0x5555555555555555ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000003ULL)))))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0x5555555555555555ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000003ULL)))))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))))) + (0x2000000000000000ULL * (((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) * ((((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + 0x0000000000000001ULL) * ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + 0x0000000000000002ULL) * (((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + 0x0000000000000003ULL)))))) ^ ((((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0x5555555555555555ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000003ULL)))))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0x5555555555555555ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000003ULL)))))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))))) + (0x2000000000000000ULL * (((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) * ((((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + 0x0000000000000001ULL) * ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + 0x0000000000000002ULL) * (((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + 0x0000000000000003ULL)))))) & 0x000000007fffffffULL) * 0x1a1e7b19d2facc67ULL) << 0x0000000000000021ULL)) ^ (((((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0x5555555555555555ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000003ULL)))))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0x5555555555555555ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000003ULL)))))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))))) + (0x2000000000000000ULL * (((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) * ((((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + 0x0000000000000001ULL) * ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + 0x0000000000000002ULL) * (((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + 0x0000000000000003ULL)))))) ^ ((((((((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0x5555555555555555ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000003ULL)))))) ^ ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))) + (0x0000000000000002ULL * (((((ctx.get_reg(dst) & 0x5555555555555555ULL) ^ (ctx.get_reg(src) & 0x5555555555555555ULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0x5555555555555555ULL) & (ctx.get_reg(src) & 0x5555555555555555ULL)))) + (0x2000000000000000ULL * ((ctx.get_reg(src) & 0x5555555555555555ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000001ULL) * (((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000002ULL) * ((ctx.get_reg(src) & 0x5555555555555555ULL) + 0x0000000000000003ULL)))))) & ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL))))))) + (0x2000000000000000ULL * (((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) * ((((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) ^ (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + (0x0000000000000002ULL * ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) & (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) - ((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)))) + 0x0000000000000001ULL) * ((((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + 0x0000000000000002ULL) * (((ctx.get_reg(dst) & 0xaaaaaaaaaaaaaaaaULL) + (ctx.get_reg(src) & 0xaaaaaaaaaaaaaaaaULL)) + 0x0000000000000003ULL)))))) & 0x000000007fffffffULL) * 0x1a1e7b19d2facc67ULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x1a1e7b19d2facc67ULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RI_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000bULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) + static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & static_cast<uint64_t>(imm)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RR_A1_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000bULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) : ((0x0000000000000002ULL * (ctx.get_reg(dst) | ctx.get_reg(src))) - (ctx.get_reg(dst) ^ ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ADD_RR_A2_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001aULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RR_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000bULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((((0x0000000000000002ULL * ((((0x0000000000000002ULL & (ctx.get_reg(dst) & (~ctx.get_reg(src)))) * (0x0000000000000002ULL | (ctx.get_reg(dst) & (~ctx.get_reg(src))))) + ((0x0000000000000002ULL & (~((ctx.get_reg(dst) & (~ctx.get_reg(src)))))) * ((~0x0000000000000002ULL) & (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & (~((ctx.get_reg(dst) ^ ctx.get_reg(src)))))) - ((((0x0000000000000002ULL & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL))) * (0x0000000000000002ULL | (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL)))) + ((0x0000000000000002ULL & (~((ctx.get_reg(dst) & (~ctx.get_reg(src)))))) * ((~0x0000000000000002ULL) & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL))))) ^ (ctx.get_reg(dst) ^ ctx.get_reg(src)))) ^ (((((0x0000000000000002ULL * ((((0x0000000000000002ULL & (ctx.get_reg(dst) & (~ctx.get_reg(src)))) * (0x0000000000000002ULL | (ctx.get_reg(dst) & (~ctx.get_reg(src))))) + ((0x0000000000000002ULL & (~((ctx.get_reg(dst) & (~ctx.get_reg(src)))))) * ((~0x0000000000000002ULL) & (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & (~((ctx.get_reg(dst) ^ ctx.get_reg(src)))))) - ((((0x0000000000000002ULL & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL))) * (0x0000000000000002ULL | (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL)))) + ((0x0000000000000002ULL & (~((ctx.get_reg(dst) & (~ctx.get_reg(src)))))) * ((~0x0000000000000002ULL) & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL))))) ^ (ctx.get_reg(dst) ^ ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x14a621526738c021ULL) << 0x0000000000000021ULL)) ^ ((((((0x0000000000000002ULL * ((((0x0000000000000002ULL & (ctx.get_reg(dst) & (~ctx.get_reg(src)))) * (0x0000000000000002ULL | (ctx.get_reg(dst) & (~ctx.get_reg(src))))) + ((0x0000000000000002ULL & (~((ctx.get_reg(dst) & (~ctx.get_reg(src)))))) * ((~0x0000000000000002ULL) & (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & (~((ctx.get_reg(dst) ^ ctx.get_reg(src)))))) - ((((0x0000000000000002ULL & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL))) * (0x0000000000000002ULL | (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL)))) + ((0x0000000000000002ULL & (~((ctx.get_reg(dst) & (~ctx.get_reg(src)))))) * ((~0x0000000000000002ULL) & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL))))) ^ (ctx.get_reg(dst) ^ ctx.get_reg(src)))) ^ (((((0x0000000000000002ULL * ((((0x0000000000000002ULL & (ctx.get_reg(dst) & (~ctx.get_reg(src)))) * (0x0000000000000002ULL | (ctx.get_reg(dst) & (~ctx.get_reg(src))))) + ((0x0000000000000002ULL & (~((ctx.get_reg(dst) & (~ctx.get_reg(src)))))) * ((~0x0000000000000002ULL) & (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & (~((ctx.get_reg(dst) ^ ctx.get_reg(src)))))) - ((((0x0000000000000002ULL & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL))) * (0x0000000000000002ULL | (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL)))) + ((0x0000000000000002ULL & (~((ctx.get_reg(dst) & (~ctx.get_reg(src)))))) * ((~0x0000000000000002ULL) & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x5555555555555555ULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xaaaaaaaaaaaaaaaaULL))))) ^ (ctx.get_reg(dst) ^ ctx.get_reg(src)))) & 0x000000007fffffffULL) * 0x14a621526738c021ULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x14a621526738c021ULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RR_A1_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000bULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((0x0000000000000002ULL * (ctx.get_reg(dst) & (~ctx.get_reg(src)))) - (ctx.get_reg(dst) ^ ctx.get_reg(src))) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_SUB_RI_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000000fULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) - static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) - (0x0000000000000002ULL * ((~ctx.get_reg(dst)) & static_cast<uint64_t>(imm)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_IMUL_RR_D3: { PROBE_START(); uint64_t a = ctx.get_reg(dst); uint64_t b = ctx.get_reg(src); uint64_t res = ((((k_dyn >> 0x0000000000000007ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (a * b) : (((a & b) * (a | b)) + ((a & (~b)) * ((~a) & b)))); ctx.set_reg(dst, res); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_IMUL_RI_D3: { PROBE_START(); uint64_t a = ctx.get_reg(dst); uint64_t b = static_cast<uint64_t>(imm); uint64_t res = ((((k_dyn >> 0x0000000000000008ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (a * b) : (((a & b) * (a | b)) + ((a & (~b)) * ((~a) & b)))); ctx.set_reg(dst, res); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RR_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000018ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((((ctx.get_reg(dst) ^ ctx.get_reg(src)) ^ ((((0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) * (0x8000000000000000ULL + (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL)))) + ((0x8000000000000000ULL & (~((ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) * ((~0x8000000000000000ULL) & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) - ((0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) * (0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL)))))) + (0x0000000000000002ULL * ((ctx.get_reg(dst) ^ ctx.get_reg(src)) & ((((0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) * (0x8000000000000000ULL + (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL)))) + ((0x8000000000000000ULL & (~((ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) * ((~0x8000000000000000ULL) & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) - ((0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) * (0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL)))))))) + (0x2000000000000000ULL * (((((0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) * (0x8000000000000000ULL + (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL)))) + ((0x8000000000000000ULL & (~((ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) * ((~0x8000000000000000ULL) & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) - ((0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) * (0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) * ((((((0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) * (0x8000000000000000ULL + (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL)))) + ((0x8000000000000000ULL & (~((ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) * ((~0x8000000000000000ULL) & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) - ((0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) * (0x8000000000000000ULL & (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))))) + 0x0000000000000001ULL) * (((0x8000000000000000ULL * (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) + 0x0000000000000002ULL) * ((0x8000000000000000ULL * (ctx.get_reg(dst) * (ctx.get_reg(dst) + 0x0000000000000001ULL))) + 0x0000000000000003ULL)))))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RR_A1_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000001ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (0x0000000000000002ULL * (ctx.get_reg(dst) & ctx.get_reg(src)))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_XOR_RI_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000007ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) | static_cast<uint64_t>(imm)) - (ctx.get_reg(dst) & static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RR_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x000000000000001cULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (((((ctx.get_reg(dst) ^ (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xff00ff00ff00ff00ULL))) - (0x0000000000000002ULL * ((ctx.get_reg(dst) ^ 0xffffffffffffffffULL) & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xff00ff00ff00ff00ULL))))) + ((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)) + (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)))) & 0x5555555555555555ULL)) + (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)) + (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)))) & 0xaaaaaaaaaaaaaaaaULL)))) ^ ((((((ctx.get_reg(dst) ^ (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xff00ff00ff00ff00ULL))) - (0x0000000000000002ULL * ((ctx.get_reg(dst) ^ 0xffffffffffffffffULL) & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xff00ff00ff00ff00ULL))))) + ((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)) + (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)))) & 0x5555555555555555ULL)) + (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)) + (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)))) & 0xaaaaaaaaaaaaaaaaULL)))) & 0x000000007fffffffULL) * 0x2eb161135ecddf4dULL) << 0x0000000000000021ULL)) ^ (((((((ctx.get_reg(dst) ^ (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xff00ff00ff00ff00ULL))) - (0x0000000000000002ULL * ((ctx.get_reg(dst) ^ 0xffffffffffffffffULL) & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xff00ff00ff00ff00ULL))))) + ((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)) + (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)))) & 0x5555555555555555ULL)) + (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)) + (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)))) & 0xaaaaaaaaaaaaaaaaULL)))) ^ ((((((ctx.get_reg(dst) ^ (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xff00ff00ff00ff00ULL))) - (0x0000000000000002ULL * ((ctx.get_reg(dst) ^ 0xffffffffffffffffULL) & (((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0x00ff00ff00ff00ffULL) + ((ctx.get_reg(dst) & (~ctx.get_reg(src))) & 0xff00ff00ff00ff00ULL))))) + ((((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) & 0x5555555555555555ULL) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)) + (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)))) & 0x5555555555555555ULL)) + (((((ctx.get_reg(dst) & 0x00000000ffffffffULL) ^ (ctx.get_reg(src) & 0x00000000ffffffffULL)) + ((ctx.get_reg(dst) & 0xffffffff00000000ULL) ^ (ctx.get_reg(src) & 0xffffffff00000000ULL))) & 0xaaaaaaaaaaaaaaaaULL) - ((((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)) + (((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))) - ((ctx.get_reg(dst) | ctx.get_reg(src)) + ((~((ctx.get_reg(dst) & ctx.get_reg(src)))) + 0x0000000000000001ULL)))) & 0xaaaaaaaaaaaaaaaaULL)))) & 0x000000007fffffffULL) * 0x2eb161135ecddf4dULL) << 0x0000000000000021ULL)) & 0x000000007fffffffULL) * 0x2eb161135ecddf4dULL) << 0x0000000000000021ULL)) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) | ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RR_A1_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000012ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) | ctx.get_reg(src))) : ((ctx.get_reg(dst) | ctx.get_reg(src)) - (ctx.get_reg(dst) ^ ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_AND_RI_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000018ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) & static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) + static_cast<uint64_t>(imm)) - (ctx.get_reg(dst) | static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RR_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000003ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) | ctx.get_reg(src)) + (((((ctx.get_reg(dst) & ctx.get_reg(src)) + ((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~((~ctx.get_reg(src)))))) + ((ctx.get_reg(dst) ^ (~ctx.get_reg(src))) - ((ctx.get_reg(dst) | (~ctx.get_reg(src))) - (ctx.get_reg(dst) & (~ctx.get_reg(src))))))) & (~ctx.get_reg(dst))) - ((~(((ctx.get_reg(dst) & ctx.get_reg(src)) + (ctx.get_reg(dst) & (~ctx.get_reg(src)))))) & ctx.get_reg(dst))) + ((((ctx.get_reg(dst) & ctx.get_reg(src)) + ((ctx.get_reg(dst) - (ctx.get_reg(dst) & (~((~ctx.get_reg(src)))))) + ((ctx.get_reg(dst) ^ (~ctx.get_reg(src))) - ((ctx.get_reg(dst) | (~ctx.get_reg(src))) - (ctx.get_reg(dst) & (~ctx.get_reg(src))))))) ^ ctx.get_reg(dst)) - ((((ctx.get_reg(dst) & ctx.get_reg(src)) + (ctx.get_reg(dst) & (~ctx.get_reg(src)))) | ctx.get_reg(dst)) - (((ctx.get_reg(dst) & ctx.get_reg(src)) + (ctx.get_reg(dst) & (~ctx.get_reg(src)))) & ctx.get_reg(dst)))))) : ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RR_A1_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000010ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? ((ctx.get_reg(dst) ^ ctx.get_reg(src)) + (ctx.get_reg(dst) & ctx.get_reg(src))) : ((ctx.get_reg(dst) + ctx.get_reg(src)) - (ctx.get_reg(dst) & ctx.get_reg(src))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_OR_RI_D3: { PROBE_START(); ctx.set_reg(dst, ((((k_dyn >> 0x0000000000000016ULL) & 0x0000000000000001ULL) == 0x0000000000000001ULL) ? (ctx.get_reg(dst) | static_cast<uint64_t>(imm)) : ((ctx.get_reg(dst) ^ static_cast<uint64_t>(imm)) + (ctx.get_reg(dst) & static_cast<uint64_t>(imm))))); PROBE_CHECK(); ctx.executed_instructions++; FETCH_NEXT(); }
    H_ROL_RI_D3: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, ((val << shift) | (val >> ((64 - shift) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROR_RI_D3: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, ((v >> s) | (v << ((64 - s) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHL_RI_D3: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, (v << s));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHR_RI_D3: {
        uint64_t _res = (ctx.get_reg(dst) >> static_cast<uint32_t>((imm & 63)));
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SAR_RI_D3: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((imm & 63));
        ctx.set_reg(dst, static_cast<uint64_t>((static_cast<int64_t>(val) >> shift)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROL_RR_D3: {
        uint64_t val = ctx.get_reg(dst);
        uint32_t shift = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, ((val << shift) | (val >> ((64 - shift) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ROR_RR_D3: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, ((v >> s) | (v << ((64 - s) & 63))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHL_RR_D3: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, (v << s));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SHR_RR_D3: {
        uint64_t v = ctx.get_reg(dst);
        uint32_t s = static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL));
        ctx.set_reg(dst, (v >> s));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SAR_RR_D3: {
        uint64_t _res = static_cast<uint64_t>((static_cast<int64_t>(ctx.get_reg(dst)) >> static_cast<uint32_t>((ctx.get_reg(src) & 0x000000000000003fULL))));
        ctx.set_reg(dst, _res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_DIV_RR_D3: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        if (b == 0x0000000000000000ULL) {
                                     ctx.trapped = true;
                                     goto EXIT_VM;
}
        ctx.set_reg(dst, (a / b));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IDIV_RR_D3: {
        int64_t a = static_cast<int64_t>(ctx.get_reg(dst));
        int64_t b = static_cast<int64_t>(ctx.get_reg(src));
        if ((b == 0) || ((b == -1) && (a == INT64_MIN))) {
                                                      ctx.trapped = true;
                                                      goto EXIT_VM;
}
        int64_t q = ((b == -1) ? static_cast<int64_t>((0x0000000000000000ULL - static_cast<uint64_t>(a))) : (a / b));
        ctx.set_reg(dst, static_cast<uint64_t>(q));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_MULH_RR_D3: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        
#if defined(__SIZEOF_INT128__)
uint64_t res = static_cast<uint64_t>(((((unsigned __int128)(a)) * ((unsigned __int128)(b))) >> 64));
ctx.set_reg(dst, res);
#else
uint64_t a_lo = static_cast<uint32_t>(a);
uint64_t a_hi = (a >> 32);
uint64_t b_lo = static_cast<uint32_t>(b);
uint64_t b_hi = (b >> 32);
uint64_t p0 = (a_lo * b_lo);
uint64_t p1 = (a_lo * b_hi);
uint64_t p2 = (a_hi * b_lo);
uint64_t p3 = (a_hi * b_hi);
uint64_t cy = ((((p0 >> 32) + static_cast<uint32_t>(p1)) + static_cast<uint32_t>(p2)) >> 32);
uint64_t res = (((p3 + (p1 >> 32)) + (p2 >> 32)) + cy);
ctx.set_reg(dst, res);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IMULH_RR_D3: {
        int64_t a = static_cast<int64_t>(ctx.get_reg(dst));
        int64_t b = static_cast<int64_t>(ctx.get_reg(src));
        
#if defined(__SIZEOF_INT128__)
signed __int128 _prod = (((signed __int128)(a)) * ((signed __int128)(b)));
uint64_t res = static_cast<uint64_t>((_prod >> 64));
ctx.set_reg(dst, res);
#else
uint64_t ua = static_cast<uint64_t>(a);
uint64_t ub = static_cast<uint64_t>(b);
uint64_t a_lo = static_cast<uint32_t>(ua);
uint64_t a_hi = (ua >> 32);
uint64_t b_lo = static_cast<uint32_t>(ub);
uint64_t b_hi = (ub >> 32);
uint64_t p0 = (a_lo * b_lo);
uint64_t p1 = (a_lo * b_hi);
uint64_t p2 = (a_hi * b_lo);
uint64_t p3 = (a_hi * b_hi);
uint64_t cy = ((((p0 >> 32) + static_cast<uint32_t>(p1)) + static_cast<uint32_t>(p2)) >> 32);
uint64_t res = (((p3 + (p1 >> 32)) + (p2 >> 32)) + cy);
if (a < 0) {
                res -= ub;
}
if (b < 0) {
                res -= ua;
}
ctx.set_reg(dst, res);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_D3: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        uint64_t _imm = static_cast<uint64_t>(imm);
        compute_sub_flags(ctx, ctx.get_reg(dst), _imm, bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RR_D3: {
        PROBE_START();
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        compute_sub_flags(ctx, a, b, bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_A1_D3: {
        PROBE_START();
        uint64_t _d = ctx.get_reg(dst);
        compute_sub_flags(ctx, _d, static_cast<uint64_t>(imm), static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RI_A2_D3: {
        PROBE_START();
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL));
        uint64_t _imm = static_cast<uint64_t>(imm);
        compute_sub_flags(ctx, ctx.get_reg(dst), _imm, bits);
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMP_RR_A1_D3: {
        PROBE_START();
        uint64_t _a = ctx.get_reg(dst);
        uint64_t _b = ctx.get_reg(src);
        compute_sub_flags(ctx, _a, _b, static_cast<uint32_t>(((word >> 50) & 0x000000000000007fULL)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_PUSH_R_D3: {
        uint64_t val = ctx.get_reg(dst);
        ctx.push(val);
        uint64_t cur_sp = ctx.get_reg(REG_RSP);
        if ((cur_sp >= 0x0000000000010008ULL) && (cur_sp <= 0x00007fffffffffffULL)) {

    uint64_t sp_val = (cur_sp - 0x0000000000000008ULL);
    ctx.set_reg(REG_RSP, sp_val);
    std::memcpy(reinterpret_cast<void*>(sp_val), (&val), sizeof(uint64_t));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_POP_R_D3: {
        uint64_t cur_sp = ctx.get_reg(REG_RSP);
        uint64_t val = 0x0000000000000000ULL;
        if ((cur_sp >= 0x0000000000010000ULL) && (cur_sp <= 0x00007fffffffffffULL)) {

    std::memcpy((&val), reinterpret_cast<const void*>(cur_sp), sizeof(uint64_t));
    ctx.set_reg(REG_RSP, (cur_sp + 0x0000000000000008ULL));
    ctx.pop();} else {
                          val = ctx.pop();
}
        ctx.set_reg(dst, val);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADC_RR_D3: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint64_t c = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a + b) + c);
        ctx.cf = ((res < a) || ((c != 0x0000000000000000ULL) && (res == a)));
        ctx.of = ((((a ^ res) & (b ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ADC_RI_D3: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint64_t c = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a + b) + c);
        ctx.cf = ((res < a) || ((c != 0x0000000000000000ULL) && (res == a)));
        ctx.of = ((((a ^ res) & (b ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SBB_RR_D3: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = ctx.get_reg(src);
        uint64_t borrow = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a - b) - borrow);
        ctx.cf = ((a < b) || ((borrow != 0x0000000000000000ULL) && (a == b)));
        ctx.of = ((((a ^ b) & (a ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SBB_RI_D3: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint64_t borrow = (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t res = ((a - b) - borrow);
        ctx.cf = ((a < b) || ((borrow != 0x0000000000000000ULL) && (a == b)));
        ctx.of = ((((a ^ b) & (a ^ res)) >> 63) != 0x0000000000000000ULL);
        ctx.zf = (res == 0x0000000000000000ULL);
        ctx.sf = (static_cast<int64_t>(res) < 0);
        ctx.set_reg(dst, res);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMP_RR_D3: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (eval_condition(ctx, cond)) {
                                    uint64_t a = ctx.get_reg(dst);
                                    uint64_t b = ctx.get_reg(src);
                                    compute_sub_flags(ctx, a, b, bits);
} else {
            ctx.sf = ((nzcv & 8) != 0);
            ctx.zf = ((nzcv & 4) != 0);
            ctx.cf = ((nzcv & 2) != 0);
            ctx.of = ((nzcv & 1) != 0);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMP_RI_D3: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint64_t b = static_cast<uint64_t>((((word >> 26) + 0x000000000000001fULL) - ((word >> 26) | 0x000000000000001fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (!eval_condition(ctx, cond)) {
                                     ctx.sf = ((nzcv & 8) != 0);
                                     ctx.zf = ((nzcv & 4) != 0);
                                     ctx.cf = ((nzcv & 2) != 0);
                                     ctx.of = ((nzcv & 1) != 0);
} else {
            uint64_t a = ctx.get_reg(dst);
            compute_sub_flags(ctx, a, b, bits);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMN_RR_D3: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (eval_condition(ctx, cond)) {
                                    uint64_t a = ctx.get_reg(dst);
                                    uint64_t b = ctx.get_reg(src);
                                    compute_add_flags(ctx, a, b, bits);
} else {
            ctx.sf = ((nzcv & 8) != 0);
            ctx.zf = ((nzcv & 4) != 0);
            ctx.cf = ((nzcv & 2) != 0);
            ctx.of = ((nzcv & 1) != 0);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CCMN_RI_D3: {
        uint8_t cond = static_cast<uint8_t>((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL)));
        uint8_t nzcv = static_cast<uint8_t>((((word >> 22) + 0x000000000000000fULL) - ((word >> 22) | 0x000000000000000fULL)));
        uint64_t b = static_cast<uint64_t>((((word >> 26) + 0x000000000000001fULL) - ((word >> 26) | 0x000000000000001fULL)));
        uint32_t bits = static_cast<uint32_t>((((word >> 50) + 0x000000000000007fULL) - ((word >> 50) | 0x000000000000007fULL)));
        if (!eval_condition(ctx, cond)) {
                                     ctx.sf = ((nzcv & 8) != 0);
                                     ctx.zf = ((nzcv & 4) != 0);
                                     ctx.cf = ((nzcv & 2) != 0);
                                     ctx.of = ((nzcv & 1) != 0);
} else {
            uint64_t a = ctx.get_reg(dst);
            compute_add_flags(ctx, a, b, bits);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_GET_FLAGS_R_D3: {
        uint64_t f = ((((0x0000000000000002ULL | (ctx.cf ? 0x0000000000000001ULL : 0x0000000000000000ULL)) | (ctx.zf ? 0x0000000000000040ULL : 0x0000000000000000ULL)) | (ctx.sf ? 0x0000000000000080ULL : 0x0000000000000000ULL)) | (ctx.of ? 0x0000000000000800ULL : 0x0000000000000000ULL));
        ctx.set_reg(dst, f);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SET_FLAGS_R_D3: {
        uint64_t mask = ctx.get_reg(src);
        ctx.cf = (((mask >> 0) & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.zf = (((mask >> 6) & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.sf = (((mask >> 7) & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.of = (((mask >> 11) & 0x0000000000000001ULL) != 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_D3: {
        size_t _target = static_cast<size_t>(imm);
        vIP_idx = _target;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_A1_D3: {
        size_t _target = static_cast<size_t>(imm);
        vIP_idx = _target;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JMP_A2_D3: {
        vIP_idx = static_cast<size_t>(((static_cast<uint64_t>(imm) ^ 0x0000000000005877ULL) ^ 0x0000000000005877ULL));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JCC_D3: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t base_vip = static_cast<uint64_t>(((word >> 0x0000000000000016ULL) & 0x00000000001fffffULL));
        uint64_t enc_delta = static_cast<uint64_t>(((word >> 0x000000000000002bULL) & 0x00000000001fffffULL));
        uint64_t salt = (((static_cast<uint64_t>(cond) * 0x0000000000005877ULL) ^ 0x000000001337beefULL) & 0x00000000001fffffULL);
        uint64_t delta = (enc_delta ^ salt);
        uint64_t t_true = (base_vip ^ delta);
        uint64_t t_false = base_vip;
        uint64_t c = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t _mask = (0x0000000000000000ULL - c);
        vIP_idx = static_cast<size_t>(((t_true & _mask) | (t_false & (~_mask))));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_JCC_A1_D3: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t base_vip = static_cast<uint64_t>(((word >> 0x0000000000000016ULL) & 0x00000000001fffffULL));
        uint64_t enc_delta = static_cast<uint64_t>(((word >> 0x000000000000002bULL) & 0x00000000001fffffULL));
        uint64_t salt = (((static_cast<uint64_t>(cond) * 0x0000000000005877ULL) ^ 0x000000001337beefULL) & 0x00000000001fffffULL);
        uint64_t delta = (enc_delta ^ salt);
        uint64_t t_true = (base_vip ^ delta);
        uint64_t t_false = base_vip;
        uint64_t c = (eval_condition(ctx, cond) ? 0x0000000000000001ULL : 0x0000000000000000ULL);
        uint64_t _mask = (0x0000000000000000ULL - c);
        vIP_idx = static_cast<size_t>(((t_true & _mask) | (t_false & (~_mask))));
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CMOV_D3: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        uint64_t _s = ctx.get_reg(src);
        uint64_t _d = ctx.get_reg(dst);
        ctx.set_reg(dst, (eval_condition(ctx, cond) ? _s : _d));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SETCC_D3: {
        PROBE_START();
        uint8_t cond = static_cast<uint8_t>((((word >> 0x0000000000000012ULL) + 0x000000000000000fULL) - ((word >> 0x0000000000000012ULL) | 0x000000000000000fULL)));
        ctx.set_reg(dst, static_cast<uint64_t>((eval_condition(ctx, cond) ? 1 : 0)));
        PROBE_CHECK();
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CALL_D3: {
        ctx.push(static_cast<uint64_t>(vIP_idx));
        size_t _target_vip = static_cast<size_t>(imm);
        vIP_idx = _target_vip;
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_IJMP_R_D3: {
        uint64_t target = ctx.get_reg(dst);
        if (target < count) {
                         vIP_idx = static_cast<size_t>(target);
} else {
            if (target != 0x0000000000000000ULL) {
                                                      #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                                      uint64_t a1 = ctx.get_reg(REG_RCX);
                                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                                      uint64_t a3 = ctx.get_reg(REG_RBX);
                                                      uint64_t a4 = ctx.get_reg(REG_RSI);
                                                      uint64_t a5 = ctx.get_reg(REG_RDI);
                                                      #elif defined(ASGARD_GUEST_RISCV64)
                                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                                      uint64_t a1 = ctx.get_reg(REG_RDX);
                                                      uint64_t a2 = ctx.get_reg(REG_RCX);
                                                      uint64_t a3 = ctx.get_reg(REG_RSI);
                                                      uint64_t a4 = ctx.get_reg(REG_RDI);
                                                      uint64_t a5 = ctx.get_reg(REG_R8);
                                                      #else
                                                      uint64_t a0 = ctx.get_reg(REG_RDI);
                                                      uint64_t a1 = ctx.get_reg(REG_RSI);
                                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                                      uint64_t a3 = ctx.get_reg(REG_RCX);
                                                      uint64_t a4 = ctx.get_reg(REG_R8);
                                                      uint64_t a5 = ctx.get_reg(REG_R9);
                                                      #endif
                                                      typedef uint64_t (*indirect_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                      indirect_fn_t fn = reinterpret_cast<indirect_fn_t>(target);
                                                      uint64_t ret_val = fn(a0, a1, a2, a3, a4, a5);
                                                      ctx.set_reg(REG_RAX, ret_val);
                                                      goto EXIT_VM;
            }
}
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ICALL_R_D3: {
        uint64_t target_ptr = ctx.get_reg(dst);
        if (__builtin_expect((target_ptr < count), 1)) {
                                                    uint64_t _ret = static_cast<uint64_t>(vIP_idx);
                                                    ctx.push(_ret);
                                                    vIP_idx = static_cast<size_t>(target_ptr);
} else {
            if (target_ptr != 0) {
                                      #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                      uint64_t a1 = ctx.get_reg(REG_RCX);
                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                      uint64_t a3 = ctx.get_reg(REG_RBX);
                                      uint64_t a4 = ctx.get_reg(REG_RSI);
                                      uint64_t a5 = ctx.get_reg(REG_RDI);
                                      #elif defined(ASGARD_GUEST_RISCV64)
                                      uint64_t a0 = ctx.get_reg(REG_RAX);
                                      uint64_t a1 = ctx.get_reg(REG_RDX);
                                      uint64_t a2 = ctx.get_reg(REG_RCX);
                                      uint64_t a3 = ctx.get_reg(REG_RSI);
                                      uint64_t a4 = ctx.get_reg(REG_RDI);
                                      uint64_t a5 = ctx.get_reg(REG_R8);
                                      #else
                                      uint64_t a0 = ctx.get_reg(REG_RDI);
                                      uint64_t a1 = ctx.get_reg(REG_RSI);
                                      uint64_t a2 = ctx.get_reg(REG_RDX);
                                      uint64_t a3 = ctx.get_reg(REG_RCX);
                                      uint64_t a4 = ctx.get_reg(REG_R8);
                                      uint64_t a5 = ctx.get_reg(REG_R9);
                                      #endif
                                      typedef uint64_t (*indirect_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                      indirect_fn_t fn = reinterpret_cast<indirect_fn_t>(target_ptr);
                                      uint64_t ret_val = fn(a0, a1, a2, a3, a4, a5);
                                      ctx.set_reg(REG_RAX, ret_val);
            }
}
        ctx.reanchor_running_key(static_cast<uint64_t>(vIP_idx));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RET_D3: { if (ctx.sp > 512) {
                       ctx.trapped = true;
} ctx.executed_instructions += 1; goto EXIT_VM; }
    H_EXIT_D3: { if (ctx.sp > 512) {
                       ctx.trapped = true;
} ctx.executed_instructions += 1; goto EXIT_VM; }

    H_BRIDGE_TO_FLOW_D3: {
        ctx.morph_math_to_flow(static_cast<uint64_t>(imm));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_BRIDGE_TO_MATH_D3: {
        ctx.morph_flow_to_math(static_cast<uint64_t>(imm));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FUSED_MOV_ADD_RRI_D3: {
        uint64_t _s = ctx.get_reg(src);
        uint64_t _i = static_cast<uint64_t>(imm);
        ctx.set_reg(dst, ((_s ^ _i) + (0x0000000000000002ULL * (_s & _i))));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_ADD_IMUL_RRI_D3: {
        uint64_t _sum = (ctx.get_reg(dst) + ctx.get_reg(src));
        ctx.set_reg(dst, (_sum * static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_ADD_XOR_RRI_D3: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) + ctx.get_reg(src)) ^ static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_SUB_XOR_RRI_D3: {
        uint64_t _diff = (ctx.get_reg(dst) - ctx.get_reg(src));
        uint64_t _imm = static_cast<uint64_t>(imm);
        ctx.set_reg(dst, ((_diff + _imm) - (0x0000000000000002ULL * (_diff & _imm))));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_XOR_ADD_RRI_D3: {
        uint64_t _a = ctx.get_reg(dst);
        uint64_t _b = ctx.get_reg(src);
        uint64_t _x = ((_a + _b) - (0x0000000000000002ULL * (_a & _b)));
        ctx.set_reg(dst, (_x + static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_CMP_CMOV_D3: {
        uint64_t a = ctx.get_reg(dst);
        uint64_t b = static_cast<uint64_t>(imm);
        uint8_t cond = static_cast<uint8_t>(((word >> 0x0000000000000032ULL) & 0x000000000000000fULL));
        uint32_t bits = static_cast<uint32_t>(((word >> 0x0000000000000036ULL) & 0x000000000000007fULL));
        compute_sub_flags(ctx, a, b, bits);
        uint64_t _val = (eval_condition(ctx, cond) ? ctx.get_reg(src) : a);
        ctx.set_reg(dst, _val);
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_AND_OR_RRI_D3: {
        ctx.set_reg(dst, ((ctx.get_reg(dst) & ctx.get_reg(src)) | static_cast<uint64_t>(imm)));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_FUSED_SHL_ADD_RRI_D3: {
        uint64_t _shl = (ctx.get_reg(dst) << (static_cast<uint64_t>(imm) & 0x000000000000003fULL));
        uint64_t _s = ctx.get_reg(src);
        ctx.set_reg(dst, ((_shl ^ _s) + (0x0000000000000002ULL * (_shl & _s))));
        ctx.executed_instructions += 2;
        FETCH_NEXT();
    }
    H_VADD_VV_D3: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        
#if defined(ASGARD_VECTOR_ISA) && defined(__aarch64__)
uint64x2_t vd = vcombine_u64(vcreate_u64(d0), vcreate_u64(d1));
uint64x2_t vs = vcombine_u64(vcreate_u64(s0), vcreate_u64(s1));
uint64x2_t vr = vaddq_u64(vd, vs);
ctx.set_vreg(dst, vgetq_lane_u64(vr, 0), vgetq_lane_u64(vr, 1));
#elif defined(ASGARD_VECTOR_ISA) && defined(__x86_64__)
__m128i vd = _mm_set_epi64x(static_cast<int64_t>(d1), static_cast<int64_t>(d0));
__m128i vs = _mm_set_epi64x(static_cast<int64_t>(s1), static_cast<int64_t>(s0));
__m128i vr = _mm_add_epi64(vd, vs);
ctx.set_vreg(dst, static_cast<uint64_t>(_mm_extract_epi64(vr, 0)), static_cast<uint64_t>(_mm_extract_epi64(vr, 1)));
#else
ctx.set_vreg(dst, (d0 + s0), (d1 + s1));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VSUB_VV_D3: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        uint64_t _res0 = (d0 - s0);
        uint64_t _res1 = (d1 - s1);
        ctx.set_vreg(dst, _res0, _res1);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VMUL_VV_D3: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        ctx.set_vreg(dst, static_cast<uint64_t>((d0 * s0)), static_cast<uint64_t>((d1 * s1)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VXOR_VV_D3: {
        uint64_t d0 = ctx.get_vreg_lane(dst, 0);
        uint64_t d1 = ctx.get_vreg_lane(dst, 1);
        uint64_t s0 = ctx.get_vreg_lane(src, 0);
        uint64_t s1 = ctx.get_vreg_lane(src, 1);
        uint64_t _res0 = (d0 ^ s0);
        uint64_t _res1 = (d1 ^ s1);
        ctx.set_vreg(dst, _res0, _res1);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_MOV_D3: {
        size_t _words = static_cast<size_t>(((static_cast<uint32_t>((imm & 0x00000000000003ffULL)) + 63) / 64));
        for (size_t i = 0; i < _words; ++i) {
                                         uint64_t _v = ctx.get_vreg_lane(src, i);
                                         ctx.set_vreg_lane(dst, i, _v);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_BINOP_D3: {
        uint32_t src2 = static_cast<uint32_t>((imm & 0x000000000000001fULL));
        uint32_t bits = static_cast<uint32_t>(((imm >> 5) & 0x00000000000003ffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 15) & 0x00000000000000ffULL));
        if (lane_bits == 0) {
                         lane_bits = 64;
}
        uint32_t vop = static_cast<uint32_t>(((imm >> 23) & 0x000000000000001fULL));
        uint32_t elem = static_cast<uint32_t>(((imm >> 28) & 0x0000000000000003ULL));
        uint64_t mask = ((lane_bits == 8) ? 0x00000000000000ffULL : ((lane_bits == 16) ? 0x000000000000ffffULL : ((lane_bits == 32) ? 0x00000000ffffffffULL : 0xffffffffffffffffULL)));
        size_t bit = 0;
        while (bit < bits) {
                        size_t chunk = (bit / 64);
                        uint32_t shift = static_cast<uint32_t>((bit % 64));
                        uint64_t a = ((ctx.get_vreg_lane(src, chunk) >> shift) & mask);
                        uint64_t b = ((ctx.get_vreg_lane(src2, chunk) >> shift) & mask);
                        uint64_t value = 0x0000000000000000ULL;
                        if ((elem == 1) && (vop <= 2)) {
                                                            float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                                            float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                                            float fr = ((vop == 0) ? (fa + fb) : ((vop == 1) ? (fa - fb) : (fa * fb)));
                                                            value = std::bit_cast<uint32_t>(fr);
                        } else {
                                    if ((elem == 1) && (vop == 11)) {
                                    
                                        float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                        float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                        value = std::bit_cast<uint32_t>(std::fmin(fa, fb));
                                    } else {
                                                if ((elem == 1) && (vop == 12)) {
                                                
                                                    float fa = std::bit_cast<float>(static_cast<uint32_t>(a));
                                                    float fb = std::bit_cast<float>(static_cast<uint32_t>(b));
                                                    value = std::bit_cast<uint32_t>(std::fmax(fa, fb));
                                                } else {
                                                            if ((elem == 2) && (vop <= 2)) {
                                                            
                                                                double fa = std::bit_cast<double>(a);
                                                                double fb = std::bit_cast<double>(b);
                                                                double fr = ((vop == 0) ? (fa + fb) : ((vop == 1) ? (fa - fb) : (fa * fb)));
                                                                value = std::bit_cast<uint64_t>(fr);
                                                            } else {
                                                                    if ((elem == 2) && (vop == 11)) {
                                                                    
                                                                    double fa = std::bit_cast<double>(a);
                                                                    double fb = std::bit_cast<double>(b);
                                                                    value = std::bit_cast<uint64_t>(std::fmin(fa, fb));
                                                                    } else {
                                                                    
                                                                    if ((elem == 2) && (vop == 12)) {
                                                                    
                                                                    double fa = std::bit_cast<double>(a);
                                                                    double fb = std::bit_cast<double>(b);
                                                                    value = std::bit_cast<uint64_t>(std::fmax(fa, fb));
                                                                    } else {
                                                                    
                                                                    int64_t sa = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(a))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(a))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(a))) : static_cast<int64_t>(a))));
                                                                    int64_t sb = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(b))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(b))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(b))) : static_cast<int64_t>(b))));
                                                                    switch (vop) {
                                                                    
                                                                    case 0: {
                                                                    
                                                                    value = (a + b);
                                                                    break;
                                                                    }
                                                                    case 1: {
                                                                    
                                                                    value = (a - b);
                                                                    break;
                                                                    }
                                                                    case 2: {
                                                                    
                                                                    value = (a * b);
                                                                    break;
                                                                    }
                                                                    case 3: {
                                                                    
                                                                    value = (a & b);
                                                                    break;
                                                                    }
                                                                    case 4: {
                                                                    
                                                                    value = (a | b);
                                                                    break;
                                                                    }
                                                                    case 5: {
                                                                    
                                                                    value = (a ^ b);
                                                                    break;
                                                                    }
                                                                    case 6: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a << cnt));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 7: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a >> cnt));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 8: {
                                                                    
                                                                    {
                                                                    uint32_t cnt = static_cast<uint32_t>((ctx.get_vreg_lane(src2, 0) & 0x00000000000000ffULL));
                                                                    value = ((cnt >= lane_bits) ? ((sa < 0) ? mask : 0x0000000000000000ULL) : (static_cast<uint64_t>((sa >> cnt)) & mask));
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 9: {
                                                                    
                                                                    value = ((a == b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 10: {
                                                                    
                                                                    value = ((sa > sb) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 11: {
                                                                    
                                                                    value = ((sa < sb) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 12: {
                                                                    
                                                                    value = ((sa > sb) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 13: {
                                                                    
                                                                    value = ((a < b) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 14: {
                                                                    
                                                                    value = ((a > b) ? a : b);
                                                                    break;
                                                                    }
                                                                    case 15: {
                                                                    
                                                                    value = (static_cast<uint64_t>(((sa < 0) ? (-sa) : sa)) & mask);
                                                                    break;
                                                                    }
                                                                    case 16: {
                                                                    
                                                                    value = ((~a) & b);
                                                                    break;
                                                                    }
                                                                    case 17: {
                                                                    
                                                                    {
                                                                    size_t block_lane = ((bit / lane_bits) % (128 / lane_bits));
                                                                    size_t half_idx = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (half_idx * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 18: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_idx = ((num_lanes / 2) + (block_lane / 2));
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (half_idx * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 21: {
                                                                    
                                                                    {
                                                                    uint8_t ctrl = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if ((ctrl & 128) != 0) {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    } else {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + ((ctrl & 15) * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 23: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_len = (num_lanes / 2);
                                                                    size_t src_reg = ((block_lane < half_len) ? src : src2);
                                                                    size_t sel_elem = ((block_lane < half_len) ? (block_lane * 2) : ((block_lane - half_len) * 2));
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 24: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t half_len = (num_lanes / 2);
                                                                    size_t src_reg = ((block_lane < half_len) ? src : src2);
                                                                    size_t sel_elem = ((block_lane < half_len) ? ((block_lane * 2) + 1) : (((block_lane - half_len) * 2) + 1));
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 25: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t k = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t sel_elem = (k * 2);
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 26: {
                                                                    
                                                                    {
                                                                    size_t num_lanes = (128 / lane_bits);
                                                                    size_t block_lane = ((bit / lane_bits) % num_lanes);
                                                                    size_t k = (block_lane / 2);
                                                                    size_t src_reg = (((block_lane % 2) == 0) ? src : src2);
                                                                    size_t sel_elem = ((k * 2) + 1);
                                                                    size_t src_bit = (((bit / 128) * 128) + (sel_elem * lane_bits));
                                                                    value = ((ctx.get_vreg_lane(src_reg, (src_bit / 64)) >> (src_bit % 64)) & mask);
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 28: {
                                                                    
                                                                    {
                                                                    uint8_t idx = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if (idx < 16) {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + (idx * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    } else {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 29: {
                                                                    
                                                                    {
                                                                    uint8_t idx = static_cast<uint8_t>((b & 0x00000000000000ffULL));
                                                                    if (idx < 16) {
                                                                    
                                                                    size_t src_bit = (((bit / 128) * 128) + (idx * 8));
                                                                    value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000000000ffULL);
                                                                    } else {
                                                                    
                                                                    value = ((ctx.get_vreg_lane(dst, chunk) >> shift) & 0x00000000000000ffULL);
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 30: {
                                                                    
                                                                    {
                                                                    int64_t min_val = ((lane_bits == 64) ? static_cast<int64_t>(0x8000000000000000ULL) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(0x0000000080000000ULL))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(32768))) : static_cast<int64_t>(((int8_t)(128))))));
                                                                    if (sb == 0) {
                                                                    
                                                                    value = 0xffffffffffffffffULL;
                                                                    } else {
                                                                    
                                                                    if ((sb == -1) && (sa == min_val)) {
                                                                    
                                                                    value = static_cast<uint64_t>(sa);
                                                                    } else {
                                                                    
                                                                    value = static_cast<uint64_t>((sa / sb));
                                                                    }
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 31: {
                                                                    
                                                                    value = ((b != 0) ? (a / b) : mask);
                                                                    break;
                                                                    }
                                                                    case 32: {
                                                                    
                                                                    {
                                                                    int64_t min_val = ((lane_bits == 64) ? static_cast<int64_t>(0x8000000000000000ULL) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(0x0000000080000000ULL))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(32768))) : static_cast<int64_t>(((int8_t)(128))))));
                                                                    if (sb == 0) {
                                                                    
                                                                    value = a;
                                                                    } else {
                                                                    
                                                                    if ((sb == -1) && (sa == min_val)) {
                                                                    
                                                                    value = 0x0000000000000000ULL;
                                                                    } else {
                                                                    
                                                                    value = static_cast<uint64_t>((sa % sb));
                                                                    }
                                                                    }
                                                                    break;
                                                                    }
                                                                    }
                                                                    case 33: {
                                                                    
                                                                    value = ((b != 0) ? (a % b) : a);
                                                                    break;
                                                                    }
                                                                    case 34: {
                                                                    
                                                                    value = ((a != b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 35: {
                                                                    
                                                                    value = ((sa <= sb) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 36: {
                                                                    
                                                                    value = ((a < b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    case 37: {
                                                                    
                                                                    value = ((a <= b) ? mask : 0x0000000000000000ULL);
                                                                    break;
                                                                    }
                                                                    default: {
                                                                    
                                                                    value = (a ^ b);
                                                                    break;
                                                                    }
                                                                    }
                                                                    }
                                                                    }
                                                            }
                                                }
                                    }
                        }
                        uint64_t old_value = ctx.get_vreg_lane(dst, chunk);
                        uint64_t packed_mask = (mask << shift);
                        ctx.set_vreg_lane(dst, chunk, ((old_value & (~packed_mask)) | ((value & mask) << shift)));
                        bit += lane_bits;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_IMM_D3: {
        uint64_t imm_val = (imm & 0x00000000000000ffULL);
        uint32_t bits = static_cast<uint32_t>(((imm >> 8) & 0x00000000000003ffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 18) & 0x00000000000000ffULL));
        if (lane_bits == 0) {
                         lane_bits = 64;
}
        uint32_t vop = static_cast<uint32_t>(((imm >> 26) & 0x000000000000001fULL));
        uint64_t mask = ((lane_bits == 8) ? 0x00000000000000ffULL : ((lane_bits == 16) ? 0x000000000000ffffULL : ((lane_bits == 32) ? 0x00000000ffffffffULL : 0xffffffffffffffffULL)));
        size_t bit = 0;
        while (bit < bits) {
                        size_t chunk = (bit / 64);
                        uint32_t shift = static_cast<uint32_t>((bit % 64));
                        uint64_t a = ((ctx.get_vreg_lane(src, chunk) >> shift) & mask);
                        int64_t sa = ((lane_bits == 8) ? static_cast<int64_t>(((int8_t)(a))) : ((lane_bits == 16) ? static_cast<int64_t>(((int16_t)(a))) : ((lane_bits == 32) ? static_cast<int64_t>(((int32_t)(a))) : static_cast<int64_t>(a))));
                        uint64_t value = 0x0000000000000000ULL;
                        switch (vop) {
                                        case 6: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a << cnt));
                                                          break;
                                                     }
                                        }
                                        case 7: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? 0x0000000000000000ULL : (a >> cnt));
                                                          break;
                                                     }
                                        }
                                        case 8: {
                                                     {
                                                          uint32_t cnt = static_cast<uint32_t>(imm_val);
                                                          value = ((cnt >= lane_bits) ? ((sa < 0) ? mask : 0x0000000000000000ULL) : (static_cast<uint64_t>((sa >> cnt)) & mask));
                                                          break;
                                                     }
                                        }
                                        case 21: {
                                                      {
                                                           size_t lane_in_128 = ((bit / 32) % 4);
                                                           size_t sel = ((imm_val >> (lane_in_128 * 2)) & 0x0000000000000003ULL);
                                                           size_t src_bit = (((bit / 128) * 128) + (sel * 32));
                                                           value = ((ctx.get_vreg_lane(src, (src_bit / 64)) >> (src_bit % 64)) & 0x00000000ffffffffULL);
                                                           break;
                                                      }
                                        }
                                        case 22: {
                                                      {
                                                           size_t lane_idx = (bit / lane_bits);
                                                           size_t sel = ((imm_val >> (lane_idx % 8)) & 0x0000000000000001ULL);
                                                           value = ((sel == 0) ? a : ((ctx.get_vreg_lane(dst, chunk) >> shift) & mask));
                                                           break;
                                                      }
                                        }
                                        default: {
                                                      value = a;
                                                      break;
                                        }
                        }
                        uint64_t old_value = ctx.get_vreg_lane(dst, chunk);
                        uint64_t packed_mask = (mask << shift);
                        ctx.set_vreg_lane(dst, chunk, ((old_value & (~packed_mask)) | ((value & mask) << shift)));
                        bit += lane_bits;
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_CLEAR_UPPER_D3: {
        ctx.set_vreg_lane(dst, 2, 0x0000000000000000ULL);
        ctx.set_vreg_lane(dst, 3, 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_ZERO_UPPER_D3: {
        for (size_t i = 0; i < 16; ++i) {
                                     ctx.set_vreg_lane(i, 2, 0x0000000000000000ULL);
                                     ctx.set_vreg_lane(i, 3, 0x0000000000000000ULL);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_PMOVMSKB_D3: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x00000000000003ffULL));
        uint32_t num_bytes = (bits / 8);
        uint64_t mask = 0x0000000000000000ULL;
        for (size_t b_idx = 0; b_idx < num_bytes; ++b_idx) {
                                                        uint64_t byte_val = ((ctx.get_vreg_lane(src, (b_idx / 8)) >> ((b_idx % 8) * 8)) & 0x00000000000000ffULL);
                                                        if ((byte_val & 0x0000000000000080ULL) != 0x0000000000000000ULL) {
                                                        
                                                            mask |= (0x0000000000000001ULL << b_idx);
                                                        }
}
        ctx.set_reg(dst, mask);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_LOAD_D3: {
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x00000000000003ffULL));
        uint64_t address = (ctx.get_reg(src) + static_cast<uint64_t>(imm));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     uint64_t value = 0x0000000000000000ULL;
                                                     std::memcpy((&value), reinterpret_cast<const void*>((address + (i * 8))), sizeof(value));
                                                     ctx.set_vreg_lane(dst, i, value);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_STORE_D3: {
        uint32_t bits = static_cast<uint32_t>(((word >> 50) & 0x00000000000003ffULL));
        uint64_t address = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        for (size_t i = 0; i < ((bits + 63) / 64); ++i) {
                                                     std::memcpy(reinterpret_cast<void*>((address + (i * 8))), (&ctx.vregs[(src & 31)][(i & 7)]), sizeof(uint64_t));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_SPLAT_D3: {
        uint32_t bits = static_cast<uint32_t>((imm & 0x000000000000ffffULL));
        uint32_t lane_bits = static_cast<uint32_t>(((imm >> 16) & 0x000000000000ffffULL));
        uint64_t val = ctx.get_reg(src);
        uint64_t mask = ((lane_bits >= 64) ? 0xffffffffffffffffULL : ((0x0000000000000001ULL << lane_bits) - 0x0000000000000001ULL));
        uint64_t val_masked = (val & mask);
        uint32_t num_lanes = ((lane_bits > 0) ? (bits / lane_bits) : 0);
        for (size_t l = 0; l < num_lanes; ++l) {
                                            uint32_t pos = (l * lane_bits);
                                            uint32_t chunk = (pos / 64);
                                            uint32_t shift = (pos % 64);
                                            uint64_t packed_mask = ((lane_bits >= 64) ? 0xffffffffffffffffULL : (mask << shift));
                                            uint64_t cur = ctx.get_vreg_lane(dst, chunk);
                                            cur = ((cur & (~packed_mask)) | (val_masked << shift));
                                            ctx.set_vreg_lane(dst, chunk, cur);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_VEC_EXT_D3: {
        uint32_t src2 = static_cast<uint32_t>((imm & 0x000000000000001fULL));
        uint32_t shift_bytes = static_cast<uint32_t>(((imm >> 5) & 0x000000000000000fULL));
        uint32_t bits = static_cast<uint32_t>(((imm >> 9) & 0x00000000000003ffULL));
        if (bits == 0) {
                    bits = 128;
}
        for (size_t byte_idx = 0; byte_idx < (bits / 8); ++byte_idx) {
                                                                  size_t total_idx = ((byte_idx % 16) + shift_bytes);
                                                                  uint64_t val = 0x0000000000000000ULL;
                                                                  if (total_idx < 16) {
                                                                  
                                                                    size_t bit_pos = (((byte_idx / 16) * 128) + (total_idx * 8));
                                                                    val = ((ctx.get_vreg_lane(src, (bit_pos / 64)) >> (bit_pos % 64)) & 0x00000000000000ffULL);
                                                                  } else {
                                                                  
                                                                    size_t m_idx = (total_idx - 16);
                                                                    size_t bit_pos = (((byte_idx / 16) * 128) + (m_idx * 8));
                                                                    val = ((ctx.get_vreg_lane(src2, (bit_pos / 64)) >> (bit_pos % 64)) & 0x00000000000000ffULL);
                                                                  }
                                                                  size_t chunk = ((byte_idx * 8) / 64);
                                                                  uint32_t shift = static_cast<uint32_t>(((byte_idx * 8) % 64));
                                                                  uint64_t old_v = ctx.get_vreg_lane(dst, chunk);
                                                                  uint64_t clr = (old_v & (~((0x00000000000000ffULL << shift))));
                                                                  ctx.set_vreg_lane(dst, chunk, (clr | (val << shift)));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_CALL_EXTERN_D3: {
        size_t sym_idx = ((size_t)(imm));
        void* sym_ptr = asgard_resolve_sym_idx(((int32_t)(sym_idx)));
        if (sym_ptr) {
                  uint32_t sym_h = g_external_symbols[sym_idx].hash;
                  uint32_t sym_ah = g_external_symbols[sym_idx].alt_hash;
                  
                  #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
                  uint64_t a0 = ctx.get_reg(REG_RAX);
                  uint64_t a1 = ctx.get_reg(REG_RCX);
                  uint64_t a2 = ctx.get_reg(REG_RDX);
                  uint64_t a3 = ctx.get_reg(REG_RBX);
                  uint64_t a4 = ctx.get_reg(REG_RSI);
                  uint64_t a5 = ctx.get_reg(REG_RDI);
                  uint64_t a6 = ctx.get_reg(REG_R8);
                  uint64_t a7 = ctx.get_reg(REG_R9);
                  #elif defined(ASGARD_GUEST_RISCV64)
                  uint64_t a0 = ctx.get_reg(REG_RAX);
                  uint64_t a1 = ctx.get_reg(REG_RDX);
                  uint64_t a2 = ctx.get_reg(REG_RCX);
                  uint64_t a3 = ctx.get_reg(REG_RSI);
                  uint64_t a4 = ctx.get_reg(REG_RDI);
                  uint64_t a5 = ctx.get_reg(REG_R8);
                  uint64_t a6 = ctx.get_reg(REG_R9);
                  uint64_t a7 = ctx.get_reg(REG_R12);
                  #else
                  uint64_t a0 = (ctx.get_reg(REG_RDI) ? ctx.get_reg(REG_RDI) : ctx.get_reg(REG_RAX));
                  uint64_t a1 = ctx.get_reg(REG_RSI);
                  uint64_t a2 = ctx.get_reg(REG_RDX);
                  uint64_t a3 = ctx.get_reg(REG_RCX);
                  uint64_t a4 = ctx.get_reg(REG_R8);
                  uint64_t a5 = ctx.get_reg(REG_R9);
                  uint64_t a6 = ctx.get_reg(REG_RAX);
                  uint64_t a7 = ctx.get_reg(REG_RBX);
                  #endif
                  
                  const uint64_t* stk = reinterpret_cast<const uint64_t*>(ctx.get_reg(REG_RSP));
                  uint64_t ret_val = 0x0000000000000000ULL;
                  if ((((((sym_h == 0x42fcf5cfU) || (sym_ah == 0x42fcf5cfU)) || (sym_h == 0x07554acdU)) || (sym_ah == 0x07554acdU)) || (sym_h == 0xe76fb4aaU)) || (sym_ah == 0xe76fb4aaU)) {
                  
                      typedef int (*printf_fn_t)(const char*, ...);
                      printf_fn_t pfn = reinterpret_cast<printf_fn_t>(sym_ptr);
                      
                      #if defined(__APPLE__) && defined(__aarch64__)
                      ret_val = ((uint64_t)(pfn(((const char*)(a0)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                      #else
                      ret_val = ((uint64_t)(pfn(((const char*)(a0)), a1, a2, a3, a4, a5, a6, a7)));
                      #endif
                      
                  } else {
                              if ((((((((((((((((sym_h == 0xfcb512e2U) || (sym_ah == 0xfcb512e2U)) || (sym_h == 0x4b3c5330U)) || (sym_ah == 0x4b3c5330U)) || (sym_h == 0x937d1ef6U)) || (sym_ah == 0x937d1ef6U)) || (sym_h == 0xcb76d42bU)) || (sym_ah == 0xcb76d42bU)) || (sym_h == 0xd54ce817U)) || (sym_ah == 0xd54ce817U)) || (sym_h == 0xbbed3905U)) || (sym_ah == 0xbbed3905U)) || (sym_h == 0x42c07c7cU)) || (sym_ah == 0x42c07c7cU)) || (sym_h == 0x24559dbdU)) || (sym_ah == 0x24559dbdU)) {
                              
                                  typedef int (*fprintf_fn_t)(void*, const char*, ...);
                                  fprintf_fn_t fpfn = reinterpret_cast<fprintf_fn_t>(sym_ptr);
                                  
                                  #if defined(__APPLE__) && defined(__aarch64__)
                                  ret_val = ((uint64_t)(fpfn(((void*)(a0)), ((const char*)(a1)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                  #else
                                  ret_val = ((uint64_t)(fpfn(((void*)(a0)), ((const char*)(a1)), a2, a3, a4, a5, a6, a7)));
                                  #endif
                                  
                              } else {
                                          if ((((((((sym_h == 0x7fe32b00U) || (sym_ah == 0x7fe32b00U)) || (sym_h == 0xbcbf60eeU)) || (sym_ah == 0xbcbf60eeU)) || (sym_h == 0x70e2d349U)) || (sym_ah == 0x70e2d349U)) || (sym_h == 0x44fa3468U)) || (sym_ah == 0x44fa3468U)) {
                                          
                                              typedef int (*sprintf_fn_t)(char*, const char*, ...);
                                              sprintf_fn_t spfn = reinterpret_cast<sprintf_fn_t>(sym_ptr);
                                              
                                              #if defined(__APPLE__) && defined(__aarch64__)
                                              ret_val = ((uint64_t)(spfn(((char*)(a0)), ((const char*)(a1)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                              #else
                                              ret_val = ((uint64_t)(spfn(((char*)(a0)), ((const char*)(a1)), a2, a3, a4, a5, a6, a7)));
                                              #endif
                                              
                                          } else {
                                                      if ((((((((sym_h == 0x54ee11faU) || (sym_ah == 0x54ee11faU)) || (sym_h == 0x933075f4U)) || (sym_ah == 0x933075f4U)) || (sym_h == 0x3fd5eb6fU)) || (sym_ah == 0x3fd5eb6fU)) || (sym_h == 0x5b3553b4U)) || (sym_ah == 0x5b3553b4U)) {
                                                      
                                                          typedef int (*snprintf_fn_t)(char*, size_t, const char*, ...);
                                                          snprintf_fn_t snpfn = reinterpret_cast<snprintf_fn_t>(sym_ptr);
                                                          
                                                          #if defined(__APPLE__) && defined(__aarch64__)
                                                          ret_val = ((uint64_t)(snpfn(((char*)(a0)), ((size_t)(a1)), ((const char*)(a2)), stk[0], stk[1], stk[2], stk[3], stk[4], stk[5], stk[6], stk[7])));
                                                          #else
                                                          ret_val = ((uint64_t)(snpfn(((char*)(a0)), ((size_t)(a1)), ((const char*)(a2)), a3, a4, a5, a6, a7)));
                                                          #endif
                                                          
                                                      } else {
                                                                  typedef uint64_t (*extern_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
                                                                  extern_fn_t fn = reinterpret_cast<extern_fn_t>(sym_ptr);
                                                                  ret_val = fn(a0, a1, a2, a3, a4, a5, a6, a7);
                                                      }
                                          }
                              }
                  }
                  ctx.set_reg(REG_RAX, ret_val);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_64_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint64_t _val = asgard::oblivious_mem::oblivious_load_u64(_addr);
ctx.set_reg(dst, _val);
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint64_t _v = 0x0000000000000000ULL;
std::memcpy((&_v), reinterpret_cast<const void*>(_ptr), sizeof(uint64_t));
ctx.set_reg(dst, _v);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_32_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(asgard::oblivious_mem::oblivious_load_u32(static_cast<uintptr_t>(addr)))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint32_t _v32 = 0x00000000U;
std::memcpy((&_v32), reinterpret_cast<const void*>(_ptr), sizeof(uint32_t));
ctx.set_reg(dst, ((uint64_t)(_v32)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_16_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _addr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint16_t _v16 = asgard::oblivious_mem::oblivious_load_u16(_addr);
ctx.set_reg(dst, ((uint64_t)(_v16)));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)((*(reinterpret_cast<const uint16_t*>(addr))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_8_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(asgard::oblivious_mem::oblivious_load_u8(static_cast<uintptr_t>(addr)))));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(src)) + static_cast<uintptr_t>(imm));
uint8_t _v8 = 0x00;
std::memcpy((&_v8), reinterpret_cast<const void*>(_ptr), sizeof(uint8_t));
ctx.set_reg(dst, ((uint64_t)(_v8)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S32_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(((int32_t)(asgard::oblivious_mem::oblivious_load_u32(static_cast<uintptr_t>(addr)))))))));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int32_t*>(addr))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S16_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(((int16_t)(asgard::oblivious_mem::oblivious_load_u16(static_cast<uintptr_t>(addr)))))))));
#else
const char* _base = reinterpret_cast<const char*>(ctx.get_reg(src));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int16_t*>((_base + imm)))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_LOAD_S8_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)(((int8_t)(asgard::oblivious_mem::oblivious_load_u8(static_cast<uintptr_t>(addr)))))))));
#else
uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
ctx.set_reg(dst, ((uint64_t)(((int64_t)((*(reinterpret_cast<const int8_t*>(addr))))))));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_64_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
asgard::oblivious_mem::oblivious_store_u64(static_cast<uintptr_t>(addr), ctx.get_reg(src), (&ctx.decoy_sink));
#else
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
(*(reinterpret_cast<uint64_t*>(addr))) = ctx.get_reg(src);
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_32_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
asgard::oblivious_mem::oblivious_store_u32(static_cast<uintptr_t>(addr), ((uint32_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
(*(reinterpret_cast<uint32_t*>(addr))) = ((uint32_t)(ctx.get_reg(src)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_16_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
asgard::oblivious_mem::oblivious_store_u16(static_cast<uintptr_t>(addr), ((uint16_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
uint16_t _v16 = ((uint16_t)(ctx.get_reg(src)));
std::memcpy(reinterpret_cast<void*>(_ptr), (&_v16), sizeof(uint16_t));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_STORE_8_D3: {
        
#if defined(ASGARD_OBLIVIOUS_MEM)
uintptr_t _ptr = (static_cast<uintptr_t>(ctx.get_reg(dst)) + static_cast<uintptr_t>(imm));
asgard::oblivious_mem::oblivious_store_u8(_ptr, ((uint8_t)(ctx.get_reg(src))), (&ctx.decoy_sink));
#else
uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
(*(reinterpret_cast<uint8_t*>(addr))) = ((uint8_t)(ctx.get_reg(src)));
#endif

        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_RESOLVE_SYM_D3: {
        size_t sym_idx = ((size_t)(imm));
        void* sym_ptr = asgard_resolve_sym_idx(((int32_t)(sym_idx)));
        ctx.set_reg(dst, ((uint64_t)(sym_ptr)));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FADD_DD_D3: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((std::bit_cast<double>(_s) + std::bit_cast<double>(_i))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FSUB_DD_D3: {
        double _a = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
        double _b = std::bit_cast<double>(ctx.get_vreg_lane(static_cast<uint8_t>(imm), 0));
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((_a - _b)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FMUL_DD_D3: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        uint64_t b_raw = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        double a = std::bit_cast<double>(a_raw);
        double b = std::bit_cast<double>(b_raw);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>((a * b)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FDIV_DD_D3: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        double a = std::bit_cast<double>(_s);
        double b = std::bit_cast<double>(_i);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((b != 0.0) ? (a / b) : 0.0)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FSQRT_D_D3: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        double a = std::bit_cast<double>(_s);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((a >= 0.0) ? std::sqrt(a) : 0.0)), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCMP_DD_D3: {
        uint64_t _s = ctx.get_vreg_lane(src, 0);
        uint64_t _i = ctx.get_vreg_lane(((uint8_t)(imm)), 0);
        double a = std::bit_cast<double>(_s);
        double b = std::bit_cast<double>(_i);
        bool _nan = (std::isnan(a) || std::isnan(b));
        bool _eq = (a == b);
        bool _lt = (a < b);
        ctx.zf = (_nan || _eq);
        ctx.cf = (_nan || _lt);
        ctx.pf = _nan;
        ctx.sf = false;
        ctx.of = false;
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVTZS_D3: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        double a = std::bit_cast<double>(a_raw);
        ctx.set_reg(dst, ((uint64_t)(((int64_t)(a)))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_SCVTF_D3: {
        int64_t _s = static_cast<int64_t>(ctx.get_reg(src));
        double _d = static_cast<double>(_s);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(_d), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVTZU_D3: {
        uint64_t a_raw = ctx.get_vreg_lane(src, 0);
        double a = std::bit_cast<double>(a_raw);
        ctx.set_reg(dst, ((a < 0.0) ? 0x0000000000000000ULL : ((uint64_t)(a))));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_UCVTF_D3: {
        uint64_t _v = ctx.get_reg(src);
        ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(_v))), 0x0000000000000000ULL);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCVT_D3: {
        if (((uint32_t)(imm)) == 1) {
                                 double d64 = std::bit_cast<double>(ctx.get_vreg_lane(src, 0));
                                 float f32 = ((float)(d64));
                                 uint32_t u32 = std::bit_cast<uint32_t>(f32);
                                 ctx.set_vreg(dst, ((ctx.get_vreg_lane(dst, 0) & 0xffffffff00000000ULL) | ((uint64_t)(u32))), 0x0000000000000000ULL);
} else {
            float f32 = std::bit_cast<float>(((uint32_t)(ctx.get_vreg_lane(src, 0))));
            ctx.set_vreg(dst, std::bit_cast<uint64_t>(((double)(f32))), 0x0000000000000000ULL);
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_LOAD_D3: {
        uint64_t addr = (ctx.get_reg(src) + ((uint64_t)(imm)));
        std::atomic<uint64_t>* ptr = reinterpret_cast<std::atomic<uint64_t>*>(addr);
        ctx.set_reg(dst, ptr->load(std::memory_order_seq_cst));
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_STORE_D3: {
        uint64_t _addr = (ctx.get_reg(dst) + static_cast<uint64_t>(imm));
        __atomic_store_n(reinterpret_cast<uint64_t*>(_addr), ctx.get_reg(src), __ATOMIC_SEQ_CST);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_CAS_D3: {
        std::atomic<uint64_t>* ptr = reinterpret_cast<std::atomic<uint64_t>*>((ctx.get_reg(dst) + ((uint64_t)(imm))));
        uint64_t expected = ctx.get_reg(src);
        while (!ptr->compare_exchange_weak(expected, ctx.get_reg(REG_RAX), std::memory_order_seq_cst, std::memory_order_seq_cst)) {

    if (expected != ctx.get_reg(src)) {
                                           break;
    }
}
        ctx.set_reg(src, expected);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_ADD_D3: {
        uint64_t* ptr = reinterpret_cast<uint64_t*>((ctx.get_reg(dst) + ((uint64_t)(imm))));
        uint64_t old = __atomic_load_n(ptr, __ATOMIC_RELAXED);
        uint64_t add_val = ctx.get_reg(src);
        while (!__atomic_compare_exchange_n(ptr, (&old), (old + add_val), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {

    
}
        ctx.set_reg(src, old);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_ATOMIC_SWP_D3: {
        uint64_t addr = (ctx.get_reg(dst) + ((uint64_t)(imm)));
        std::atomic<uint64_t>* ptr = reinterpret_cast<std::atomic<uint64_t>*>(addr);
        uint64_t old = ptr->exchange(ctx.get_reg(src), std::memory_order_seq_cst);
        ctx.set_reg(src, old);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FENCE_D3: { std::atomic_thread_fence(std::memory_order_seq_cst); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_VR_D3: { ctx.set_vreg_lane(dst, 0, ctx.get_reg(src)); ctx.executed_instructions++; FETCH_NEXT(); }
    H_MOV_RV_D3: {
        uint64_t _val = ctx.get_vreg_lane(src, 0);
        uint64_t _buf[1];
        std::memcpy(_buf, (&_val), sizeof(uint64_t));
        ctx.set_reg(dst, _buf[0]);
        ctx.executed_instructions++;
        FETCH_NEXT();
    }
    H_FCSEL_VV_D3: {
        uint8_t cond = ((uint8_t)((((word >> 18) + 0x000000000000000fULL) - ((word >> 18) | 0x000000000000000fULL))));
        if (eval_condition(ctx, cond)) {
                                    ctx.set_vreg_lane(dst, 0, ctx.get_vreg_lane(src, 0));
}
        ctx.executed_instructions++;
        FETCH_NEXT();
    }


                                    EXIT_VM:
                                    if (__builtin_expect(asg_vm_trace_on, 0)) { fputs("# E\n", stderr); }
                                        for (size_t i = 0; i < count; ++i) {
        SCRUB_WORD(&work_bc[i], 0x5A5A5A5A13375877ULL ^ ((uint64_t)seed + (uint64_t)i));
    }
                                        if (scrub_source && bytecode) {
        for (size_t i = 0; i < count; ++i) {
            SCRUB_WORD(&const_cast<uint64_t*>(bytecode)[i], 0xDEADBEEFCAFEBABEULL ^ ((uint64_t)seed + (uint64_t)i));
        }
    }
                                    if (heap_work_bc != nullptr) {
                                                                    free(heap_work_bc);
                                    }
                                    
                                    #undef DISPATCH_OPCODE
                                    
                                    
                                    #undef FETCH_NEXT
                                    
                                    return (!ctx.trapped);
                                }
                                
                                static inline bool execute_threaded(VMContext& ctx, const uint64_t* bytecode, size_t count, bool scrub_source) {
                                
                                    return execute_threaded(ctx, bytecode, count, asgard_wbox_derive_seed(), scrub_source);
                                }
                                
                                static inline __attribute__((noinline)) uint64_t asgard_vm_call(const uint64_t* bc, size_t len, uint64_t a0 = 0, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0, uint64_t a4 = 0, uint64_t a5 = 0, uint64_t a6 = 0, uint64_t a7 = 0) {
                                
                                    vanguard_threaded_vm::VMContext ctx = {};
                                    ctx.init(asgard_wbox_derive_seed());
                                    alignas(16) static thread_local uint8_t host_stack[1048576];
                                    ctx.set_reg(vanguard_threaded_vm::REG_RSP, ((uint64_t)(((host_stack + sizeof(host_stack)) - 0x0000000000002000ULL))));
                                    ctx.set_reg(vanguard_threaded_vm::REG_RBP, ((uint64_t)(((host_stack + sizeof(host_stack)) - 0x0000000000002000ULL))));
                                    #if defined(ASGARD_GUEST_ARM64) || (!defined(ASGARD_GUEST_X86_64) && !defined(ASGARD_GUEST_RISCV64) && (defined(__aarch64__) || defined(_M_ARM64)))
    // ARM64 guest calling convention mapping (x0->RAX, x1->RCX, x2->RDX, x3->RBX, x4->RSI, x5->RDI, x6->R8, x7->R9)
    ctx.set_reg(vanguard_threaded_vm::REG_RAX, a0);
    ctx.set_reg(vanguard_threaded_vm::REG_RCX, a1);
    ctx.set_reg(vanguard_threaded_vm::REG_RDX, a2);
    ctx.set_reg(vanguard_threaded_vm::REG_RBX, a3);
    ctx.set_reg(vanguard_threaded_vm::REG_RSI, a4);
    ctx.set_reg(vanguard_threaded_vm::REG_RDI, a5);
    ctx.set_reg(vanguard_threaded_vm::REG_R8,  a6);
    ctx.set_reg(vanguard_threaded_vm::REG_R9,  a7);
#elif defined(ASGARD_GUEST_RISCV64)
    // RISC-V LP64 ABI argument mapping (a0->RAX, a1->RDX, a2->RCX, a3->RSI, a4->RDI, a5->R8, a6->R9, a7->R12)
    ctx.set_reg(vanguard_threaded_vm::REG_RAX, a0);
    ctx.set_reg(vanguard_threaded_vm::REG_RDX, a1);
    ctx.set_reg(vanguard_threaded_vm::REG_RCX, a2);
    ctx.set_reg(vanguard_threaded_vm::REG_RSI, a3);
    ctx.set_reg(vanguard_threaded_vm::REG_RDI, a4);
    ctx.set_reg(vanguard_threaded_vm::REG_R8,  a5);
    ctx.set_reg(vanguard_threaded_vm::REG_R9,  a6);
    ctx.set_reg(vanguard_threaded_vm::REG_R12, a7);
#else
    // x86_64 guest calling convention (System V / Windows x64 ABI argument registers)
    ctx.set_reg(vanguard_threaded_vm::REG_RDI, a0);
    ctx.set_reg(vanguard_threaded_vm::REG_RSI, a1);
    ctx.set_reg(vanguard_threaded_vm::REG_RDX, a2);
    ctx.set_reg(vanguard_threaded_vm::REG_RCX, a3);
    ctx.set_reg(vanguard_threaded_vm::REG_R8,  a4);
    ctx.set_reg(vanguard_threaded_vm::REG_R9,  a5);
    ctx.set_reg(vanguard_threaded_vm::REG_RAX, 0);
#endif
                                    vanguard_threaded_vm::execute_threaded(ctx, bc, len, asgard_wbox_derive_seed(), false);
                                    uint64_t ret_val = ctx.get_rax();
                                    if (__builtin_expect(ctx.trapped || ctx.canary_head != vanguard_threaded_vm::VMContext::CANARY_VAL || ctx.canary_tail != vanguard_threaded_vm::VMContext::CANARY_VAL, 0)) {
        ret_val ^= 0xDEADBEEF5A5A5A5AULL ^ ctx.reg_mask;
    }
                                    return (((ret_val ^ 0x5877cafe1337beefULL) + (0x0000000000000002ULL * (ret_val & 0x5877cafe1337beefULL))) - 0x5877cafe1337beefULL);
                                }

} // namespace vanguard_threaded_vm

