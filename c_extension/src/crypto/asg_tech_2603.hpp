#pragma once
// ============================================================================

// ASGARD-5877: Tech-2603 (arXiv:2603.18355)

// Anti-VPC-Tracking & Non-Linear Dispatch Runtime

// Thwarts PUSHAN/VM-Doctor heuristic VPC identification via:

//   1. Non-linear affine bijective VPC hopping: next_vpc = (a * vpc + b) & mask

//   2. Dual-variable Split-VPC: physical_slot = masked ^ (key & 0x7FFFFFFF)

//   3. Decoy padding with entropy whitening

// ============================================================================

#include <cstdint>

#include <cstddef>

#include <bit>

namespace asgard::tech_2603 {
                             
                             struct alignas(16) SplitVPC {
                                                              uint64_t key = 0x0000000000000000ULL;
                                                              uint64_t masked = 0x0000000000000000ULL;
                                                              uint32_t epoch = 0x00000000U;
                                                              static inline constexpr uint64_t MASK_31 = 0x000000007fffffffULL;
                                                              __attribute__((always_inline)) inline size_t resolve() const noexcept {
                                                              
                                                                  const uint64_t key_low = (key & MASK_31);
                                                                  return static_cast<size_t>((masked ^ key_low));
                                                              }
                                                              __attribute__((always_inline)) inline void advance(size_t next_slot, uint64_t dynamic_key) noexcept {
                                                              
                                                                  epoch += 1;
                                                                  // SplitMix64 evolution of the key state
                                                                  uint64_t s = (key ^ (dynamic_key ^ (static_cast<uint64_t>(epoch) * 0x9e3779b97f4a7c15ULL)));
                                                                  s += 0x9e3779b97f4a7c15ULL;
                                                                  uint64_t z = s;
                                                                  z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL);
                                                                  z = ((z ^ (z >> 27)) * 0x94d049bb133111ebULL);
                                                                  key = (z ^ (z >> 31));
                                                                  const uint64_t key_low = (key & MASK_31);
                                                                  masked = (static_cast<uint64_t>(next_slot) ^ key_low);
                                                              }
                                                              
                             };
                             
                             template <size_t Capacity>
                             struct NonLinearVPCDispatcher {
                                                                static_assert(((Capacity & (Capacity - 1)) == 0), "Capacity must be power-of-two");
                                                                static inline constexpr size_t MASK = (Capacity - 1);
                                                                uint64_t a_mul = 1;
                                                                uint64_t a_inv = 1;
                                                                uint64_t b_add = 0;
                                                                const int32_t* successor_lut = nullptr;
                                                                [[nodiscard]] constexpr size_t logical_to_physical(size_t logical_idx) const noexcept {
                                                                
                                                                    return (((logical_idx * a_mul) + b_add) & MASK);
                                                                }
                                                                [[nodiscard]] constexpr size_t physical_to_logical(size_t physical_idx) const noexcept {
                                                                
                                                                    return (((physical_idx - b_add) * a_inv) & MASK);
                                                                }
                                                                [[nodiscard]] inline size_t next_physical(size_t current_physical) const noexcept {
                                                                
                                                                    if (successor_lut != nullptr) {
                                                                    
                                                                    int32_t succ = successor_lut[(current_physical & MASK)];
                                                                    return ((succ >= 0) ? static_cast<size_t>(succ) : current_physical);
                                                                    }
                                                                    // Direct affine stepping: i -> i + 1 in logical space
                                                                    size_t logical = physical_to_logical(current_physical);
                                                                    return logical_to_physical((logical + 1));
                                                                }
                                                                
                             };

} // namespace asgard::tech_2603
