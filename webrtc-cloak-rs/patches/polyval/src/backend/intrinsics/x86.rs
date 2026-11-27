//! PCLMULQDQ / VPCLMULQDQ optimized POLYVAL implementation using R/F Algorithm
//! Adapted from the implementation in the Apache 2.0 + MIT-licensed HPCrypt library
//! Copyright (c) 2024 HPCrypt Contributors
//!
//! Uses two-tier runtime dispatch on x86/x86_64:
//! - Tier 1 (`avx` + `pclmulqdq`): 3-operand VEX-encoded `vpclmulqdq` fast path
//! - Tier 2 (`sse2` + `pclmulqdq`): 2-operand Legacy SSE `pclmulqdq` fast path for
//!   non-AVX CPUs that still implement hardware AES-NI + CLMUL
//!
//! Uses the R/F algorithm from "Efficient GHASH Implementation Using CLMUL":
//! - 4 CLMULs per block for multiplication (R and F terms)
//! - 1 CLMUL for reduction (Lemma 3)
//! - 4-block aggregated processing with single reduction
//!
//! <https://eprint.iacr.org/2025/2171.pdf>

#![allow(unsafe_op_in_unsafe_fn)]

use super::ExpandedKey;
use crate::{Block, ParBlocks, field_element::FieldElement};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// P1 polynomial: x^63 + x^62 + x^57 = 0xC200000000000000
const P1: u64 = 0xC200000000000000;

cpufeatures::new!(clmul_avx, "avx", "pclmulqdq");
cpufeatures::new!(clmul_sse, "sse2", "pclmulqdq");

/// Two-tier CPU feature token covering both VEX (`avx`+`pclmulqdq`) and
/// Legacy SSE (`sse2`+`pclmulqdq`) hardware CLMUL backends.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InitToken {
    avx: clmul_avx::InitToken,
    sse: clmul_sse::InitToken,
}

impl InitToken {
    #[inline]
    pub(crate) fn init_get() -> (Self, bool) {
        let (avx, has_avx) = clmul_avx::init_get();
        let (sse, has_sse) = clmul_sse::init_get();
        (Self { avx, sse }, has_avx || has_sse)
    }

    #[inline]
    pub(crate) fn get(&self) -> bool {
        self.avx.get() || self.sse.get()
    }
}

/// Returns the active x86 POLYVAL backend name at runtime.
#[inline]
pub(super) fn backend_name() -> &'static str {
    if clmul_avx::get() {
        "avx+pclmulqdq"
    } else if clmul_sse::get() {
        "sse2+pclmulqdq"
    } else {
        "soft"
    }
}

/// Byte array which is the inner type of `FieldElement`
type ByteArray = [u8; 16];

impl FieldElement {
    #[target_feature(enable = "sse2")]
    #[inline]
    unsafe fn from_m128i(reg: __m128i) -> Self {
        let mut out = ByteArray::default();
        _mm_storeu_si128(out.as_mut_ptr().cast(), reg);
        out.into()
    }

    #[target_feature(enable = "sse2")]
    #[inline]
    unsafe fn to_m128i(self) -> __m128i {
        load_bytes(&self.into())
    }
}

/// Convert 16 bytes into `__m128i`.
///
/// # Safety
/// Requires SSE2 support
#[target_feature(enable = "sse2")]
#[inline]
unsafe fn load_bytes(bytes: &ByteArray) -> __m128i {
    _mm_loadu_si128(bytes.as_ptr().cast())
}

macro_rules! impl_clmul_tier {
    ($mod_name:ident, $($tf:literal),+) => {
        mod $mod_name {
            use super::*;

            #[target_feature($(enable = $tf),+)]
            #[inline]
            pub(super) unsafe fn proc_block(
                key: &ExpandedKey,
                acc: FieldElement,
                block: &Block,
            ) -> FieldElement {
                let data = load_bytes(&block.0);
                let y = _mm_xor_si128(acc.to_m128i(), data);
                FieldElement::from_m128i(gf128_mul_rf(y, key.h1.to_m128i(), key.d1.to_m128i()))
            }

            #[target_feature($(enable = $tf),+)]
            #[inline]
            pub(super) unsafe fn proc_par_blocks(
                key: &ExpandedKey,
                acc: FieldElement,
                par_blocks: &ParBlocks,
            ) -> FieldElement {
                let m0 = load_bytes(&par_blocks[0].0);
                let m1 = load_bytes(&par_blocks[1].0);
                let m2 = load_bytes(&par_blocks[2].0);
                let m3 = load_bytes(&par_blocks[3].0);

                let y0 = _mm_xor_si128(acc.to_m128i(), m0);

                let (r0, f0) = rf_mul_unreduced(y0, key.h4.to_m128i(), key.d4.to_m128i());
                let (r1, f1) = rf_mul_unreduced(m1, key.h3.to_m128i(), key.d3.to_m128i());
                let (r2, f2) = rf_mul_unreduced(m2, key.h2.to_m128i(), key.d2.to_m128i());
                let (r3, f3) = rf_mul_unreduced(m3, key.h1.to_m128i(), key.d1.to_m128i());

                let r = _mm_xor_si128(_mm_xor_si128(r0, r1), _mm_xor_si128(r2, r3));
                let f = _mm_xor_si128(_mm_xor_si128(f0, f1), _mm_xor_si128(f2, f3));

                FieldElement::from_m128i(reduce_rf(r, f))
            }

            #[target_feature($(enable = $tf),+)]
            pub(super) unsafe fn expand_key(h: &[u8; 16]) -> ExpandedKey {
                let h1 = load_bytes(h);
                let d1 = compute_d(h1);

                let h2 = gf128_mul_rf(h1, h1, d1);
                let d2 = compute_d(h2);

                let h3 = gf128_mul_rf(h2, h1, d1);
                let d3 = compute_d(h3);

                let h4 = gf128_mul_rf(h2, h2, d2);
                let d4 = compute_d(h4);

                ExpandedKey {
                    h1: FieldElement::from_m128i(h1),
                    d1: FieldElement::from_m128i(d1),
                    h2: FieldElement::from_m128i(h2),
                    d2: FieldElement::from_m128i(d2),
                    h3: FieldElement::from_m128i(h3),
                    d3: FieldElement::from_m128i(d3),
                    h4: FieldElement::from_m128i(h4),
                    d4: FieldElement::from_m128i(d4),
                }
            }

            #[target_feature($(enable = $tf),+)]
            #[inline]
            unsafe fn compute_d(h: __m128i) -> __m128i {
                #[allow(clippy::cast_possible_wrap)]
                let p = _mm_set_epi64x(P1 as i64, 0);
                let h_swap = _mm_shuffle_epi32(h, 0x4e);
                let t = _mm_clmulepi64_si128(h, p, 0x10);
                _mm_xor_si128(h_swap, t)
            }

            #[target_feature($(enable = $tf),+)]
            #[inline]
            unsafe fn rf_mul_unreduced(m: __m128i, h: __m128i, d: __m128i) -> (__m128i, __m128i) {
                let r0 = _mm_clmulepi64_si128(m, d, 0x10);
                let r1 = _mm_clmulepi64_si128(m, h, 0x11);
                let r = _mm_xor_si128(r0, r1);

                let f0 = _mm_clmulepi64_si128(m, d, 0x00);
                let f1 = _mm_clmulepi64_si128(m, h, 0x01);
                let f = _mm_xor_si128(f0, f1);

                (r, f)
            }

            #[target_feature($(enable = $tf),+)]
            #[inline]
            unsafe fn reduce_rf(r: __m128i, f: __m128i) -> __m128i {
                #[allow(clippy::cast_possible_wrap)]
                let p1 = _mm_set_epi64x(0, P1 as i64);
                let f1 = _mm_srli_si128(f, 8);
                let f0_shifted = _mm_slli_si128(f, 8);
                let p1_f0 = _mm_clmulepi64_si128(f, p1, 0x00);

                let result = _mm_xor_si128(r, f1);
                let result = _mm_xor_si128(result, f0_shifted);
                _mm_xor_si128(result, p1_f0)
            }

            #[target_feature($(enable = $tf),+)]
            #[inline]
            unsafe fn gf128_mul_rf(m: __m128i, h: __m128i, d: __m128i) -> __m128i {
                let (r, f) = rf_mul_unreduced(m, h, d);
                reduce_rf(r, f)
            }
        }
    };
}

impl_clmul_tier!(avx_tier, "avx", "pclmulqdq");
impl_clmul_tier!(sse_tier, "sse2", "pclmulqdq");

/// Update with a single block (5 CLMULs) via AVX VEX or Legacy SSE PCLMULQDQ.
///
/// # Safety
/// Caller must ensure `InitToken::init_get()` returned `true`.
#[inline]
pub(super) unsafe fn proc_block(
    key: &ExpandedKey,
    acc: FieldElement,
    block: &Block,
) -> FieldElement {
    if clmul_avx::get() {
        avx_tier::proc_block(key, acc, block)
    } else {
        sse_tier::proc_block(key, acc, block)
    }
}

/// Process 4 blocks with R/F algorithm and aggregated reduction (17 CLMULs total).
///
/// # Safety
/// Caller must ensure `InitToken::init_get()` returned `true`.
#[inline]
pub(super) unsafe fn proc_par_blocks(
    key: &ExpandedKey,
    acc: FieldElement,
    par_blocks: &ParBlocks,
) -> FieldElement {
    if clmul_avx::get() {
        avx_tier::proc_par_blocks(key, acc, par_blocks)
    } else {
        sse_tier::proc_par_blocks(key, acc, par_blocks)
    }
}

/// Expand POLYVAL key powers H^1..H^4 and D^1..D^4.
///
/// # Safety
/// Caller must ensure `InitToken::init_get()` returned `true`.
pub(super) unsafe fn expand_key(h: &[u8; 16]) -> ExpandedKey {
    if clmul_avx::get() {
        avx_tier::expand_key(h)
    } else {
        sse_tier::expand_key(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_tier_matches_software_field_arithmetic() {
        if !clmul_sse::get() {
            return;
        }
        let h_bytes: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        // SAFETY: guarded by `clmul_sse::get()` above.
        let key = unsafe { sse_tier::expand_key(&h_bytes) };
        let h_fe = FieldElement::from(crate::Key::from(h_bytes));

        let mut raw_blocks = [[0u8; 16]; 5];
        for (idx, blk) in raw_blocks.iter_mut().enumerate() {
            for (j, byte) in blk.iter_mut().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                {
                    *byte = ((idx * 37 + j * 13 + 0x5a) & 0xff) as u8;
                }
            }
        }

        let mut soft_acc = FieldElement::default();
        for blk in &raw_blocks {
            let b: &Block = blk.into();
            soft_acc = (soft_acc + b.into()) * h_fe;
        }

        let par: ParBlocks = [
            Block::from(raw_blocks[0]),
            Block::from(raw_blocks[1]),
            Block::from(raw_blocks[2]),
            Block::from(raw_blocks[3]),
        ]
        .into();
        let tail = Block::from(raw_blocks[4]);

        // SAFETY: guarded by `clmul_sse::get()` above.
        let sse_acc = unsafe {
            let acc4 = sse_tier::proc_par_blocks(&key, FieldElement::default(), &par);
            sse_tier::proc_block(&key, acc4, &tail)
        };
        let soft_tag: ByteArray = soft_acc.into();
        let sse_tag: ByteArray = sse_acc.into();
        assert_eq!(sse_tag, soft_tag);
    }
}
