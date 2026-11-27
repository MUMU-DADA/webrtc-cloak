//! Constant-time portable Poly1305 backend.
//!
//! Uses 64-bit 3-limb radix-2^44 (`u64` + `u128`, 9 multiplies/block) on 64-bit targets
//! (`aarch64`, non-AVX2 `x86_64`, `riscv64`, `loongarch64`, `powerpc64le`), and 32-bit
//! 5-limb radix-2^26 (`u32` + `u64`, 25 multiplies/block) on 32-bit targets.
//! Both derive from Andrew Moon's public-domain `poly1305-donna`.

use universal_hash::{
    UhfBackend, UhfClosure,
    common::{BlockSizeUser, ParBlocksSizeUser},
    consts::{U1, U16},
};

use crate::{Block, Key, Tag};

#[cfg(target_pointer_width = "64")]
#[derive(Clone, Default)]
pub(crate) struct State {
    r: [u64; 3],
    s: [u64; 2],
    h: [u64; 3],
    pad: [u64; 2],
}

#[cfg(target_pointer_width = "64")]
impl State {
    const MASK44: u64 = 0x0000_0fff_ffff_ffff;
    const MASK42: u64 = 0x0000_03ff_ffff_ffff;

    /// Initialize Poly1305 [`State`] with the given key (64-bit radix-2^44).
    pub(crate) fn new(key: &Key) -> State {
        // RFC 8439 clamp: bytes 3,7,11,15 &= 0x0f; bytes 4,8,12 &= 0xfc.
        let t0 = u64::from_le_bytes(key[0..8].try_into().unwrap()) & 0x0fff_fffc_0fff_ffff;
        let t1 = u64::from_le_bytes(key[8..16].try_into().unwrap()) & 0x0fff_fffc_0fff_fffc;

        let r0 = t0 & Self::MASK44;
        let r1 = ((t0 >> 44) | (t1 << 20)) & Self::MASK44;
        let r2 = (t1 >> 24) & Self::MASK42;

        // 2^132 = 4 * 2^130 == 20 (mod 2^130 - 5)
        let s1 = r1 * 20;
        let s2 = r2 * 20;

        let pad0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let pad1 = u64::from_le_bytes(key[24..32].try_into().unwrap());

        State {
            r: [r0, r1, r2],
            s: [s1, s2],
            h: [0, 0, 0],
            pad: [pad0, pad1],
        }
    }

    /// Compute a Poly1305 block using 3-limb radix-2^44 arithmetic (9 wide multiplies).
    #[inline]
    pub(crate) fn compute_block(&mut self, block: &Block, partial: bool) {
        let hibit: u64 = if partial { 0 } else { 1u64 << 40 };

        let t0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(block[8..16].try_into().unwrap());

        // h += m
        let h0 = self.h[0] + (t0 & Self::MASK44);
        let h1 = self.h[1] + (((t0 >> 44) | (t1 << 20)) & Self::MASK44);
        let h2 = self.h[2] + ((t1 >> 24) | hibit);

        let r0 = u128::from(self.r[0]);
        let r1 = u128::from(self.r[1]);
        let r2 = u128::from(self.r[2]);
        let s1 = u128::from(self.s[0]);
        let s2 = u128::from(self.s[1]);

        let h0w = u128::from(h0);
        let h1w = u128::from(h1);
        let h2w = u128::from(h2);

        // h *= r (mod 2^130 - 5)
        let d0 = h0w * r0 + h1w * s2 + h2w * s1;
        let mut d1 = h0w * r1 + h1w * r0 + h2w * s2;
        let mut d2 = h0w * r2 + h1w * r1 + h2w * r0;

        // Partial carry propagation
        let c0 = (d0 >> 44) as u64;
        let mut nh0 = (d0 as u64) & Self::MASK44;
        d1 += u128::from(c0);

        let c1 = (d1 >> 44) as u64;
        let mut nh1 = (d1 as u64) & Self::MASK44;
        d2 += u128::from(c1);

        let c2 = (d2 >> 42) as u64;
        let nh2 = (d2 as u64) & Self::MASK42;
        nh0 += c2 * 5;

        let c3 = nh0 >> 44;
        nh0 &= Self::MASK44;
        nh1 += c3;

        self.h[0] = nh0;
        self.h[1] = nh1;
        self.h[2] = nh2;
    }

    #[allow(unused, reason = "this method is used by some targets")]
    pub(crate) fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = U16>) {
        f.call(self);
    }

    /// Finalize output producing a [`Tag`].
    pub(crate) fn finalize(&mut self) -> Tag {
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        // Full carry propagation
        let mut c = h1 >> 44;
        h1 &= Self::MASK44;
        h2 += c;
        c = h2 >> 42;
        h2 &= Self::MASK42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= Self::MASK44;
        h1 += c;
        c = h1 >> 44;
        h1 &= Self::MASK44;
        h2 += c;
        c = h2 >> 42;
        h2 &= Self::MASK42;
        h0 += c * 5;
        c = h0 >> 44;
        h0 &= Self::MASK44;
        h1 += c;

        // Compute g = h + 5 - 2^130
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 44;
        g0 &= Self::MASK44;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 44;
        g1 &= Self::MASK44;

        let mut g2 = h2.wrapping_add(c).wrapping_sub(1u64 << 42);

        // Constant-time select h if h < p, else g
        let mut mask = (g2 >> 63).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;

        // Pack h mod 2^128 into two u64 words
        let f0 = h0 | (h1 << 44);
        let f1 = (h1 >> 20) | (h2 << 24);

        // mac = (h + pad) mod 2^128
        let sum0 = u128::from(f0) + u128::from(self.pad[0]);
        let out0 = sum0 as u64;
        let out1 = f1
            .wrapping_add(self.pad[1])
            .wrapping_add((sum0 >> 64) as u64);

        let mut tag = Block::default();
        tag[0..8].copy_from_slice(&out0.to_le_bytes());
        tag[8..16].copy_from_slice(&out1.to_le_bytes());
        tag
    }
}

#[cfg(not(target_pointer_width = "64"))]
#[derive(Clone, Default)]
pub(crate) struct State {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

#[cfg(not(target_pointer_width = "64"))]
impl State {
    /// Initialize Poly1305 [`State`] with the given key (32-bit radix-2^26).
    pub(crate) fn new(key: &Key) -> State {
        let mut poly = State::default();

        // r &= 0x0ffffffc_0ffffffc_0ffffffc_0fffffff
        poly.r[0] = (u32::from_le_bytes(key[0..4].try_into().unwrap())) & 0x3ff_ffff;
        poly.r[1] = (u32::from_le_bytes(key[3..7].try_into().unwrap()) >> 2) & 0x3ff_ff03;
        poly.r[2] = (u32::from_le_bytes(key[6..10].try_into().unwrap()) >> 4) & 0x3ff_c0ff;
        poly.r[3] = (u32::from_le_bytes(key[9..13].try_into().unwrap()) >> 6) & 0x3f0_3fff;
        poly.r[4] = (u32::from_le_bytes(key[12..16].try_into().unwrap()) >> 8) & 0x00f_ffff;

        poly.pad[0] = u32::from_le_bytes(key[16..20].try_into().unwrap());
        poly.pad[1] = u32::from_le_bytes(key[20..24].try_into().unwrap());
        poly.pad[2] = u32::from_le_bytes(key[24..28].try_into().unwrap());
        poly.pad[3] = u32::from_le_bytes(key[28..32].try_into().unwrap());

        poly
    }

    /// Compute a Poly1305 block.
    pub(crate) fn compute_block(&mut self, block: &Block, partial: bool) {
        let hibit = if partial { 0 } else { 1 << 24 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        // h += m
        h0 += (u32::from_le_bytes(block[0..4].try_into().unwrap())) & 0x3ff_ffff;
        h1 += (u32::from_le_bytes(block[3..7].try_into().unwrap()) >> 2) & 0x3ff_ffff;
        h2 += (u32::from_le_bytes(block[6..10].try_into().unwrap()) >> 4) & 0x3ff_ffff;
        h3 += (u32::from_le_bytes(block[9..13].try_into().unwrap()) >> 6) & 0x3ff_ffff;
        h4 += (u32::from_le_bytes(block[12..16].try_into().unwrap()) >> 8) | hibit;

        // h *= r
        let d0 = (u64::from(h0) * u64::from(r0))
            + (u64::from(h1) * u64::from(s4))
            + (u64::from(h2) * u64::from(s3))
            + (u64::from(h3) * u64::from(s2))
            + (u64::from(h4) * u64::from(s1));

        let mut d1 = (u64::from(h0) * u64::from(r1))
            + (u64::from(h1) * u64::from(r0))
            + (u64::from(h2) * u64::from(s4))
            + (u64::from(h3) * u64::from(s3))
            + (u64::from(h4) * u64::from(s2));

        let mut d2 = (u64::from(h0) * u64::from(r2))
            + (u64::from(h1) * u64::from(r1))
            + (u64::from(h2) * u64::from(r0))
            + (u64::from(h3) * u64::from(s4))
            + (u64::from(h4) * u64::from(s3));

        let mut d3 = (u64::from(h0) * u64::from(r3))
            + (u64::from(h1) * u64::from(r2))
            + (u64::from(h2) * u64::from(r1))
            + (u64::from(h3) * u64::from(r0))
            + (u64::from(h4) * u64::from(s4));

        let mut d4 = (u64::from(h0) * u64::from(r4))
            + (u64::from(h1) * u64::from(r3))
            + (u64::from(h2) * u64::from(r2))
            + (u64::from(h3) * u64::from(r1))
            + (u64::from(h4) * u64::from(r0));

        // (partial) h %= p
        let mut c: u32;
        c = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x3ff_ffff;
        d1 += u64::from(c);

        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x3ff_ffff;
        d2 += u64::from(c);

        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x3ff_ffff;
        d3 += u64::from(c);

        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x3ff_ffff;
        d4 += u64::from(c);

        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    #[allow(unused, reason = "this method is used by some targets")]
    pub(crate) fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = U16>) {
        f.call(self);
    }

    /// Finalize output producing a [`Tag`].
    pub(crate) fn finalize(&mut self) -> Tag {
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;

        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;

        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;

        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ff_ffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ff_ffff;

        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ff_ffff;

        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ff_ffff;

        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        h0 |= h1 << 26;
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);

        // h = mac = (h + pad) % (2^128)
        let mut f: u64;
        f = u64::from(h0) + u64::from(self.pad[0]);
        h0 = f as u32;

        f = u64::from(h1) + u64::from(self.pad[1]) + (f >> 32);
        h1 = f as u32;

        f = u64::from(h2) + u64::from(self.pad[2]) + (f >> 32);
        h2 = f as u32;

        f = u64::from(h3) + u64::from(self.pad[3]) + (f >> 32);
        h3 = f as u32;

        let mut tag = Block::default();
        tag[0..4].copy_from_slice(&h0.to_le_bytes());
        tag[4..8].copy_from_slice(&h1.to_le_bytes());
        tag[8..12].copy_from_slice(&h2.to_le_bytes());
        tag[12..16].copy_from_slice(&h3.to_le_bytes());

        tag
    }
}

impl BlockSizeUser for State {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for State {
    type ParBlocksSize = U1;
}

impl UhfBackend for State {
    fn proc_block(&mut self, block: &Block) {
        self.compute_block(block, false);
    }
}
