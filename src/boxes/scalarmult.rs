// Copyright(c) 2018 3NSoft Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! This module provides curve25519 math functions, analogous to thus from
//! crypto_scalarmult/curve25519/ref/smult.c and
//! crypto_scalarmult/curve25519/ref/base.c

fn add(out: &mut [u32], a: &[u32], b: &[u32]) {
	let mut u: u32 = 0;
	for j in 0..31 { u += a[j] + b[j]; out[j] = u & 255; u >>= 8; }
	u += a[31] + b[31]; out[31] = u;
}

fn sub(out: &mut [u32], a: &[u32], b: &[u32]) {
	let mut u: u32 = 218;
	for j in 0..31 {
		u += a[j] + 65280 - b[j];
		out[j] = u & 255;
		u >>= 8;
	}
	u += a[31] - b[31];
	out[31] = u;
}

fn squeeze(a: &mut [u32]) {
  let mut u: u32 = 0;
  for j in 0..31 { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u & 127;
  u = 19 * (u >> 7);
  for j in 0..31 { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u;
}

static MINUSP: [u32; 32] = [
	19, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 128 ];

fn freeze(a: &mut [u32]) {
	let mut aorig: [u32; 32] = [0; 32];
	for j in 0..32 { aorig[j] = a[j]; }
	add(a, &aorig, &MINUSP);
	let negative = -(((a[31] >> 7) & 1) as i32) as u32;
	for j in 0..32 { a[j] ^= negative & (aorig[j] ^ a[j]); }
}

fn mult(out: &mut [u32], a: &[u32], b: &[u32]) {
	for i in 0..32 {
		let mut u: u32 = 0;
		for j in 0..i+1 { u += a[j] * b[i - j]; }
		for j in i+1..32 { u += 38 * a[j] * b[i + 32 - j] };
		out[i] = u;
	}
	squeeze(out);
}

fn mult121665(out: &mut [u32], a: &[u32]) {
	let mut u:u32 = 0;
	for j in 0..31 { u += 121665 * a[j]; out[j] = u & 255; u >>= 8; }
	u += 121665 * a[31]; out[31] = u & 127;
	u = 19 * (u >> 7);
	for j in 0..31 { u += out[j]; out[j] = u & 255; u >>= 8; }
	u += out[31]; out[31] = u;
}

fn square(out: &mut [u32], a: &[u32]) {
	for i in 0..32 {
		let mut u: u32 = 0;
		let mut j: usize = 0;
		while j < (i - j) { u += a[j] * a[i - j]; j += 1; }
		j = i + 1;
		while j < (i + 32 - j) { u += 38 * a[j] * a[i + 32 - j]; j += 1; }
		u *= 2;
		if (i & 1) == 0 {
			u += a[i / 2] * a[i / 2];
			u += 38 * a[i / 2 + 16] * a[i / 2 + 16];
		}
		out[i] = u;
	}
	squeeze(out);
}

fn select(p: &mut [u32], q: &mut [u32], r: &[u32], s: &[u32], b: u32) {
	let bminus1 = (b - 1) as u32;
	for j in 0..64 {
		let mut t = bminus1 & (r[j] ^ s[j]);
		p[j] = s[j] ^ t;
		q[j] = r[j] ^ t;
	}
}

fn mainloop(work1: &mut [u32], work2: &mut [u32], e: &[u32]) {
	let mut xzm1: [u32; 64] = [0; 64];
	let mut xzm: [u32; 64] = [0; 64];
	let mut xzmb: [u32; 64] = [0; 64];
	let mut xzm1b: [u32; 64] = [0; 64];
	let mut xznb: [u32; 64] = [0; 64];
	let mut xzn1b: [u32; 64] = [0; 64];
	let mut a0: [u32; 64] = [0; 64];
	let mut a1: [u32; 64] = [0; 64];
	let mut b0: [u32; 64] = [0; 64];
	let mut b1: [u32; 64] = [0; 64];
	let mut c1: [u32; 64] = [0; 64];
	let mut r: [u32; 32] = [0; 32];
	let mut s: [u32; 32] = [0; 32];
	let mut t: [u32; 32] = [0; 32];
	let mut u: [u32; 32] = [0; 32];

	xzm1[0..32].copy_from_slice(work1);
	xzm1[32] = 1;

	xzm[0] = 1;
	for j in 1..64 { xzm[j] = 0; }

	let mut pos: usize = 254;
	loop {
		let mut b = e[pos / 8] >> (pos & 7);
		b &= 1;
		select(&mut xzmb, &mut xzm1b, &xzm, &xzm1, b);
		add(&mut a0[0..32], &xzmb[0..32], &xzmb[32..]);
		sub(&mut a0[32..], &xzmb[0..32], &xzmb[32..]);
		add(&mut a1[0..32], &xzm1b[0..32], &xzm1b[32..]);
		sub(&mut a1[32..], &xzm1b[0..32], &xzm1b[32..]);
		square(&mut b0[0..32], &a0[0..32]);
		square(&mut b0[32..], &a0[32..]);
		mult(&mut b1[0..32], &a1[0..32], &a0[32..]);
		mult(&mut b1[32..], &a1[32..], &a0[0..32]);
		add(&mut c1[0..32], &b1[0..32], &b1[32..]);
		sub(&mut c1[32..], &b1[0..32], &b1[32..]);
		square(&mut r[0..32], &c1[32..]);
		sub(&mut s[0..32], &b0[0..32], &b0[32..]);
		mult121665(&mut t[0..32], &s[0..32]);
		add(&mut u[0..32], &t[0..32], &b0[0..32]);
		mult(&mut xznb[0..32], &b0[0..32], &b0[32..]);
		mult(&mut xznb[32..], &s[0..32], &u[0..32]);
		square(&mut xzn1b[0..32], &c1[0..32]);
		mult(&mut xzn1b[32..], &r[0..32], &work1);
		select(&mut xzm, &mut xzm1, &xznb, &xzn1b, b);
		if pos == 0 { break; }
		pos -= 1;
	}

	work1.copy_from_slice(&xzm[0..32]);
	work2.copy_from_slice(&xzm[32..64]);
}

fn recip(out: &mut [u32], z: &[u32]) {
	let mut z2: [u32; 32] = [0; 32];
	let mut z9: [u32; 32] = [0; 32];
	let mut z11: [u32; 32] = [0; 32];
	let mut z2_5_0: [u32; 32] = [0; 32];
	let mut z2_10_0: [u32; 32] = [0; 32];
	let mut z2_20_0: [u32; 32] = [0; 32];
	let mut z2_50_0: [u32; 32] = [0; 32];
	let mut z2_100_0: [u32; 32] = [0; 32];
	let mut t0: [u32; 32] = [0; 32];
	let mut t1: [u32; 32] = [0; 32];

	/* 2 */ square(&mut z2, &z);
	/* 4 */ square(&mut t1, &z2);
	/* 8 */ square(&mut t0, &t1);
	/* 9 */ mult(&mut z9, &t0, &z);
	/* 11 */ mult(&mut z11, &z9, &z2);
	/* 22 */ square(&mut t0, &z11);
	/* 2^5 - 2^0 = 31 */ mult(&mut z2_5_0, &t0, &z9);

	/* 2^6 - 2^1 */ square(&mut t0, &z2_5_0);
	/* 2^7 - 2^2 */ square(&mut t1, &t0);
	/* 2^8 - 2^3 */ square(&mut t0, &t1);
	/* 2^9 - 2^4 */ square(&mut t1, &t0);
	/* 2^10 - 2^5 */ square(&mut t0, &t1);
	/* 2^10 - 2^0 */ mult(&mut z2_10_0, &t0, &z2_5_0);

	/* 2^11 - 2^1 */ square(&mut t0, &z2_10_0);
	/* 2^12 - 2^2 */ square(&mut t1, &t0);
	/* 2^20 - 2^10 */ for _ in 1..5 { square(&mut t0, &t1); square(&mut t1, &t0); }
	/* 2^20 - 2^0 */ mult(&mut z2_20_0, &t1, &z2_10_0);

	/* 2^21 - 2^1 */ square(&mut t0, &z2_20_0);
	/* 2^22 - 2^2 */ square(&mut t1, &t0);
	/* 2^40 - 2^20 */ for _ in 1..10 { square(&mut t0, &t1); square(&mut t1, &t0); }
	/* 2^40 - 2^0 */ mult(&mut t0, &t1, &z2_20_0);

	/* 2^41 - 2^1 */ square(&mut t1, &t0);
	/* 2^42 - 2^2 */ square(&mut t0, &t1);
	/* 2^50 - 2^10 */ for _ in 1..5 { square(&mut t1, &t0); square(&mut t0, &t1); }
	/* 2^50 - 2^0 */ mult(&mut z2_50_0, &t0, &z2_10_0);

	/* 2^51 - 2^1 */ square(&mut t0, &z2_50_0);
	/* 2^52 - 2^2 */ square(&mut t1, &t0);
	/* 2^100 - 2^50 */ for _ in 1..25 { square(&mut t0, &t1); square(&mut t1, &t0); }
	/* 2^100 - 2^0 */ mult(&mut z2_100_0, &t1, &z2_50_0);

	/* 2^101 - 2^1 */ square(&mut t1, &z2_100_0);
	/* 2^102 - 2^2 */ square(&mut t0, &t1);
	/* 2^200 - 2^100 */ for _ in 1..50 { square(&mut t1, &t0); square(&mut t0, &t1); }
	/* 2^200 - 2^0 */ mult(&mut t1, &t0, &z2_100_0);

	/* 2^201 - 2^1 */ square(&mut t0, &t1);
	/* 2^202 - 2^2 */ square(&mut t1, &t0);
	/* 2^250 - 2^50 */ for _ in 1..25 { square(&mut t0, &t1); square(&mut t1, &t0); }
	/* 2^250 - 2^0 */ mult(&mut t0, &t1, &z2_50_0);

	/* 2^251 - 2^1 */ square(&mut t1, &t0);
	/* 2^252 - 2^2 */ square(&mut t0, &t1);
	/* 2^253 - 2^3 */ square(&mut t1, &t0);
	/* 2^254 - 2^4 */ square(&mut t0, &t1);
	/* 2^255 - 2^5 */ square(&mut t1, &t0);
	/* 2^255 - 21 */ mult(out, &t1, &z11);
}

pub fn curve25519(q: &mut [u8], n: &[u8], p: &[u8]) {
	let mut work1: [u32; 32]= [0; 32];
	let mut work2: [u32; 32]= [0; 32];
	let mut work3: [u32; 32]= [0; 32];
	let mut e: [u32; 32]= [0; 32];
	for i in 0..32 { e[i] = n[i] as u32; }
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;
	for i in 0..32 { work1[i] = p[i] as u32; }
	mainloop(&mut work1, &mut work2, &e);
	let mut t_work2: [u32; 32]= [0; 32];
	t_work2.copy_from_slice(&work2);
	recip(&mut work2, &t_work2);
	mult(&mut work3, &work1, &work2);
	freeze(&mut work3);
	for i in 0..32 { q[i] = work3[i] as u8; }
}

const BASE: [u8; 32] = [
	9, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0 ];

pub fn curve25519_base(q: &mut [u8], n: &[u8]) {
  return curve25519(q, n, &BASE);
}


#[cfg(test)]
mod tests {

	use boxes::scalarmult::curve25519_base;
	use boxes::scalarmult::curve25519;
	use util::verify::compare;

	/// Test analogs of tests/scalarmult.c, tests/scalarmult2.c,
	/// tests/scalarmult5.c, and tests/scalarmult6.c
	/// 
	#[test]
	fn scalarmults() {

		let alicesk: [u8; 32] = [
			0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
			0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
			0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
			0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a ];
		let mut alicepk: [u8; 32] = [0; 32];

		let bobsk: [u8; 32] = [
			0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
			0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
			0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
			0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb ];
		let mut bobpk: [u8; 32] = [0; 32];

		// Testing of 'curve25519_base', analog to tests/scalarmult.c
		curve25519_base(&mut alicepk, &alicesk);
		// taken from tests/scalarmult.out
		assert!(compare(&alicepk, &[
			0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
			0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
			0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
			0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a ]));

		// Testing of 'curve25519_base', analog to tests/scalarmult2.c
		curve25519_base(&mut bobpk, &bobsk);
		// taken from tests/scalarmult2.out
		assert!(compare(&bobpk, &[
			0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
			0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
			0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
			0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f ]));

		// Testing of 'curve25519', analog to tests/scalarmult5.c
		let mut k: [u8; 32] = [0; 32];
		curve25519(&mut k, &alicesk, &bobpk);
		// taken from tests/scalarmult5.out
		assert!(compare(&k, &[
			0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,
			0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
			0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,
			0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42 ]));

		// Testing of 'curve25519', analog to tests/scalarmult6.c
		let mut k2: [u8; 32] = [0; 32];
		curve25519(&mut k2, &bobsk, &alicepk);
		assert!(compare(&k2, &k));
		
	}

}