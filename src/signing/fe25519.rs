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

//! This module provides functionality found in
//! crypto_sign/ed25519/ref/fe25519.c


/// Analog of struct fe25519 in crypto_sign/ed25519/ref/fe25519.h
pub struct Fe25519 {
	pub v: [u32; 32],
}

#[inline]
pub fn make_fe25519() -> Fe25519 {
	Fe25519 { v: [0; 32] }
}

#[inline]
pub fn make_copy_fe25519(x: &Fe25519) -> Fe25519 {
	let mut copy = make_fe25519();
	copy.v.copy_from_slice(&x.v);
	copy
}

#[inline]
pub fn fe25519_cp(r: &mut Fe25519, x: &Fe25519) {
	r.v.copy_from_slice(&x.v);
}

/// Analog of equal in crypto_sign/ed25519/ref/fe25519.c
/// All inputs are 16-bit.
#[inline]
fn equal(a: u32, b: u32) -> u32 {
	let mut x = a ^ b; /* 0: yes; 1..65535: no */
	x -= 1; /* 4294967295: yes; 0..65534: no */
	x >>= 31; /* 1: yes; 0: no */
	x
}

/// Analog of ge in crypto_sign/ed25519/ref/fe25519.c
/// All inputs are 16-bit.
#[inline]
fn ge(a: u32, b: u32) -> u32 {
	let mut x = a;
	x -= b; /* 0..65535: yes; 4294901761..4294967295: no */
	x >>= 31; /* 0: yes; 1: no */
	x ^= 1; /* 1: yes; 0: no */
	x
}

/// Analog of times19 in crypto_sign/ed25519/ref/fe25519.c
#[inline]
fn times19(a: u32) -> u32 {
	(a << 4) + (a << 1) + a
}

/// Analog of times38 in crypto_sign/ed25519/ref/fe25519.c
#[inline]
fn times38(a: u32) -> u32 {
	(a << 5) + (a << 2) + (a << 1)
}

/// Analog of reduce_add_sub in crypto_sign/ed25519/ref/fe25519.c
fn reduce_add_sub(r: &mut Fe25519) {
	for _ in 0..4 {
		let mut t = r.v[31] >> 7;
		r.v[31] &= 127;
		t = times19(t);
		r.v[0] += t;
		for i in 0..31 {
			t = r.v[i] >> 8;
			r.v[i+1] += t;
			r.v[i] &= 255;
		}
	}
}

/// Analog of reduce_mul in crypto_sign/ed25519/ref/fe25519.c
fn reduce_mul(r: &mut Fe25519) {
	for _ in 0..2 {
		let mut t = r.v[31] >> 7;
		r.v[31] &= 127;
		t = times19(t);
		r.v[0] += t;
		for i in 0..31 {
			t = r.v[i] >> 8;
			r.v[i+1] += t;
			r.v[i] &= 255;
		}
	}
}

/// Analog of fe25519_freeze in crypto_sign/ed25519/ref/fe25519.c
/// reduction modulo 2^255-19
fn fe25519_freeze(r: &mut Fe25519) {
	let mut m = equal(r.v[31],127);
	let mut i: usize = 30;
	while i > 0 {
		m &= equal(r.v[i],255);
		i -= 1;
	}
	m &= ge(r.v[0],237);

	m = 0 - m;

	r.v[31] -= m&127;
	i = 30;
	while i > 0 {
		r.v[i] -= m&255;
		i -= 1;
	}
	r.v[0] -= m&237;
}

/// Analog of fe25519_unpack in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_unpack(r: &mut Fe25519, x: &[u8]) {
	for i in 0..32 { r.v[i] = x[i] as u32; }
	r.v[31] &= 127;
}

/// Analog of fe25519_unpack in crypto_sign/ed25519/ref/fe25519.c
/// Assumes input x being reduced below 2^255
pub fn fe25519_pack(r: &mut [u8], x: &Fe25519) {
	let mut y = make_copy_fe25519(x);
	fe25519_freeze(&mut y);
	for i in 0..32 { r[i] = y.v[i] as u8; }
}

/// Analog of fe25519_iseq_vartime in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_iseq_vartime(x: &Fe25519, y: &Fe25519) -> bool {
	let mut t1 = make_copy_fe25519(x);
	let mut t2 = make_copy_fe25519(y);
	fe25519_freeze(&mut t1);
	fe25519_freeze(&mut t2);
	for i in 0..32 {
		if t1.v[i] != t2.v[i] { return false; }
	}
	true
}

/// Analog of fe25519_cmov in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_cmov(r: &mut Fe25519, x: &Fe25519, b: u8) {
  let mut mask: u32 = b as u32;
  mask = 0 - mask;
  for i in 0..32 { r.v[i] ^= mask & (x.v[i] ^ r.v[i]); }
}

/// Analog of fe25519_getparity in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_getparity(x: &Fe25519) -> u8 {
	let mut t = make_copy_fe25519(x);
	fe25519_freeze(&mut t);
	(t.v[0] & 1) as u8
}

/// Analog of fe25519_setone in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_setone(r: &mut Fe25519) {
	r.v[0] = 1;
	for i in 1..32 { r.v[i] = 0; }
}

/// Analog of fe25519_setzero in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_setzero(r: &mut Fe25519) {
	for i in 0..32 { r.v[i]=0; }
}

const ZERO_FE25519: Fe25519 = Fe25519 { v: [0; 32] };

/// Analog of fe25519_neg in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_neg(r: &mut Fe25519, x: &Fe25519) {
	let t = make_copy_fe25519(x);
	fe25519_sub(r, &ZERO_FE25519, &t);
}

/// Analog of fe25519_add in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_add(r: &mut Fe25519, x: &Fe25519, y: &Fe25519) {
	for i in 0..32 { r.v[i] = x.v[i] + y.v[i]; }
	reduce_add_sub(r);
}

/// Analog of fe25519_sub in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_sub(r: &mut Fe25519, x: &Fe25519, y: &Fe25519) {
	let mut t: [u32; 32] = [0; 32];
	t[0] = x.v[0] + 0x1da;
	t[31] = x.v[31] + 0xfe;
	for i in 1..31 { t[i] = x.v[i] + 0x1fe; }
	for i in 0..32 { r.v[i] = t[i] - y.v[i]; }
	reduce_add_sub(r);
}

/// Analog of fe25519_mul in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_mul(r: &mut Fe25519, x: &Fe25519, y: &Fe25519) {
	let mut t: [u32; 63] = [0; 63];

	for i in 0..32 {
		for j in 0..32 {
			t[i+j] += x.v[i] * y.v[j];
		}
	}

	for i in 32..63 {
		r.v[i-32] = t[i-32] + times38(t[i]);
	}
	r.v[31] = t[31]; // result now in r[0]...r[31]

	reduce_mul(r);
}

/// Analog of fe25519_square in crypto_sign/ed25519/ref/fe25519.c
#[inline]
pub fn fe25519_square(r: &mut Fe25519, x: &Fe25519) {
	fe25519_mul(r, x, x);
}

// pub fn fe25519_square_same(x: &mut Fe25519, t: &mut Fe25519) {
// 	t.v.copy_from_slice(&x.v);
// 	fe25519_mul(x, t, t);
// }

/// Analog of fe25519_invert in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_invert(r: &mut Fe25519, x: &Fe25519) {
	let mut z2 = make_fe25519();
	let mut z9 = make_fe25519();
	let mut z11 = make_fe25519();
	let mut z2_5_0 = make_fe25519();
	let mut z2_10_0 = make_fe25519();
	let mut z2_20_0 = make_fe25519();
	let mut z2_50_0 = make_fe25519();
	let mut z2_100_0 = make_fe25519();
	let mut t0 = make_fe25519();
	let mut t1 = make_fe25519();
	
	/* 2 */ fe25519_square(&mut z2, x);
	/* 4 */ fe25519_square(&mut t1, &z2);
	/* 8 */ fe25519_square(&mut t0, &t1);
	/* 9 */ fe25519_mul(&mut z9, &t0, x);
	/* 11 */ fe25519_mul(&mut z11, &z9, &z2);
	/* 22 */ fe25519_square(&mut t0, &z11);
	/* 2^5 - 2^0 = 31 */ fe25519_mul(&mut z2_5_0, &t0, &z9);

	/* 2^6 - 2^1 */ fe25519_square(&mut t0, &z2_5_0);
	/* 2^7 - 2^2 */ fe25519_square(&mut t1, &t0);
	/* 2^8 - 2^3 */ fe25519_square(&mut t0, &t1);
	/* 2^9 - 2^4 */ fe25519_square(&mut t1, &t0);
	/* 2^10 - 2^5 */ fe25519_square(&mut t0, &t1);
	/* 2^10 - 2^0 */ fe25519_mul(&mut z2_10_0, &t0, &z2_5_0);

	/* 2^11 - 2^1 */ fe25519_square(&mut t0, &z2_10_0);
	/* 2^12 - 2^2 */ fe25519_square(&mut t1, &t0);
	/* 2^20 - 2^10 */ for _ in 1..5 { fe25519_square(&mut t0, &t1); fe25519_square(&mut t1, &t0); }
	/* 2^20 - 2^0 */ fe25519_mul(&mut z2_20_0, &t1, &z2_10_0);

	/* 2^21 - 2^1 */ fe25519_square(&mut t0, &z2_20_0);
	/* 2^22 - 2^2 */ fe25519_square(&mut t1, &t0);
	/* 2^40 - 2^20 */ for _ in 1..10 { fe25519_square(&mut t0, &t1); fe25519_square(&mut t1, &t0); }
	/* 2^40 - 2^0 */ fe25519_mul(&mut t0, &t1, &z2_20_0);

	/* 2^41 - 2^1 */ fe25519_square(&mut t1, &t0);
	/* 2^42 - 2^2 */ fe25519_square(&mut t0, &t1);
	/* 2^50 - 2^10 */ for _ in 1..5 { fe25519_square(&mut t1, &t0); fe25519_square(&mut t0, &t1); }
	/* 2^50 - 2^0 */ fe25519_mul(&mut z2_50_0, &t0, &z2_10_0);

	/* 2^51 - 2^1 */ fe25519_square(&mut t0, &z2_50_0);
	/* 2^52 - 2^2 */ fe25519_square(&mut t1, &t0);
	/* 2^100 - 2^50 */ for _ in 1..25 { fe25519_square(&mut t0, &t1); fe25519_square(&mut t1, &t0); }
	/* 2^100 - 2^0 */ fe25519_mul(&mut z2_100_0, &t1, &z2_50_0);

	/* 2^101 - 2^1 */ fe25519_square(&mut t1, &z2_100_0);
	/* 2^102 - 2^2 */ fe25519_square(&mut t0, &t1);
	/* 2^200 - 2^100 */ for _ in 1..50 { fe25519_square(&mut t1, &t0); fe25519_square(&mut t0, &t1); }
	/* 2^200 - 2^0 */ fe25519_mul(&mut t1, &t0, &z2_100_0);

	/* 2^201 - 2^1 */ fe25519_square(&mut t0, &t1);
	/* 2^202 - 2^2 */ fe25519_square(&mut t1, &t0);
	/* 2^250 - 2^50 */ for _ in 1..25 { fe25519_square(&mut t0, &t1); fe25519_square(&mut t1, &t0); }
	/* 2^250 - 2^0 */ fe25519_mul(&mut t0, &t1, &z2_50_0);

	/* 2^251 - 2^1 */ fe25519_square(&mut t1, &t0);
	/* 2^252 - 2^2 */ fe25519_square(&mut t0, &t1);
	/* 2^253 - 2^3 */ fe25519_square(&mut t1, &t0);
	/* 2^254 - 2^4 */ fe25519_square(&mut t0, &t1);
	/* 2^255 - 2^5 */ fe25519_square(&mut t1, &t0);
	/* 2^255 - 21 */ fe25519_mul(r, &t1, &z11);
}

/// Analog of fe25519_pow2523 in crypto_sign/ed25519/ref/fe25519.c
pub fn fe25519_pow2523(r: &mut Fe25519, x: &Fe25519) {
	let mut z2 = make_fe25519();
	let mut z9 = make_fe25519();
	let mut z11 = make_fe25519();
	let mut z2_5_0 = make_fe25519();
	let mut z2_10_0 = make_fe25519();
	let mut z2_20_0 = make_fe25519();
	let mut z2_50_0 = make_fe25519();
	let mut z2_100_0 = make_fe25519();
	let mut t = make_fe25519();
	let mut t2 = make_fe25519();

	/* 2 */ fe25519_square(&mut z2, x);
	/* 4 */ fe25519_square(&mut t, &z2);
	/* 8 */ fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2);
	/* 9 */ fe25519_mul(&mut z9, &t, x);
	/* 11 */ fe25519_mul(&mut z11, &z9, &z2);
	/* 22 */ fe25519_square(&mut t, &z11);
	/* 2^5 - 2^0 = 31 */ fe25519_mul(&mut z2_5_0, &t, &z9);

	/* 2^6 - 2^1 */ fe25519_square(&mut t, &z2_5_0);
	/* 2^10 - 2^5 */ for _ in 1..5 { fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2); }
	/* 2^10 - 2^0 */ fe25519_mul(&mut z2_10_0, &t, &z2_5_0);

	/* 2^11 - 2^1 */ fe25519_square(&mut t, &z2_10_0);
	/* 2^20 - 2^10 */ for _ in 1..10 { fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2); }
	/* 2^20 - 2^0 */ fe25519_mul(&mut z2_20_0, &t, &z2_10_0);

	/* 2^21 - 2^1 */ fe25519_square(&mut t, &z2_20_0);
	/* 2^40 - 2^20 */ for _ in 1..20 { fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2); }
	/* 2^40 - 2^0 */ fe25519_mul(&mut t2, &t, &z2_20_0); fe25519_cp(&mut t, &t2);

	/* 2^41 - 2^1 */ fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2);
	/* 2^50 - 2^10 */ for _ in 1..10 { fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2); }
	/* 2^50 - 2^0 */ fe25519_mul(&mut z2_50_0, &t, &z2_10_0);

	/* 2^51 - 2^1 */ fe25519_square(&mut t, &z2_50_0);
	/* 2^100 - 2^50 */ for _ in 1..50 { fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2); }
	/* 2^100 - 2^0 */ fe25519_mul(&mut z2_100_0, &t, &z2_50_0);

	/* 2^101 - 2^1 */ fe25519_square(&mut t, &z2_100_0);
	/* 2^200 - 2^100 */ for _ in 1..100 { fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2); }
	/* 2^200 - 2^0 */ fe25519_mul(&mut t2, &t, &z2_100_0); fe25519_cp(&mut t, &t2);

	/* 2^201 - 2^1 */ fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2);
	/* 2^250 - 2^50 */ for _ in 1..50 { fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2); }
	/* 2^250 - 2^0 */ fe25519_mul(&mut t2, &t, &z2_50_0); fe25519_cp(&mut t, &t2);

	/* 2^251 - 2^1 */ fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2);
	/* 2^252 - 2^2 */ fe25519_square(&mut t2, &t); fe25519_cp(&mut t, &t2);
	/* 2^252 - 3 */ fe25519_mul(r, &t, x);
}

