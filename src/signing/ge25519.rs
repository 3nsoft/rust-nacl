// Copyright(c) 2018, 2021 3NSoft Inc.
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
//! crypto_sign/ed25519/ref/ge25519.c

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use crate::{ subw };

use super::fe25519::*;
use super::sc25519::*;

/// Analog of constant ge25519_base_multiples_affine in
/// crypto_sign/ed25519/ref/ge25519.c
/// Multiples of the base point in affine representation
use super::ge25519_base::ge25519_base_multiples_affine;

/// Analog of struct ge25519 in crypto_sign/ed25519/ref/ge25519.h
pub struct Ge25519 {
	pub x: Fe25519,
	pub y: Fe25519,
	pub z: Fe25519,
	pub t: Fe25519,
}

pub fn make_ge25519() -> Ge25519 {
	Ge25519 {
		x: make_fe25519(),
		y: make_fe25519(),
		z: make_fe25519(),
		t: make_fe25519(),
	}
}

fn copy_ge25519(r: &mut Ge25519, x: &Ge25519) {
	fe25519_cp(&mut r.x, &x.x);
	fe25519_cp(&mut r.y, &x.y);
	fe25519_cp(&mut r.z, &x.z);
	fe25519_cp(&mut r.t, &x.t);
}


/* 
 * Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2 
 * with d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
 * Base point: (15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960);
 */

/// Analog of constant ge25519_ecd in crypto_sign/ed25519/ref/ge25519.c
/// d
const ge25519_ecd: Fe25519 = Fe25519 {
	v: [
		0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75,
		0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00,
		0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C,
		0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52 ]
};

/// Analog of constant ge25519_ec2d in crypto_sign/ed25519/ref/ge25519.c
/// 2*d
const ge25519_ec2d: Fe25519 = Fe25519 {
	v: [
		0x59, 0xF1, 0xB2, 0x26, 0x94, 0x9B, 0xD6, 0xEB,
		0x56, 0xB1, 0x83, 0x82, 0x9A, 0x14, 0xE0, 0x00,
		0x30, 0xD1, 0xF3, 0xEE, 0xF2, 0x80, 0x8E, 0x19,
		0xE7, 0xFC, 0xDF, 0x56, 0xDC, 0xD9, 0x06, 0x24 ]
};

/// Analog of constant ge25519_sqrtm1 in crypto_sign/ed25519/ref/ge25519.c
/// sqrt(-1)
const ge25519_sqrtm1: Fe25519 = Fe25519 {
	v: [
		0xB0, 0xA0, 0x0E, 0x4A, 0x27, 0x1B, 0xEE, 0xC4,
		0x78, 0xE4, 0x2F, 0xAD, 0x06, 0x18, 0x43, 0x2F,
		0xA7, 0xD7, 0xFB, 0x3D, 0x99, 0x00, 0x4D, 0x2B,
		0x0B, 0xDF, 0xC1, 0x4F, 0x80, 0x24, 0x83, 0x2B ]
};

/// Analog of macro'ed struct ge25519_p3 in crypto_sign/ed25519/ref/ge25519.c
type Ge25519_p3 = Ge25519;

/// Analog of struct ge25519_p1p1 in crypto_sign/ed25519/ref/ge25519.c
struct Ge25519_p1p1 {
	x: Fe25519,
	y: Fe25519,
	z: Fe25519,
	t: Fe25519,
}

fn make_ge25519_p1p1() -> Ge25519_p1p1 {
	Ge25519_p1p1 {
		x: make_fe25519(),
		y: make_fe25519(),
		z: make_fe25519(),
		t: make_fe25519(),
	}
}

// Analog of struct ge25519_p2 in crypto_sign/ed25519/ref/ge25519.c
//
// It is `Ge25519` without `t`:
// struct Ge25519_p2 {
// 	x: Fe25519,
// 	y: Fe25519,
// 	z: Fe25519,
// }
// Original code casts `Ge25519` to `Ge25519_p2`, but casts in rust are
// not there yet for non-primitive types.
// There are functions that will have `_mix` in name (following an example of
// `mixadd`). These are used in C with casts, while we have to improvise.

/// Analog of struct ge25519_aff in crypto_sign/ed25519/ref/ge25519.c
pub struct Ge25519_aff {
	pub x: Fe25519,
	pub y: Fe25519,
}

fn make_ge25519_aff() -> Ge25519_aff {
	Ge25519_aff {
		x: make_fe25519(),
		y: make_fe25519(),
	}
}

fn copy_ge25519_aff(r: &mut Ge25519_aff, x: &Ge25519_aff) {
	fe25519_cp(&mut r.x, &x.x);
	fe25519_cp(&mut r.y, &x.y);
}

fn copy_ge25519_aff_mix(r: &mut Ge25519, x: &Ge25519_aff) {
	fe25519_cp(&mut r.x, &x.x);
	fe25519_cp(&mut r.y, &x.y);
}

/// Analog of constant ge25519_base in crypto_sign/ed25519/ref/ge25519.c
/// Packed coordinates of the base point
pub const ge25519_base: Ge25519 = Ge25519 {
	x: Fe25519 {
		v: [
			0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9,
			0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
			0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0,
			0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21 ]
	},
	y: Fe25519 {
		v: [
			0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
			0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
			0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
			0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 ]
	},
	z: Fe25519 {
		v: [
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
	},
	t: Fe25519 {
		v: [
			0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D,
			0xF5, 0x52, 0x51, 0x77, 0x80, 0x9F, 0xF0, 0x20,
			0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66,
			0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67 ]
	}
};

/// Analog of p1p1_to_p2 in crypto_sign/ed25519/ref/ge25519.c
fn p1p1_to_p2_mix(r: &mut Ge25519, p: &Ge25519_p1p1) {
	fe25519_mul(&mut r.x, &p.x, &p.t);
	fe25519_mul(&mut r.y, &p.y, &p.z);
	fe25519_mul(&mut r.z, &p.z, &p.t);
}

/// Analog of p1p1_to_p3 in crypto_sign/ed25519/ref/ge25519.c
fn p1p1_to_p3(r: &mut Ge25519_p3, p: &Ge25519_p1p1) {
	p1p1_to_p2_mix(r, p);
	fe25519_mul(&mut r.t, &p.x, &p.y);
}

/// Analog of ge25519_mixadd2 in crypto_sign/ed25519/ref/ge25519.c
fn ge25519_mixadd2(r: &mut Ge25519_p3, q: &Ge25519_aff) {
	let mut a = make_fe25519();
	let mut b = make_fe25519();
	let mut t1 = make_fe25519();
	let mut t2 = make_fe25519();
	let mut c = make_fe25519();
	let mut d = make_fe25519();
	let mut e = make_fe25519();
	let mut f = make_fe25519();
	let mut g = make_fe25519();
	let mut h = make_fe25519();
	let mut qt = make_fe25519();
	let mut t3 = make_fe25519();
	fe25519_mul(&mut qt, &q.x, &q.y);
	fe25519_sub(&mut a, &r.y, &r.x); /* A = (Y1-X1)*(Y2-X2) */
	fe25519_add(&mut b, &r.y, &r.x); /* B = (Y1+X1)*(Y2+X2) */
	fe25519_sub(&mut t1, &q.y, &q.x);
	fe25519_add(&mut t2, &q.y, &q.x);
	fe25519_mul(&mut t3, &a, &t1); fe25519_cp(&mut a, &t3);
	fe25519_mul(&mut t3, &b, &t2); fe25519_cp(&mut b, &t3);
	fe25519_sub(&mut e, &b, &a); /* E = B-A */
	fe25519_add(&mut h, &b, &a); /* H = B+A */
	fe25519_mul(&mut c, &r.t, &qt); /* C = T1*k*T2 */
	fe25519_mul(&mut t3, &c, &ge25519_ec2d); fe25519_cp(&mut c, &t3);
	fe25519_add(&mut d, &r.z, &r.z); /* D = Z1*2 */
	fe25519_sub(&mut f, &d, &c); /* F = D-C */
	fe25519_add(&mut g, &d, &c); /* G = D+C */
	fe25519_mul(&mut r.x, &e, &f);
	fe25519_mul(&mut r.y, &h, &g);
	fe25519_mul(&mut r.z, &g, &f);
	fe25519_mul(&mut r.t, &e, &h);
}

/// Analog of add_p1p1 in crypto_sign/ed25519/ref/ge25519.c
fn add_p1p1(r: &mut Ge25519_p1p1, p: &Ge25519_p3, q: &Ge25519_p3) {
	let mut a = make_fe25519();
	let mut b = make_fe25519();
	let mut c = make_fe25519();
	let mut d = make_fe25519();
	let mut t = make_fe25519();
	let mut t2 = make_fe25519();

	fe25519_sub(&mut a, &p.y, &p.x); /* A = (Y1-X1)*(Y2-X2) */
	fe25519_sub(&mut t, &q.y, &q.x);
	fe25519_mul(&mut t2, &a, &t); fe25519_cp(&mut a, &t2);
	fe25519_add(&mut b, &p.x, &p.y); /* B = (Y1+X1)*(Y2+X2) */
	fe25519_add(&mut t, &q.x, &q.y);
	fe25519_mul(&mut t2, &b, &t); fe25519_cp(&mut b, &t2);
	fe25519_mul(&mut c, &p.t, &q.t); /* C = T1*k*T2 */
	fe25519_mul(&mut t2, &c, &ge25519_ec2d); fe25519_cp(&mut c, &t2);
	fe25519_mul(&mut d, &p.z, &q.z); /* D = Z1*2*Z2 */
	fe25519_add(&mut t2, &d, &d); fe25519_cp(&mut d, &t2);
	fe25519_sub(&mut r.x, &b, &a); /* E = B-A */
	fe25519_sub(&mut r.t, &d, &c); /* F = D-C */
	fe25519_add(&mut r.z, &d, &c); /* G = D+C */
	fe25519_add(&mut r.y, &b, &a); /* H = B+A */
}

/// Analog of dbl_p1p1 in crypto_sign/ed25519/ref/ge25519.c
/// See http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
fn dbl_p1p1_casted_p2(r: &mut Ge25519_p1p1, p: &Ge25519) {
	let mut a = make_fe25519();
	let mut b = make_fe25519();
	let mut c = make_fe25519();
	let mut d = make_fe25519();
	let mut t = make_fe25519();

	fe25519_square(&mut a, &p.x);
	fe25519_square(&mut b, &p.y);
	fe25519_square(&mut c, &p.z);
	fe25519_add(&mut t, &c, &c); fe25519_cp(&mut c, &t);
	fe25519_neg(&mut d, &a);

	fe25519_add(&mut r.x, &p.x, &p.y);
	fe25519_square(&mut t, &r.x); fe25519_cp(&mut r.x, &t);
	fe25519_sub(&mut t, &r.x, &a); fe25519_cp(&mut r.x, &t);
	fe25519_sub(&mut t, &r.x, &b); fe25519_cp(&mut r.x, &t);
	fe25519_add(&mut r.z, &d, &b);
	fe25519_sub(&mut r.t, &r.z, &c);
	fe25519_sub(&mut r.y, &d, &b);
}

/// Analog of cmov_aff in crypto_sign/ed25519/ref/ge25519.c
/// Constant-time version of: if(b) r = p
fn cmov_aff(r: &mut Ge25519_aff, p: &Ge25519_aff, b: u8) {
	fe25519_cmov(&mut r.x, &p.x, b);
	fe25519_cmov(&mut r.y, &p.y, b);
}

/// Analog of equal in crypto_sign/ed25519/ref/ge25519.c
fn equal(b: i8, c: i8) -> u8 {
	let ub: u8 = b as u8;
	let uc: u8 = c as u8;
	let x: u8 = ub ^ uc; /* 0: yes; 1..255: no */
	let mut y: u32 = x as u32; /* 0: yes; 1..255: no */
	y = subw!( y, 1 ); /* 4294967295: yes; 0..254: no */
	y >>= 31; /* 1: yes; 0: no */
	y as u8
}

/// Analog of negative in crypto_sign/ed25519/ref/ge25519.c
fn negative(b: i8) -> u8 {
	let mut x: u64 = b as u64; /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
	x >>= 63; /* 1: yes; 0: no */
	x as u8
}

/// Analog of choose_t in crypto_sign/ed25519/ref/ge25519.c
fn choose_t(t: &mut Ge25519_aff, pos: usize, b: i8) {
	/* constant time */
	let mut v = make_fe25519();
	copy_ge25519_aff(t, &ge25519_base_multiples_affine[5*pos+0]);
	cmov_aff(t, &ge25519_base_multiples_affine[5*pos+1], equal(b,1)|equal(b,-1));
	cmov_aff(t, &ge25519_base_multiples_affine[5*pos+2], equal(b,2)|equal(b,-2));
	cmov_aff(t, &ge25519_base_multiples_affine[5*pos+3], equal(b,3)|equal(b,-3));
	cmov_aff(t, &ge25519_base_multiples_affine[5*pos+4], equal(b,-4));
	fe25519_neg(&mut v, &t.x);
	fe25519_cmov(&mut t.x, &v, negative(b));
}

/// Analog of setneutral in crypto_sign/ed25519/ref/ge25519.c
fn setneutral(r: &mut Ge25519) {
	fe25519_setzero(&mut r.x);
	fe25519_setone(&mut r.y);
	fe25519_setone(&mut r.z);
	fe25519_setzero(&mut r.t);
}

/* ********************************************************************
 *                    EXPORTED FUNCTIONS
 ******************************************************************** */

/// Analog of ge25519_unpackneg_vartime in crypto_sign/ed25519/ref/ge25519.c
/// return true on success, false otherwise
pub fn ge25519_unpackneg_vartime(r: &mut Ge25519_p3, p: &[u8]) -> bool {
	let mut t = make_fe25519();
	let mut chk = make_fe25519();
	let mut num = make_fe25519();
	let mut den = make_fe25519();
	let mut den2 = make_fe25519();
	let mut den4 = make_fe25519();
	let mut den6 = make_fe25519();
	let mut t2 = make_fe25519();

	fe25519_setone(&mut r.z);
	let par = p[31] >> 7;
	fe25519_unpack(&mut r.y, p); 
	fe25519_square(&mut num, &r.y); /* x = y^2 */
	fe25519_mul(&mut den, &num, &ge25519_ecd); /* den = dy^2 */
	fe25519_sub(&mut t2, &num, &r.z); fe25519_cp(&mut num, &t2); /* x = y^2-1 */
	fe25519_add(&mut t2, &r.z, &den); fe25519_cp(&mut den, &t2); /* den = dy^2+1 */

	/* Computation of sqrt(num/den) */
	/* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
	fe25519_square(&mut den2, &den);
	fe25519_square(&mut den4, &den2);
	fe25519_mul(&mut den6, &den4, &den2);
	fe25519_mul(&mut t, &den6, &num);
	fe25519_mul(&mut t2, &t, &den); fe25519_cp(&mut t, &t2);

	fe25519_pow2523(&mut t2, &t); fe25519_cp(&mut t, &t2);
	/* 2. computation of r.x = t * num * den^3 */
	fe25519_mul(&mut t2, &t, &num); fe25519_cp(&mut t, &t2);
	fe25519_mul(&mut t2, &t, &den); fe25519_cp(&mut t, &t2);
	fe25519_mul(&mut t2, &t, &den); fe25519_cp(&mut t, &t2);
	fe25519_mul(&mut r.x, &t, &den);

	/* 3. Check whether sqrt computation gave correct result, multiply by sqrt(-1) if not: */
	fe25519_square(&mut chk, &r.x);
	fe25519_mul(&mut t2, &chk, &den); fe25519_cp(&mut chk, &t2);
	if !fe25519_iseq_vartime(&mut chk, &num) {
		fe25519_mul(&mut t2, &r.x, &ge25519_sqrtm1); fe25519_cp(&mut r.x, &t2);
	}

	/* 4. Now we have one of the two square roots, except if input was not a square */
	fe25519_square(&mut chk, &r.x);
	fe25519_mul(&mut t2, &chk, &den); fe25519_cp(&mut chk, &t2);
	if !fe25519_iseq_vartime(&chk, &num) {
		return false;
	}

	/* 5. Choose the desired square root according to parity: */
	if fe25519_getparity(&r.x) != (1-par) {
		fe25519_neg(&mut t2, &r.x); fe25519_cp(&mut r.x, &t2);
	}

	fe25519_mul(&mut r.t, &r.x, &r.y);
	true
}

/// Analog of ge25519_pack in crypto_sign/ed25519/ref/ge25519.c
pub fn ge25519_pack(r: &mut [u8], p: & Ge25519_p3) {
	let mut tx = make_fe25519();
	let mut ty = make_fe25519();
	let mut zi = make_fe25519();
	fe25519_invert(&mut zi, &p.z); 
	fe25519_mul(&mut tx, &p.x, &zi);
	fe25519_mul(&mut ty, &p.y, &zi);
	fe25519_pack(r, &ty);
	r[31] ^= fe25519_getparity(&tx) << 7;
}

/// Analog of ge25519_double_scalarmult_vartime in
/// crypto_sign/ed25519/ref/ge25519.c
/// computes [s1]p1 + [s2]p2
pub fn ge25519_double_scalarmult_vartime(r: &mut Ge25519_p3,
		p1: &Ge25519_p3, s1: &Sc25519, p2: &Ge25519_p3, s2: &Sc25519) {
	let mut tp1p1 = make_ge25519_p1p1();
	let mut pre: [Ge25519_p3; 16] = [
		make_ge25519(), make_ge25519(), make_ge25519(), make_ge25519(),
		make_ge25519(), make_ge25519(), make_ge25519(), make_ge25519(),
		make_ge25519(), make_ge25519(), make_ge25519(), make_ge25519(),
		make_ge25519(), make_ge25519(), make_ge25519(), make_ge25519()	];
	let mut b: [u8; 127] = [0; 127];

	/* precomputation   s2 s1 */
	/*                  00 00 */
	setneutral(&mut pre[0]);
	/*                  00 01 */
	copy_ge25519(&mut pre[1], p1);
	/*                  00 10 */
	dbl_p1p1_casted_p2(&mut tp1p1, &p1); p1p1_to_p3(&mut pre[2], &tp1p1);
	/*                  00 11 */
	add_p1p1(&mut tp1p1, &pre[1], &pre[2]); p1p1_to_p3(&mut pre[3], &tp1p1);
	/*                  01 00 */
	copy_ge25519(&mut pre[4], p2);
	/*                  01 01 */
	add_p1p1(&mut tp1p1, &pre[1], &pre[4]); p1p1_to_p3(&mut pre[5], &tp1p1);
	/*                  01 10 */
	add_p1p1(&mut tp1p1,&pre[2], &pre[4]); p1p1_to_p3(&mut pre[6], &tp1p1);
	/*                  01 11 */
	add_p1p1(&mut tp1p1,&pre[3], &pre[4]); p1p1_to_p3(&mut pre[7], &tp1p1);
	/*                  10 00 */
	dbl_p1p1_casted_p2(&mut tp1p1, &p2); p1p1_to_p3(&mut pre[8], &tp1p1);
	/*                  10 01 */
	add_p1p1(&mut tp1p1, &pre[1], &pre[8]); p1p1_to_p3(&mut pre[9], &tp1p1);
	/*                  10 10 */
	dbl_p1p1_casted_p2(&mut tp1p1, &pre[5]); p1p1_to_p3(&mut pre[10], &tp1p1);
	/*                  10 11 */
	add_p1p1(&mut tp1p1,&pre[3], &pre[8]);      p1p1_to_p3(&mut pre[11], &tp1p1);
	/*                  11 00 */
	add_p1p1(&mut tp1p1,&pre[4], &pre[8]);      p1p1_to_p3(&mut pre[12], &tp1p1);
	/*                  11 01 */
	add_p1p1(&mut tp1p1,&pre[1],&pre[12]);      p1p1_to_p3(&mut pre[13], &tp1p1);
	/*                  11 10 */
	add_p1p1(&mut tp1p1,&pre[2],&pre[12]);      p1p1_to_p3(&mut pre[14], &tp1p1);
	/*                  11 11 */
	add_p1p1(&mut tp1p1,&pre[3],&pre[12]);      p1p1_to_p3(&mut pre[15], &tp1p1);

	sc25519_2interleave2(&mut b, s1, s2);

	/* scalar multiplication */
	copy_ge25519(r, &pre[b[126] as usize]);
	let mut i: i8 = 125;
	while i >= 0 {
		dbl_p1p1_casted_p2(&mut tp1p1, &r);
		p1p1_to_p2_mix(r, &tp1p1);
		dbl_p1p1_casted_p2(&mut tp1p1, &r);
		if b[i as usize] != 0 {
			p1p1_to_p3(r, &tp1p1);
			add_p1p1(&mut tp1p1, r, &pre[b[i as usize] as usize]);
		}
		if i != 0 { p1p1_to_p2_mix(r, &tp1p1); }
		else { p1p1_to_p3(r, &tp1p1); }
		i -= 1;
	}
}

/// Analog of ge25519_scalarmult_base in crypto_sign/ed25519/ref/ge25519.c
pub fn ge25519_scalarmult_base(r: &mut Ge25519_p3, s: &Sc25519) {
	let mut b: [i8; 85] = [0; 85];
	let mut t = make_ge25519_aff();
	sc25519_window3(&mut b, s);

	choose_t(&mut t, 0, b[0]);
	copy_ge25519_aff_mix(r, &t);
	fe25519_setone(&mut r.z);
	fe25519_mul(&mut r.t, &r.x, &r.y);
	for i in 1..85 {
		choose_t(&mut t, i, b[i]);
		ge25519_mixadd2(r, &t);
	}
}