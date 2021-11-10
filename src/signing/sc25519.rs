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
//! crypto_sign/ed25519/ref/sc25519.c

use crate::util::ops::{ subw, add2 };

/// Analog of struct sc25519 in crypto_sign/ed25519/ref/sc25519.h
pub struct Sc25519 {
	pub v: [u32; 32],
}

#[inline]
pub fn make_sc25519() -> Sc25519 {
	Sc25519 { v: [0; 32] }
}

/// Analog of struct shortsc25519 in crypto_sign/ed25519/ref/sc25519.h
/// but is never used, hence commented out
// pub struct ShortSc25519 {
// 	pub v: [u32; 16],
// }


/* Arithmetic modulo the group order m = 2^252 +  27742317777372353535851937790883648493 = 7237005577332262213973186563042994240857116359379907606001950938285454250989 */

#[allow(non_upper_case_globals)]
const m: [u32; 32] = [
	0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
	0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 ];

#[allow(non_upper_case_globals)]
const mu: [u32; 33] = [
	0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED,
	0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21,
	0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x0F ];

/// Analog of lt in crypto_sign/ed25519/ref/sc25519.c
/// All inputs are 16-bit.
#[inline]
fn lt(a: u32, b: u32) -> u32 {
  let mut x: u32 = a;
  x = subw!( x, b ); /* 0..65535: no; 4294901761..4294967295: yes */
  x >>= 31; /* 0: no; 1: yes */
  x
}

/// Analog of reduce_add_sub in crypto_sign/ed25519/ref/sc25519.c
/// Reduce coefficients of r before calling reduce_add_sub
fn reduce_add_sub(r: &mut Sc25519) {
	let mut pb: u32 = 0;
	let mut b: u32 = 0;
	let mut t: [u8; 32] = [0; 32];

	for i in 0..32 {
		pb += m[i];
		b = lt(r.v[i], pb);
		t[i] = add2!( subw!( r.v[i], pb ), b<<8 ) as u8;
		pb = b;
	}
	let mask: u32 = subw!( b, 1 );
	for i in 0..32 { 
		r.v[i] ^= mask & (r.v[i] ^ (t[i] as u32));
	}
}

/// Analog of barrett_reduce in crypto_sign/ed25519/ref/sc25519.c
/// Reduce coefficients of x before calling barrett_reduce
fn barrett_reduce(r: &mut Sc25519, x: &[u32]) {
	/* See HAC, Alg. 14.42 */
	let mut q2: [u32; 66] = [0; 66];
	//   crypto_uint32 *q3 = q2 + 33;
	let mut r1: [u32; 33] = [0; 33];
	let mut r2: [u32; 33] = [0; 33];

	for i in 0..33 {
		for j in 0..33 {
			if i+j >= 31 { q2[i+j] += mu[i]*x[j+31]; }
		}
	}
	let mut carry: u32 = q2[31] >> 8;
	q2[32] += carry;
	carry = q2[32] >> 8;
	q2[33] += carry;

	r1.copy_from_slice(&x[0..33]);
	let q3 = &q2[33..];
	for i in 0..32 {
		for j in 0..33 {
			if i+j < 33 { r2[i+j] += m[i]*q3[j]; }
		}
	}

	for i in 0..32 {
		carry = r2[i] >> 8;
		r2[i+1] += carry;
		r2[i] &= 0xff;
	}

	let mut pb: u32 = 0;

	for i in 0..32 {
		pb += r2[i];
		let b = lt(r1[i],pb);
		r.v[i] = add2!( subw!( r1[i], pb ), b<<8 );
		pb = b;
	}

	/* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3 
	* If so: Handle  it here!
	*/

	reduce_add_sub(r);
	reduce_add_sub(r);
}

/// Analog of sc25519_from32bytes in crypto_sign/ed25519/ref/sc25519.c
pub fn sc25519_from32bytes(r: &mut Sc25519, x: &[u8]) {
	let mut t: [u32; 64] = [0; 64];
	for i in 0..32 { t[i] = x[i] as u32; }
	barrett_reduce(r, &t);
}

/// Analog of sc25519_from64bytes in crypto_sign/ed25519/ref/sc25519.c
pub fn sc25519_from64bytes(r: &mut Sc25519, x: &[u8]) {
	let mut t: [u32; 64] = [0; 64];
	for i in 0..64 { t[i] = x[i] as u32; }
	barrett_reduce(r, &t);
}

/// Analog of sc25519_to32bytes in crypto_sign/ed25519/ref/sc25519.c
pub fn sc25519_to32bytes(r: &mut [u8], x: &Sc25519) {
  for i in 0..32 { r[i] = x.v[i] as u8; }
}

/// Analog of sc25519_add in crypto_sign/ed25519/ref/sc25519.c
pub fn sc25519_add(r: &mut Sc25519, x: &Sc25519, y: &Sc25519) {
	for i in 0..32 { r.v[i] = x.v[i] + y.v[i]; }
	for i in 0..31 {
		let carry = r.v[i] >> 8;
		r.v[i+1] += carry;
		r.v[i] &= 0xff;
	}
	reduce_add_sub(r);
}

/// Analog of sc25519_mul in crypto_sign/ed25519/ref/sc25519.c
pub fn sc25519_mul(r: &mut Sc25519, x: &Sc25519, y: &Sc25519) {
	let mut t: [u32; 64] = [0; 64];

	for i in 0..32 {
		for j in 0..32 {
			t[i+j] += x.v[i] * y.v[j];
		}
	}

	/* Reduce coefficients */
	for i in 0..63 {
		let carry = t[i] >> 8;
		t[i+1] += carry;
		t[i] &= 0xff;
	}

	barrett_reduce(r, &t);
}

/// Analog of sc25519_window3 in crypto_sign/ed25519/ref/sc25519.c
pub fn sc25519_window3(r: &mut [i8], s: &Sc25519) {
	for i in 0..10 {
		r[8*i+0]  = ( s.v[3*i+0]       & 7) as i8;
		r[8*i+1]  = ((s.v[3*i+0] >> 3) & 7) as i8;
		r[8*i+2]  = ((s.v[3*i+0] >> 6) & 7) as i8;
		r[8*i+2] ^= ((s.v[3*i+1] << 2) & 7) as i8;
		r[8*i+3]  = ((s.v[3*i+1] >> 1) & 7) as i8;
		r[8*i+4]  = ((s.v[3*i+1] >> 4) & 7) as i8;
		r[8*i+5]  = ((s.v[3*i+1] >> 7) & 7) as i8;
		r[8*i+5] ^= ((s.v[3*i+2] << 1) & 7) as i8;
		r[8*i+6]  = ((s.v[3*i+2] >> 2) & 7) as i8;
		r[8*i+7]  = ((s.v[3*i+2] >> 5) & 7) as i8;
	}
	r[80]  = ( s.v[30]       & 7) as i8;
	r[81]  = ((s.v[30] >> 3) & 7) as i8;
	r[82]  = ((s.v[30] >> 6) & 7) as i8;
	r[82] ^= ((s.v[31] << 2) & 7) as i8;
	r[83]  = ((s.v[31] >> 1) & 7) as i8;
	r[84]  = ((s.v[31] >> 4) & 7) as i8;

	/* Making it signed */
	let mut carry: i8 = 0;
	for i in 0..84 {
		r[i] += carry;
		r[i+1] += r[i] >> 3;
		r[i] &= 7;
		carry = r[i] >> 2;
		r[i] -= carry<<3;
	}
	r[84] += carry;
}

/// Analog of sc25519_2interleave2 in crypto_sign/ed25519/ref/sc25519.c
pub fn sc25519_2interleave2(r: &mut[u8], s1: &Sc25519, s2: &Sc25519) {
	for i in 0..31 {
		r[4*i]   = (( s1.v[i]       & 3) ^ (( s2.v[i]       & 3) << 2)) as u8;
		r[4*i+1] = (((s1.v[i] >> 2) & 3) ^ (((s2.v[i] >> 2) & 3) << 2)) as u8;
		r[4*i+2] = (((s1.v[i] >> 4) & 3) ^ (((s2.v[i] >> 4) & 3) << 2)) as u8;
		r[4*i+3] = (((s1.v[i] >> 6) & 3) ^ (((s2.v[i] >> 6) & 3) << 2)) as u8;
	}
	r[124] = (( s1.v[31]       & 3) ^ (( s2.v[31]       & 3) << 2)) as u8;
	r[125] = (((s1.v[31] >> 2) & 3) ^ (((s2.v[31] >> 2) & 3) << 2)) as u8;
	r[126] = (((s1.v[31] >> 4) & 3) ^ (((s2.v[31] >> 4) & 3) << 2)) as u8;
}