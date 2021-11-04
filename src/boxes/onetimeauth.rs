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

//! This module provides poly1305, mirroring functions from
//! crypto_onetimeauth/poly1305/ref/auth.c and
//! crypto_onetimeauth/poly1305/ref/verify.c

fn add(h: &mut [u32], c: &[u32]) {
	let mut u: u32 = 0;
	for j in 0..17 { u += h[j] + c[j]; h[j] = u & 255; u >>= 8; }
}

fn squeeze(h: &mut [u32]) {
	let mut u: u32 = 0;
	for j in 0..16 { u += h[j]; h[j] = u & 255; u >>= 8; }
	u += h[16]; h[16] = u & 3;
	u = 5 * (u >> 2);
	for j in 0..16 { u += h[j]; h[j] = u & 255; u >>= 8; }
	u += h[16]; h[16] = u;
}

static MINUSP: &[u32] = &[
	5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252 ];

fn freeze(h: &mut [u32]) {
	let mut horig: [u32; 17] = [0; 17];
	for j in 0..17 { horig[j] = h[j]; }
	add(h, MINUSP);
	let negative = -((h[16] >> 7) as i32) as u32;
	for j in 0..17 { h[j] ^= negative & (horig[j] ^ h[j]); }
}

fn mulmod(h: &mut [u32], r: &[u32]) {
	let mut hr: [u32; 17] = [0; 17];
	for i in 0..17 {
		let mut u = 0 as u32;
		for j in 0..i+1 { u += h[j] * r[i - j]; }
		for j in (i+1)..17 { u += 320 * h[j] * r[i + 17 - j]; }
		hr[i] = u;
	}
	for i in 0..17 { h[i] = hr[i]; }
	squeeze(h);
}

pub fn poly1305(out: &mut [u8], inc: &[u8], k: &[u8]) {
	let mut r: [u32; 17] = [0; 17];
	let mut h: [u32; 17] = [0; 17];
	let mut c: [u32; 17] = [0; 17];

	r[0] = k[0] as u32;
	r[1] = k[1] as u32;
	r[2] = k[2] as u32;
	r[3] = (k[3] & 15) as u32;
	r[4] = (k[4] & 252) as u32;
	r[5] = k[5] as u32;
	r[6] = k[6] as u32;
	r[7] = (k[7] & 15) as u32;
	r[8] = (k[8] & 252) as u32;
	r[9] = k[9] as u32;
	r[10] = k[10] as u32;
	r[11] = (k[11] & 15) as u32;
	r[12] = (k[12] & 252) as u32;
	r[13] = k[13] as u32;
	r[14] = k[14] as u32;
	r[15] = (k[15] & 15) as u32;
	r[16] = 0;

	let mut inlen = inc.len();
	let mut inc_start = 0;

	while inlen > 0 {
		for j in 0..17 { c[j] = 0; }
		let mut j = 0;
		while (j < 16) && (j < inlen) {
			c[j] = inc[inc_start+j] as u32;
			j += 1;
		}
		c[j] = 1;
		inc_start += j; inlen -= j;
		add(&mut h, &c);
		mulmod(&mut h, &r);
	}

	freeze(&mut h);

	for j in 0..16 { c[j] = k[j + 16] as u32; }
	c[16] = 0;
	add(&mut h, &c);
	for j in 0..16 { out[j] = h[j] as u8; }

}

use crate::util::verify::compare_v16;

pub fn poly1305_verify(h: &[u8], inc: &[u8], k: &[u8]) -> bool {
  let mut correct: [u8; 16] = [0; 16];
  poly1305(&mut correct, inc, k);
  compare_v16(h, &correct)
}

#[cfg(test)]
mod tests {

	use super::{ poly1305, poly1305_verify };
	use crate::util::verify::compare_v16;

	// Analog to tests/onetimeauth.c, expected result from tests/onetimeauth.out
	#[test]
	fn test_of_poly1305_in_onetimeauth() {

		let rs: [u8; 32] = [
			0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91,
			0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25,
			0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65,
			0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80 ];
		
		let c: [u8; 131] = [
			0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73,
			0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce,
			0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4,
			0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a,
			0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b,
			0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72,
			0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2,
			0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38,
			0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a,
			0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae,
			0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea,
			0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda,
			0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde,
			0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3,
			0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6,
			0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74,
			0xe3,0x55,0xa5 ];

		// this vector is for calculated poly hash
		let mut a: [u8; 16] = [0; 16];
		
		poly1305(&mut a, &c, &rs);

		// taken from tests/onetimeauth.out
		assert!(compare_v16(&a, &[
			0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5,
			0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9 ]));

		assert!(poly1305_verify(&a, &c, &rs));

	}
	
}