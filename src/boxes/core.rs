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

//! This module provides core salsa20, mirroring functions from
//! crypto_core/salsa20/ref/core.c

use crate::util::ops::{ add2, incr };

#[inline]
fn rotate(u: u32, c: i32) -> u32 {
	(u << c) | (u >> (32 - c))
}

#[inline]
fn load_littleendian(x: &[u8]) -> u32 {
	(x[0] as u32) |
	((x[1] as u32) << 8) |
	((x[2] as u32) << 16) |
	((x[3] as u32) << 24)
}

#[inline]
fn store_littleendian(x: &mut [u8], mut u: u32) {
	x[0] = u as u8; u >>= 8;
	x[1] = u as u8; u >>= 8;
	x[2] = u as u8; u >>= 8;
	x[3] = u as u8;
}

/// Analog of crypto_core in crypto_core/salsa20/ref/core.c
/// 
pub fn salsa20(out: &mut [u8], inc: &[u8], k: &[u8], c: &[u8]) {

	let j0 = load_littleendian(&c[0..4]);
	let mut x0 = j0;
	let j1 = load_littleendian(&k[0..4]);
	let mut x1 = j1;
	let j2 = load_littleendian(&k[4..8]);
	let mut x2 = j2;
	let j3 = load_littleendian(&k[8..12]);
	let mut x3 = j3;
	let j4 = load_littleendian(&k[12..16]);
	let mut x4 = j4;
	let j5 = load_littleendian(&c[4..8]);
	let mut x5 = j5;
	let j6 = load_littleendian(&inc[0..4]);
	let mut x6 = j6;
	let j7 = load_littleendian(&inc[4..8]);
	let mut x7 = j7;
	let j8 = load_littleendian(&inc[8..12]);
	let mut x8 = j8;
	let j9 = load_littleendian(&inc[12..16]);
	let mut x9 = j9;
	let j10 = load_littleendian(&c[8..12]);
	let mut x10 = j10;
	let j11 = load_littleendian(&k[16..20]);
	let mut x11 = j11;
	let j12 = load_littleendian(&k[20..24]);
	let mut x12 = j12;
	let j13 = load_littleendian(&k[24..28]);
	let mut x13 = j13;
	let j14 = load_littleendian(&k[28..32]);
	let mut x14 = j14;
	let j15 = load_littleendian(&c[12..16]);
	let mut x15 = j15;

	for _ in 0..10 {
		 x4 ^= rotate(add2!( x0,x12), 7);
		 x8 ^= rotate(add2!( x4, x0), 9);
		x12 ^= rotate(add2!( x8, x4),13);
		 x0 ^= rotate(add2!(x12, x8),18);
		 x9 ^= rotate(add2!( x5, x1), 7);
		x13 ^= rotate(add2!( x9, x5), 9);
		 x1 ^= rotate(add2!(x13, x9),13);
		 x5 ^= rotate(add2!( x1,x13),18);
		x14 ^= rotate(add2!(x10, x6), 7);
		 x2 ^= rotate(add2!(x14,x10), 9);
		 x6 ^= rotate(add2!( x2,x14),13);
		x10 ^= rotate(add2!( x6, x2),18);
		 x3 ^= rotate(add2!(x15,x11), 7);
		 x7 ^= rotate(add2!( x3,x15), 9);
		x11 ^= rotate(add2!( x7, x3),13);
		x15 ^= rotate(add2!(x11, x7),18);
		 x1 ^= rotate(add2!( x0, x3), 7);
		 x2 ^= rotate(add2!( x1, x0), 9);
		 x3 ^= rotate(add2!( x2, x1),13);
		 x0 ^= rotate(add2!( x3, x2),18);
		 x6 ^= rotate(add2!( x5, x4), 7);
		 x7 ^= rotate(add2!( x6, x5), 9);
		 x4 ^= rotate(add2!( x7, x6),13);
		 x5 ^= rotate(add2!( x4, x7),18);
		x11 ^= rotate(add2!(x10, x9), 7);
		 x8 ^= rotate(add2!(x11,x10), 9);
		 x9 ^= rotate(add2!( x8,x11),13);
		x10 ^= rotate(add2!( x9, x8),18);
		x12 ^= rotate(add2!(x15,x14), 7);
		x13 ^= rotate(add2!(x12,x15), 9);
		x14 ^= rotate(add2!(x13,x12),13);
		x15 ^= rotate(add2!(x14,x13),18);
	}

	incr!( x0, j0);
	incr!( x1, j1);
	incr!( x2, j2);
	incr!( x3, j3);
	incr!( x4, j4);
	incr!( x5, j5);
	incr!( x6, j6);
	incr!( x7, j7);
	incr!( x8, j8);
	incr!( x9, j9);
	incr!(x10,j10);
	incr!(x11,j11);
	incr!(x12,j12);
	incr!(x13,j13);
	incr!(x14,j14);
	incr!(x15,j15);

	store_littleendian(&mut out[0..4],   x0);
	store_littleendian(&mut out[4..8],   x1);
	store_littleendian(&mut out[8..12],  x2);
	store_littleendian(&mut out[12..16], x3);
	store_littleendian(&mut out[16..20], x4);
	store_littleendian(&mut out[20..24], x5);
	store_littleendian(&mut out[24..28], x6);
	store_littleendian(&mut out[28..32], x7);
	store_littleendian(&mut out[32..36], x8);
	store_littleendian(&mut out[36..40], x9);
	store_littleendian(&mut out[40..44], x10);
	store_littleendian(&mut out[44..48], x11);
	store_littleendian(&mut out[48..52], x12);
	store_littleendian(&mut out[52..56], x13);
	store_littleendian(&mut out[56..60], x14);
	store_littleendian(&mut out[60..64], x15);

}
/// Analog of crypto_core in crypto_core/hsalsa20/ref2/core.c
/// 
pub fn hsalsa20(out: &mut [u8], inc: &[u8], k: &[u8], c: &[u8]) {

	let mut x0 = load_littleendian(&c[0..4]);
	let mut x1 = load_littleendian(&k[0..4]);
	let mut x2 = load_littleendian(&k[4..8]);
	let mut x3 = load_littleendian(&k[8..12]);
	let mut x4 = load_littleendian(&k[12..16]);
	let mut x5 = load_littleendian(&c[4..8]);
	let mut x6 = load_littleendian(&inc[0..4]);
	let mut x7 = load_littleendian(&inc[4..8]);
	let mut x8 = load_littleendian(&inc[8..12]);
	let mut x9 = load_littleendian(&inc[12..16]);
	let mut x10 = load_littleendian(&c[8..12]);
	let mut x11 = load_littleendian(&k[16..20]);
	let mut x12 = load_littleendian(&k[20..24]);
	let mut x13 = load_littleendian(&k[24..28]);
	let mut x14 = load_littleendian(&k[28..32]);
	let mut x15 = load_littleendian(&c[12..16]);

	for _ in 0..10 {
		 x4 ^= rotate(add2!( x0,x12), 7);
		 x8 ^= rotate(add2!( x4, x0), 9);
		x12 ^= rotate(add2!( x8, x4),13);
		 x0 ^= rotate(add2!(x12, x8),18);
		 x9 ^= rotate(add2!( x5, x1), 7);
		x13 ^= rotate(add2!( x9, x5), 9);
		 x1 ^= rotate(add2!(x13, x9),13);
		 x5 ^= rotate(add2!( x1,x13),18);
		x14 ^= rotate(add2!(x10, x6), 7);
		 x2 ^= rotate(add2!(x14,x10), 9);
		 x6 ^= rotate(add2!( x2,x14),13);
		x10 ^= rotate(add2!( x6, x2),18);
		 x3 ^= rotate(add2!(x15,x11), 7);
		 x7 ^= rotate(add2!( x3,x15), 9);
		x11 ^= rotate(add2!( x7, x3),13);
		x15 ^= rotate(add2!(x11, x7),18);
		 x1 ^= rotate(add2!( x0, x3), 7);
		 x2 ^= rotate(add2!( x1, x0), 9);
		 x3 ^= rotate(add2!( x2, x1),13);
		 x0 ^= rotate(add2!( x3, x2),18);
		 x6 ^= rotate(add2!( x5, x4), 7);
		 x7 ^= rotate(add2!( x6, x5), 9);
		 x4 ^= rotate(add2!( x7, x6),13);
		 x5 ^= rotate(add2!( x4, x7),18);
		x11 ^= rotate(add2!(x10, x9), 7);
		 x8 ^= rotate(add2!(x11,x10), 9);
		 x9 ^= rotate(add2!( x8,x11),13);
		x10 ^= rotate(add2!( x9, x8),18);
		x12 ^= rotate(add2!(x15,x14), 7);
		x13 ^= rotate(add2!(x12,x15), 9);
		x14 ^= rotate(add2!(x13,x12),13);
		x15 ^= rotate(add2!(x14,x13),18);
	}

	store_littleendian(&mut out[0..4],   x0);
	store_littleendian(&mut out[4..8],   x5);
	store_littleendian(&mut out[8..12],  x10);
	store_littleendian(&mut out[12..16], x15);
	store_littleendian(&mut out[16..20], x6);
	store_littleendian(&mut out[20..24], x7);
	store_littleendian(&mut out[24..28], x8);
	store_littleendian(&mut out[28..32], x9);

}

#[cfg(test)]
mod tests {
	
	use super::{ salsa20, hsalsa20 };
	use crate::util::verify::compare;

	// Analog of tests/core4.c, expected result printed in tests/core4.out
	#[test]
	fn test_of_salsa20_core4() {
		
		let k: [u8; 32] = [
			  1,  2,  3,  4,  5,  6,  7,  8,
			  9, 10, 11, 12, 13, 14, 15, 16,
			201,202,203,204,205,206,207,208,
			209,210,211,212,213,214,215,216 ];

		let inc: [u8; 16] = [
			101,102,103,104,105,106,107,108,
			109,110,111,112,113,114,115,116 ];

		let c: [u8; 16] = [
			101,120,112, 97,110,100, 32, 51,
			 50, 45, 98,121,116,101, 32,107 ];
		
		let mut out: [u8; 64] = [0; 64];
		
		salsa20(&mut out, &inc, &k, &c);
		
		// taken from tests/core4.out
		assert!(compare(&out, &[
			 69, 37, 68, 39, 41, 15,107,193,
			255,139,122,  6,170,233,217, 98,
			 89,144,182,106, 21, 51,200, 65,
			239, 49,222, 34,215,114, 40,126,
			104,197,  7,225,197,153, 31,  2,
			102, 78, 76,176, 84,245,246,184,
			177,160,133,130,  6, 72,149,119,
			192,195,132,236,234,103,246, 74 ]));

	}

	// Analog of tests/core1.c, expected result printed in tests/core1.out;
	// and analog of tests/core2.c, expected result printed in tests/core2.out
	#[test]
	fn test_of_hsalsa20_core_1_and_2() {

		// analog of tests/core1.c
		
		let shared: [u8; 32] = [
			0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,
			0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
			0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,
			0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42 ];
		
		let zero: [u8; 16] = [0; 16];	// original has 32 bytes, but 16 are used by crypto_core_hsalsa20
		
		let c: [u8; 16] = [
			0x65,0x78,0x70,0x61,0x6e,0x64,0x20,0x33,
			0x32,0x2d,0x62,0x79,0x74,0x65,0x20,0x6b ];
		
		let mut firstkey: [u8; 32] = [0; 32];
		
		hsalsa20(&mut firstkey, &zero, &shared, &c);	// writes result into firstkey
		
		// taken from tests/core1.out
		assert!(compare(&firstkey, &[
			0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,
			0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,
			0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,
			0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89 ]));

		// analog of tests/core2.c
		
		let nonceprefix: [u8; 16] = [
			0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,
			0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6 ];
		
		let mut secondkey: [u8; 32] = [0; 32];
		
		hsalsa20(&mut secondkey, &nonceprefix, &firstkey, &c);
		
		// taken from tests/core2.out
		assert!(compare(&secondkey, &[
			0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9,
			0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88,
			0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9,
			0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4 ]));
		
	}
	
}