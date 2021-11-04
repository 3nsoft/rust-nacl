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

//! This module provides salsa streaming, mirroring functions from
//! crypto_stream/salsa20/ref/stream.c, crypto_stream/salsa20/ref/xor.c,
//! crypto_stream/xsalsa20/ref/stream.c and crypto_stream/xsalsa20/ref/xor.c

use super::core::{ salsa20, hsalsa20 };
use crate::util::Resetable;

// string "expand 32-byte k" in ascii form
pub const SIGMA: &[u8] = &[
	101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107 ];

fn stream_32(c: &mut [u8], n: &[u8], k: &[u8]) {
	if c.len() != 32 { panic!("This code expects array c to be 32 bytes"); }
	let mut inc: [u8; 16] = [0; 16];
	inc[0..8].copy_from_slice(&n[0..8]);
	let mut block: [u8; 64] = [0; 64];
	salsa20(&mut block, &inc, k, SIGMA);
	c.copy_from_slice(&block[0..32]);
}

fn stream_xor(c0: &mut [u8], c: &mut [u8], m: &[u8], m_pad_len: usize,
		n: &[u8], k: &[u8]) {
	let mlen = m.len();
	let mut m_with_pad_len = mlen + m_pad_len;
	if (mlen == 0) || (m_pad_len > 32) || ((c.len() + 32) != m_with_pad_len)
	|| (c0.len() != 32) {
		panic!("Given mismatching sizes: c0 is {}, c is {}, m is {} and m_pad is {}", c0.len(), c.len(), mlen, m_pad_len);
	}

	let mut block: [u8; 64] = [0; 64];

	let mut inc: [u8; 16] = [0; 16];
	for i in 0..8 { inc[i] = n[i]; }

	if m_with_pad_len < 64 {
		salsa20(&mut block, &inc, k, SIGMA);
		c0[0..m_pad_len].copy_from_slice(&block[0..m_pad_len]);
		if m_pad_len < 32 {
			for i in m_pad_len..32 { c0[i] = m[i-m_pad_len] ^ block[i]; }
		}
		for i in 32..m_with_pad_len { c[i-32] = m[i-m_pad_len] ^ block[i]; }
		return;
	}

	{ // first loop with pad
		salsa20(&mut block, &inc, k, SIGMA);
		c0[0..m_pad_len].copy_from_slice(&block[0..m_pad_len]);
		if m_pad_len < 32 {
			for i in m_pad_len..32 { c0[i] = m[i-m_pad_len] ^ block[i]; }
		}
		for i in 32..64 { c[i-32] = m[i-m_pad_len] ^ block[i]; }
		
		let mut u: u32 = 1;
		for i in 8..16 {
			u += inc[i] as u32;
			inc[i] = u as u8;
			u >>= 8;
		}

	}

	m_with_pad_len -= 64;
	let mut c_start = 32;
	let mut m_start = 64 - m_pad_len;

	while m_with_pad_len >= 64 {
		salsa20(&mut block, &inc, k, SIGMA);
		for i in 0..64 { c[c_start+i] = m[m_start+i] ^ block[i]; }

		let mut u: u32 = 1;
		for i in 8..16 {
			u += inc[i] as u32;
			inc[i] = u as u8;
			u >>= 8;
		}

		m_with_pad_len -= 64;
		c_start += 64;
		m_start += 64;
	}

	if m_with_pad_len > 0 {
		salsa20(&mut block, &inc, k, SIGMA);
		for i in 0..m_with_pad_len { c[c_start+i] = m[m_start+i] ^ block[i]; }
	}
}

pub fn xsalsa20(c: &mut [u8], n: &[u8], k: &[u8]) {
	let mut subkey: [u8; 32] = [0; 32];
	hsalsa20(&mut subkey, n, k, SIGMA);
	stream_32(c, &n[16..24], &subkey);
	subkey.reset();
}

pub fn xsalsa20_xor(c0: &mut [u8], c: &mut [u8], m: &[u8], m_pad_len: usize,
		n: &[u8], k: &[u8]) {
	let mut subkey: [u8; 32] = [0; 32];
	hsalsa20(&mut subkey, n, k, SIGMA);
	stream_xor(c0, c, m, m_pad_len, &n[16..24], &subkey);
	subkey.reset();
}

#[cfg(test)]
mod tests {

	use super::{ xsalsa20, xsalsa20_xor };
	use crate::util::verify::compare;
	
	// Analog of tests/stream3.c, with expected result printed in
	// tests/stream3.out
	//
	#[test]
	fn stream3() {
		
		let firstkey: [u8; 32] = [
			0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,
			0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,
			0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,
			0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89 ];
		
		let nonce: [u8; 24] = [
			0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,
			0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,
			0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37 ];
		
		let mut rs: [u8; 32] = [0; 32];
		
		xsalsa20(&mut rs, &nonce, &firstkey);
		
		// taken from tests/stream3.out
		assert!(compare(&rs, &[
			0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91,
			0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25,
			0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65,
			0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80 ]));
	}

	// Analog of tests/stream4.c, with expected result printed in
	// tests/stream4.out
	//
	#[test]
	fn stream4() {
		
		let firstkey: [u8; 32] = [
			0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,
			0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,
			0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,
			0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89 ];
		
		let nonce: [u8; 24] = [
			0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,
			0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,
			0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37 ];
		
		let m: [u8; 131] = [
			0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5,
			0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b,
			0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4,
			0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc,
			0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a,
			0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29,
			0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4,
			0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31,
			0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d,
			0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57,
			0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a,
			0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde,
			0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd,
			0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52,
			0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40,
			0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64,
			0x5e,0x07,0x05 ];
		
		let mut c0: [u8; 32] = [0; 32];
		let mut c: [u8; 131] = [0; 131];
		
		xsalsa20_xor(&mut c0, &mut c, &m, 32, &nonce, &firstkey);
		
		// taken from tests/stream4.out
		assert!(compare(&c, &[
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
			0xe3,0x55,0xa5 ]));
	}

}