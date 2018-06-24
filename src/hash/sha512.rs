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

#![allow(non_upper_case_globals)]

use util::Resetable;

/// Analog of load_bigendian in crypto_hashblocks/sha512/ref/blocks.c
#[inline]
fn load_bigendian(x: &[u8]) -> u64 {
	(x[7] as u64)
	| ((x[6] as u64) << 8) 
	| ((x[5] as u64) << 16) 
	| ((x[4] as u64) << 24) 
	| ((x[3] as u64) << 32) 
	| ((x[2] as u64) << 40) 
	| ((x[1] as u64) << 48) 
	| ((x[0] as u64) << 56)
}

/// Analog of store_bigendian in crypto_hashblocks/sha512/ref/blocks.c
#[inline]
fn store_bigendian(x: &mut [u8], mut u: u64) {
	x[7] = u as u8; u >>= 8;
	x[6] = u as u8; u >>= 8;
	x[5] = u as u8; u >>= 8;
	x[4] = u as u8; u >>= 8;
	x[3] = u as u8; u >>= 8;
	x[2] = u as u8; u >>= 8;
	x[1] = u as u8; u >>= 8;
	x[0] = u as u8;
}

macro_rules! SHR {
	($x: expr, $n: expr) => (($x) >> ($n))
}

macro_rules! ROTR {
	($x: expr, $n: expr) => ((($x) >> ($n)) | (($x) << (64 - ($n))))
}

macro_rules! Ch {
	($x: expr, $y: expr, $z: expr) => (($x & $y) ^ (!$x & $z))
}

macro_rules! Maj {
	($x: expr, $y: expr, $z: expr) => (($x & $y) ^ ($x & $z) ^ ($y & $z))
}

macro_rules! Sigma0 {
	($x: expr) => (ROTR!($x,28) ^ ROTR!($x,34) ^ ROTR!($x,39))
}

macro_rules! Sigma1 {
	($x: expr) => (ROTR!($x,14) ^ ROTR!($x,18) ^ ROTR!($x,41))
}

macro_rules! sigma0 {
	($x: expr) => (ROTR!($x, 1) ^ ROTR!($x, 8) ^ SHR!($x,7))
}

macro_rules! sigma1 {
	($x: expr) => (ROTR!($x,19) ^ ROTR!($x,61) ^ SHR!($x,6))
}

macro_rules! M {
	($w0: expr, $w14: expr, $w9: expr, $w1: expr) => {
		$w0 = sigma1!($w14) + $w9 + sigma0!($w1) + $w0;
	}
}

macro_rules! EXPAND {
	($w0: expr, $w1: expr, $w2: expr, $w3: expr, $w4: expr, $w5: expr,
			$w6: expr, $w7: expr, $w8: expr, $w9: expr, $w10: expr,
			$w11: expr, $w12: expr, $w13: expr, $w14: expr, $w15: expr) => {
		M!($w0 ,$w14,$w9 ,$w1 );
		M!($w1 ,$w15,$w10,$w2 );
		M!($w2 ,$w0 ,$w11,$w3 );
		M!($w3 ,$w1 ,$w12,$w4 );
		M!($w4 ,$w2 ,$w13,$w5 );
		M!($w5 ,$w3 ,$w14,$w6 );
		M!($w6 ,$w4 ,$w15,$w7 );
		M!($w7 ,$w5 ,$w0 ,$w8 );
		M!($w8 ,$w6 ,$w1 ,$w9 );
		M!($w9 ,$w7 ,$w2 ,$w10);
		M!($w10,$w8 ,$w3 ,$w11);
		M!($w11,$w9 ,$w4 ,$w12);
		M!($w12,$w10,$w5 ,$w13);
		M!($w13,$w11,$w6 ,$w14);
		M!($w14,$w12,$w7 ,$w15);
		M!($w15,$w13,$w8 ,$w0 );
	}
}

macro_rules! F {
	($w: expr, $k: expr,
			$a: expr, $b: expr, $c: expr, $d: expr,
			$e: expr, $f: expr, $g: expr, $h: expr) => {
		let t1 = $h + Sigma1!($e) + Ch!($e, $f, $g) + $k + $w;
		let t2 = Sigma0!($a) + Maj!($a, $b, $c);
		$h = $g;
		$g = $f;
		$f = $e;
		$e = $d + t1;
		$d = $c;
		$c = $b;
		$b = $a;
		$a = t1 + t2;
	}
}

fn crypto_hashblocks(statebytes: &mut [u8], inc: &[u8]) -> usize {
	let total_len = inc.len();
	let mut hashed_len = 0;
	let mut state: [u64; 8] = [0; 8];

	let mut a = load_bigendian(&statebytes[0..8]);		state[0] = a;
	let mut b = load_bigendian(&statebytes[8..16]);		state[1] = b;
	let mut c = load_bigendian(&statebytes[16..24]);	state[2] = c;
	let mut d = load_bigendian(&statebytes[24..32]);	state[3] = d;
	let mut e = load_bigendian(&statebytes[32..40]);	state[4] = e;
	let mut f = load_bigendian(&statebytes[40..48]);	state[5] = f;
	let mut g = load_bigendian(&statebytes[48..56]);	state[6] = g;
	let mut h = load_bigendian(&statebytes[56..64]);	state[7] = h;

	while (total_len - hashed_len) >= 128 {
		let chunk = &inc[hashed_len..hashed_len+128];

		let mut w0  = load_bigendian(&chunk[0..8]);
		let mut w1  = load_bigendian(&chunk[8..16]);
		let mut w2  = load_bigendian(&chunk[16..24]);
		let mut w3  = load_bigendian(&chunk[24..32]);
		let mut w4  = load_bigendian(&chunk[32..40]);
		let mut w5  = load_bigendian(&chunk[40..48]);
		let mut w6  = load_bigendian(&chunk[48..56]);
		let mut w7  = load_bigendian(&chunk[56..64]);
		let mut w8  = load_bigendian(&chunk[64..72]);
		let mut w9  = load_bigendian(&chunk[72..80]);
		let mut w10 = load_bigendian(&chunk[80..88]);
		let mut w11 = load_bigendian(&chunk[88..96]);
		let mut w12 = load_bigendian(&chunk[96..104]);
		let mut w13 = load_bigendian(&chunk[104..112]);
		let mut w14 = load_bigendian(&chunk[112..120]);
		let mut w15 = load_bigendian(&chunk[120..128]);

		F!(w0 ,0x428a2f98d728ae22, a,b,c,d,e,f,g,h);
		F!(w1 ,0x7137449123ef65cd, a,b,c,d,e,f,g,h);
		F!(w2 ,0xb5c0fbcfec4d3b2f, a,b,c,d,e,f,g,h);
		F!(w3 ,0xe9b5dba58189dbbc, a,b,c,d,e,f,g,h);
		F!(w4 ,0x3956c25bf348b538, a,b,c,d,e,f,g,h);
		F!(w5 ,0x59f111f1b605d019, a,b,c,d,e,f,g,h);
		F!(w6 ,0x923f82a4af194f9b, a,b,c,d,e,f,g,h);
		F!(w7 ,0xab1c5ed5da6d8118, a,b,c,d,e,f,g,h);
		F!(w8 ,0xd807aa98a3030242, a,b,c,d,e,f,g,h);
		F!(w9 ,0x12835b0145706fbe, a,b,c,d,e,f,g,h);
		F!(w10,0x243185be4ee4b28c, a,b,c,d,e,f,g,h);
		F!(w11,0x550c7dc3d5ffb4e2, a,b,c,d,e,f,g,h);
		F!(w12,0x72be5d74f27b896f, a,b,c,d,e,f,g,h);
		F!(w13,0x80deb1fe3b1696b1, a,b,c,d,e,f,g,h);
		F!(w14,0x9bdc06a725c71235, a,b,c,d,e,f,g,h);
		F!(w15,0xc19bf174cf692694, a,b,c,d,e,f,g,h);

		EXPAND!(w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14,w15);

		F!(w0 ,0xe49b69c19ef14ad2, a,b,c,d,e,f,g,h);
		F!(w1 ,0xefbe4786384f25e3, a,b,c,d,e,f,g,h);
		F!(w2 ,0x0fc19dc68b8cd5b5, a,b,c,d,e,f,g,h);
		F!(w3 ,0x240ca1cc77ac9c65, a,b,c,d,e,f,g,h);
		F!(w4 ,0x2de92c6f592b0275, a,b,c,d,e,f,g,h);
		F!(w5 ,0x4a7484aa6ea6e483, a,b,c,d,e,f,g,h);
		F!(w6 ,0x5cb0a9dcbd41fbd4, a,b,c,d,e,f,g,h);
		F!(w7 ,0x76f988da831153b5, a,b,c,d,e,f,g,h);
		F!(w8 ,0x983e5152ee66dfab, a,b,c,d,e,f,g,h);
		F!(w9 ,0xa831c66d2db43210, a,b,c,d,e,f,g,h);
		F!(w10,0xb00327c898fb213f, a,b,c,d,e,f,g,h);
		F!(w11,0xbf597fc7beef0ee4, a,b,c,d,e,f,g,h);
		F!(w12,0xc6e00bf33da88fc2, a,b,c,d,e,f,g,h);
		F!(w13,0xd5a79147930aa725, a,b,c,d,e,f,g,h);
		F!(w14,0x06ca6351e003826f, a,b,c,d,e,f,g,h);
		F!(w15,0x142929670a0e6e70, a,b,c,d,e,f,g,h);

		EXPAND!(w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14,w15);

		F!(w0 ,0x27b70a8546d22ffc, a,b,c,d,e,f,g,h);
		F!(w1 ,0x2e1b21385c26c926, a,b,c,d,e,f,g,h);
		F!(w2 ,0x4d2c6dfc5ac42aed, a,b,c,d,e,f,g,h);
		F!(w3 ,0x53380d139d95b3df, a,b,c,d,e,f,g,h);
		F!(w4 ,0x650a73548baf63de, a,b,c,d,e,f,g,h);
		F!(w5 ,0x766a0abb3c77b2a8, a,b,c,d,e,f,g,h);
		F!(w6 ,0x81c2c92e47edaee6, a,b,c,d,e,f,g,h);
		F!(w7 ,0x92722c851482353b, a,b,c,d,e,f,g,h);
		F!(w8 ,0xa2bfe8a14cf10364, a,b,c,d,e,f,g,h);
		F!(w9 ,0xa81a664bbc423001, a,b,c,d,e,f,g,h);
		F!(w10,0xc24b8b70d0f89791, a,b,c,d,e,f,g,h);
		F!(w11,0xc76c51a30654be30, a,b,c,d,e,f,g,h);
		F!(w12,0xd192e819d6ef5218, a,b,c,d,e,f,g,h);
		F!(w13,0xd69906245565a910, a,b,c,d,e,f,g,h);
		F!(w14,0xf40e35855771202a, a,b,c,d,e,f,g,h);
		F!(w15,0x106aa07032bbd1b8, a,b,c,d,e,f,g,h);

		EXPAND!(w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14,w15);

		F!(w0 ,0x19a4c116b8d2d0c8, a,b,c,d,e,f,g,h);
		F!(w1 ,0x1e376c085141ab53, a,b,c,d,e,f,g,h);
		F!(w2 ,0x2748774cdf8eeb99, a,b,c,d,e,f,g,h);
		F!(w3 ,0x34b0bcb5e19b48a8, a,b,c,d,e,f,g,h);
		F!(w4 ,0x391c0cb3c5c95a63, a,b,c,d,e,f,g,h);
		F!(w5 ,0x4ed8aa4ae3418acb, a,b,c,d,e,f,g,h);
		F!(w6 ,0x5b9cca4f7763e373, a,b,c,d,e,f,g,h);
		F!(w7 ,0x682e6ff3d6b2b8a3, a,b,c,d,e,f,g,h);
		F!(w8 ,0x748f82ee5defb2fc, a,b,c,d,e,f,g,h);
		F!(w9 ,0x78a5636f43172f60, a,b,c,d,e,f,g,h);
		F!(w10,0x84c87814a1f0ab72, a,b,c,d,e,f,g,h);
		F!(w11,0x8cc702081a6439ec, a,b,c,d,e,f,g,h);
		F!(w12,0x90befffa23631e28, a,b,c,d,e,f,g,h);
		F!(w13,0xa4506cebde82bde9, a,b,c,d,e,f,g,h);
		F!(w14,0xbef9a3f7b2c67915, a,b,c,d,e,f,g,h);
		F!(w15,0xc67178f2e372532b, a,b,c,d,e,f,g,h);

		EXPAND!(w0,w1,w2,w3,w4,w5,w6,w7,w8,w9,w10,w11,w12,w13,w14,w15);

		F!(w0 ,0xca273eceea26619c, a,b,c,d,e,f,g,h);
		F!(w1 ,0xd186b8c721c0c207, a,b,c,d,e,f,g,h);
		F!(w2 ,0xeada7dd6cde0eb1e, a,b,c,d,e,f,g,h);
		F!(w3 ,0xf57d4f7fee6ed178, a,b,c,d,e,f,g,h);
		F!(w4 ,0x06f067aa72176fba, a,b,c,d,e,f,g,h);
		F!(w5 ,0x0a637dc5a2c898a6, a,b,c,d,e,f,g,h);
		F!(w6 ,0x113f9804bef90dae, a,b,c,d,e,f,g,h);
		F!(w7 ,0x1b710b35131c471b, a,b,c,d,e,f,g,h);
		F!(w8 ,0x28db77f523047d84, a,b,c,d,e,f,g,h);
		F!(w9 ,0x32caab7b40c72493, a,b,c,d,e,f,g,h);
		F!(w10,0x3c9ebe0a15c9bebc, a,b,c,d,e,f,g,h);
		F!(w11,0x431d67c49c100d4c, a,b,c,d,e,f,g,h);
		F!(w12,0x4cc5d4becb3e42b6, a,b,c,d,e,f,g,h);
		F!(w13,0x597f299cfc657e2a, a,b,c,d,e,f,g,h);
		F!(w14,0x5fcb6fab3ad6faec, a,b,c,d,e,f,g,h);
		F!(w15,0x6c44198c4a475817, a,b,c,d,e,f,g,h);

		a += state[0];
		b += state[1];
		c += state[2];
		d += state[3];
		e += state[4];
		f += state[5];
		g += state[6];
		h += state[7];

		state[0] = a;
		state[1] = b;
		state[2] = c;
		state[3] = d;
		state[4] = e;
		state[5] = f;
		state[6] = g;
		state[7] = h;

		hashed_len += 128;
	}

	store_bigendian(&mut statebytes[0..8],		state[0]);
	store_bigendian(&mut statebytes[8..16],	state[1]);
	store_bigendian(&mut statebytes[16..24],	state[2]);
	store_bigendian(&mut statebytes[24..32],	state[3]);
	store_bigendian(&mut statebytes[32..40],	state[4]);
	store_bigendian(&mut statebytes[40..48],	state[5]);
	store_bigendian(&mut statebytes[48..56],	state[6]);
	store_bigendian(&mut statebytes[56..64],	state[7]);

	hashed_len
}

const iv: [u8; 64] = [
	0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
	0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
	0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
	0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
	0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
	0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
	0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
	0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79 ];

pub fn hash_sha512(out: &mut [u8], inc: &[u8]) {
	let mut h: [u8; 64] = [0; 64];

	h.copy_from_slice(&iv);

	let hashed_len = crypto_hashblocks(&mut h, inc);
	let odd_bytes = &inc[hashed_len..];

	hash_padded_block(&mut h, odd_bytes, inc.len());

	out.copy_from_slice(&h);
}

fn hash_padded_block(h: &mut [u8], odd_bytes: &[u8], total_len: usize) {
	let mut padded: [u8; 256] = [0; 256];
	let odd_len = odd_bytes.len();

	padded[0..odd_len].copy_from_slice(odd_bytes);
	padded[odd_len] = 0x80;

	if odd_len < 112 {
		padded[119] = (total_len >> 61) as u8;
		padded[120] = (total_len >> 53) as u8;
		padded[121] = (total_len >> 45) as u8;
		padded[122] = (total_len >> 37) as u8;
		padded[123] = (total_len >> 29) as u8;
		padded[124] = (total_len >> 21) as u8;
		padded[125] = (total_len >> 13) as u8;
		padded[126] = (total_len >> 5) as u8;
		padded[127] = (total_len << 3) as u8;
		crypto_hashblocks(h, &padded[0..128]);
	} else {
		padded[247] = (total_len >> 61) as u8;
		padded[248] = (total_len >> 53) as u8;
		padded[249] = (total_len >> 45) as u8;
		padded[250] = (total_len >> 37) as u8;
		padded[251] = (total_len >> 29) as u8;
		padded[252] = (total_len >> 21) as u8;
		padded[253] = (total_len >> 13) as u8;
		padded[254] = (total_len >> 5) as u8;
		padded[255] = (total_len << 3) as u8;
		crypto_hashblocks(h, &padded);
	}
}

pub struct Sha512 {
	cache: [u8; 128],
	cached_bytes: usize,
	total_len: usize,
	h: [u8; 64]
}

impl Sha512 {

	pub fn new() -> Sha512 {
		Sha512 {
			cache: [0; 128],
			h: [0; 64],
			total_len: 0,
			cached_bytes: 0,
		}
	}
	
	/// This absorbs given bytes, hashing even blocks, and internally caching
	/// odd bytes to hash either with next bytes, or as padded bytes when digest
	/// is called.
	/// 
	pub fn update(&mut self, m: &[u8]) {
		let mlen = m.len();
		if mlen == 0 { return; }
		if self.total_len == 0 {
			self.h.copy_from_slice(&iv);
		}
		self.total_len += m.len();
		let mut m_start = 0;

		if self.cached_bytes > 0 {
			let delta = mlen.min(128-self.cached_bytes);
			for i in 0..delta {
				self.cache[self.cached_bytes + i] = m[i];
			}
			m_start = delta;
			if (self.cached_bytes + delta) < 128 {
				self.cached_bytes += delta;
				return;
			} else {
				crypto_hashblocks(&mut self.h, &self.cache);
				self.cached_bytes = 0;
				if m_start == m.len() { return; }
			}
		}
		
		m_start += crypto_hashblocks(&mut self.h, &m[m_start..]);
		
		self.cached_bytes = mlen - m_start;
		for i in 0..self.cached_bytes {
			self.cache[i] = m[m_start+i];
		}
		self.cache[self.cached_bytes..].reset();
	}

	/// Completes hashing and returns sha512 hash bytes.
	/// If no bytes were given to update prior to this call, panic will ensue.
	/// 
	pub fn digest(&mut self) -> Vec<u8> {
		if self.total_len == 0 { panic!("No bytes have been hashed"); }
		hash_padded_block(
			&mut self.h, &self.cache[0..self.cached_bytes], self.total_len);
		let v = self.h.to_vec();
		self.clear();
		v
	}

	/// This clears internal state of the hasher.
	pub fn clear(&mut self) {
		self.total_len = 0;
		self.cached_bytes = 0;
		self.h.reset();
		self.cache.reset();
	}
}

#[cfg(test)]
mod tests {

	use hash::sha512::{ hash_sha512, Sha512 };
	use util::verify::compare;

	// Analog of tests/hash.c, with result printed in tests/hash.out
	//
	#[test]
	fn sha512() {
		let x = "testing\n".as_bytes();
		let mut result: [u8; 64] = [0; 64];
		hash_sha512(&mut result, &x);
		assert!(compare(&result, &[
			0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b, 0x3c, 0xb7,
			0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b,
			0x4b, 0x34, 0x47, 0x98, 0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e,
			0x3a, 0xe5, 0x93, 0x1b, 0xaa, 0xe8, 0xc7, 0xca, 0xcf, 0xea,
			0x4b, 0x62, 0x94, 0x52, 0xc3, 0x80, 0x26, 0xa8, 0x1d, 0x13,
			0x8b, 0xc7, 0xaa, 0xd1, 0xaf, 0x3e, 0xf7, 0xbf, 0xd5, 0xec,
			0x64, 0x6d, 0x6c, 0x28 ]));
	}

	#[test]
	fn hash_of_short_vector() {
		let x = [
			0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b, 0x3c, 0xb7,
			0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b,
			0x4b, 0x34, 0x47, 0x98, 0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e,
			0x3a, 0xe5, 0x93 ];
		let mut result: [u8; 64] = [0; 64];
		hash_sha512(&mut result, &x);
		assert!(compare(&result, &[
			0xe3, 0x47, 0x65, 0x5d, 0x31, 0xac, 0x3b, 0xfa, 0xe1, 0xd4,
			0x0b, 0xbd, 0x04, 0x54, 0xfd, 0x58, 0x0b, 0x5d, 0xde, 0xb3,
			0xe7, 0x63, 0xd1, 0xd7, 0x4d, 0xc3, 0xf0, 0x1c, 0x47, 0x1e,
			0x6f, 0x10, 0x4a, 0xa5, 0x40, 0x53, 0xef, 0xa1, 0x9b, 0xed,
			0xd6, 0x27, 0xcd, 0x4b, 0xa1, 0xc0, 0xb4, 0x4d, 0x30, 0xe1,
			0x4f, 0x7f, 0xc5, 0x91, 0xa0, 0x1c, 0x60, 0xd2, 0xcb, 0x6f,
			0x45, 0x8f, 0x40, 0x8b ]));
	}

	#[test]
	fn hasher_with_short_vector() {
		let x = [
			0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b, 0x3c, 0xb7,
			0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b,
			0x4b, 0x34, 0x47, 0x98, 0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e,
			0x3a, 0xe5, 0x93 ];
		let mut hasher = Sha512::new();
		hasher.update(&x[0..10]);
		hasher.update(&x[10..]);
		let result = hasher.digest();
		assert!(compare(&result, &[
			0xe3, 0x47, 0x65, 0x5d, 0x31, 0xac, 0x3b, 0xfa, 0xe1, 0xd4,
			0x0b, 0xbd, 0x04, 0x54, 0xfd, 0x58, 0x0b, 0x5d, 0xde, 0xb3,
			0xe7, 0x63, 0xd1, 0xd7, 0x4d, 0xc3, 0xf0, 0x1c, 0x47, 0x1e,
			0x6f, 0x10, 0x4a, 0xa5, 0x40, 0x53, 0xef, 0xa1, 0x9b, 0xed,
			0xd6, 0x27, 0xcd, 0x4b, 0xa1, 0xc0, 0xb4, 0x4d, 0x30, 0xe1,
			0x4f, 0x7f, 0xc5, 0x91, 0xa0, 0x1c, 0x60, 0xd2, 0xcb, 0x6f,
			0x45, 0x8f, 0x40, 0x8b ]));
	}

	#[test]
	fn hasher_with_longer_vector() {
		let x = [
			0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b, 0x3c, 0xb7,
			0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b,
			0x4b, 0x34, 0x47, 0x98, 0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e,
			0xe3, 0x47, 0x65, 0x5d, 0x31, 0xac, 0x3b, 0xfa, 0xe1, 0xd4,
			0x0b, 0xbd, 0x04, 0x54, 0xfd, 0x58, 0x0b, 0x5d, 0xde, 0xb3,
			0xe7, 0x63, 0xd1, 0xd7, 0x4d, 0xc3, 0xf0, 0x1c, 0x47, 0x1e,
			0x6f, 0x10, 0x4a, 0xa5, 0x40, 0x53, 0xef, 0xa1, 0x9b, 0xed,
			0xd6, 0x27, 0xcd, 0x4b, 0xa1, 0xc0, 0xb4, 0x4d, 0x30, 0xe1,
			0x4f, 0x7f, 0xc5, 0x91, 0xa0, 0x1c, 0x60, 0xd2, 0xcb, 0x6f,
			0x6f, 0x10, 0x4a, 0xa5, 0x40, 0x53, 0xef, 0xa1, 0x9b, 0xed,
			0xd6, 0x27, 0xcd, 0x4b, 0xa1, 0xc0, 0xb4, 0x4d, 0x30, 0xe1,
			0x4f, 0x7f, 0xc5, 0x91, 0xa0, 0x1c, 0x60, 0xd2, 0xcb, 0x6f,
			0x45, 0x8f, 0x40, 0x8b, 0x3a, 0xe5, 0x93, 0x93 ];
		let mut hasher = Sha512::new();
		hasher.update(&x[0..56]);
		hasher.update(&x[56..]);
		let result = hasher.digest();
		assert!(compare(&result, &[
			0xbd, 0xb1, 0x1, 0x77, 0x73, 0x6b, 0x2b, 0xa2, 0x64, 0xac,
			0x73, 0x3c, 0xfe, 0xb, 0xaf, 0x21, 0x28, 0x7f, 0x41, 0xfb,
			0xa6, 0x90, 0xe3, 0xe6, 0xe9, 0xe, 0xd7, 0x88, 0x34, 0xb7,
			0x93, 0xfa, 0x4f, 0xd7, 0xf, 0x97, 0x4c, 0x2f, 0xa2, 0xc4,
			0x2e, 0x59, 0x1c, 0xb7, 0xdb, 0xa5, 0x2e, 0x47, 0x17, 0x2,
			0xd8, 0x86, 0x16, 0x3e, 0x61, 0xbf, 0x4c, 0xc, 0x58, 0xca,
			0x35, 0x48, 0x23, 0xba ]));
	}

	#[test]
	fn hasher_with_longer_vector2() {
		let x = [
			0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b, 0x3c, 0xb7,
			0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b,
			0x4b, 0x34, 0x47, 0x98, 0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e,
			0xe3, 0x47, 0x65, 0x5d, 0x31, 0xac, 0x3b, 0xfa, 0xe1, 0xd4,
			0x0b, 0xbd, 0x04, 0x54, 0xfd, 0x58, 0x0b, 0x5d, 0xde, 0xb3,
			0xe7, 0x63, 0xd1, 0xd7, 0x4d, 0xc3, 0xf0, 0x1c, 0x47, 0x1e,
			0x6f, 0x10, 0x4a, 0xa5, 0x40, 0x53, 0xef, 0xa1, 0x9b, 0xed,
			0xd6, 0x27, 0xcd, 0x4b, 0xa1, 0xc0, 0xb4, 0x4d, 0x30, 0xe1,
			0x4f, 0x7f, 0xc5, 0x91, 0xa0, 0x1c, 0x60, 0xd2, 0xcb, 0x6f,
			0x6f, 0x10, 0x4a, 0xa5, 0x40, 0x53, 0xef, 0xa1, 0x9b, 0xed,
			0xd6, 0x27, 0xcd, 0x4b, 0xa1, 0xc0, 0xb4, 0x4d, 0x30, 0xe1,
			0x28, 0x22, 0x8a, 0x0c, 0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b,
			0x4b, 0x34, 0x47, 0x98, 0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e,
			0xe3, 0x47, 0x65, 0x5d, 0x31, 0xac, 0x3b, 0xfa, 0xe1, 0xd4,
			0x0b, 0xbd, 0x04, 0x54, 0xfd, 0x58, 0x0b, 0x5d, 0xde, 0xb3,
			0xe7, 0x63, 0xd1, 0xd7, 0x4d, 0xc3, 0xf0, 0x1c, 0x47, 0x1e,
			0x6f, 0x10, 0x4a, 0xa5, 0x40, 0x53, 0xef, 0xa1, 0x9b, 0xed,
			0xd6, 0x27, 0xcd, 0x4b, 0xa1, 0xc0, 0xb4, 0x4d, 0x30, 0xe1,
			0x4f, 0x7f, 0xc5, 0x91, 0xa0, 0x1c, 0x60, 0xd2, 0xcb, 0x6f,
			0x6f, 0x10, 0x4a, 0xa5, 0x40, 0x53, 0xef, 0xa1, 0x9b, 0xed,
			0x4f, 0x7f, 0xc5, 0x91, 0xa0, 0x1c, 0x60, 0xd2, 0xcb, 0x6f,
			0x45, 0x8f, 0x40 ];
		let mut hasher = Sha512::new();
		hasher.update(&x[0..10]);
		hasher.update(&x[10..20]);
		hasher.update(&x[20..]);
		let result = hasher.digest();
		assert!(compare(&result, &[
			0x2a, 0x68, 0x28, 0x7b, 0x3e, 0xb6, 0x7d, 0xa1, 0x5d, 0xf1,
			0x84, 0x37, 0xca, 0x1e, 0xce, 0x6a, 0x75, 0xe9, 0x2d, 0x60,
			0x11, 0x3e, 0x48, 0xba, 0x6c, 0x69, 0x9f, 0x7d, 0x76, 0xea,
			0x6d, 0xef, 0xe5, 0x92, 0xb8, 0x41, 0x8d, 0x10, 0xff, 0xe5,
			0x6d, 0x74, 0x6d, 0x2c, 0x2e, 0x67, 0xdc, 0x6d, 0x99, 0x3b,
			0x7b, 0x27, 0xc2, 0xbd, 0x29, 0x62, 0xe7, 0x67, 0x01, 0xd6,
			0x26, 0xa6, 0x9c, 0x0f ]));
	}

}