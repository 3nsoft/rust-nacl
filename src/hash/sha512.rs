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

fn crypto_hashblocks(statebytes: &mut [u8], mut inc: &[u8]) {
	let mut inlen = inc.len();
	let mut state: [u64; 8] = [0; 8];

	let mut a = load_bigendian(&statebytes[0..8]);		state[0] = a;
	let mut b = load_bigendian(&statebytes[8..16]);		state[1] = b;
	let mut c = load_bigendian(&statebytes[16..24]);	state[2] = c;
	let mut d = load_bigendian(&statebytes[24..32]);	state[3] = d;
	let mut e = load_bigendian(&statebytes[32..40]);	state[4] = e;
	let mut f = load_bigendian(&statebytes[40..48]);	state[5] = f;
	let mut g = load_bigendian(&statebytes[48..56]);	state[6] = g;
	let mut h = load_bigendian(&statebytes[56..64]);	state[7] = h;

	while inlen >= 128 {
		let mut w0  = load_bigendian(&inc[0..8]);
		let mut w1  = load_bigendian(&inc[8..16]);
		let mut w2  = load_bigendian(&inc[16..24]);
		let mut w3  = load_bigendian(&inc[24..32]);
		let mut w4  = load_bigendian(&inc[32..40]);
		let mut w5  = load_bigendian(&inc[40..48]);
		let mut w6  = load_bigendian(&inc[48..56]);
		let mut w7  = load_bigendian(&inc[56..64]);
		let mut w8  = load_bigendian(&inc[64..72]);
		let mut w9  = load_bigendian(&inc[72..80]);
		let mut w10 = load_bigendian(&inc[80..88]);
		let mut w11 = load_bigendian(&inc[88..96]);
		let mut w12 = load_bigendian(&inc[96..104]);
		let mut w13 = load_bigendian(&inc[104..112]);
		let mut w14 = load_bigendian(&inc[112..120]);
		let mut w15 = load_bigendian(&inc[120..128]);

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

		inc = &inc[128..];
		inlen -= 128;
	}

	store_bigendian(&mut statebytes[0..8],		state[0]);
	store_bigendian(&mut statebytes[8..16],	state[1]);
	store_bigendian(&mut statebytes[16..24],	state[2]);
	store_bigendian(&mut statebytes[24..32],	state[3]);
	store_bigendian(&mut statebytes[32..40],	state[4]);
	store_bigendian(&mut statebytes[40..48],	state[5]);
	store_bigendian(&mut statebytes[48..56],	state[6]);
	store_bigendian(&mut statebytes[56..64],	state[7]);

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

pub fn hash_sha512(out: &mut [u8], mut inc: &[u8]) {
	let mut h: [u8; 64] = [0; 64];

	h.copy_from_slice(&iv);

	crypto_hashblocks(&mut h, inc);
	let bytes = inc.len();
	let inlen = bytes & 127;
	inc = &inc[(bytes-inlen)..];

	let mut padded: [u8; 256] = [0; 256];
	padded[0..inlen].copy_from_slice(inc);
	padded[inlen] = 0x80;

	if inlen < 112 {
		padded[119] = (bytes >> 61) as u8;
		padded[120] = (bytes >> 53) as u8;
		padded[121] = (bytes >> 45) as u8;
		padded[122] = (bytes >> 37) as u8;
		padded[123] = (bytes >> 29) as u8;
		padded[124] = (bytes >> 21) as u8;
		padded[125] = (bytes >> 13) as u8;
		padded[126] = (bytes >> 5) as u8;
		padded[127] = (bytes << 3) as u8;
		crypto_hashblocks(&mut h, &padded[0..128]);
	} else {
		padded[247] = (bytes >> 61) as u8;
		padded[248] = (bytes >> 53) as u8;
		padded[249] = (bytes >> 45) as u8;
		padded[250] = (bytes >> 37) as u8;
		padded[251] = (bytes >> 29) as u8;
		padded[252] = (bytes >> 21) as u8;
		padded[253] = (bytes >> 13) as u8;
		padded[254] = (bytes >> 5) as u8;
		padded[255] = (bytes << 3) as u8;
		crypto_hashblocks(&mut h, &padded);
	}

	out.copy_from_slice(&h);
}


#[cfg(test)]
mod tests {

	use hash::sha512::hash_sha512;
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
}