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

/// Encode a length len/4 vector of (uint32_t) into a length len vector of
/// (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
/// 
fn be32enc_vect(dst: &mut [u8], src: &[u32], len: usize) {
	for i in 0..(len / 4) { be32enc(dst, i*4, src[i]); }
}

#[inline]
fn be32enc(p: &mut [u8], ind: usize, x: u32) {
	p[ind+3] = x as u8;
	p[ind+2] = (x >> 8) as u8;
	p[ind+1] = (x >> 16) as u8;
	p[ind] = (x >> 24) as u8;
}

/// Decode a big-endian length len vector of (unsigned char) into a length
/// len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
/// 
fn be32dec_vect(dst: &mut [u32], src: &[u8], len: usize) {
	for i in 0..(len / 4) { dst[i] = be32dec(src, i*4); }
}

#[inline]
fn be32dec(p: &[u8], ind: usize) -> u32 {
	(p[ind+3] as u32) + ((p[ind+2] as u32) << 8) +
	((p[ind+1] as u32) << 16) + ((p[ind] as u32) << 24)
}

// Elementary functions used by SHA256
macro_rules! Ch {
	($x: expr, $y: expr, $z: expr) => (($x & ($y ^ $z)) ^ $z)
}
macro_rules! Maj {
	($x: expr, $y: expr, $z: expr) => (($x & ($y | $z)) | ($y & $z))
}
macro_rules! SHR {
	($x: expr, $n: expr) => ($x >> $n)
}
macro_rules! ROTR {
	($x: expr, $n: expr) => (($x >> $n) | ($x << (32 - $n)))
}
macro_rules! S0 {
	($x: expr) => (ROTR!($x, 2) ^ ROTR!($x, 13) ^ ROTR!($x, 22))
}
macro_rules! S1 {
	($x: expr) => (ROTR!($x, 6) ^ ROTR!($x, 11) ^ ROTR!($x, 25))
}
macro_rules! s0 {
	($x: expr) => (ROTR!($x, 7) ^ ROTR!($x, 18) ^ SHR!($x, 3))
}
macro_rules! s1 {
	($x: expr) => (ROTR!($x, 17) ^ ROTR!($x, 19) ^ SHR!($x, 10))
}

// SHA256 round function
macro_rules! RND {
	($a: expr, $b: expr, $c: expr, $d: expr, $e: expr, $f: expr, $g: expr, $h: expr, $k: expr, $t0: expr, $t1: expr) => {
		$t0 = $h + S1!($e) + Ch!($e, $f, $g) + $k;
		$t1 = S0!($a) + Maj!($a, $b, $c);
		$d += $t0;
		$h  = $t0 + $t1;
	}
}

// Adjusted round function for rotating state
macro_rules! RNDr {
	($S: expr, $W: expr, $i: expr, $k: expr, $t0: expr, $t1: expr) => {
		RND!($S[(64 - $i) % 8], $S[(65 - $i) % 8], $S[(66 - $i) % 8],
			$S[(67 - $i) % 8], $S[(68 - $i) % 8], $S[(69 - $i) % 8],
			$S[(70 - $i) % 8], $S[(71 - $i) % 8], $W[$i] + $k, $t0, $t1);
	}
}

/// SHA256 block compression function.  The 256-bit state is transformed via
/// the 512-bit input block to produce a new state.
///
fn sha256_transform(state: &mut [u32], block: &[u8]) {
	let mut w: [u32; 64] = [0; 64];
	let mut s: [u32; 8] = [0; 8];
	let mut t0;
	let mut t1;

	/* 1. Prepare message schedule W. */
	be32dec_vect(&mut w, &block, 64);
	for i in 16..64 {
		w[i] = s1!(w[i - 2]) + w[i - 7] + s0!(w[i - 15]) + w[i - 16];
	}

	/* 2. Initialize working variables. */
	s.copy_from_slice(state);

	/* 3. Mix. */
	RNDr!(s, w, 0, 0x428a2f98, t0, t1);
	RNDr!(s, w, 1, 0x71374491, t0, t1);
	RNDr!(s, w, 2, 0xb5c0fbcf, t0, t1);
	RNDr!(s, w, 3, 0xe9b5dba5, t0, t1);
	RNDr!(s, w, 4, 0x3956c25b, t0, t1);
	RNDr!(s, w, 5, 0x59f111f1, t0, t1);
	RNDr!(s, w, 6, 0x923f82a4, t0, t1);
	RNDr!(s, w, 7, 0xab1c5ed5, t0, t1);
	RNDr!(s, w, 8, 0xd807aa98, t0, t1);
	RNDr!(s, w, 9, 0x12835b01, t0, t1);
	RNDr!(s, w, 10, 0x243185be, t0, t1);
	RNDr!(s, w, 11, 0x550c7dc3, t0, t1);
	RNDr!(s, w, 12, 0x72be5d74, t0, t1);
	RNDr!(s, w, 13, 0x80deb1fe, t0, t1);
	RNDr!(s, w, 14, 0x9bdc06a7, t0, t1);
	RNDr!(s, w, 15, 0xc19bf174, t0, t1);
	RNDr!(s, w, 16, 0xe49b69c1, t0, t1);
	RNDr!(s, w, 17, 0xefbe4786, t0, t1);
	RNDr!(s, w, 18, 0x0fc19dc6, t0, t1);
	RNDr!(s, w, 19, 0x240ca1cc, t0, t1);
	RNDr!(s, w, 20, 0x2de92c6f, t0, t1);
	RNDr!(s, w, 21, 0x4a7484aa, t0, t1);
	RNDr!(s, w, 22, 0x5cb0a9dc, t0, t1);
	RNDr!(s, w, 23, 0x76f988da, t0, t1);
	RNDr!(s, w, 24, 0x983e5152, t0, t1);
	RNDr!(s, w, 25, 0xa831c66d, t0, t1);
	RNDr!(s, w, 26, 0xb00327c8, t0, t1);
	RNDr!(s, w, 27, 0xbf597fc7, t0, t1);
	RNDr!(s, w, 28, 0xc6e00bf3, t0, t1);
	RNDr!(s, w, 29, 0xd5a79147, t0, t1);
	RNDr!(s, w, 30, 0x06ca6351, t0, t1);
	RNDr!(s, w, 31, 0x14292967, t0, t1);
	RNDr!(s, w, 32, 0x27b70a85, t0, t1);
	RNDr!(s, w, 33, 0x2e1b2138, t0, t1);
	RNDr!(s, w, 34, 0x4d2c6dfc, t0, t1);
	RNDr!(s, w, 35, 0x53380d13, t0, t1);
	RNDr!(s, w, 36, 0x650a7354, t0, t1);
	RNDr!(s, w, 37, 0x766a0abb, t0, t1);
	RNDr!(s, w, 38, 0x81c2c92e, t0, t1);
	RNDr!(s, w, 39, 0x92722c85, t0, t1);
	RNDr!(s, w, 40, 0xa2bfe8a1, t0, t1);
	RNDr!(s, w, 41, 0xa81a664b, t0, t1);
	RNDr!(s, w, 42, 0xc24b8b70, t0, t1);
	RNDr!(s, w, 43, 0xc76c51a3, t0, t1);
	RNDr!(s, w, 44, 0xd192e819, t0, t1);
	RNDr!(s, w, 45, 0xd6990624, t0, t1);
	RNDr!(s, w, 46, 0xf40e3585, t0, t1);
	RNDr!(s, w, 47, 0x106aa070, t0, t1);
	RNDr!(s, w, 48, 0x19a4c116, t0, t1);
	RNDr!(s, w, 49, 0x1e376c08, t0, t1);
	RNDr!(s, w, 50, 0x2748774c, t0, t1);
	RNDr!(s, w, 51, 0x34b0bcb5, t0, t1);
	RNDr!(s, w, 52, 0x391c0cb3, t0, t1);
	RNDr!(s, w, 53, 0x4ed8aa4a, t0, t1);
	RNDr!(s, w, 54, 0x5b9cca4f, t0, t1);
	RNDr!(s, w, 55, 0x682e6ff3, t0, t1);
	RNDr!(s, w, 56, 0x748f82ee, t0, t1);
	RNDr!(s, w, 57, 0x78a5636f, t0, t1);
	RNDr!(s, w, 58, 0x84c87814, t0, t1);
	RNDr!(s, w, 59, 0x8cc70208, t0, t1);
	RNDr!(s, w, 60, 0x90befffa, t0, t1);
	RNDr!(s, w, 61, 0xa4506ceb, t0, t1);
	RNDr!(s, w, 62, 0xbef9a3f7, t0, t1);
	RNDr!(s, w, 63, 0xc67178f2, t0, t1);

	/* 4. Mix local working variables into global state */
	for i in 0..8 { state[i] += s[i]; }

	/* Clean the stack. */
	w.copy_from_slice(&ZEROS_U32_64);
	s.copy_from_slice(&ZEROS_U32_8);
	t0 = 0;
	t1 = 0;
}

const ZEROS_U32_64: [u32; 64] = [0; 64];
const ZEROS_U32_8: [u32; 8] = [0; 8];

const PAD: [u8; 64] = [
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];

pub struct Sha256Ctx {
	state: [u32; 8],
	count: [u32; 2],
	buf: [u8; 64],
}

pub struct HmacSha256Ctx {
	ictx: Sha256Ctx,
	octx: Sha256Ctx,
}

#[inline]
pub fn make_sha256_ctx() -> Sha256Ctx {
	Sha256Ctx {
		state: [0; 8],
		count: [0; 2],
		buf: [0; 64],
	}
}

pub fn make_hmac_sha256_ctx() -> HmacSha256Ctx {
	return HmacSha256Ctx {
		ictx: make_sha256_ctx(),
		octx: make_sha256_ctx(),
	}
}

// Add padding and terminating bit-count.
fn sha256_pad(ctx: &mut Sha256Ctx) {
	let mut len: [u8; 8] = [0; 8];

	// Convert length to a vector of bytes -- we do this now rather
	// than later because the length will change after we pad.
	be32enc_vect(&mut len, &ctx.count, 8);

	// Add 1--64 bytes so that the resulting length is 56 mod 64
	let r = (ctx.count[1] >> 3) & 0x3f;
	let plen = if r < 56 { 56 - r } else { 120 - r };
	sha256_update(ctx, &PAD[0..(plen as usize)]);

	// Add the terminating bit-count
	sha256_update(ctx, &len);
}

// SHA-256 initialization.  Begins a SHA-256 operation.
pub fn sha256_init(ctx: &mut Sha256Ctx) {

	/* Zero bits processed so far */
	ctx.count[0] = 0;
	ctx.count[1] = 0;

	/* Magic initialization constants */
	ctx.state[0] = 0x6A09E667;
	ctx.state[1] = 0xBB67AE85;
	ctx.state[2] = 0x3C6EF372;
	ctx.state[3] = 0xA54FF53A;
	ctx.state[4] = 0x510E527F;
	ctx.state[5] = 0x9B05688C;
	ctx.state[6] = 0x1F83D9AB;
	ctx.state[7] = 0x5BE0CD19;
}

// Add bytes into the hash
pub fn sha256_update(ctx: &mut Sha256Ctx, mut src: &[u8]) {
	let mut len = src.len() as u32;
	let mut bitlen: [u32; 2] = [0; 2];

	// Number of bytes left in the buffer from previous updates
	let r = (ctx.count[1] >> 3) & 0x3f;

	// Convert the length into a number of bits
	bitlen[1] = len << 3;
	bitlen[0] = len >> 29;

	// Update number of bits
	ctx.count[1] += bitlen[1];
	if ctx.count[1] < bitlen[1] { ctx.count[0] += 1; }
	ctx.count[0] += bitlen[0];

	// Handle the case where we don't need to perform any transforms
	if len < (64 - r) {
		ctx.buf[(r as usize)..((r+len) as usize)].copy_from_slice(&src[0..(len as usize)]);
		return;
	}

	// Finish the current block
	ctx.buf[(r as usize)..].copy_from_slice(&src[0..(64-r as usize)]);

	sha256_transform(&mut ctx.state, &ctx.buf);
	src = &src[((64-r) as usize)..];
	len -= 64 - r;

	// Perform complete blocks
	while len >= 64 {
		sha256_transform(&mut ctx.state, src);
		src = &src[64..];
		len -= 64;
	}

	// Copy left over data into buffer
	ctx.buf[0..(len as usize)].copy_from_slice(&src[0..(len as usize)]);
}

// SHA-256 finalization.  Pads the input data, exports the hash value,
// and clears the context state.
pub fn sha256_final(digest: &mut [u8], ctx: &mut Sha256Ctx) {

	// Add padding
	sha256_pad(ctx);

	// Write the hash
	be32enc_vect(digest, &ctx.state, 32);

	// Clear the context state
	clear_sha_ctx(ctx);
}

fn clear_sha_ctx(ctx: &mut Sha256Ctx) {
	ctx.buf.copy_from_slice(&ZEROS_U8_64);
	ctx.count.copy_from_slice(&ZEROS_U32_2);
	ctx.state.copy_from_slice(&ZEROS_U32_8);
}

const ZEROS_U8_64: [u8; 64] = [0; 64];
const ZEROS_U32_2: [u32; 2] = [0; 2];


// Initialize an HMAC-SHA256 operation with the given key.
fn hmac_sha256_init(ctx: &mut HmacSha256Ctx, k: &[u8]) {
	let k_len = k.len();

	// If Klen > 64, the key is really SHA256(K).
	if k_len > 64 {
		let mut khash: [u8; 32] = [0; 32];
		sha256_init(&mut ctx.ictx);
		sha256_update(&mut ctx.ictx, k);
		sha256_final(&mut khash, &mut ctx.ictx);

		hmac_sha256_init(ctx, &mut khash);

		// Clean the stack.
		khash.copy_from_slice(&ZEROS_U8_32);
		return;
	}

	let mut pad: [u8; 64] = [0; 64];

	// Inner SHA256 operation is SHA256(K xor [block of 0x36] || data).
	sha256_init(&mut ctx.ictx);
	for i in 0..k_len { pad[i] = 0x36 ^ k[i]; }
	sha256_update(&mut ctx.ictx, &pad);

	// Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash).
	sha256_init(&mut ctx.octx);
	for i in 0..k_len { pad[i] = 0x5c ^ k[i]; }
	sha256_update(&mut ctx.octx, &pad);

}

const ZEROS_U8_32: [u8; 32] = [0; 32];


// Add bytes to the HMAC-SHA256 operation.
fn hmac_sha256_update(ctx: &mut HmacSha256Ctx, inc: &[u8]) {
	// Feed data to the inner SHA256 operation.
	sha256_update(&mut ctx.ictx, inc);
}

// Finish an HMAC-SHA256 operation.
fn hmac_sha256_final(digest: &mut [u8], ctx: &mut HmacSha256Ctx) {
	let mut ihash: [u8; 32] = [0; 32];

	// Finish the inner SHA256 operation.
	sha256_final(&mut ihash, &mut ctx.ictx);

	// Feed the inner hash to the outer SHA256 operation.
	sha256_update(&mut ctx.octx, &ihash);

	// Finish the outer SHA256 operation.
	sha256_final(digest, &mut ctx.octx);

	// Clean the stack.
	ihash.copy_from_slice(&ZEROS_U8_32);
}

// PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
// Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
// write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
//
pub fn pbkdf2_sha256(passwd: &[u8], salt: &[u8], c: u64, buf: &mut[u8]) {
	let dk_len = buf.len();
	let mut ps_hctx = make_hmac_sha256_ctx();
	let mut hctx = make_hmac_sha256_ctx();
	let mut ivec: [u8; 4] = [0; 4];
	let mut u: [u8; 32] = [0; 32];
	let mut t: [u8; 32] = [0; 32];

	// Compute HMAC state after processing P and S.
	hmac_sha256_init(&mut ps_hctx, &passwd);
	hmac_sha256_update(&mut ps_hctx, &salt);

	// Iterate through the blocks.
	let mut i: usize = 0;
	while (i * 32) < dk_len {
		// Generate INT(i + 1).
		be32enc(&mut ivec, 0, (i + 1) as u32);

		// Compute U_1 = PRF(P, S || INT(i)).
		copy_hmac_ctx(&mut hctx, &ps_hctx);
		hmac_sha256_update(&mut hctx, &ivec);
		hmac_sha256_final(&mut u, &mut hctx);

		// T_i = U_1 ...
		t.copy_from_slice(&u);

		for _ in 2..c {
			// Compute U_j.
			hmac_sha256_init(&mut hctx, &passwd);
			hmac_sha256_update(&mut hctx, &u);
			hmac_sha256_final(&mut u, &mut hctx);

			// ... xor U_j ...
			for k in 0..32 { t[k] ^= u[k]; }
		}

		// Copy as many bytes as necessary into buf.
		let mut clen = dk_len - i * 32;
		if clen > 32 { clen = 32; }
		buf[(i*32)..(i*32+clen)].copy_from_slice(&t[0..clen]);

		i += 1;
	}

	// Clean PShctx, since we never called _Final on it.
	clear_hmac_ctx(&mut ps_hctx);
}

fn clear_hmac_ctx(ctx: &mut HmacSha256Ctx) {
	clear_sha_ctx(&mut ctx.ictx);
	clear_sha_ctx(&mut ctx.octx);
}

fn copy_hmac_ctx(dst: &mut HmacSha256Ctx, src: &HmacSha256Ctx) {
	copy_sha_ctx(&mut dst.ictx, &src.ictx);
	copy_sha_ctx(&mut dst.octx, &src.octx);
}

fn copy_sha_ctx(dst: &mut Sha256Ctx, src: &Sha256Ctx) {
	dst.buf.copy_from_slice(&src.buf);
	dst.count.copy_from_slice(&src.count);
	dst.state.copy_from_slice(&src.state);
}


#[cfg(test)]
mod tests {

	use scrypt::sha256::pbkdf2_sha256;
	use scrypt::sha256::make_hmac_sha256_ctx;
	use scrypt::sha256::make_sha256_ctx;
	use scrypt::sha256::sha256_init;
	use scrypt::sha256::sha256_update;
	use scrypt::sha256::sha256_final;
	use util::verify::compare;

	// Test SHA-256 for use in scrypt.
	//
	#[test]
	fn sha256_for_scrypt() {
		let x = "testing\n".as_bytes();
		let mut hctx = make_sha256_ctx();
		sha256_init(&mut hctx);
		sha256_update(&mut hctx, &x[0..3]);
		sha256_update(&mut hctx, &x[3..5]);
		sha256_update(&mut hctx, &x[5..]);
		let mut result: [u8; 32] = [0; 32];
		sha256_final(&mut result, &mut hctx);
		assert!(compare(&result, &[
			0x12, 0xa6, 0x1f, 0x4e, 0x17, 0x3f, 0xb3, 0xa1,
			0x1c, 0x05, 0xd6, 0x47, 0x1f, 0x74, 0x72, 0x8f,
			0x76, 0x23, 0x1b, 0x4a, 0x5f, 0xcd, 0x96, 0x67,
			0xce, 0xf3, 0xaf, 0x87, 0xa3, 0xae, 0x4d, 0xc2 ]));
	}

	// Test PBKDF2 with HMAC-SHA-256, test vector #1
	//
	#[test]
	fn pbkdf2_sha256_vect1() {
		let p = "passwd".as_bytes();
		let s = "salt".as_bytes();
		let c: u64 = 1;
		let mut result: [u8; 64] = [0; 64];

		pbkdf2_sha256(&p, &s, c, &mut result);

		assert!(compare(&result, &[
			0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16,
			0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05, 0xf9, 0x41, 0x85, 0x21,
			0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d,
			0xac, 0xbc, 0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45,
			0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31, 0x7c, 0x71,
			0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5, 0x09, 0x11, 0x20, 0x41,
			0xd3, 0xa1, 0x97, 0x83 ]));
	}

	// Test PBKDF2 with HMAC-SHA-256, test vector #2
	//
	#[test]
	fn pbkdf2_sha256_vect2() {
		let p = "Password".as_bytes();
		let s = "NaCl".as_bytes();
		let c: u64 = 80000;
		let mut result: [u8; 64] = [0; 64];

		pbkdf2_sha256(&p, &s, c, &mut result);

		assert!(compare(&result, &[
			0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c,
			0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9, 0x64, 0x1a, 0x44, 0x18,
			0xd0, 0x4c, 0x04, 0x14, 0xae, 0xff, 0x08, 0x87, 0x6b, 0x34,
			0xab, 0x56, 0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54,
			0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17, 0x6a, 0x27,
			0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78, 0x47, 0x8f, 0x62, 0xb3,
			0x97, 0xf3, 0x3c, 0x8d ]));
	}

}