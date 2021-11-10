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

#![allow(non_snake_case)]

use crate::util::ops::{ incr, add2 };

use super::sha256::pbkdf2_sha256;
use crate::util::{ Error };

/// Analog of le32dec in lib/util/sysendian.h
#[inline]
fn le32dec(p: &[u8]) -> u32 {
	(p[0] as u32) + ((p[1] as u32) << 8) +
	((p[2] as u32) << 16) + ((p[3] as u32) << 24)
}

/// Analog of le32enc in lib/util/sysendian.h
#[inline]
fn le32enc(p: &mut [u8], x: u32) {
	p[0] = (x & 0xff) as u8;
	p[1] = ((x >> 8) & 0xff) as u8;
	p[2] = ((x >> 16) & 0xff) as u8;
	p[3] = ((x >> 24) & 0xff) as u8;
}

/// Analog of macro used in salsa20_8 in lib/crypto/crypto_scrypt-ref.c
macro_rules! R {
	($a: expr, $b: expr) => ((($a) << ($b)) | (($a) >> (32 - ($b))))
}

/// salsa20_8(B):
/// Apply the salsa20/8 core to the provided block.
/// Analog of salsa20_8 in lib/crypto/crypto_scrypt-ref.c
fn salsa20_8(B: &mut [u8]) {

	/* Convert little-endian values in. */
	let mut B32: [u32; 16] = [0; 16];
	for i in 0..16 {
		B32[i] = le32dec(&B[i*4..4+i*4]);
	}

	/* Compute x = doubleround^4(B32). */
	let mut x: [u32; 16] = [0; 16];
	for i in 0..16 {
		x[i] = B32[i];
	}
	for _ in 0..4 {
		/* Operate on columns. */
		x[ 4] ^= R!(add2!(x[ 0],x[12]), 7);  x[ 8] ^= R!(add2!(x[ 4],x[ 0]), 9);
		x[12] ^= R!(add2!(x[ 8],x[ 4]),13);  x[ 0] ^= R!(add2!(x[12],x[ 8]),18);

		x[ 9] ^= R!(add2!(x[ 5],x[ 1]), 7);  x[13] ^= R!(add2!(x[ 9],x[ 5]), 9);
		x[ 1] ^= R!(add2!(x[13],x[ 9]),13);  x[ 5] ^= R!(add2!(x[ 1],x[13]),18);

		x[14] ^= R!(add2!(x[10],x[ 6]), 7);  x[ 2] ^= R!(add2!(x[14],x[10]), 9);
		x[ 6] ^= R!(add2!(x[ 2],x[14]),13);  x[10] ^= R!(add2!(x[ 6],x[ 2]),18);

		x[ 3] ^= R!(add2!(x[15],x[11]), 7);  x[ 7] ^= R!(add2!(x[ 3],x[15]), 9);
		x[11] ^= R!(add2!(x[ 7],x[ 3]),13);  x[15] ^= R!(add2!(x[11],x[ 7]),18);

		/* Operate on rows. */
		x[ 1] ^= R!(add2!(x[ 0],x[ 3]), 7);  x[ 2] ^= R!(add2!(x[ 1],x[ 0]), 9);
		x[ 3] ^= R!(add2!(x[ 2],x[ 1]),13);  x[ 0] ^= R!(add2!(x[ 3],x[ 2]),18);

		x[ 6] ^= R!(add2!(x[ 5],x[ 4]), 7);  x[ 7] ^= R!(add2!(x[ 6],x[ 5]), 9);
		x[ 4] ^= R!(add2!(x[ 7],x[ 6]),13);  x[ 5] ^= R!(add2!(x[ 4],x[ 7]),18);

		x[11] ^= R!(add2!(x[10],x[ 9]), 7);  x[ 8] ^= R!(add2!(x[11],x[10]), 9);
		x[ 9] ^= R!(add2!(x[ 8],x[11]),13);  x[10] ^= R!(add2!(x[ 9],x[ 8]),18);

		x[12] ^= R!(add2!(x[15],x[14]), 7);  x[13] ^= R!(add2!(x[12],x[15]), 9);
		x[14] ^= R!(add2!(x[13],x[12]),13);  x[15] ^= R!(add2!(x[14],x[13]),18);
	}

	/* Compute B32 = B32 + x. */
	for i in 0..16 {
		incr!( B32[i], x[i] );
	}

	/* Convert little-endian values out. */
	for i in 0..16 {
		le32enc(&mut B[4*i..4+4*i], B32[i]);
	}
}

/// Analog of blkcpy in lib/crypto/crypto_scrypt-ref.c
fn blkcpy(dest: &mut [u8], src: &[u8], len: usize) {
	for i in 0..len {
		dest[i] = src[i];
	}
}

/// Analog of blkxor in lib/crypto/crypto_scrypt-ref.c
fn blkxor(dest: &mut [u8], src: &[u8], len: usize) {
	for i in 0..len {
		dest[i] ^= src[i];
	}
}

/// blockmix_salsa8(B, Y, r):
/// Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
/// length; the temporary space Y must also be the same size.
/// Analog of blockmix_salsa8 in lib/crypto/crypto_scrypt-ref.c
fn blockmix_salsa8(B: &mut [u8], Y: &mut [u8], r: usize) {
	let mut X: [u8; 64] = [0; 64];

	/* 1: X <-- B_{2r - 1} */
	blkcpy(&mut X, &B[(2 * r - 1) * 64 ..], 64);

	/* 2: for i = 0 to 2r - 1 do */
	for i in 0..2*r {
		/* 3: X <-- H(X \xor B_i) */
		blkxor(&mut X, &B[i * 64 ..], 64);
		salsa20_8(&mut X);

		/* 4: Y_i <-- X */
		blkcpy(&mut Y[i * 64 ..], &X, 64);
	}

	/* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
	for i in 0..r {
		blkcpy(&mut B[i * 64 ..], &Y[(i * 2) * 64 ..], 64);
	}
	for i in 0..r {
		blkcpy(&mut B[(i + r) * 64 ..], &Y[(i * 2 + 1) * 64 ..], 64);
	}
}

/// Analog of le64dec in lib/util/sysendian.h
#[inline]
fn le64dec(p: &[u8]) -> u64 {
	(p[0] as u64) + ((p[1] as u64) << 8) +
	((p[2] as u64) << 16) + ((p[3] as u64) << 24) +
	((p[4] as u64) << 32) + ((p[5] as u64) << 40) +
	((p[6] as u64) << 48) + ((p[7] as u64) << 56)
}

/// integerify(B, r):
/// Return the result of parsing B_{2r-1} as a little-endian integer.
/// Analog of integerify in lib/crypto/crypto_scrypt-ref.c
fn integerify(B: &[u8], r: usize) -> u64 {
	let X = &B[(2 * r - 1) * 64 ..];
	le64dec(X)
}

struct ProgressIndicator<'a> {
	completed: u32,
	delta_percent: u32,
	delta_n: u32,
	progress_cb: &'a dyn Fn(u32) -> (),
}

impl ProgressIndicator<'_> {

	fn new<'a>(
		N: u32, p: u32, start_percent: u32, progress_cb: &'a dyn Fn(u32) -> ()
	) -> ProgressIndicator {
		(progress_cb)(start_percent);
		let total_n = 2*N*p;
		let total_percent = 100 - start_percent;
		let (delta_n, delta_percent) = if total_n < total_percent {
			(1, total_percent/total_n)
		} else {
			(total_n/total_percent, 1)
		};
		ProgressIndicator {
			completed: start_percent,
			delta_n: delta_n,
			delta_percent: delta_percent,
			progress_cb: progress_cb,
		}
	}

	fn addDelta(&mut self) -> () {
		if self.completed <= 100 - self.delta_percent {
			self.completed += self.delta_percent;
			(self.progress_cb)(self.completed);
		}
	}

}

/// smix(B, r, N, V, XY):
/// Compute B = SMix_r(B, N).  The input B must be 128r bytes in length; the
/// temporary storage V must be 128rN bytes in length; the temporary storage
/// X and Y must be 128r each or total 256r bytes in length.  The value N must
/// be a power of 2.
/// Analog of smix in lib/crypto/crypto_scrypt-ref.c
fn smix(
	B: &mut [u8], r: usize, N: usize, V: &mut [u8], X: &mut [u8], Y: &mut [u8],
	progress: &mut ProgressIndicator
) {
	let mut i_for_progress_report = progress.delta_n;

	/* 1: X <-- B */
	blkcpy(X, B, 128 * r);

	/* 2: for i = 0 to N - 1 do */
	for i in 0..N {
		/* 3: V_i <-- X */
		blkcpy(&mut V[i * (128 * r) ..], X, 128 * r);

		/* 4: X <-- H(X) */
		blockmix_salsa8(X, Y, r);

		if i as u32 == i_for_progress_report {
			progress.addDelta();
			i_for_progress_report += progress.delta_n;
		}
	}

	i_for_progress_report = progress.delta_n;

	/* 6: for i = 0 to N - 1 do */
	for i in 0..N {
		/* 7: j <-- Integerify(X) mod N */
		let j = (integerify(X, r) as usize) & (N - 1);

		/* 8: X <-- H(X \xor V_j) */
		blkxor(X, &V[j * (128 * r) ..], 128 * r);
		blockmix_salsa8(X, Y, r);

		if i as u32 == i_for_progress_report {
			progress.addDelta();
			i_for_progress_report += progress.delta_n;
		}
	}

	/* 10: B' <-- X */
	blkcpy(B, X, 128 * r);
}

fn allocate_byte_array(len: usize) -> Vec<u8> {
	let mut v: Vec<u8> = Vec::with_capacity(len);
	unsafe {
		v.set_len(len);
	}
	v
}

/// crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
/// Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
/// p, buflen) and write the result into buf.  The parameters r, p, and buflen
/// must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
/// must be a power of 2.
/// Return 0 on success; or -1 on error.
/// 
/// This rust implementation notes:
/// - we asks for `logN` to enforce N being a power of 2.
/// - we use standard memory allocation. When run in operating system,
///   allocation calls return ok even on infinite amount, pushing error/panic
///   later into the process that populates all of this area with random bytes.
/// 
pub fn scrypt(
	passwd: &[u8], salt: &[u8], logN: u8, r: usize, p: usize, dk_len: usize,
	progress_cb: &dyn Fn(u32) -> ()
) -> Result<Vec<u8>, Error> {
	// uint8_t * B;
	// uint8_t * V;
	// uint8_t * XY;
	// uint32_t i;

	/* Sanity-check parameters. */
	if r * p >= 2usize.pow(30) {
		// XXX specific error, bad args, with details in the message

	}
	if dk_len > (2usize.pow(32) - 1) * 32 {
		// XXX specific error, bad args, with details in the message

	}
	if logN < 1 {
		// XXX specific error, bad args, with details in the message

	}

	let N = 2usize.pow(logN as u32);

	/* Allocate memory. */
	let mut B = allocate_byte_array(128 * r * p);
	let mut X = allocate_byte_array(128 * r);
	let mut Y = allocate_byte_array(128 * r);
	let mut V = allocate_byte_array(128 * r * N);

	/* 1: (B_0 ... B_{p-1}) <-- PBKDF2(P, S, 1, p * MFLen) */
	pbkdf2_sha256(passwd, salt, 1, &mut B);
	let mut progress = ProgressIndicator::new(
		N as u32, p as u32, 3, progress_cb);

	/* 2: for i = 0 to p - 1 do */
	for i in 0..p {
		/* 3: B_i <-- MF(B_i, N) */
		smix(&mut B[i * 128 * r ..], r, N, &mut V, &mut X, &mut Y, &mut progress);
	}

	/* 5: DK <-- PBKDF2(P, B, 1, dkLen) */
	let mut buf = allocate_byte_array(dk_len);
	pbkdf2_sha256(passwd, &B, 1, &mut buf);
	progress_cb(100);

	/* Success! */
	Ok(buf)
}


#[cfg(test)]
mod tests {

	use::std::cell::Cell;
	use std::mem;
	use super::{ allocate_byte_array, scrypt };
	use crate::util::verify::compare;

	#[test]
	fn show_funky_allocation_in_os() {
		assert_eq!(8, mem::size_of::<usize>());
		let x = allocate_byte_array(128);
		assert!(x.capacity() == 128);
		assert_eq!(x.len(), 128);
		let gb = 1024*1024*1024 as usize;
		let mut big = allocate_byte_array(gb);
		assert_eq!(big.capacity(), gb);
		assert_eq!(big.len(), gb);
		big[gb-234] = 89;
		big[gb-1] = 70;
	}

	/// Testing scrypt with logN==4, r==1, p==1.
	/// See scrypt rfc https://tools.ietf.org/html/rfc7914
	/// 
	#[test]
	fn with_logn_4_r_1_p_1() {
		let P = "".as_bytes();
		let S = "".as_bytes();
		let logN: u8 = 4;
		let r: usize = 1;
		let p: usize = 1;
		let expectation = [
			0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19,
			0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44,
			0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2,
			0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
			0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3,
			0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c,
			0x38, 0xd1, 0x89, 0x06 ];
		let hlen = expectation.len();
		let progress = Cell::new(0 as u32);
		let h = scrypt(P, S, logN, r, p, hlen, & |p| {
			assert!(p >= progress.get());
			progress.set(p);
			print!(" {}%", p);
		}).unwrap();
		assert!(compare(&h, &expectation));
		assert!(progress.get() > 0);
	}

	/// Testing scrypt with logN==10, r==8, p==16.
	/// See scrypt rfc https://tools.ietf.org/html/rfc7914
	/// 
	#[test]
	fn with_logn_10_r_8_p_16() {
		let P = "password".as_bytes();
		let S = "NaCl".as_bytes();
		let logN: u8 = 10;
		let r: usize = 8;
		let p: usize = 16;
		let expectation = [
			0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56,
			0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb,
			0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37,
			0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
			0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27,
			0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d, 0x83, 0x60, 0xcb, 0xdf,
			0xa2, 0xcc, 0x06, 0x40 ];
		let hlen = expectation.len();
		let progress = Cell::new(0 as u32);
		let h = scrypt(P, S, logN, r, p, hlen, & |p| {
			assert!(p >= progress.get());
			progress.set(p);
			print!(" {}%", p);
		}).unwrap();
		assert!(compare(&h, &expectation));
		assert!(progress.get() > 0);
	}

	/// Testing scrypt with logN==14, r==8, p==1.
	/// See scrypt rfc https://tools.ietf.org/html/rfc7914
	/// 
	#[test]
	fn with_logn_14_r_8_p_1() {
		let P = "pleaseletmein".as_bytes();
		let S = "SodiumChloride".as_bytes();
		let logN: u8 = 14;
		let r: usize = 8;
		let p: usize = 1;
		let expectation = [
			0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c,
			0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb, 0xfd, 0xa8, 0xfb, 0xba,
			0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d,
			0xa1, 0xf2, 0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf,
			0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9, 0xe6, 0x1e,
			0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b,
			0x45, 0x57, 0x58, 0x87 ];
		let hlen = expectation.len();
		let progress = Cell::new(0 as u32);
		let h = scrypt(P, S, logN, r, p, hlen, & |p| {
			assert!(p >= progress.get());
			progress.set(p);
			print!(" {}%", p);
		}).unwrap();
		assert!(compare(&h, &expectation));
		assert!(progress.get() > 0);
	}

	/// Testing scrypt with logN==20, r==8, p==1.
	/// See scrypt rfc https://tools.ietf.org/html/rfc7914
	/// 
	#[test]
	fn with_logn_20_r_8_p_1() {
		let P = "pleaseletmein".as_bytes();
		let S = "SodiumChloride".as_bytes();
		let logN: u8 = 20;
		let r: usize = 8;
		let p: usize = 1;
		let expectation = [
			0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae, 0xad, 0xdb,
			0xbe, 0x09, 0xcf, 0x70, 0xf8, 0x81, 0xec, 0x56, 0x8d, 0x57,
			0x4a, 0x2f, 0xfd, 0x4d, 0xab, 0xe5, 0xee, 0x98, 0x20, 0xad,
			0xaa, 0x47, 0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f,
			0xfa, 0x1c, 0x6d, 0x92, 0x7c, 0x40, 0xf4, 0xc3, 0x37, 0x30,
			0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb, 0xcb, 0xf4, 0x5c, 0x6f,
			0xa7, 0x7a, 0x41, 0xa4 ];
		let hlen = expectation.len();
		let progress = Cell::new(0 as u32);
		let h = scrypt(P, S, logN, r, p, hlen, & |p| {
			assert!(p >= progress.get());
			progress.set(p);
			print!(" {}%", p);
		}).unwrap();
		assert!(compare(&h, &expectation));
		assert!(progress.get() > 0);
	}

}