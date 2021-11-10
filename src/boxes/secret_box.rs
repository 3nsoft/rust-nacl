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

//! This module provides secret box pack and open functionality.
//! It also provide ability to use cipner format with-nonce.

use super::stream::{ xsalsa20_xor, xsalsa20 };
use super::onetimeauth::{ poly1305, poly1305_verify };
use crate::util::{ Error, make_cipher_verification_error, make_conf_error,
	Resetable };

/// Analog of crypto_secretbox in crypto_secretbox/xsalsa20poly1305/ref/box.c
/// with an addition that there no zero pads, neither in incoming message, nor
/// in a resulting cipher pack.
/// 
fn xsalsa20_poly1305_pad_and_pack(c: &mut [u8], m: &[u8], n: &[u8], k: &[u8]) {
	if c.len() < (POLY_LENGTH + m.len()) { panic!(
		"Given array c is too short for output."); }
	let mut poly_key: [u8; 32] = [0; 32];
	xsalsa20_xor(&mut poly_key, &mut c[POLY_LENGTH..], m, 32, n, k);
	let mut poly_out: [u8; POLY_LENGTH] = [0; POLY_LENGTH];
	poly1305(&mut poly_out, &c[POLY_LENGTH..], &poly_key);
	// write poly output into cipher pack
	c[0..POLY_LENGTH].copy_from_slice(&poly_out);
	// clear
	poly_key.reset();
}

/// This function packs given message into xsalsa20+poly1305 secret-box bytes
/// layout (trimmed of prefixed zeros, unlike crypto_secretbox from
/// crypto_secretbox/xsalsa20poly1305/ref/box.c).
/// 
pub fn pack(m: &[u8], n: &[u8], k: &[u8]) -> Result<Vec<u8>, Error> {

	if m.len() == 0 { return Err(make_conf_error(format!(
		"Message array m is empty"))); }
	if n.len() != NONCE_LENGTH { return Err(make_conf_error(format!(
		"Nonce array n should have {} elements (bytes) in it, but it is {} elements long.", NONCE_LENGTH, n.len()))); }
	if k.len() != KEY_LENGTH { return Err(make_conf_error(format!(
		"Key array k should have {} elements (bytes) in it, but it is {} elements long.", KEY_LENGTH, k.len()))); }

	let mut c: Vec<u8> = vec![0; POLY_LENGTH+m.len()];
	xsalsa20_poly1305_pad_and_pack(&mut c, m, n, k);
	Ok(c)
}

/// This function opens xsalsa20+poly1305 formatted cipher, returning a message,
/// trimmed of prefixed zeros, unlike crypto_secretbox_open from
/// crypto_secretbox/xsalsa20poly1305/ref/box.c. Note also that cipher doesn't
/// have leading zeros, unlike C version.
/// 
pub fn open(c: &[u8], n: &[u8], k: &[u8]) -> Result<Vec<u8>, Error> {
	
	if c.len() < POLY_LENGTH+1 { return Err(make_conf_error(format!(
		"Cipher array c should have at least 17 elements (bytes) in it, but is only {} elements long.", c.len()))); }
	if n.len() != NONCE_LENGTH { return Err(make_conf_error(format!(
		"Nonce array n should have {} elements (bytes) in it, but it is {} elements long.", NONCE_LENGTH, n.len()))); }
	if k.len() != KEY_LENGTH { return Err(make_conf_error(format!(
		"Key array k should have {} elements (bytes) in it, but it is {} elements long.", KEY_LENGTH, k.len()))); }
	
	let mut subkey: [u8; KEY_LENGTH] = [0; KEY_LENGTH];
	xsalsa20(&mut subkey, n, k);
	
	let poly_part_of_c = &c[0..POLY_LENGTH];
	let msg_part_of_c = &c[POLY_LENGTH..];
	
	if !poly1305_verify(poly_part_of_c, msg_part_of_c, &subkey) {
		return Err(make_cipher_verification_error());
	}
	
	let mut m: Vec<u8> = vec![0; c.len()-POLY_LENGTH];

	xsalsa20_xor(&mut subkey, &mut m, &c, 16, &n, &k);

	// first 32 bytes, dumped into subkey, should be cleared
	subkey[0..32].reset();
	
	Ok(m)
}


pub mod format_wn {

	use super::{ NONCE_LENGTH, POLY_LENGTH, KEY_LENGTH,
		open as original_open, xsalsa20_poly1305_pad_and_pack};
	use crate::util::{ Error, make_conf_error };

	/// This function packs given message into  with-nonce layout, which is
	/// nonce, followed by poly1305 hash, followed by xsalsa20 cipher.
	/// 
	pub fn pack(m: &[u8], n: &[u8], k: &[u8]) -> Result<Vec<u8>, Error> {

		if m.len() == 0 { return Err(make_conf_error(format!(
			"Message array m is empty"))); }
		if n.len() != NONCE_LENGTH { return Err(make_conf_error(format!(
			"Nonce array n should have {} elements (bytes) in it, but it is {} elements long.", NONCE_LENGTH, n.len()))); }
		if k.len() != KEY_LENGTH { return Err(make_conf_error(format!(
			"Key array k should have {} elements (bytes) in it, but it is {} elements long.", KEY_LENGTH, k.len()))); }

		let mut c: Vec<u8> = vec![0; NONCE_LENGTH+POLY_LENGTH+m.len()];
		xsalsa20_poly1305_pad_and_pack(&mut c[NONCE_LENGTH..], &m, &n, &k);
		c[0..NONCE_LENGTH].copy_from_slice(n);	// sets first bytes to nonce value
		Ok(c)
	}

	/// This function opens cipher that has a with-nonce layout, which is
	/// nonce, followed by poly1305 hash, followed by xsalsa20 cipher.
	/// 
	pub fn open(c: &[u8], k: &[u8]) -> Result<Vec<u8>, Error> {
		if c.len() < 41 { return Err(make_conf_error(format!(
			"Array c with nonce and cipher should have at least 41 bytes in it, but is only {} byte long.", c.len()))); }
		original_open(&c[NONCE_LENGTH..], &c[0..NONCE_LENGTH], k)
	}
	
	pub fn copy_nonce_from(c: &[u8]) -> Result<&[u8], Error> {
		if c.len() < 41 { return Err(make_conf_error(format!(
			"Array c with nonce and cipher should have at least 41 bytes in it, but is only {} byte long.", c.len()))); }
		Ok(&c[0..NONCE_LENGTH])
	}

// /**
//  * This is an encryptor that packs bytes according to "with-nonce" format.
//  */
// export interface Encryptor {
	
// 	/**
// 	 * This encrypts given bytes using internally held nonce, which is
// 	 * advanced for every packing operation, ensuring that every call will
// 	 * have a different nonce.
// 	 * @param m is a byte array that should be encrypted
// 	 * @return byte array with cipher formatted with nonce
// 	 */
// 	pack(m: Uint8Array): Uint8Array;
	
// 	/**
// 	 * This method securely wipes internal key, and drops resources, so that
// 	 * memory can be GC-ed.
// 	 */
// 	destroy(): void;
	
// 	/**
// 	 * @return an integer, by which nonce is advanced.
// 	 */
// 	getDelta(): number;
	
// }

// /**
//  * This is an dencryptor that unpacks bytes from "with-nonce" format.
//  */
// export interface Decryptor {
	
// 	/**
// 	 * @param c is a byte array with cipher, formatted with nonce.
// 	 * @return decrypted bytes.
// 	 */
// 	open(c: Uint8Array): Uint8Array;
	
// 	/**
// 	 * This method securely wipes internal key, and drops resources, so that
// 	 * memory can be GC-ed.
// 	 */
// 	destroy(): void;
	
// }
	
// 	/**
// 	 * 
// 	 * @param key for new encryptor.
// 	 * Note that key will be copied, thus, if given array shall never be used anywhere, it should
// 	 * be wiped after this call.
// 	 * @param nextNonce is nonce, which should be used for the very first packing.
// 	 * All further packing will be done with new nonce, as it is automatically advanced.
// 	 * Note that nextNonce will be copied.
// 	 * @param delta is a number between 1 and 255 inclusive, used to advance nonce.
// 	 * When missing, it defaults to one.
// 	 * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
// 	 * It may be undefined, in which case an internally created one is used.
// 	 * @return a frozen object with pack & open functions, and destroy
// 	 * It is NaCl's secret box for a given key, with automatically advancing nonce.
// 	 */
// 	export function makeEncryptor(key: Uint8Array, nextNonce: Uint8Array,
// 			delta?: number, arrFactory?: arrays.Factory): Encryptor {
// 		if (!(nextNonce instanceof Uint8Array)) { throw new TypeError("Nonce array nextNonce must be Uint8Array."); }
// 		if (nextNonce.length !== 24) { throw new Error(
// 				"Nonce array nextNonce should have 24 elements (bytes) in it, but it is "+
// 				nextNonce.length+" elements long."); }
// 		if (!(key instanceof Uint8Array)) { throw new TypeError("Key array key must be Uint8Array."); }
// 		if (key.length !== 32) { throw new Error(
// 				"Key array key should have 32 elements (bytes) in it, but it is "+
// 				key.length+" elements long."); }
// 		if ('number' !== typeof delta) {
// 			delta = 1;
// 		} else if ((delta < 1) || (delta > 255)) {
// 			throw new Error("Given delta is out of bounds.");
// 		}
		
// 		// set variable in the closure
// 		if (!arrFactory) {
// 			arrFactory = arrays.makeFactory();
// 		}
// 		key = new Uint8Array(key);
// 		nextNonce = new Uint8Array(nextNonce);
// 		var counter = 0;
// 		var counterMax = Math.floor(0xfffffffffffff / delta);
		
// 		// arrange and freeze resulting object
// 		var encryptor: Encryptor = {
// 			pack: (m) => {
// 				if (!key) { throw new Error("This encryptor cannot be used, " +
// 					"as it had already been destroyed."); }
// 				if (counter > counterMax) { throw new Error("This encryptor "+
// 						"has been used too many times. Further use may "+
// 						"lead to duplication of nonces."); }
// 				var c = pack(m, nextNonce, key, arrFactory);
// 				nonceUtils.advance(nextNonce, delta);
// 				counter += 1;
// 				return c;
// 			},
// 			destroy: () => {
// 				if (!key) { return; }
// 				arrFactory.wipe(key, nextNonce);
// 				key = null;
// 				nextNonce = null;
// 				arrFactory = null;
// 			},
// 			getDelta: () => {
// 				return delta;
// 			}
// 		};
// 		Object.freeze(encryptor);
		
// 		return encryptor;
// 	}
	
// 	/**
// 	 * 
// 	 * @param key for new decryptor.
// 	 * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
// 	 * It may be undefined, in which case an internally created one is used.
// 	 * Note that key will be copied, thus, if given array shall never be used anywhere,
// 	 * it should be wiped after this call.
// 	 * @return a frozen object with pack & open and destroy functions.
// 	 */
// 	export function makeDecryptor(key: Uint8Array,
// 			arrFactory?: arrays.Factory): Decryptor {
// 		if (!(key instanceof Uint8Array)) { throw new TypeError(
// 				"Key array key must be Uint8Array."); }
// 		if (key.length !== 32) { throw new Error(
// 				"Key array key should have 32 elements (bytes) in it, but it is "+
// 				key.length+" elements long."); }
		
// 		// set variable in the closure
// 		if (!arrFactory) {
// 			arrFactory = arrays.makeFactory();
// 		}
// 		key = new Uint8Array(key);
		
// 		// arrange and freeze resulting object
// 		var decryptor = {
// 			open: (c) => {
// 				if (!key) { throw new Error("This decryptor cannot be used, " +
// 						"as it had already been destroyed."); }
// 				return open(c, key, arrFactory);
// 			},
// 			destroy: () => {
// 				if (!key) { return; }
// 				arrFactory.wipe(key);
// 				key = null;
// 				arrFactory = null;
// 			}
// 		};
// 		Object.freeze(decryptor);
		
// 		return decryptor;
// 	}

}

/// Nonce length for NaCl's boxes
pub const NONCE_LENGTH: usize = 24;

/// Key length for NaCl's boxes
pub const KEY_LENGTH: usize = 32;

/// Length of Poly hash, used in NaCl's boxes
pub const POLY_LENGTH: usize = 16;

/// NaCl secret box algorithm name for JWK's (JSON Web Key) 
pub const JWK_ALG_NAME: &str = "NaCl-sbox-XSP";


#[cfg(test)]
#[allow(non_upper_case_globals)]
mod tests {

	use crate::util::verify::compare;
	use super::{ NONCE_LENGTH, KEY_LENGTH, POLY_LENGTH, pack, open,
		format_wn };

	static firstkey: [u8; KEY_LENGTH] = [
		0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4,
		0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7,
		0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2,
		0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89 ];

	static nonce: [u8; NONCE_LENGTH] = [
		0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73,
		0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6,
		0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37 ];

	static m: [u8; 131] = [
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

	static c: [u8; 131+POLY_LENGTH] = [
		0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5,
		0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9,
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

	/// Analog of tests/secretbox3.cpp, expected result printed in
	/// tests/secretbox3.out.
	/// 
	#[test]
	fn secret_box_3() {
		let result = pack(&m, &nonce, &firstkey).unwrap();
		assert!(compare(&result, &c));
	}

	/// Analog of tests/secretbox4.cpp, expected result printed in
	/// tests/secretbox4.out.
	///
	#[test]
	fn secret_box_4() {
		let result: Vec<u8> = open(&c, &nonce, &firstkey).unwrap();
		assert!(compare(&result, &m));
	}

	/// Test opening of array with nonce and cipher
	///
	#[test]
	fn format_wn() {
		
		let c_wn = format_wn::pack(&m, &nonce, &firstkey).unwrap();
		assert!(c_wn.len() == c.len()+NONCE_LENGTH);
		assert!(c_wn.len() == m.len()+NONCE_LENGTH+POLY_LENGTH);
		assert!(compare(&c_wn[0..NONCE_LENGTH], &nonce));
		assert!(compare(&c_wn[NONCE_LENGTH..], &c));
		
		let m_opened: Vec<u8> = format_wn::open(&c_wn, &firstkey).unwrap();
		assert!(compare(&m_opened, &m));
	}

}