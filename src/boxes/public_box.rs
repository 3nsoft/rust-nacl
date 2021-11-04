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

use super::stream::SIGMA;
use super::scalarmult::{ curve25519_base, curve25519 };
use crate::util::{ Error, make_conf_error, Resetable };
use super::core::hsalsa20;
use super::secret_box;

pub use super::secret_box::{ NONCE_LENGTH, KEY_LENGTH, POLY_LENGTH};

pub static JWK_ALG_NAME: &str = "NaCl-box-CXSP";

/// This function generates a public for any given secret key, which itself
/// should be randomly generated.
/// This is an analog of crypto_box_keypair in
/// crypto_box/curve25519xsalsa20poly1305/ref/keypair.c
/// 
pub fn generate_pubkey(sk: &[u8]) -> Result<Vec<u8>, Error> {
	if sk.len() != KEY_LENGTH { return Err(make_conf_error(format!(
		"Key array sk should have {} bytes in it, but it is {} bytes long.", KEY_LENGTH, sk.len()))); }
	let mut pk: Vec<u8> = vec![0; 32];
	curve25519_base(&mut pk, &sk);
	Ok(pk)
}

/// n array in crypto_box/curve25519xsalsa20poly1305/ref/before.c
const N_TO_CALC_DHSHARED_KEY: [u8; 16] = [0; 16];

/// This function calculates a dh-style shared key (or stream key), for given
/// public and secret keys.
/// This is an analog of crypto_box_beforenm in
/// crypto_box/curve25519xsalsa20poly1305/ref/before.c
/// 
pub fn calc_dhshared_key(pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
	if pk.len() != KEY_LENGTH { return Err(make_conf_error(format!(
		"Public key array pk should have {} bytes in it, but it is {} bytes long.", KEY_LENGTH, pk.len()))); }
	if sk.len() != KEY_LENGTH { return Err(make_conf_error(format!(
		"Secret key array sk should have {} bytes in it, but it is {} bytes long.", KEY_LENGTH, sk.len()))); }
	let mut s0: [u8; 32] = [0; 32];
	curve25519(&mut s0, &sk, &pk);
	let mut s: Vec<u8> = vec![0; 32];
	hsalsa20(&mut s, &N_TO_CALC_DHSHARED_KEY, &s0, SIGMA);
	s0.reset();
	Ok(s)
}

pub mod stream {
	pub use super::secret_box::pack;
	pub use super::secret_box::open;
}

/// This function packs given message into xsalsa20+poly1305 secret-box bytes
/// layout.
/// This is an analog of crypto_box in
/// crypto_box/curve25519xsalsa20poly1305/ref/box.c
/// 
pub fn pack(m: &[u8], n: &[u8], pk: &[u8], sk: &[u8]) ->
		Result<Vec<u8>, Error> {
	let mut k = calc_dhshared_key(pk, sk)?;
	let c = stream::pack(m, n, k.as_slice());
	k.reset();
	c
}

/// This function opens xsalsa20+poly1305 formatted cipher, returning a message.
/// This is an analog of crypto_box_open in
/// crypto_box/curve25519xsalsa20poly1305/ref/box.c
/// 
pub fn open(c: &[u8], n: &[u8], pk: &[u8], sk: &[u8]) ->
		Result<Vec<u8>, Error> {
	let mut k = calc_dhshared_key(pk, sk)?;
	let m = stream::open(c, n, k.as_slice());
	k.reset();
	m
}

pub mod format_wn {

	use crate::util::{ Error, Resetable };
	use super::calc_dhshared_key;
	use super::secret_box;

	pub use secret_box::format_wn::copy_nonce_from;

	pub mod stream {
		pub use super::secret_box::format_wn::pack;
		pub use super::secret_box::format_wn::open;
	}

	/// This function packs given message into  with-nonce layout, which is
	/// nonce, followed by poly1305 hash, followed by xsalsa20 cipher.
	/// 
	pub fn pack(m: &[u8], n: &[u8], pk: &[u8], sk: &[u8]) ->
			Result<Vec<u8>, Error> {
		let mut k = calc_dhshared_key(pk, sk)?;
		let c = stream::pack(m, n, k.as_slice());
		k.reset();
		c
	}

	/// This function opens cipher that has a with-nonce layout, which is
	/// nonce, followed by poly1305 hash, followed by xsalsa20 cipher.
	/// 
	pub fn open(c: &[u8], pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
		let mut k = calc_dhshared_key(pk, sk)?;
		let m = stream::open(c, k.as_slice());
		k.reset();
		m
	}

	// /**
	//  * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
	//  * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
	//  * @param nextNonce is nonce, which should be used for the very first packing.
	//  * All further packing will be done with new nonce, as it is automatically evenly
	//  * advanced.
	//  * Note that nextNonce will be copied.
	//  * @param delta is a number between 1 and 255 inclusive, used to advance nonce.
	//  * When missing, it defaults to two.
	//  * @param arrFactory is typed arrays factory, used to allocated/find an array
	//  * for use. It may be undefined, in which case an internally created one is used.
	//  * @return a frozen object with pack & open functions, and destroy
	//  * It is NaCl's secret box for a calculated DH-shared key, with automatically
	//  * evenly advancing nonce.
	//  */
	// export function makeEncryptor(pk: Uint8Array, sk: Uint8Array,
	// 		nextNonce: Uint8Array, delta?: number,
	// 		arrFactory?: arrays.Factory): sbox.Encryptor {
	// 	if ('number' !== typeof delta) {
	// 		delta = 2;
	// 	}
	// 	if (!arrFactory) { arrFactory = arrays.makeFactory(); }
	// 	var k = calc_dhshared_key(pk, sk, arrFactory);
	// 	var enc = sbox.formatWN.makeEncryptor(k, nextNonce, delta, arrFactory);
	// 	arrFactory.wipe(k);
	// 	return enc;
	// }

	// /**
	//  * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
	//  * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
	//  * @param arrFactory is typed arrays factory, used to allocated/find an array
	//  * for use. It may be undefined, in which case an internally created one is used.
	//  * @return a frozen object with open and destroy functions.
	//  * It is NaCl's secret box for a calculated DH-shared key.
	//  */
	// export function makeDecryptor(pk: Uint8Array, sk: Uint8Array,
	// 		arrFactory?: arrays.Factory): sbox.Decryptor {
	// 	if (!arrFactory) { arrFactory = arrays.makeFactory(); }
	// 	var k = calc_dhshared_key(pk, sk, arrFactory);
	// 	var enc = sbox.formatWN.makeDecryptor(k, arrFactory);
	// 	arrFactory.wipe(k);
	// 	return enc;
	// }
	
}


#[cfg(test)]
#[allow(non_upper_case_globals)]
mod tests {

	use crate::util::verify::compare;
	use super::{ KEY_LENGTH, POLY_LENGTH, NONCE_LENGTH, pack, open };

	static alicesk: [u8; KEY_LENGTH] = [
		0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,
		0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
		0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,
		0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a ];

	static alicepk: [u8; KEY_LENGTH] = [
		0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,
		0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
		0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,
		0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a ];

	static bobsk: [u8; KEY_LENGTH] = [
		0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,
		0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
		0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,
		0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb ];

	static bobpk: [u8; KEY_LENGTH] = [
		0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,
		0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
		0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,
		0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f ];

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


	/// Analog of tests/box3.c, expected result printed in tests/box3.out.
	/// 
	#[test]
	fn box3() {
		let result = pack(&m, &nonce[..], &bobpk, &alicesk).unwrap();
		assert!(compare(&result, &c));
	}

	/// Analog of tests/box4.c, expected result printed in tests/box4.out.
	/// 
	#[test]
	fn box4() {
		let result = open(&c, &nonce[..], &alicepk, &bobsk).unwrap();
		assert!(compare(&result, &m));
	}

}