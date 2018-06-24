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

use signing::ge25519::*;
use signing::sc25519::*;
use hash::sha512::{ hash_sha512, Sha512 };
use util::{ make_conf_error, make_signature_verification_error, Error,
	Resetable, verify::compare_v32 };

pub struct Keypair {
	
	/// Secret key of this pair.
	pub skey: [u8; 64],
	
	/// Public key of this pair.
	pub pkey: [u8; 32],

}

fn make_keypair() -> Keypair {
	Keypair {
		skey: [0; 64],
		pkey: [0; 32],
	}
}

/// Analog of crypto_sign_keypair in crypto_sign/ed25519/ref/keypair.c
pub fn generate_keypair(seed: &[u8]) -> Keypair {
	let mut az: [u8; 64] = [0; 64];
	let mut scsk = make_sc25519();
	let mut gepk = make_ge25519();

	hash_sha512(&mut az, &seed);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;

	sc25519_from32bytes(&mut scsk, &az[0..32]);

	ge25519_scalarmult_base(&mut gepk, &scsk);

	let mut pair = make_keypair();
	ge25519_pack(&mut pair.pkey, &gepk);
	pair.skey[0..32].copy_from_slice(seed);
	pair.skey[32..].copy_from_slice(&pair.pkey);

	pair
}

pub fn extract_pkey(sk: &[u8]) -> Result<Vec<u8>, Error> {
	if sk.len() != 64 { return Err(make_conf_error(format!(
		"Length of given sk array is {} instead of 64", sk.len()))); }
	let mut pk: Vec<u8> = vec![0; 32];
	pk[..].copy_from_slice(&sk[32..]);
	Ok(pk)
}

/// Analog of crypto_sign in crypto_sign/ed25519/ref/sign.c
pub fn sign(m: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
	if sk.len() != 64 { return Err(make_conf_error(format!(
		"Secret key array is {} bytes long instead of 64", sk.len()))); }
	if m.len() == 0 { return Err(make_conf_error(format!(
		"Message array m is empty"))); }

	let mut pk: [u8; 32] = [0; 32];
	pk.copy_from_slice(&sk[32..]);
	/* pk: 32-byte public key A */

	let mut az: [u8; 64] = [0; 64];
	hash_sha512(&mut az, &sk[0..32]);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	/* az: 32-byte scalar a, 32-byte randomizer z */

	let mut sm: Vec<u8> = vec![0; m.len()+64];
	sm[64..].copy_from_slice(m);
	sm[32..64].copy_from_slice(&az[32..64]);
	/* sm: 32-byte uninit, 32-byte z, mlen-byte m */

	let mut nonce: [u8; 64] = [0; 64];
	hash_sha512(&mut nonce, &sm[32..]);
	/* nonce: 64-byte H(z,m) */

	let mut sck = make_sc25519();
	let mut ger = make_ge25519();
	sc25519_from64bytes(&mut sck, &nonce);
	ge25519_scalarmult_base(&mut ger, &sck);
	ge25519_pack(&mut sm[0..32], &ger);
	/* sm: 32-byte R, 32-byte z, mlen-byte m */

	sm[32..64].copy_from_slice(&pk);
	/* sm: 32-byte R, 32-byte A, mlen-byte m */

	let mut hram: [u8; 64] = [0; 64];
	hash_sha512(&mut hram, &sm);
	/* hram: 64-byte H(R,A,m) */

	let mut scs = make_sc25519();
	let mut scs_temp = make_sc25519();
	let mut scsk = make_sc25519();
	sc25519_from64bytes(&mut scs, &hram);
	sc25519_from32bytes(&mut scsk, &az[0..32]);
	sc25519_mul(&mut scs_temp, &scs, &scsk);
	sc25519_add(&mut scs, &scs_temp, &sck);
	/* scs: S = nonce + H(R,A,m)a */

	sc25519_to32bytes(&mut sm[32..64], &scs);
	/* sm: 32-byte R, 32-byte S, mlen-byte m */

	az.reset();
	scs_temp.v.reset();
	scsk.v.reset();
	nonce.reset();
	hram.reset();
	sck.v.reset();
	ger.x.v.reset();

	Ok(sm)
}

pub fn signature(m: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
	if sk.len() != 64 { return Err(make_conf_error(format!(
		"Secret key array is {} bytes long instead of 64", sk.len()))); }
	if m.len() == 0 { return Err(make_conf_error(format!(
		"Message array m is empty"))); }
	
	let mut pk: [u8; 32] = [0; 32];
	pk.copy_from_slice(&sk[32..]);
	/* pk: 32-byte public key A */

	let mut az: [u8; 64] = [0; 64];
	hash_sha512(&mut az, &sk[0..32]);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	/* az: 32-byte scalar a, 32-byte randomizer z */

	let mut sig: Vec<u8> = vec![0; 64];
	sig[32..64].copy_from_slice(&az[32..]);
	/* sig: 32-byte uninit, 32-byte z */

	let mut hasher = Sha512::new();
	hasher.update(&sig[32..]);
	hasher.update(m);
	let nonce = hasher.digest();
	/* nonce: 64-byte H(z,m) */

	let mut sck = make_sc25519();
	let mut ger = make_ge25519();
	sc25519_from64bytes(&mut sck, &nonce);
	ge25519_scalarmult_base(&mut ger, &sck);
	ge25519_pack(&mut sig[0..32], &ger);
	/* sig: 32-byte R, 32-byte z */

	hasher.update(&sig[0..32]);
	hasher.update(&pk);
	hasher.update(m);
	let hram = hasher.digest();
	/* hram: 64-byte H(R,A,m) */

	let mut scs = make_sc25519();
	let mut scs_temp = make_sc25519();
	let mut scsk = make_sc25519();
	sc25519_from64bytes(&mut scs, &hram);
	sc25519_from32bytes(&mut scsk, &az[0..32]);
	sc25519_mul(&mut scs_temp, &scs, &scsk);
	sc25519_add(&mut scs, &scs_temp, &sck);
	/* scs: S = nonce + H(R,A,m)a */

	sc25519_to32bytes(&mut sig[32..64], &scs);
	/* sig: 32-byte R, 32-byte S */

	Ok(sig)
}

/// Analog of crypto_sign_open in crypto_sign/ed25519/ref/open.c
pub fn open(sm: &[u8], pk: &[u8]) -> Result<Vec<u8>, Error> {
	if pk.len() != 32 { return Err(make_conf_error(format!(
		"Public key array is {} bytes long instead of 32", pk.len()))); }

	let mut get1 = make_ge25519();
	if (sm.len() < 64)
	|| ((sm[63] & 224) != 0)
	|| !ge25519_unpackneg_vartime(&mut get1, pk) {
		return Err(make_signature_verification_error());
	}

	let mut rcopy: [u8; 32] = [0; 32];
	rcopy.copy_from_slice(&sm[0..32]);

	let mut scs = make_sc25519();
	sc25519_from32bytes(&mut scs, &sm[32..64]);

	let mut m: Vec<u8> = sm.to_vec();
	m[32..64].copy_from_slice(pk);
	let mut hram: [u8; 64] = [0; 64];
	hash_sha512(&mut hram, &m);

	let mut schram = make_sc25519();
	sc25519_from64bytes(&mut schram, &hram);

	let mut get2 = make_ge25519();
	ge25519_double_scalarmult_vartime(
		&mut get2, &get1, &schram, &ge25519_base, &scs);
	let mut rcheck: [u8; 32] = [0; 32];
	ge25519_pack(&mut rcheck, &get2);

	if compare_v32(&rcopy, &rcheck) {
		Ok(m[64..].to_vec())
	} else {
		Err(make_signature_verification_error())
	}
}

pub fn verify(sig: &[u8], m: &[u8], pk: &[u8]) -> Result<bool, Error> {
	if pk.len() != 32 { return Err(make_conf_error(format!(
		"Public key array is {} bytes long instead of 32", pk.len()))); }

	let mut get1 = make_ge25519();
	if (sig.len() < 64)
	|| ((sig[63] & 224) != 0)
	|| !ge25519_unpackneg_vartime(&mut get1, pk) {
		return Ok(false);
	}

	let mut rcopy: [u8; 32] = [0; 32];
	rcopy.copy_from_slice(&sig[0..32]);

	let mut scs = make_sc25519();
	sc25519_from32bytes(&mut scs, &sig[32..64]);

	let mut hasher = Sha512::new();
	hasher.update(&sig[0..32]);
	hasher.update(pk);
	hasher.update(m);
	let hram = hasher.digest();

	let mut schram = make_sc25519();
	sc25519_from64bytes(&mut schram, &hram);

	let mut get2 = make_ge25519();
	ge25519_double_scalarmult_vartime(
		&mut get2, &get1, &schram, &ge25519_base, &scs);
	let mut rcheck: [u8; 32] = [0; 32];
	ge25519_pack(&mut rcheck, &get2);

	Ok(compare_v32(&rcopy, &rcheck))
}


#[cfg(test)]
mod tests {

	use signing::sign::{ generate_keypair, sign, open, signature, verify };
	use util::verify::compare;

	#[test]
	fn test1() {

		let key_seed: [u8; 32] = [
			0xae, 0x38, 0x86, 0x7b, 0xd2, 0x65, 0xcb, 0x86, 0x57, 0x0e,
			0x90, 0x0e, 0x24, 0xa1, 0x75, 0x03, 0x2f, 0x74, 0xab, 0x4d,
			0xa1, 0xbd, 0xf5, 0xc9, 0x12, 0x3e, 0x4c, 0x98, 0x12, 0xaa,
			0x0c, 0x95 ];

		let expected_pkey: [u8; 32] = [
			0xd0, 0xa5, 0xe8, 0xca, 0xeb, 0xff, 0xb8, 0x2a, 0x5e, 0x6d,
			0x24, 0x4a, 0x94, 0x94, 0x3c, 0xd5, 0x34, 0x03, 0x68, 0x0d,
			0x93, 0x02, 0x82, 0xb2, 0xc0, 0x7b, 0x1f, 0xfd, 0xbd, 0x21,
			0x39, 0xd0 ];

		// Testing signing keys generation
		let pair = generate_keypair(&key_seed);
		assert!(compare(&pair.pkey, &expected_pkey));

		// Testing of message signing");
		let m = "testing\n".as_bytes();

		let expected_signed_m = [
			0x74, 0xff, 0xb4, 0x4b, 0xf0, 0x46, 0xf9, 0xe9, 0x86, 0x87,
			0xa4, 0x6b, 0x28, 0xc3, 0x38, 0x6e, 0x78, 0xb0, 0x62, 0x53,
			0x2f, 0xf6, 0x45, 0x39, 0x97, 0x24, 0x0b, 0xa0, 0xab, 0xee,
			0x5d, 0x7e, 0x44, 0xc8, 0x80, 0x2f, 0x86, 0xf5, 0x34, 0x21,
			0x32, 0x7f, 0xb4, 0x3f, 0xa6, 0xd8, 0x9c, 0x0a, 0xdf, 0x5b,
			0x91, 0x04, 0x9a, 0x67, 0xba, 0x3b, 0xf0, 0xdd, 0x7c, 0xd1,
			0x5d, 0xbd, 0x89, 0x0a, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e,
			0x67, 0x0a ];

		let signed_m = sign(&m, &pair.skey).unwrap();
		assert!(compare(&signed_m, &expected_signed_m));

		let result = open(&signed_m, &pair.pkey).unwrap();
		assert!(compare(&result, &m));
		
		// Testing of separated-signature functionality
		let sig = signature(&m, &pair.skey).unwrap();
		assert!(compare(&sig, &expected_signed_m[0..64]));
		assert!(verify(&sig, &m, &pair.pkey).unwrap());
	}

	#[test]
	fn test2() {

		struct SeedAndPKey {
			seed: [u8; 32],
			pkey: [u8; 32]
		}
		
		let seed_and_pkeys = [
			SeedAndPKey {
				seed: [ 0x13, 0xca, 0x75, 0xbe, 0x97, 0x13, 0x61, 0x62, 0xb4, 0x36,
					0x95, 0xfa, 0xd2, 0xa2, 0xb2, 0xcb, 0xb4, 0x35, 0xc9, 0xad,
					0x0a, 0x0f, 0xf5, 0xb6, 0x58, 0x7e, 0xd9, 0xd0, 0xcf, 0xfb,
					0x59, 0xec ],
				pkey: [ 0xed, 0xef, 0xc9, 0x54, 0x05, 0xce, 0x9f, 0x81, 0x7d, 0x2b,
					0xd8, 0xb9, 0x48, 0x0c, 0x3f, 0xfb, 0xa8, 0xd9, 0x6a, 0x6e,
					0x00, 0x87, 0x90, 0x6a, 0xe2, 0xe9, 0xa9, 0x2f, 0xf5, 0xa9,
					0xdc, 0xe7 ] },
			SeedAndPKey {
				seed: [ 0xee, 0xdd, 0xec, 0xfa, 0x96, 0x70, 0x23, 0x6b, 0xdd, 0x4b,
						0xba, 0x59, 0xae, 0x69, 0x65, 0x7a, 0x83, 0xb9, 0x74, 0x9a,
						0xd7, 0xd7, 0x68, 0x21, 0xe8, 0x64, 0x1a, 0x4b, 0xe3, 0x1a,
						0x5b, 0x74 ],
				pkey: [ 0x20, 0x95, 0x60, 0x39, 0xa6, 0x6f, 0x66, 0x63, 0xe0, 0x08,
						0xa3, 0xac, 0xd2, 0x96, 0x76, 0x5e, 0xea, 0x21, 0xe5, 0x6c,
						0x3d, 0x2f, 0xea, 0xb7, 0xc7, 0x4d, 0x0c, 0x9d, 0x2f, 0x6e,
						0xc5, 0xe4 ] },
			SeedAndPKey {
				seed: [ 0x9a, 0xae, 0xe7, 0xc6, 0xf9, 0xd7, 0xe4, 0x9c, 0x64, 0x05,
						0xa9, 0x81, 0xa6, 0xe3, 0xa6, 0x52, 0x5b, 0x62, 0x5f, 0xa1,
						0xae, 0x92, 0x5c, 0xec, 0x12, 0x2f, 0x2d, 0xe3, 0x3d, 0x4d,
						0x30, 0x3c ],
				pkey: [ 0xe3, 0x43, 0x33, 0xb1, 0x42, 0xc5, 0xc5, 0x86, 0x14, 0x86,
						0x46, 0x37, 0x0d, 0xfc, 0xf7, 0x21, 0x48, 0x50, 0x24, 0x6d,
						0x69, 0x7f, 0x6d, 0x32, 0x60, 0x47, 0xdf, 0xa7, 0x85, 0xd6,
						0xee, 0xd5 ] } ];

		let m = "<From https://doc.rust-lang.org/book/second-edition/ch04-03-slices.html>
We’ll discuss iterators in more detail in Chapter 13. For now, know that iter is a method that returns each element in a collection and that enumerate wraps the result of iter and returns each element as part of a tuple instead. The first element of the tuple returned from enumerate is the index, and the second element is a reference to the element. This is a bit more convenient than calculating the index ourselves.

Because the enumerate method returns a tuple, we can use patterns to destructure that tuple, just like everywhere else in Rust. So in the for loop, we specify a pattern that has i for the index in the tuple and &item for the single byte in the tuple. Because we get a reference to the element from .iter().enumerate(), we use & in the pattern.

Inside the for loop, we search for the byte that represents the space by using the byte literal syntax. If we find a space, we return the position. Otherwise, we return the length of the string by using s.len():

    if item == b' ' {
        return i;
    }
}
s.len()

We now have a way to find out the index of the end of the first word in the string, but there’s a problem. We’re returning a usize on its own, but it’s only a meaningful number in the context of the &String. In other words, because it’s a separate value from the String, there’s no guarantee that it will still be valid in the future. Consider the program in Listing 4-8 that uses the first_word function from Listing 4-7:
...".as_bytes();

		for sp in seed_and_pkeys.iter() {
			let pair = generate_keypair(&sp.seed);
			assert!(compare(&pair.pkey, &sp.pkey));
			let signed_m = sign(&m, &pair.skey).unwrap();
			let sig = signature(&m, &pair.skey).unwrap();
			assert!(compare(&sig, &signed_m[0..64]));
			let result = open(&signed_m, &pair.pkey).unwrap();
			assert!(compare(&result, &m));
			assert!(verify(&sig, &m, &pair.pkey).unwrap());
		}
		
	}

}