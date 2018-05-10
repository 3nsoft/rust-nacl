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
use hash::sha512::hash_sha512;
use util::Error;
use util::make_conf_error;
use util::make_signature_verification_error;
use util::verify::compare_v32;

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

	let mut sm: Vec<u8> = vec![0; (m.len()+64)];
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

	Ok(sm)
}

// export function signature(m: Uint8Array, sk: Uint8Array,
// 		arrFactory?: arrays.Factory): Uint8Array {
// 	if (!(sk instanceof Uint8Array)) { throw new TypeError(
// 			"Key array sk must be Uint8Array."); }
// 	if (sk.length !== 64) { throw new Error("Key array sk should have 64 "+
// 			"elements (bytes) in it, but it is "+sk.length+" elements long."); }
// 	if (!arrFactory) {
// 		arrFactory = arrays.makeFactory();
// 	}
	
// 	var hasher = sha512.makeHasher(false, arrFactory);
// 	var sck = sc.make_sc25519(arrFactory);
// 	var scs = sc.make_sc25519(arrFactory);
// 	var scsk = sc.make_sc25519(arrFactory);
// 	var ger = ge.make_ge25519(arrFactory);

// 	var pk = arrFactory.getUint8Array(32);
// 	pk.set(sk.subarray(32));
// 	/* pk: 32-byte public key A */

// 	hasher.update(sk.subarray(0, 32));
// 	var az = hasher.digest();
// 	az[0] &= 248;
// 	az[31] &= 127;
// 	az[31] |= 64;
// 	/* az: 32-byte scalar a, 32-byte randomizer z */

// 	var sig = arrFactory.getUint8Array(64);
// 	sig.subarray(32, 64).set(az.subarray(32));
// 	/* sig: 32-byte uninit, 32-byte z */

// 	hasher.update(sig.subarray(32));
// 	hasher.update(m);
// 	var nonce = hasher.digest();
// 	/* nonce: 64-byte H(z,m) */

// 	sc.from64bytes(sck, nonce, arrFactory);
// 	ge.scalarmult_base(ger, sck, arrFactory);
// 	ge.pack(sig.subarray(0, 32), ger, arrFactory);
// 	/* sig: 32-byte R, 32-byte z */

// 	hasher.update(sig.subarray(0, 32));
// 	hasher.update(pk);
// 	hasher.update(m);
// 	var hram = hasher.digest();
// 	/* hram: 64-byte H(R,A,m) */

// 	sc.from64bytes(scs, hram, arrFactory);
// 	sc.from32bytes(scsk, az, arrFactory);
// 	sc.mul(scs, scs, scsk, arrFactory);
// 	sc.add(scs, scs, sck, arrFactory);
// 	/* scs: S = nonce + H(R,A,m)a */

// 	sc.to32bytes(sig.subarray(32), scs);
// 	/* sig: 32-byte R, 32-byte S */

// 	arrFactory.recycle(az, nonce, hram, sck, scs, scsk, pk);
// 	hasher.destroy();
// 	arrFactory.wipeRecycled();
	
// 	return sig;
// }

/// Analog of crypto_sign_open in crypto_sign/ed25519/ref/open.c
pub fn open(sm: &[u8], pk: &[u8]) -> Result<Vec<u8>, Error> {
	if pk.len() != 32 { return Err(make_conf_error(format!(
		"Public key array is {} bytes long instead of 32", pk.len()))); }

	let mut get1 = make_ge25519();
	if (sm.len() < 64)
	|| ((sm[63] & 224) != 0)
	|| ge25519_unpackneg_vartime(&mut get1, pk) {
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

// export function verify(sig: Uint8Array, m: Uint8Array, pk: Uint8Array,
// 		arrFactory?: arrays.Factory): boolean {
// 	if (!(pk instanceof Uint8Array)) { throw new TypeError(
// 			"Key array pk must be Uint8Array."); }
// 	if (pk.length !== 32) { throw new Error("Key array pk should have 32 "+
// 			"elements (bytes) in it, but it is "+pk.length+" elements long."); }
// 	if (!arrFactory) {
// 		arrFactory = arrays.makeFactory();
// 	}
// 	var rcopy = arrFactory.getUint8Array(32);
// 	var rcheck = arrFactory.getUint8Array(32);
// 	var get1 = ge.make_ge25519(arrFactory);
// 	var get2 = ge.make_ge25519(arrFactory);
// 	var schram = sc.make_sc25519(arrFactory);
// 	var scs = sc.make_sc25519(arrFactory);

// 	if ((sig.length < 64) || (sig[63] & 224) ||
// 			!ge.unpackneg_vartime(get1,pk,arrFactory)) { return false; }

// 	rcopy.set(sig.subarray(0, 32));

// 	sc.from32bytes(scs, sig.subarray(32, 64), arrFactory);

// 	var hasher = sha512.makeHasher(true, arrFactory);
	
// 	hasher.update(sig.subarray(0, 32));
// 	hasher.update(pk);
// 	hasher.update(m);
// 	var hram = hasher.digest();

// 	sc.from64bytes(schram, hram, arrFactory);

// 	ge.double_scalarmult_vartime(get2, get1, schram, ge.base, scs, arrFactory);
// 	ge.pack(rcheck, get2, arrFactory);

// 	var isOK = vectVerify.v32(rcopy,rcheck);
	
// 	arrFactory.recycle(rcopy, rcheck, hram, schram, scs);
// 	ge.recycle_ge25519(arrFactory, get1, get2);
// 	hasher.destroy();
// 	arrFactory.wipeRecycled();
	
// 	return isOK;
// }


#[cfg(test)]
mod tests {

	use signing::sign::generate_keypair;
	use signing::sign::sign;
	use signing::sign::open;
	use util::verify::compare;

	#[test]
	fn test1() {

		let mut keySeed: [u8; 32] = [
			0xae, 0x38, 0x86, 0x7b, 0xd2, 0x65, 0xcb, 0x86, 0x57, 0x0e,
			0x90, 0x0e, 0x24, 0xa1, 0x75, 0x03, 0x2f, 0x74, 0xab, 0x4d,
			0xa1, 0xbd, 0xf5, 0xc9, 0x12, 0x3e, 0x4c, 0x98, 0x12, 0xaa,
			0x0c, 0x95 ];

		let mut expectedPKey: [u8; 32] = [
			0xd0, 0xa5, 0xe8, 0xca, 0xeb, 0xff, 0xb8, 0x2a, 0x5e, 0x6d,
			0x24, 0x4a, 0x94, 0x94, 0x3c, 0xd5, 0x34, 0x03, 0x68, 0x0d,
			0x93, 0x02, 0x82, 0xb2, 0xc0, 0x7b, 0x1f, 0xfd, 0xbd, 0x21,
			0x39, 0xd0 ];

		// Testing signing keys generation
		let pair = generate_keypair(&keySeed);
		assert!(compare(&pair.pkey, &expectedPKey));

		// Testing of message signing");
		let m = "testing\n".as_bytes();

		let signed_m = sign(&m, &pair.skey).unwrap();
		let result = open(&signed_m, &pair.pkey).unwrap();
		assert!(compare(&result, &m));
		
		// // Testing of separated-signature functionality
		// var sig = sign.signature(m, pair.skey, arrFactory);
		// compare(test, sig, signed_m.subarray(0,64));
		// test.ok(sign.verify(sig, m, pair.pkey, arrFactory),
		// 		"FAILED signature verification.");
		// test.done();
	}

}