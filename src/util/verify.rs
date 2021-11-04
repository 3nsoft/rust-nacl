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

//! This module provides constant time comparison utility, analogous to
//! crypto_verify/.../ref/verify.c

pub fn compare_v16(x: &[u8], y: &[u8]) -> bool {
	let mut differentbits = 0;
	for i in 0..16 {
		differentbits |= x[i] ^ y[i];
	}
	differentbits == 0
}

pub fn compare_v32(x: &[u8], y: &[u8]) -> bool {
	let mut differentbits = 0;
	for i in 0..32 {
		differentbits |= x[i] ^ y[i];
	}
	differentbits == 0
}

pub fn compare(x: &[u8], y: &[u8]) -> bool {
	let len = x.len();
	if (len ^ y.len()) != 0 { return false; }
	let mut differentbits = 0;
	for i in 0..len {
		differentbits |= x[i] ^ y[i];
	}
	differentbits == 0
}


#[cfg(test)]
mod tests {
	
	use super::{ compare_v16, compare_v32, compare };

	#[test]
	fn constant_time_comparisons() {

		let x: [u8; 55] = [4; 55];
		let mut y: [u8; 55] = [4; 55];

		assert!(compare(&x, &y));
		assert!(compare_v16(&x[0..16], &y[0..16]));
		assert!(compare_v32(&x[0..32], &y[0..32]));

		y[3] += 1;

		assert!(!compare(&x, &y));
		assert!(!compare_v16(&x[0..16], &y[0..16]));
		assert!(!compare_v32(&x[0..32], &y[0..32]));

	}

}