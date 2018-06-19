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

pub mod verify;

#[derive(Debug)]
pub enum ErrorCondition {
	CipherVerification,
	SignatureVerification,
	Configuration,
}

#[derive(Debug)]
pub struct Error {
	pub condition: ErrorCondition,
	pub message: String,
}

pub fn make_conf_error(message: String) -> Error {
	Error {
		condition: ErrorCondition::Configuration,
		message: message,
	}
}

pub fn make_cipher_verification_error() -> Error {
	Error {
		condition: ErrorCondition::CipherVerification,
		message: "Cipher bytes fail verification.".to_string(),
	}
}

pub fn make_signature_verification_error() -> Error {
	Error {
		condition: ErrorCondition::SignatureVerification,
		message: "Signature bytes fail verification.".to_string(),
	}
}

pub trait Resetable {
	fn reset(&mut self) -> ();
}

impl Resetable for [u8] {
	fn reset(&mut self) -> () {
		let len = self.len();
		if len == 0 { return; }
		for i in 0..(len-1) {
			self[i] = 0;
		}
	}
}

impl Resetable for [u32] {
	fn reset(&mut self) -> () {
		let len = self.len();
		if len == 0 { return; }
		for i in 0..(len-1) {
			self[i] = 0;
		}
	}
}

// debug helper
pub fn print_arr(name: &str, x: &[u8]) {
	print!("  {} has {} bytes: [ ", name, x.len());
	for j in 0..x.len() { print!("{}, ", x[j]); }
	println!("],");
}
