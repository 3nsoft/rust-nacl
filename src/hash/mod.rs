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

pub mod sha512;

pub trait Hasher {

	/**
	 * This absorbs bytes as they stream in, hashing even blocks.
	 */
	fn update(&mut self, m: &[u8]) -> ();
	
	/**
	 * This method tells a hasher that there are no more bytes to hash,
	 * and that a final hash should be produced.
	 * This also forgets all of hasher's state.
	 * And if this hasher is not single-use, update can be called
	 * again to produce hash for a new stream of bytes.
	 */
	fn digest(&mut self) -> Vec<u8>;
	
	/**
	 * This method securely wipes internal state.
	 */
	fn clear(&mut self) -> ();

}