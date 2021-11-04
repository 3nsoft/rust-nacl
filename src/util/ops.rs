// Copyright(c) 2021 3NSoft Inc.
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


#[macro_export]
macro_rules! add2 {
	($a: expr, $b: expr) => {
		$a.wrapping_add($b)
	}
}

#[macro_export]
macro_rules! add4 {
	($a: expr, $b: expr, $c: expr, $d: expr) => {
		$a.wrapping_add($b.wrapping_add($c.wrapping_add($d)))
	}
}

#[macro_export]
macro_rules! add5 {
	($a: expr, $b: expr, $c: expr, $d: expr, $e: expr) => {
		$a.wrapping_add($b.wrapping_add($c.wrapping_add($d).wrapping_add($e)))
	}
}

#[macro_export]
macro_rules! subw {
	($a: expr, $b: expr) => {
		$a.wrapping_sub($b)
	}
}

#[macro_export]
macro_rules! incr {
	($a: expr, $b: expr) => {
		$a = $a.wrapping_add($b)
	}
}
