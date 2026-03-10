// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// ported to V from Go's crypto/internal/fips140/mlkem
module mlkem

type FieldElement = u16 // integer modulo q, always reduced
type RingElement = [256]u16
type NttElement = [256]u16

fn field_check_reduced(a u16) !FieldElement {
	if a >= q {
		return error('unreduced field element')
	}
	return FieldElement(a)
}

fn field_reduce_once(a u16) FieldElement {
	x := a - q
	// If x underflowed, then x >= 2^16 - q > 2^15, so the top bit is set.
	return FieldElement(x + (x >> 15) * q)
}

fn field_add(a FieldElement, b FieldElement) FieldElement {
	return field_reduce_once(u16(a + b))
}

fn field_sub(a FieldElement, b FieldElement) FieldElement {
	return field_reduce_once(u16(a - b + q))
}

const barrett_multiplier = u32(5039) // floor(2^24 / q)
const barrett_shift = u32(24)

// field_reduce reduces a value a < 2q^2 using Barrett reduction
fn field_reduce(a u32) FieldElement {
	quotient := u32((u64(a) * barrett_multiplier) >> barrett_shift)
	return field_reduce_once(u16(a - quotient * u32(q)))
}

fn field_mul(a FieldElement, b FieldElement) FieldElement {
	return field_reduce(u32(a) * u32(b))
}

// field_mul_sub returns a * (b - c), fused to save a reduction
fn field_mul_sub(a FieldElement, b FieldElement, c FieldElement) FieldElement {
	return field_reduce(u32(a) * u32(u16(b) - u16(c) + q))
}

// field_add_mul returns a * b + c * d, fused to save two reductions
fn field_add_mul(a FieldElement, b FieldElement, c FieldElement, d FieldElement) FieldElement {
	x := u32(a) * u32(b)
	return field_reduce(x + u32(c) * u32(d))
}

// compress maps a field element to [0, 2^d-1] (FIPS 203, definition 4.7)
// computes round((x * 2^d) / q) via Barrett reduction with round-half-up
fn compress(x FieldElement, d u8) u16 {
	dividend := u32(x) << d
	mut quotient := u32(u64(dividend) * barrett_multiplier >> barrett_shift)
	remainder := dividend - quotient * u32(q)
	// remainder is in [0, 2q); round by checking which third it falls in
	quotient += ((u32(q) / 2 - remainder) >> 31) & 1
	quotient += ((u32(q) + u32(q) / 2 - remainder) >> 31) & 1
	mask := (u32(1) << d) - 1
	return u16(quotient & mask)
}

// decompress maps y in [0, 2^d-1] to a field element (FIPS 203, definition 4.8)
// computes round((y * q) / 2^d) with round-half-up
fn decompress(y u16, d u8) FieldElement {
	dividend := u32(y) * u32(q)
	mut quotient := dividend >> d
	quotient += (dividend >> (d - 1)) & 1 // round using MSB of remainder
	return FieldElement(u16(quotient))
}

@[direct_array_access]
fn poly_add_ntt(a NttElement, b NttElement) NttElement {
	mut s := NttElement{}
	for i in 0 .. 256 {
		s[i] = field_add(a[i], b[i])
	}
	return s
}

@[direct_array_access]
fn poly_add_ring(a RingElement, b RingElement) RingElement {
	mut s := RingElement{}
	for i in 0 .. 256 {
		s[i] = field_add(a[i], b[i])
	}
	return s
}

@[direct_array_access]
fn poly_sub_ring(a RingElement, b RingElement) RingElement {
	mut s := RingElement{}
	for i in 0 .. 256 {
		s[i] = field_sub(a[i], b[i])
	}
	return s
}
