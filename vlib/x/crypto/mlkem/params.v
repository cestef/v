// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// ported to V from Go's crypto/internal/fips140/mlkem

// ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) per FIPS 203
// https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
module mlkem

// s. 8, table 3
const n = 256
const q = u16(3329)

// byte sizes for ByteEncode_d (algo. 5)
const encoding_size_12 = n * 12 / 8 // 384
const encoding_size_11 = n * 11 / 8 // 352
const encoding_size_10 = n * 10 / 8 // 320
const encoding_size_5 = n * 5 / 8 // 160
const encoding_size_4 = n * 4 / 8 // 128
const encoding_size_1 = n * 1 / 8 // 32

const message_size = encoding_size_1

pub const shared_key_size = 32
pub const seed_size = 32 + 32

pub enum Kind {
	ml_kem_512
	ml_kem_768
	ml_kem_1024
}

struct Params {
	k   int
	eta int // η₁ (η₂ is always 2)
	d_u int
	d_v int
}

const params_512 = Params{
	k:   2
	eta: 3
	d_u: 10
	d_v: 4
}

const params_768 = Params{
	k:   3
	eta: 2
	d_u: 10
	d_v: 4
}

const params_1024 = Params{
	k:   4
	eta: 2
	d_u: 11
	d_v: 5
}

fn (k Kind) params() Params {
	return match k {
		.ml_kem_512 { params_512 }
		.ml_kem_768 { params_768 }
		.ml_kem_1024 { params_1024 }
	}
}

pub fn (k Kind) encapsulation_key_size() int {
	p := k.params()
	return p.k * encoding_size_12 + 32
}

pub fn (k Kind) ciphertext_size() int {
	p := k.params()
	return p.k * (n * p.d_u / 8) + n * p.d_v / 8
}

// precomputed public sizes for each parameter set
pub const encapsulation_key_size_512 = 2 * encoding_size_12 + 32 // 800
pub const encapsulation_key_size_768 = 3 * encoding_size_12 + 32 // 1184
pub const encapsulation_key_size_1024 = 4 * encoding_size_12 + 32 // 1568

pub const ciphertext_size_512 = 2 * encoding_size_10 + encoding_size_4 // 768
pub const ciphertext_size_768 = 3 * encoding_size_10 + encoding_size_4 // 1088
pub const ciphertext_size_1024 = 4 * encoding_size_11 + encoding_size_5 // 1568

const decapsulation_key_size_512 = 2 * encoding_size_12 + encapsulation_key_size_512 + 32 + 32
const decapsulation_key_size_768 = 3 * encoding_size_12 + encapsulation_key_size_768 + 32 + 32
const decapsulation_key_size_1024 = 4 * encoding_size_12 + encapsulation_key_size_1024 + 32 + 32
