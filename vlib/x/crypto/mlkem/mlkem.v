// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// ported to V from Go's crypto/internal/fips140/mlkem

// ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) per FIPS 203
// https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
module mlkem

import crypto.rand
import crypto.sha3
import crypto.internal.subtle

@[direct_array_access]
fn slice_to_32(s []u8) [32]u8 {
	mut a := [32]u8{}
	for i in 0 .. 32 {
		a[i] = s[i]
	}
	return a
}

pub struct DecapsulationKey {
	d [32]u8 // decapsulation key seed
	z [32]u8 // implicit rejection sampling seed
	p Params
	rho [32]u8 // sampleNTT seed for A, stored for the encapsulation key
	h   [32]u8 // H(ek), stored for ML-KEM.Decaps_internal
	// encryption key (parsed)
	t []NttElement // len = k
	a []NttElement // len = k*k
	// decryption key (parsed)
	s []NttElement // len = k
}

// bytes returns the 64-byte seed (d || z)
pub fn (dk &DecapsulationKey) bytes() []u8 {
	mut b := []u8{len: 0, cap: seed_size}
	for v in dk.d {
		b << v
	}
	for v in dk.z {
		b << v
	}
	return b
}

// expanded_bytes returns the NIST expanded encoding: ByteEncode_12(s) || ek || H(ek) || z
pub fn (dk &DecapsulationKey) expanded_bytes() []u8 {
	mut b := []u8{len: 0, cap: dk.p.k * encoding_size_12 + dk.p.k * encoding_size_12 + 32 + 32 + 32}
	// ByteEncode_12(s)
	for i in 0 .. dk.p.k {
		poly_byte_encode(mut b, dk.s[i])
	}
	// ek = ByteEncode_12(t) || rho
	for i in 0 .. dk.p.k {
		poly_byte_encode(mut b, dk.t[i])
	}
	for v in dk.rho {
		b << v
	}
	// H(ek) || z
	for v in dk.h {
		b << v
	}
	for v in dk.z {
		b << v
	}
	return b
}

// encapsulation_key returns the public encapsulation key from this decapsulation key
pub fn (dk &DecapsulationKey) encapsulation_key() EncapsulationKey {
	return EncapsulationKey{
		p:   dk.p
		rho: dk.rho
		h:   dk.h
		t:   dk.t.clone()
		a:   dk.a.clone()
	}
}

pub struct EncapsulationKey {
	p   Params
	rho [32]u8 // sampleNTT seed for A
	h   [32]u8 // H(ek)
	// encryption key (parsed)
	t []NttElement // len = k
	a []NttElement // len = k*k
}

// bytes returns the encapsulation key in its encoded form
pub fn (ek &EncapsulationKey) bytes() []u8 {
	mut b := []u8{len: 0, cap: ek.p.k * encoding_size_12 + 32}
	for i in 0 .. ek.p.k {
		poly_byte_encode(mut b, ek.t[i])
	}
	for v in ek.rho {
		b << v
	}
	return b
}

// generate creates a new decapsulation key with fresh randomness
pub fn DecapsulationKey.generate(kind Kind) !DecapsulationKey {
	d := slice_to_32(rand.read(32)!)
	z := slice_to_32(rand.read(32)!)
	return kem_key_gen(d, z, kind.params())
}

// from_seed derives a decapsulation key from a 64-byte seed (d || z)
pub fn DecapsulationKey.from_seed(seed []u8, kind Kind) !DecapsulationKey {
	if seed.len != seed_size {
		return error('mlkem: invalid seed length')
	}
	d := slice_to_32(seed[..32])
	z := slice_to_32(seed[32..])
	return kem_key_gen(d, z, kind.params())
}

// from_expanded_bytes parses a decapsulation key from NIST expanded encoding
pub fn DecapsulationKey.from_expanded_bytes(raw []u8, kind Kind) !DecapsulationKey {
	return parse_dk(raw, kind.params())
}

// from_bytes parses an encapsulation key
pub fn EncapsulationKey.from_bytes(raw []u8, kind Kind) !EncapsulationKey {
	return parse_ek(raw, kind.params())
}

// encapsulate produces a shared key and ciphertext
pub fn (ek &EncapsulationKey) encapsulate() !([]u8, []u8) {
	m := slice_to_32(rand.read(32)!)
	return kem_encaps(ek, m)
}

// encapsulate_internal is a derandomized version, for testing
pub fn (ek &EncapsulationKey) encapsulate_internal(m [32]u8) ([]u8, []u8) {
	return kem_encaps(ek, m)
}

// decapsulate recovers the shared key from a ciphertext
pub fn (dk &DecapsulationKey) decapsulate(ciphertext []u8) ![]u8 {
	expected_ct_size := dk.p.k * (n * dk.p.d_u / 8) + n * dk.p.d_v / 8
	if ciphertext.len != expected_ct_size {
		return error('mlkem: invalid ciphertext length')
	}
	return kem_decaps(dk, ciphertext)
}

// algo. 16: ML-KEM.KeyGen_internal (s. 7.2) + algo. 13: K-PKE.KeyGen (s. 5.1)
@[direct_array_access]
fn kem_key_gen(d [32]u8, z [32]u8, p Params) DecapsulationKey {
	mut g := sha3.new512() or { panic(err) }
	g.write(d[..]) or { panic(err) }
	g.write([u8(p.k)]) or { panic(err) }
	gg := g.checksum()

	rho := gg[..32]
	sigma := gg[32..]

	mut aa := []NttElement{len: p.k * p.k}
	for i in 0 .. u8(p.k) {
		for j in 0 .. u8(p.k) {
			aa[i * p.k + j] = sample_ntt(rho, j, i)
		}
	}

	mut nn := u8(0)
	mut s := []NttElement{len: p.k}
	for i in 0 .. p.k {
		s[i] = ntt(sample_poly_cbd(sigma, nn, p.eta))
		nn++
	}
	mut e := []NttElement{len: p.k}
	for i in 0 .. p.k {
		e[i] = ntt(sample_poly_cbd(sigma, nn, p.eta))
		nn++
	}

	mut t := []NttElement{len: p.k}
	for i in 0 .. p.k { // t = A * s + e
		t[i] = e[i]
		for j in 0 .. p.k {
			t[i] = poly_add_ntt(t[i], ntt_mul(aa[i * p.k + j], s[j]))
		}
	}

	rho32 := slice_to_32(rho)

	// h(ek) — encode ek directly to avoid cloning t and a
	mut ek_bytes := []u8{len: 0, cap: p.k * encoding_size_12 + 32}
	for i in 0 .. p.k {
		poly_byte_encode(mut ek_bytes, t[i])
	}
	for v in rho32 {
		ek_bytes << v
	}
	mut hh := sha3.new256() or { panic(err) }
	hh.write(ek_bytes) or { panic(err) }

	return DecapsulationKey{
		d:   d
		z:   z
		p:   p
		rho: rho32
		h:   slice_to_32(hh.checksum())
		t:   t
		a:   aa
		s:   s
	}
}

// parse_ek parses an encapsulation key (initial stages of algo. 14, s. 5.2)
@[direct_array_access]
fn parse_ek(ek_pke []u8, p Params) !EncapsulationKey {
	expected_size := p.k * encoding_size_12 + 32
	if ek_pke.len != expected_size {
		return error('mlkem: invalid encapsulation key length')
	}

	mut hh := sha3.new256() or { return err }
	hh.write(ek_pke) or { return err }
	h := slice_to_32(hh.checksum())

	mut t := []NttElement{len: p.k}
	mut off := 0
	for i in 0 .. p.k {
		t[i] = poly_byte_decode(ek_pke[off..off + encoding_size_12])!
		off += encoding_size_12
	}
	mut rho := [32]u8{}
	for i in 0 .. 32 {
		rho[i] = ek_pke[off + i]
	}

	mut aa := []NttElement{len: p.k * p.k}
	for i in 0 .. u8(p.k) {
		for j in 0 .. u8(p.k) {
			aa[i * p.k + j] = sample_ntt(rho[..], j, i)
		}
	}

	return EncapsulationKey{
		p:   p
		rho: rho
		h:   h
		t:   t
		a:   aa
	}
}

// algo. 17: ML-KEM.Encaps_internal (s. 7.2)
fn kem_encaps(ek &EncapsulationKey, m [32]u8) ([]u8, []u8) {
	mut g := sha3.new512() or { panic(err) }
	g.write(m[..]) or { panic(err) }
	g.write(ek.h[..]) or { panic(err) }
	gg := g.checksum()
	k_out := gg[..shared_key_size].clone()
	r := gg[shared_key_size..]
	c := pke_encrypt(ek.p, ek.t, ek.a, m, r)
	return k_out, c
}

// algo. 14: K-PKE.Encrypt (s. 5.2), t and A^T are precomputed in parse_ek
@[direct_array_access]
fn pke_encrypt(p Params, t []NttElement, a []NttElement, m [32]u8, rnd []u8) []u8 {
	mut nn := u8(0)
	mut r := []NttElement{len: p.k}
	mut e1 := []RingElement{len: p.k}
	for i in 0 .. p.k {
		r[i] = ntt(sample_poly_cbd(rnd, nn, p.eta))
		nn++
	}
	for i in 0 .. p.k {
		e1[i] = sample_poly_cbd(rnd, nn, 2) // eta_2 is always 2
		nn++
	}
	e2 := sample_poly_cbd(rnd, nn, 2)

	// u = NTT^-1(A^T * r) + e1
	mut u := []RingElement{len: p.k}
	for i in 0 .. p.k {
		mut u_hat := NttElement{}
		for j in 0 .. p.k {
			// i and j are inverted: we need A^T.
			u_hat = poly_add_ntt(u_hat, ntt_mul(a[j * p.k + i], r[j]))
		}
		u[i] = poly_add_ring(e1[i], inverse_ntt(u_hat))
	}

	mu := ring_decode_and_decompress_1(m)

	// v = NTT^-1(t^T * r) + e2 + mu
	mut v_ntt := NttElement{}
	for i in 0 .. p.k {
		v_ntt = poly_add_ntt(v_ntt, ntt_mul(t[i], r[i]))
	}
	v := poly_add_ring(poly_add_ring(inverse_ntt(v_ntt), e2), mu)

	// encode ciphertext
	mut c := []u8{len: 0, cap: p.k * (n * p.d_u / 8) + n * p.d_v / 8}
	for i in 0 .. p.k {
		if p.d_u == 10 {
			ring_compress_and_encode_10(mut c, u[i])
		} else {
			ring_compress_and_encode_11(mut c, u[i])
		}
	}
	if p.d_v == 4 {
		ring_compress_and_encode_4(mut c, v)
	} else {
		ring_compress_and_encode_5(mut c, v)
	}
	return c
}

// algo. 18: ML-KEM.Decaps_internal (s. 7.3)
fn kem_decaps(dk &DecapsulationKey, c []u8) []u8 {
	m := pke_decrypt(dk, c)
	mut g := sha3.new512() or { panic(err) }
	g.write(m) or { panic(err) }
	g.write(dk.h[..]) or { panic(err) }
	gg := g.checksum()
	k_prime := gg[..shared_key_size]
	r := gg[shared_key_size..]

	mut j := sha3.new_shake256()
	j.write(dk.z[..])
	j.write(c)
	mut k_out := j.read(shared_key_size)

	c1 := pke_encrypt(dk.p, dk.t, dk.a, slice_to_32(m), r)

	subtle.constant_time_copy(subtle.constant_time_compare(c, c1), mut k_out, k_prime)
	return k_out
}

// algo. 15: K-PKE.Decrypt (s. 5.3), s is retained from kem_key_gen
@[direct_array_access]
fn pke_decrypt(dk &DecapsulationKey, c []u8) []u8 {
	p := dk.p
	encoding_size_du := n * p.d_u / 8

	mut u := []RingElement{len: p.k}
	for i in 0 .. p.k {
		chunk := c[encoding_size_du * i..encoding_size_du * (i + 1)]
		if p.d_u == 10 {
			mut arr := [encoding_size_10]u8{}
			for j in 0 .. encoding_size_10 {
				arr[j] = chunk[j]
			}
			u[i] = ring_decode_and_decompress_10(arr)
		} else {
			u[i] = ring_decode_and_decompress_11(chunk)
		}
	}

	v_bytes := c[encoding_size_du * p.k..]
	mut v := RingElement{}
	if p.d_v == 4 {
		mut arr := [encoding_size_4]u8{}
		for j in 0 .. encoding_size_4 {
			arr[j] = v_bytes[j]
		}
		v = ring_decode_and_decompress_4(arr)
	} else {
		v = ring_decode_and_decompress_5(v_bytes)
	}

	// s^T * NTT(u)
	mut mask := NttElement{}
	for i in 0 .. p.k {
		mask = poly_add_ntt(mask, ntt_mul(dk.s[i], ntt(u[i])))
	}
	w := poly_sub_ring(v, inverse_ntt(mask))

	mut result := []u8{len: 0, cap: encoding_size_1}
	ring_compress_and_encode_1(mut result, w)
	return result
}

// parse_dk parses a decapsulation key from NIST expanded encoding
@[direct_array_access]
fn parse_dk(dk_bytes []u8, p Params) !DecapsulationKey {
	expected_size := p.k * encoding_size_12 + p.k * encoding_size_12 + 32 + 32 + 32
	if dk_bytes.len != expected_size {
		return error('mlkem: invalid decapsulation key length')
	}

	mut off := 0

	// decode s
	mut s := []NttElement{len: p.k}
	for i in 0 .. p.k {
		s[i] = poly_byte_decode(dk_bytes[off..off + encoding_size_12])!
		off += encoding_size_12
	}

	// decode t and rho (the encapsulation key portion)
	ek_start := off
	mut t := []NttElement{len: p.k}
	for i in 0 .. p.k {
		t[i] = poly_byte_decode(dk_bytes[off..off + encoding_size_12])!
		off += encoding_size_12
	}
	rho := slice_to_32(dk_bytes[off..off + 32])
	off += 32
	ek_end := off

	// verify H(ek) matches
	mut hh := sha3.new256() or { return err }
	hh.write(dk_bytes[ek_start..ek_end]) or { return err }
	h := slice_to_32(hh.checksum())

	stored_h := slice_to_32(dk_bytes[off..off + 32])
	off += 32
	if h != stored_h {
		return error('mlkem: decapsulation key H(ek) mismatch')
	}

	z := slice_to_32(dk_bytes[off..off + 32])

	// reconstruct A from rho
	mut aa := []NttElement{len: p.k * p.k}
	for i in 0 .. u8(p.k) {
		for j in 0 .. u8(p.k) {
			aa[i * p.k + j] = sample_ntt(rho[..], j, i)
		}
	}

	return DecapsulationKey{
		z:   z
		p:   p
		rho: rho
		h:   h
		t:   t
		a:   aa
		s:   s
	}
}
