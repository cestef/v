// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// ported to V from Go's crypto/internal/fips140/mlkem
module mlkem

// algo. 5: ByteEncode_12 (s. 4.2.1)
@[direct_array_access]
fn poly_byte_encode(mut b []u8, f NttElement) {
	for i := 0; i < n; i += 2 {
		x := u32(f[i]) | u32(f[i + 1]) << 12
		b << u8(x)
		b << u8(x >> 8)
		b << u8(x >> 16)
	}
}

// algo. 6: ByteDecode_12 (s. 4.2.1), also performs the modulus check
@[direct_array_access]
fn poly_byte_decode(b []u8) !NttElement {
	if b.len != encoding_size_12 {
		return error('mlkem: invalid encoding length')
	}
	mut f := NttElement{}
	mut j := 0
	for i := 0; i < n; i += 2 {
		d := u32(b[j]) | u32(b[j + 1]) << 8 | u32(b[j + 2]) << 16
		f[i] = field_check_reduced(u16(d & 0xfff))!
		f[i + 1] = field_check_reduced(u16(d >> 12))!
		j += 3
	}
	return f
}

// Compress_1 followed by ByteEncode_1
@[direct_array_access]
fn ring_compress_and_encode_1(mut s []u8, f RingElement) {
	mut buf := [encoding_size_1]u8{}
	for i in 0 .. n {
		buf[i / 8] |= u8(compress(f[i], 1) << (i % 8))
	}
	for v in buf {
		s << v
	}
}

// ByteDecode_1 followed by Decompress_1
@[direct_array_access]
fn ring_decode_and_decompress_1(b [encoding_size_1]u8) RingElement {
	mut f := RingElement{}
	for i in 0 .. n {
		b_i := (b[i / 8] >> (i % 8)) & 1
		// 0 decompresses to 0, and 1 to ceil(q/2)
		f[i] = FieldElement(b_i) * ((q + 1) / 2)
	}
	return f
}

// Compress_4 followed by ByteEncode_4
@[direct_array_access]
fn ring_compress_and_encode_4(mut s []u8, f RingElement) {
	mut buf := [encoding_size_4]u8{}
	for i := 0; i < n; i += 2 {
		buf[i / 2] = u8(compress(f[i], 4) | compress(f[i + 1], 4) << 4)
	}
	for v in buf {
		s << v
	}
}

// ByteDecode_4 followed by Decompress_4
@[direct_array_access]
fn ring_decode_and_decompress_4(b [encoding_size_4]u8) RingElement {
	mut f := RingElement{}
	for i := 0; i < n; i += 2 {
		f[i] = decompress(u16(b[i / 2] & 0x0f), 4)
		f[i + 1] = decompress(u16(b[i / 2] >> 4), 4)
	}
	return f
}

// Compress_10 followed by ByteEncode_10
@[direct_array_access]
fn ring_compress_and_encode_10(mut s []u8, f RingElement) {
	mut buf := [encoding_size_10]u8{}
	mut j := 0
	for i := 0; i < n; i += 4 {
		mut x := u64(0)
		x |= u64(compress(f[i], 10))
		x |= u64(compress(f[i + 1], 10)) << 10
		x |= u64(compress(f[i + 2], 10)) << 20
		x |= u64(compress(f[i + 3], 10)) << 30
		buf[j] = u8(x)
		buf[j + 1] = u8(x >> 8)
		buf[j + 2] = u8(x >> 16)
		buf[j + 3] = u8(x >> 24)
		buf[j + 4] = u8(x >> 32)
		j += 5
	}
	for v in buf {
		s << v
	}
}

// ByteDecode_10 followed by Decompress_10
@[direct_array_access]
fn ring_decode_and_decompress_10(bb [encoding_size_10]u8) RingElement {
	mut f := RingElement{}
	mut j := 0
	for i := 0; i < n; i += 4 {
		x := u64(bb[j]) | u64(bb[j + 1]) << 8 | u64(bb[j + 2]) << 16 | u64(bb[j + 3]) << 24 | u64(bb[j + 4]) << 32
		j += 5
		f[i] = decompress(u16((x >> 0) & 0x3ff), 10)
		f[i + 1] = decompress(u16((x >> 10) & 0x3ff), 10)
		f[i + 2] = decompress(u16((x >> 20) & 0x3ff), 10)
		f[i + 3] = decompress(u16((x >> 30) & 0x3ff), 10)
	}
	return f
}

// generic Compress_d followed by ByteEncode_d, for d=5,11
@[direct_array_access]
fn ring_compress_and_encode_d(mut s []u8, f RingElement, d u8) {
	mut b := u8(0)
	mut b_idx := u8(0)
	for i in 0 .. n {
		c := compress(f[i], d)
		mut c_idx := u8(0)
		for c_idx < d {
			b |= u8(c >> c_idx) << b_idx
			bits := min_u8(8 - b_idx, d - c_idx)
			b_idx += bits
			c_idx += bits
			if b_idx == 8 {
				s << b
				b = 0
				b_idx = 0
			}
		}
	}
}

// generic ByteDecode_d followed by Decompress_d, for d=5,11
@[direct_array_access]
fn ring_decode_and_decompress_d(b []u8, d u8) RingElement {
	mut f := RingElement{}
	mut bi := 0
	mut b_idx := u8(0)
	for i in 0 .. n {
		mut c := u16(0)
		mut c_idx := u8(0)
		for c_idx < d {
			c |= u16(b[bi] >> b_idx) << c_idx
			c &= (u16(1) << d) - 1
			bits := min_u8(8 - b_idx, d - c_idx)
			b_idx += bits
			c_idx += bits
			if b_idx == 8 {
				bi++
				b_idx = 0
			}
		}
		f[i] = decompress(c, d)
	}
	return f
}

// wrappers for ML-KEM-1024 (d_u=11, d_v=5)
fn ring_compress_and_encode_5(mut s []u8, f RingElement) {
	ring_compress_and_encode_d(mut s, f, 5)
}

fn ring_decode_and_decompress_5(b []u8) RingElement {
	return ring_decode_and_decompress_d(b, 5)
}

fn ring_compress_and_encode_11(mut s []u8, f RingElement) {
	ring_compress_and_encode_d(mut s, f, 11)
}

fn ring_decode_and_decompress_11(b []u8) RingElement {
	return ring_decode_and_decompress_d(b, 11)
}

fn min_u8(a u8, b u8) u8 {
	if a < b {
		return a
	}
	return b
}
