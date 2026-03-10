// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// ported to V from Go's crypto/internal/fips140/mlkem
module mlkem

import crypto.sha3

// algo. 8: SamplePolyCBD (s. 4.1, definition 4.3)
@[direct_array_access]
fn sample_poly_cbd(s []u8, b u8, eta int) RingElement {
	mut prf := sha3.new_shake256()
	prf.write(s)
	prf.write([b])
	bb := prf.read(64 * eta)

	mut f := RingElement{}
	if eta == 2 {
		// eta=2: 4 bits per coefficient, 2 bytes per pair
		for i := 0; i < n; i += 2 {
			byte_val := bb[i / 2]
			b_7, b_6, b_5, b_4 := byte_val >> 7, (byte_val >> 6) & 1, (byte_val >> 5) & 1, (byte_val >> 4) & 1
			b_3, b_2, b_1, b_0 := (byte_val >> 3) & 1, (byte_val >> 2) & 1, (byte_val >> 1) & 1, byte_val & 1
			f[i] = field_sub(FieldElement(b_0 + b_1), FieldElement(b_2 + b_3))
			f[i + 1] = field_sub(FieldElement(b_4 + b_5), FieldElement(b_6 + b_7))
		}
	} else {
		// eta=3: 6 bits per coefficient (ML-KEM-512 only)
		mut bit_idx := 0
		for i in 0 .. n {
			mut a_sum := u16(0)
			mut b_sum := u16(0)
			for j in 0 .. eta {
				a_sum += u16((bb[(bit_idx + j) / 8] >> ((bit_idx + j) % 8)) & 1)
			}
			bit_idx += eta
			for j in 0 .. eta {
				b_sum += u16((bb[(bit_idx + j) / 8] >> ((bit_idx + j) % 8)) & 1)
			}
			bit_idx += eta
			f[i] = field_sub(FieldElement(a_sum), FieldElement(b_sum))
		}
	}
	return f
}

// algo. 7: SampleNTT (s. 4.1)
@[direct_array_access]
fn sample_ntt(rho []u8, ii u8, jj u8) NttElement {
	mut xof := sha3.new_shake128()
	xof.write(rho)
	xof.write([ii, jj])

	mut a := NttElement{}
	mut j := 0
	mut buf := [24]u8{}
	mut off := 24 // starts in a "buffer fully consumed" state
	for {
		if off >= 24 {
			buf = sha3_read_24(mut xof)
			off = 0
		}
		d1 := u16(buf[off]) | u16(buf[off + 1]) << 8
		d1_masked := d1 & 0x0fff
		d2 := (u16(buf[off + 1]) | u16(buf[off + 2]) << 8) >> 4
		off += 3
		if d1_masked < q {
			a[j] = FieldElement(d1_masked)
			j++
		}
		if j >= 256 {
			break
		}
		if d2 < q {
			a[j] = FieldElement(d2)
			j++
		}
		if j >= 256 {
			break
		}
	}
	return a
}

fn sha3_read_24(mut xof sha3.Shake) [24]u8 {
	b := xof.read(24)
	mut a := [24]u8{}
	for i in 0 .. 24 {
		a[i] = b[i]
	}
	return a
}
