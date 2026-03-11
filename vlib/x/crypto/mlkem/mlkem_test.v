module mlkem

fn test_roundtrip_768() {
	dk := DecapsulationKey.generate(.ml_kem_768)!
	ek := dk.encapsulation_key()

	shared_key, ciphertext := ek.encapsulate()!
	recovered_key := dk.decapsulate(ciphertext)!

	assert shared_key == recovered_key, 'ML-KEM-768 roundtrip failed'
}

fn test_roundtrip_512() {
	dk := DecapsulationKey.generate(.ml_kem_512)!
	ek := dk.encapsulation_key()

	shared_key, ciphertext := ek.encapsulate()!
	recovered_key := dk.decapsulate(ciphertext)!

	assert shared_key == recovered_key, 'ML-KEM-512 roundtrip failed'
}

fn test_roundtrip_1024() {
	dk := DecapsulationKey.generate(.ml_kem_1024)!
	ek := dk.encapsulation_key()

	shared_key, ciphertext := ek.encapsulate()!
	recovered_key := dk.decapsulate(ciphertext)!

	assert shared_key == recovered_key, 'ML-KEM-1024 roundtrip failed'
}

fn test_encapsulation_key_roundtrip_768() {
	dk := DecapsulationKey.generate(.ml_kem_768)!
	ek := dk.encapsulation_key()

	// Serialize and re-parse the encapsulation key
	ek_bytes := ek.bytes()
	ek2 := EncapsulationKey.from_bytes(ek_bytes, .ml_kem_768)!

	// Encapsulate with the re-parsed key
	shared_key, ciphertext := ek2.encapsulate()!
	recovered_key := dk.decapsulate(ciphertext)!

	assert shared_key == recovered_key, 'encapsulation key roundtrip failed'
}

fn test_seed_roundtrip_768() {
	dk := DecapsulationKey.generate(.ml_kem_768)!
	seed := dk.bytes()

	dk2 := DecapsulationKey.from_seed(seed, .ml_kem_768)!

	// Keys derived from same seed should produce same encapsulation key
	assert dk.encapsulation_key().bytes() == dk2.encapsulation_key().bytes(), 'seed roundtrip failed'
}

fn test_invalid_ciphertext_768() {
	dk := DecapsulationKey.generate(.ml_kem_768)!
	ek := dk.encapsulation_key()

	_, ciphertext := ek.encapsulate()!

	// Corrupt ciphertext
	mut bad_ct := ciphertext.clone()
	bad_ct[0] ^= 0xff

	// Decapsulation should succeed but return a different (implicit rejection) key
	bad_key := dk.decapsulate(bad_ct)!
	good_key := dk.decapsulate(ciphertext)!
	assert bad_key != good_key, 'corrupted ciphertext should produce different key'
}

fn test_wrong_ciphertext_length() {
	dk := DecapsulationKey.generate(.ml_kem_768)!
	dk.decapsulate([]u8{len: 10}) or { return }
	assert false, 'should have returned error for wrong length'
}

fn test_shared_key_size() {
	dk := DecapsulationKey.generate(.ml_kem_768)!
	ek := dk.encapsulation_key()
	shared_key, _ := ek.encapsulate()!
	assert shared_key.len == shared_key_size
}
