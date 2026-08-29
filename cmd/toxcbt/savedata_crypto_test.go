package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tox "github.com/TokTok/go-toxcore-c"
)

const testPassphrase = "correct horse battery staple"

// encryptFixture returns an encrypted copy of a valid plaintext profile.
func encryptFixture(t *testing.T, plain []byte, passphrase string) []byte {
	t.Helper()
	c, err := newProfileCipher([]byte(passphrase), nil)
	if err != nil {
		t.Fatalf("newProfileCipher: %v", err)
	}
	defer c.close()
	ciphertext, err := c.encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return ciphertext
}

func TestProfileCipherRoundTrip(t *testing.T) {
	plain := toxProfile('s', 'e', 'c', 'r', 'e', 't')
	ciphertext := encryptFixture(t, plain, testPassphrase)

	if !isEncryptedProfile(ciphertext) {
		t.Fatalf("ciphertext does not carry the toxEsave marker: % x", ciphertext[:8])
	}
	if bytes.Contains(ciphertext, plain[savedataHeadSize:]) {
		t.Error("the plaintext payload is still visible in the ciphertext")
	}

	// Reading it back is the interesting half: the key has to be re-derived
	// from the salt stored in the file.
	reader, err := newProfileCipher([]byte(testPassphrase), ciphertext)
	if err != nil {
		t.Fatalf("deriving from the stored salt: %v", err)
	}
	defer reader.close()

	got, err := reader.decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round trip returned % x, want % x", got, plain)
	}
}

func TestProfileCipherRejectsWrongPassphrase(t *testing.T) {
	ciphertext := encryptFixture(t, toxProfile('x'), testPassphrase)

	wrong, err := newProfileCipher([]byte("hunter2"), ciphertext)
	if err != nil {
		t.Fatalf("newProfileCipher: %v", err)
	}
	defer wrong.close()

	if _, err := wrong.decrypt(ciphertext); err == nil {
		t.Error("decryption succeeded with the wrong passphrase")
	}
}

func TestProfileCipherRejectsShortAndEmptyInput(t *testing.T) {
	c, err := newProfileCipher([]byte(testPassphrase), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()

	if _, err := c.decrypt([]byte("toxEsave")); err == nil {
		t.Error("a truncated file must not be handed to the C decryptor")
	}
	if _, err := c.encrypt(nil); err == nil {
		t.Error("encrypting nothing should be an error, not a cgo dereference of data[0]")
	}
	if _, err := newProfileCipher(nil, nil); err == nil {
		t.Error("an empty passphrase must be refused before it reaches cgo")
	}
}

func TestLoadProfileEncryptedWithoutPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	if err := os.WriteFile(path, encryptFixture(t, toxProfile('x'), testPassphrase), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, _, err := loadProfile(path, nil)
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("err = %v, want a complaint that the profile is encrypted", err)
	}
}

func TestLoadProfileDecrypts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	plain := toxProfile('i', 'd')
	if err := os.WriteFile(path, encryptFixture(t, plain, testPassphrase), 0o600); err != nil {
		t.Fatal(err)
	}

	data, cipher, found, err := loadProfile(path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	defer cipher.close()

	if !found || !bytes.Equal(data, plain) {
		t.Errorf("loaded % x, want % x", data, plain)
	}
	if cipher == nil {
		t.Error("an encrypted profile must come back with the cipher for later saves")
	}
}

func TestLoadProfileWrongPassphraseIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	if err := os.WriteFile(path, encryptFixture(t, toxProfile('x'), testPassphrase), 0o600); err != nil {
		t.Fatal(err)
	}

	// Refusing here is what stops the bot from starting fresh and then
	// overwriting a recoverable profile with a brand-new identity.
	if _, _, _, err := loadProfile(path, []byte("wrong")); err == nil {
		t.Error("the wrong passphrase loaded a profile")
	}
}

// A passphrase set against a plaintext profile is a migration request.
func TestLoadProfileMigratesPlaintextOnNextSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bot.tox")
	plain := toxProfile('o', 'l', 'd')
	if err := os.WriteFile(path, plain, 0o600); err != nil {
		t.Fatal(err)
	}

	data, cipher, found, err := loadProfile(path, []byte(testPassphrase))
	if err != nil || !found {
		t.Fatalf("loadProfile: %v (found=%v)", err, found)
	}
	if !bytes.Equal(data, plain) {
		t.Fatal("a plaintext profile should load unchanged")
	}
	if cipher == nil {
		t.Fatal("a configured passphrase must produce a cipher for the next save")
	}
	defer cipher.close()

	ft := newFakeTox()
	ft.savedata = plain
	b := &Bot{t: ft, saveFile: path, cipher: cipher}
	b.save()

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !isEncryptedProfile(written) {
		t.Fatalf("the profile on disk is still plaintext: % x", written[:8])
	}

	// And the encrypted file must load again with the same passphrase.
	reloaded, c2, _, err := loadProfile(path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("reloading the migrated profile: %v", err)
	}
	defer c2.close()
	if !bytes.Equal(reloaded, plain) {
		t.Errorf("reloaded % x, want % x", reloaded, plain)
	}
}

func TestLoadProfileFreshWithPassphraseStillDerives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")

	data, cipher, found, err := loadProfile(path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	defer cipher.close()

	if found || data != nil {
		t.Error("there is no profile yet")
	}
	if cipher == nil {
		t.Error("the key should be derived at startup, not on the first save")
	}
}

func TestLoadProfileRejectsDamagedCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	ciphertext := encryptFixture(t, toxProfile('x'), testPassphrase)
	ciphertext[len(ciphertext)-1] ^= 0xff
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := loadProfile(path, []byte(testPassphrase)); err == nil {
		t.Error("a corrupted ciphertext was accepted")
	}
}

// A profile that decrypts to something that is not a tox save is as dangerous
// as a corrupt plaintext one, and must be refused the same way.
func TestLoadProfileRejectsDecryptedGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	if err := os.WriteFile(path, encryptFixture(t, []byte("not a profile at all"), testPassphrase), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, _, err := loadProfile(path, []byte(testPassphrase))
	if err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("err = %v, want the decrypted profile to be rejected", err)
	}
}

func TestSaveKeepsPlaintextWithoutAPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	ft := newFakeTox()
	ft.savedata = toxProfile('p')
	b := &Bot{t: ft, saveFile: path, now: func() time.Time { return time.Unix(1700000000, 0) }}

	b.save()

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if isEncryptedProfile(written) {
		t.Error("the profile was encrypted without a passphrase")
	}
	if b.lastSave.IsZero() {
		t.Error("a successful save should record its time for the health endpoint")
	}
}

// tox.IsDataEncrypted dereferences data[0]; the bot's own check must not.
func TestIsEncryptedProfileHandlesEmptyInput(t *testing.T) {
	if isEncryptedProfile(nil) || isEncryptedProfile([]byte{}) {
		t.Error("empty data is not an encrypted profile")
	}
	if !isEncryptedProfile([]byte("toxEsaveXX")) {
		t.Error("the marker was not recognised")
	}
	if tox.PASS_ENCRYPTION_EXTRA_LENGTH <= 0 {
		t.Error("the binding reports no encryption overhead; the short-input guard would be wrong")
	}
}
