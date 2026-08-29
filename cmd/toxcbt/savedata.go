package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	tox "github.com/TokTok/go-toxcore-c"
)

// A tox profile starts with a zero uint32 followed by a little-endian magic.
// An encrypted profile — what the desktop clients write by default — starts
// with an ASCII marker instead and cannot be read without a passphrase.
const (
	savedataMagic    = 0x15ED1B1F
	savedataHeadSize = 8
)

var encryptedSavedataMagic = []byte("toxEsave")

// isEncryptedProfile reports whether data carries the encrypted-profile
// marker. The binding's tox.IsDataEncrypted would do the same, but it
// dereferences data[0] and so panics on an empty file.
func isEncryptedProfile(data []byte) bool {
	return bytes.HasPrefix(data, encryptedSavedataMagic)
}

// validateSavedata rejects anything that is not a plaintext tox profile.
//
// This check is load-bearing rather than cosmetic: toxcore does not report a
// damaged profile. tox_new quietly ignores it, derives a brand-new random key
// (verified: the same corrupt bytes yield a different public key on each run),
// and the next save overwrites the file — so a recoverable profile is destroyed
// and every existing friend silently sees the bot as a stranger.
func validateSavedata(data []byte) error {
	if isEncryptedProfile(data) {
		return errors.New("profile is encrypted; this bot cannot read encrypted savedata")
	}
	if len(data) < savedataHeadSize {
		return fmt.Errorf("too short to be a tox profile (%d bytes)", len(data))
	}
	if leading := binary.LittleEndian.Uint32(data[:4]); leading != 0 {
		return fmt.Errorf("not a tox profile (leading word %#08x, want 0)", leading)
	}
	if magic := binary.LittleEndian.Uint32(data[4:savedataHeadSize]); magic != savedataMagic {
		return fmt.Errorf("not a tox profile (magic %#08x, want %#08x)", magic, uint32(savedataMagic))
	}
	return nil
}

// readRawSavedata loads the stored bytes without interpreting them. A missing
// or empty file means "start fresh".
func readRawSavedata(path string) (data []byte, found bool, err error) {
	data, err = os.ReadFile(path)
	switch {
	case err == nil && len(data) > 0:
		return data, true, nil
	case err == nil, errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// readSavedata loads a plaintext profile. A missing or empty file means "start
// fresh"; an unreadable or damaged one is an error rather than a silent fresh
// start, because either would abandon the identity the file exists to preserve.
func readSavedata(path string) (data []byte, found bool, err error) {
	data, found, err = readRawSavedata(path)
	if err != nil || !found {
		return nil, false, err
	}
	if err := validateSavedata(data); err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// profileCipher encrypts and decrypts savedata with a passphrase-derived key,
// using the same format as the desktop Tox clients (`toxEsave`).
//
// The key is derived once and reused: derivation is deliberately expensive
// (it is what makes a weak passphrase costly to attack), and the bot writes a
// profile every 30 seconds.
type profileCipher struct {
	key *tox.ToxPassKey
}

// newProfileCipher derives the key. When an already-encrypted profile is
// supplied its salt is reused, which is what allows the file to be decrypted;
// otherwise a fresh random salt is generated for a first encryption.
func newProfileCipher(passphrase, existing []byte) (*profileCipher, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase")
	}
	if isEncryptedProfile(existing) {
		ok, err, salt := tox.GetSalt(existing)
		if !ok {
			return nil, fmt.Errorf("cannot read the profile's salt: %v", err)
		}
		key, err := tox.DeriveWithSalt(passphrase, salt)
		if err != nil {
			return nil, fmt.Errorf("key derivation failed: %w", err)
		}
		return &profileCipher{key: key}, nil
	}
	key, err := tox.Derive(passphrase)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	return &profileCipher{key: key}, nil
}

func (c *profileCipher) encrypt(plaintext []byte) ([]byte, error) {
	if c == nil {
		return plaintext, nil
	}
	if len(plaintext) == 0 {
		return nil, errors.New("nothing to encrypt")
	}
	ok, err, ciphertext := c.key.Encrypt(plaintext)
	if !ok {
		if err == nil {
			err = errors.New("tox_pass_key_encrypt failed")
		}
		return nil, err
	}
	return ciphertext, nil
}

// decrypt reverses encrypt. Note that the binding's package-level PassDecrypt
// cannot be used here: in v0.2.17 it passes the plaintext output buffer as the
// passphrase pointer, so it fails for every input. The pass-key API is correct.
func (c *profileCipher) decrypt(ciphertext []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.New("no passphrase configured")
	}
	if len(ciphertext) <= tox.PASS_ENCRYPTION_EXTRA_LENGTH {
		return nil, fmt.Errorf("too short to be an encrypted profile (%d bytes)", len(ciphertext))
	}
	ok, err, plaintext := c.key.Decrypt(ciphertext)
	if !ok {
		if err == nil {
			err = errors.New("decryption failed")
		}
		return nil, fmt.Errorf("%w (wrong passphrase?)", err)
	}
	return plaintext, nil
}

func (c *profileCipher) close() {
	if c != nil && c.key != nil {
		c.key.Free()
	}
}

// loadProfile reads the profile, decrypting it when it is encrypted, and
// returns the cipher the bot must keep using for saves. A passphrase with a
// plaintext profile on disk is a migration request: the profile is loaded as
// is and the next save writes it back encrypted.
func loadProfile(path string, passphrase []byte) (data []byte, cipher *profileCipher, found bool, err error) {
	raw, found, err := readRawSavedata(path)
	if err != nil || !found {
		if len(passphrase) > 0 && err == nil {
			// No profile yet, but the operator asked for encryption; derive
			// now so a broken passphrase is reported before the first save.
			cipher, err = newProfileCipher(passphrase, nil)
		}
		return nil, cipher, found, err
	}

	if isEncryptedProfile(raw) {
		if len(passphrase) == 0 {
			return nil, nil, true, errors.New("profile is encrypted; set TOX_SAVEDATA_PASSPHRASE " +
				"(or TOX_SAVEDATA_PASSPHRASE_FILE) to open it")
		}
		cipher, err = newProfileCipher(passphrase, raw)
		if err != nil {
			return nil, nil, true, err
		}
		plain, err := cipher.decrypt(raw)
		if err != nil {
			return nil, nil, true, err
		}
		if err := validateSavedata(plain); err != nil {
			return nil, nil, true, fmt.Errorf("decrypted profile is damaged: %w", err)
		}
		return plain, cipher, true, nil
	}

	if err := validateSavedata(raw); err != nil {
		return nil, nil, true, err
	}
	if len(passphrase) > 0 {
		if cipher, err = newProfileCipher(passphrase, nil); err != nil {
			return nil, nil, true, err
		}
		slog.Warn("profile on disk is not encrypted; it will be encrypted on the next save", "path", path)
	}
	return raw, cipher, true, nil
}

// ensureWritable checks the savedata path can be written before the bot commits
// to an identity, so a read-only volume fails at startup instead of silently
// dropping every save until the profile is lost on restart.
func ensureWritable(path string) error {
	probe := path + ".probe"
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(probe)
}

// writeFileSync writes data to path and flushes it to stable storage. The fsync
// is what makes the rename in save() atomic against power loss and not merely
// against a process crash: without it the new name can survive pointing at a
// truncated file.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syncDir flushes a directory entry so a completed rename survives power loss.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

// save atomically writes the current savedata to disk, encrypting it first if a
// passphrase is configured, and flushes the runtime state sidecar alongside it.
// Empty savedata is a no-op: it would clobber a good profile, and GetSavedata
// itself panics on a zero-length buffer.
func (b *Bot) save() {
	defer b.flushState()

	if b.t.GetSavedataSize() <= 0 {
		slog.Warn("save skipped: empty savedata")
		return
	}
	data := b.t.GetSavedata()
	if b.cipher != nil {
		encrypted, err := b.cipher.encrypt(data)
		if err != nil {
			b.metrics.saveErrors++
			slog.Error("save failed: cannot encrypt profile", "err", err)
			return
		}
		data = encrypted
	}
	tmp := b.saveFile + ".tmp"

	if err := writeFileSync(tmp, data, 0o600); err != nil {
		_ = os.Remove(tmp)
		b.metrics.saveErrors++
		slog.Error("save failed", "err", err)
		return
	}
	if err := os.Rename(tmp, b.saveFile); err != nil {
		_ = os.Remove(tmp)
		b.metrics.saveErrors++
		slog.Error("save rename failed", "err", err)
		return
	}
	syncDir(filepath.Dir(b.saveFile))
	b.lastSave = b.clock()
	slog.Debug("saved profile", "path", b.saveFile, "bytes", len(data), "encrypted", b.cipher != nil)
}

// flushState persists the JSON sidecar when it has changed.
func (b *Bot) flushState() {
	if err := b.state.flush(); err != nil {
		b.metrics.saveErrors++
		slog.Error("state save failed", "path", b.state.path, "err", err)
	}
}
