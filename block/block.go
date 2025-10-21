package block

// Cipher represents a raw block cipher with fixed-size blocks.
type Cipher interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}
