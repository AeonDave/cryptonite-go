package xof

// XOF represents an extendable-output function (XOF) backed by one of the
// primitives exposed by the library. It mirrors the behaviour of hashing
// XOFs such as SHAKE, BLAKE2X, or Xoodyak Cyclist.
//
// Implementations are expected to be stateful objects supporting absorbing
// (Write), squeezing (Read), and resetting to the initial state.
type XOF interface {
	Reset()
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}
