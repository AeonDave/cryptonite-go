package wycheproof

import _ "embed"

// JSON contains the compiled Wycheproof-style vectors used across tests.
//
//go:embed testdata/wycheproof.json
var JSON []byte
