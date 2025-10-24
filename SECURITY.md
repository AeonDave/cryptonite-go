# Security Policy

## Reporting a Vulnerability

**DO NOT open public issues for security vulnerabilities.**

Security vulnerabilities should be reported via GitHub's private vulnerability reporting feature. This allows us to address issues confidentially before public disclosure.

To report a vulnerability:
1. Go to the [Security tab](https://github.com/AeonDave/cryptonite-go/security) in this repository
2. Click "Report a vulnerability"
3. Provide detailed information about the issue, including:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

We will acknowledge receipt within 48 hours and provide regular updates on our progress.

## Security Guarantees

This library provides the following security guarantees:

- **Constant-time operations** where required (Poly1305, X25519, Ed25519, ML-DSA)
- **Automatic key/nonce zeroization** via `secret` package helpers
- **Wycheproof test vectors** + fuzzing harnesses for validation
- **No CGO dependencies** → reduced supply chain risk
- **Known-answer tests (KAT)** for all algorithms
- **Tamper checks** on cryptographic operations

## Known Limitations

- **This library has NOT been independently audited.** Even though it is deployed in production, perform thorough internal review and threat modeling before upgrading or integrating it into new systems.
- **Nonce management**: Caller responsible for uniqueness (use `secret.NewNonce()` or counters)
- **Side channels**: Best-effort mitigation; validate in your threat model
- **Algorithm selection**: Some primitives are experimental (e.g., GIFT-COFB, Skinny-AEAD) – prefer mainstream options (AES-GCM, ChaCha20-Poly1305, X25519, Ed25519) unless you need specific properties
- **Post-quantum algorithms**: ML-KEM and ML-DSA implementations are based on NIST standards but should be evaluated for your specific threat model
- **Hardware acceleration**: AES-NI is used when available, but software fallbacks may have different performance characteristics

## Security Best Practices

When using this library:

1. **Key Management**: Use appropriate key sizes and rotation policies
2. **Nonce Management**: Ensure nonce uniqueness per key (consider counters or random nonces)
3. **Memory Zeroization**: Sensitive data is automatically zeroized, but verify in high-security environments
4. **Algorithm Selection**: Choose algorithms based on your security requirements and performance needs
5. **Testing**: Run the full test suite including fuzzing before deployment
6. **Updates**: Monitor for security updates and test thoroughly before upgrading

## Contact

For security-related questions or concerns, please use the vulnerability reporting process above.

