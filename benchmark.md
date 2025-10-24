# Performance Benchmarks

Benchmarks on **AMD Ryzen 7 5800X 8-Core Processor** (Windows, amd64)

## AEAD (Authenticated Encryption with Associated Data)

### Encryption

| Algorithm             | Operations/sec | Speed (MB/s)       | Memory/op | Allocs/op |
|-----------------------|----------------|--------------------|-----------|-----------|
| **AESGCM**            | 1,478,000      | <ins>1,513.66<ins> | 2,432 B   | 3         |
| **AES128SIV**         | 404,201        | 414.14             | 3,904 B   | 13        |
| **AES256SIV**         | 378,932        | 388.04             | 3,904 B   | 13        |
| **ASCON128a**         | 227,066        | 232.51             | 2,192 B   | 3         |
| **ASCON80pq**         | 201,208        | 206.26             | 2,192 B   | 3         |
| **XoodyakEncrypt**    | 170,757        | 174.83             | 2,176 B   | 2         |
| **ChaCha20Poly1305**  | 163,292        | 167.20             | 2,192 B   | 3         |
| **XChaCha20Poly1305** | 161,058        | 164.91             | 2,192 B   | 3         |
| **AESGCMSIV**         | 92,000         | 94.17              | 2,304 B   | 10        |
| **DeoxysII128**       | 11,910         | 12.20              | 1,152 B   | 1         |
| **GiftCofb**          | 4,550          | 4.66               | 1,152 B   | 1         |
| **SkinnyAeadM1**      | 2,495          | 2.55               | 1,152 B   | 1         |

### Decryption

| Algorithm             | Operations/sec | Speed (MB/s)       | Memory/op | Allocs/op |
|-----------------------|----------------|--------------------|-----------|-----------|
| **AESGCM**            | 1,584,849      | <ins>1,511.09<ins> | 2,304 B   | 3         |
| **AES128SIV**         | 438,142        | 395.02             | 3,776 B   | 13        |
| **AES256SIV**         | 459,286        | 378.39             | 3,776 B   | 13        |
| **ASCON128a**         | 275,910        | 224.93             | 1,040 B   | 2         |
| **ASCON80pq**         | 202,852        | 202.95             | 1,040 B   | 2         |
| **XoodyakEncrypt**    | 245,053        | 210.08             | 1,024 B   | 1         |
| **ChaCha20Poly1305**  | 166,708        | 157.32             | 1,040 B   | 2         |
| **XChaCha20Poly1305** | 175,689        | 141.98             | 1,040 B   | 2         |
| **AESGCMSIV**         | 108,074        | 99.97              | 2,176 B   | 10        |
| **DeoxysII128**       | 13,621         | 12.40              | 1,024 B   | 1         |
| **GiftCofb**          | 4,588          | 4.53               | 1,024 B   | 1         |
| **SkinnyAeadM1**      | 1,743          | 1.42               | 1,024 B   | 1         |

## Block Ciphers

| Algorithm   | Operations/sec | Speed (MB/s)       | Memory/op | Allocs/op |
|-------------|----------------|--------------------|-----------|-----------|
| **AES-128** | 137,301,420    | <ins>1,773.87<ins> | 0 B       | 0         |
| **AES-256** | 96,553,832     | 1,479.53           | 0 B       | 0         |

## ECDH (Elliptic Curve Diffie-Hellman)

| Algorithm  | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|------------|----------------|--------------|-----------|-----------|
| **X25519** | 26,792         | 0.75         | 32 B      | 1         |
| **X448**   | 5,745          | 0.29         | 64 B      | 1         |
| **P-256**  | 28,326         | 0.76         | 128 B     | 2         |
| **P-384**  | 3,568          | 0.14         | 216 B     | 5         |

## Hash Functions

| Algorithm       | Operations/sec | Speed (MB/s)     | Memory/op | Allocs/op |
|-----------------|----------------|------------------|-----------|-----------|
| **SHA-224**     | 584,635        | 2,063.47         | 32 B      | 1         |
| **SHA-256**     | 629,854        | 2,131.41         | 32 B      | 1         |
| **SHA-384**     | 251,696        | 835.33           | 48 B      | 1         |
| **SHA-512**     | 241,075        | 880.79           | 64 B      | 1         |
| **SHA3-224**    | 139,950        | 478.57           | 32 B      | 1         |
| **SHA3-256**    | 125,731        | 443.76           | 32 B      | 1         |
| **SHA3-384**    | 97,869         | 350.19           | 48 B      | 1         |
| **SHA3-512**    | 68,695         | 244.52           | 64 B      | 1         |
| **BLAKE2b-512** | 226,857        | 783.75           | 448 B     | 2         |
| **BLAKE2s-256** | 136,899        | 497.24           | 224 B     | 2         |
| **XoodyakHash** | 52,641         | 179.16           | 32 B      | 1         |

### SP800-185 Functions

| Algorithm           | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|---------------------|----------------|--------------|-----------|-----------|
| **TupleHash128**    | 113,539        | 20.99        | 544 B     | 14        |
| **TupleHash256**    | 116,828        | 21.96        | 544 B     | 14        |
| **ParallelHash128** | 6,259          | 22.50        | 14,952 B  | 218       |
| **ParallelHash256** | 5,821          | 20.12        | 15,464 B  | 218       |

## HPKE (Hybrid Public Key Encryption)

| Operation               | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|-------------------------|----------------|--------------|-----------|-----------|
| **SetupBaseSender**     | 15,579         | -            | 7,840 B   | 105       |
| **SetupBaseReceiver**   | 15,504         | -            | 7,664 B   | 103       |
| **Seal**                | 216,561        | 183.89       | 2,208 B   | 4         |
| **Seal/Open RoundTrip** | 7,140          | 6.22         | 18,768 B  | 215       |

## KDF (Key Derivation Functions)

| Algorithm         | Operations/sec | Speed (MB/s)    | Memory/op    | Allocs/op |
|-------------------|----------------|-----------------|--------------|-----------|
| **HKDF-SHA256**   | 1,000,000      | 30.95           | 1,537 B      | 18        |
| **HKDF-BLAKE2b**  | 488,002        | 12.90           | 4,001 B      | 19        |
| **PBKDF2-SHA1**   | 422            | 0.01            | 832 B        | 11        |
| **PBKDF2-SHA256** | 896            | 0.02            | 920 B        | 11        |
| **Argon2id**      | 488            | 0.01            | 4,199,022 B  | 19        |
| **Scrypt**        | 21             | 0.00            | 33,560,440 B | 24        |

## MAC (Message Authentication Code)

| Algorithm       | Operations/sec | Speed (MB/s)       | Memory/op | Allocs/op |
|-----------------|----------------|--------------------|-----------|-----------|
| **Poly1305**    | 1,758,736      | 3,018.91           | 176 B     | 4         |
| **HMAC-SHA256** | 777,085        | 1,509.66           | 512 B     | 6         |
| **KMAC128**     | 22,048         | 38.83              | 1,032 B   | 15        |
| **KMAC256**     | 19,027         | 34.08              | 1,064 B   | 16        |

## Post-Quantum Cryptography

### Hybrid KEM

| Operation       | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|-----------------|----------------|--------------|-----------|-----------|
| **Encapsulate** | 15,674         | -            | 2,193 B   | 34        |
| **Decapsulate** | 14,965         | 0.41         | 1,961 B   | 30        |

### ML-KEM (Kyber)

| Algorithm      | Operation    | Operations/sec | ns/op   | Speed (MB/s) | Memory/op | Allocs/op |
|----------------|--------------|----------------|---------|--------------|-----------|-----------|
| **ML-KEM-512** | Encapsulate  | 22,804         | 52,541  | -            | 13,248 B  | 793       |
| **ML-KEM-512** | Decapsulate  | 19,134         | 62,958  | 0.51         | 15,552 B  | 1,050     |
| **ML-KEM-768** | Encapsulate  | 15,310         | 77,591  | -            | 22,560 B  | 1,565     |
| **ML-KEM-768** | Decapsulate  | 12,196         | 95,554  | 0.33         | 26,016 B  | 1,950     |
| **ML-KEM-1024** | Encapsulate  | 10,000         | 111,334 | -            | 34,704 B  | 2,593     |
| **ML-KEM-1024** | Decapsulate  | 8,743          | 133,430 | 0.24         | 39,056 B  | 3,106     |

### Envelope

| Operation | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|-----------|----------------|--------------|-----------|-----------|
| **Seal**  | 13,712         | 11.85        | 8,848 B   | 80        |
| **Open**  | 14,058         | 11.81        | 6,312 B   | 74        |

## Digital Signatures

| Algorithm       | Operation | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|-----------------|-----------|----------------|--------------|-----------|-----------|
| **Ed25519**     | Sign      | 57,715         | 49.78        | 128 B     | 2         |
| **Ed25519**     | Verify    | 27,942         | 23.87        | 0 B       | 0         |
| **MLDSA44**     | Sign      | 3,088          | 2.73         | 171,171 B | 64        |
| **MLDSA44**     | Verify    | 14,065         | 10.96        | 44,512 B  | 14        |
| **MLDSA65**     | Sign      | 2,217          | 1.92         | 237,874 B | 68        |
| **MLDSA65**     | Verify    | 7,693          | 6.50         | 72,592 B  | 16        |
| **MLDSA87**     | Sign      | 2,670          | 2.72         | 215,936 B | 38        |
| **MLDSA87**     | Verify    | 5,017          | 4.37         | 121,280 B | 18        |
| **ECDSA P-256** | Sign      | 31,812         | 26.49        | 7,132 B   | 81        |
| **ECDSA P-256** | Verify    | 19,893         | 17.30        | 976 B     | 17        |

## Stream Ciphers

| Algorithm     | Operations/sec | Speed (MB/s)     | Memory/op | Allocs/op |
|---------------|----------------|------------------|-----------|-----------|
| **XChaCha20** | 64,406         | 220.55           | 0 B       | 0         |
| **ChaCha20**  | 63,528         | 218.23           | 0 B       | 0         |

## XOF (Extendable-Output Functions)

| Algorithm      | Operations/sec | Speed (MB/s)     | Memory/op | Allocs/op |
|----------------|----------------|------------------|-----------|-----------|
| **Blake2bXOF** | 207,360        | 176.48           | 640 B     | 1         |
| **Blake2sXOF** | 138,902        | 120.54           | 320 B     | 1         |
| **XoodyakXOF** | 42,565         | 36.30            | 96 B      | 1         |
| **SHAKE128**   | 12,050         | 10.30            | 416 B     | 1         |
| **SHAKE256**   | 9,543          | 8.15             | 416 B     | 1         |
| **CSHAKE128**  | 10,000         | 9.56             | 864 B     | 10        |
| **CSHAKE256**  | 9,549          | 8.14             | 800 B     | 10        |

---

### Note

* All tests were executed using `go test -bench . -benchmem -count=1`
* Speeds are expressed in MB/s (megabytes per second)
* **Memory/op** indicates the number of bytes allocated per operation
* **Allocs/op** indicates the number of memory allocations per operation
