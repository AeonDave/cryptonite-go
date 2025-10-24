# Performance Benchmarks

Benchmarks on **AMD Ryzen 7 5800X 8-Core Processor** (Windows, amd64)

## AEAD (Authenticated Encryption with Associated Data)

### Encryption

| Algorithm             | Operations/sec | Speed (MB/s)       | Memory/op | Allocs/op |
|-----------------------|----------------|--------------------|-----------|-----------|
| **AESGCM**            | 1,781,193      | <ins>1,627.97<ins> | 2,432 B   | 3         |
| **AES128SIV**         | 519,230        | 453.24             | 3,904 B   | 13        |
| **AES256SIV**         | 483,336        | 404.34             | 3,904 B   | 13        |
| **ASCON128a**         | 246,561        | 225.48             | 2,192 B   | 3         |
| **XoodyakEncrypt**    | 256,364        | 215.95             | 2,176 B   | 2         |
| **ASCON80pq**         | 229,557        | 204.15             | 2,192 B   | 3         |
| **ChaCha20Poly1305**  | 216,733        | 182.47             | 2,192 B   | 3         |
| **XChaCha20Poly1305** | 206,982        | 176.52             | 2,192 B   | 3         |
| **AESGCMSIV**         | 120,109        | 103.26             | 2,304 B   | 10        |
| **DeoxysII128**       | 14,815         | 12.78              | 1,152 B   | 1         |
| **GiftCofb**          | 5,424          | 4.65               | 1,152 B   | 1         |
| **SkinnyAeadM1**      | 3,026          | 2.56               | 1,152 B   | 1         |

### Decryption

| Algorithm             | Operations/sec | Speed (MB/s)       | Memory/op | Allocs/op |
|-----------------------|----------------|--------------------|-----------|-----------|
| **AESGCM**            | 1,575,438      | <ins>1,357.57<ins> | 2,304 B   | 3         |
| **AES128SIV**         | 462,592        | 412.04             | 3,776 B   | 13        |
| **AES256SIV**         | 411,255        | 374.49             | 3,776 B   | 13        |
| **ASCON128a**         | 275,188        | 253.45             | 1,040 B   | 2         |
| **XoodyakEncrypt**    | 254,185        | 220.41             | 1,024 B   | 1         |
| **ASCON80pq**         | 247,119        | 209.96             | 1,040 B   | 2         |
| **ChaCha20Poly1305**  | 210,932        | 188.33             | 1,040 B   | 2         |
| **XChaCha20Poly1305** | 211,380        | 177.82             | 1,040 B   | 2         |
| **AESGCMSIV**         | 91,759         | 92.26              | 2,176 B   | 10        |
| **DeoxysII128**       | 14,332         | 12.05              | 1,024 B   | 1         |
| **GiftCofb**          | 5,362          | 4.66               | 1,024 B   | 1         |
| **SkinnyAeadM1**      | 1,764          | 1.49               | 1,024 B   | 1         |

## Block Ciphers

| Algorithm   | Operations/sec | Speed (MB/s)       | Memory/op | Allocs/op |
|-------------|----------------|--------------------|-----------|-----------|
| **AES-128** | 141,852,304    | <ins>1,865.76<ins> | 0 B       | 0         |
| **AES-256** | 127,502,730    | 1,557.44           | 0 B       | 0         |

## ECDH (Elliptic Curve Diffie-Hellman)

| Algorithm  | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|------------|----------------|--------------|-----------|-----------|
| **X25519** | 32,882         | 0.88         | 32 B      | 1         |
| **P-256**  | 28,309         | 0.76         | 128 B     | 2         |
| **P-384**  | 3,409          | 0.14         | 216 B     | 5         |

## Hash Functions

| Algorithm       | Operations/sec | Speed (MB/s)     | Memory/op | Allocs/op |
|-----------------|----------------|------------------|-----------|-----------|
| **BLAKE2b-512** | 235,917        | <ins>823.40<ins> | 448 B     | 2         |
| **BLAKE2s-256** | 149,517        | 512.86           | 224 B     | 2         |
| **XoodyakHash** | 55,000         | 185.84           | 32 B      | 1         |
| **SHA3-224**    | 13,009         | 45.05            | 32 B      | 1         |
| **SHA3-256**    | 12,315         | 41.27            | 32 B      | 1         |
| **SHA3-384**    | 9,670          | 32.59            | 48 B      | 1         |
| **SHA3-512**    | 6,806          | 22.99            | 64 B      | 1         |

### SP800-185 Functions

| Algorithm           | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|---------------------|----------------|--------------|-----------|-----------|
| **TupleHash128**    | 119,626        | 22.46        | 544 B     | 14        |
| **TupleHash256**    | 120,272        | 21.78        | 544 B     | 14        |
| **ParallelHash128** | 6,931          | 23.39        | 14,952 B  | 218       |
| **ParallelHash256** | 6,537          | 21.70        | 15,464 B  | 218       |

## HPKE (Hybrid Public Key Encryption)

| Operation               | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|-------------------------|----------------|--------------|-----------|-----------|
| **SetupBaseSender**     | 13,594         | -            | 7,840 B   | 105       |
| **SetupBaseReceiver**   | 14,746         | -            | 7,664 B   | 103       |
| **Seal**                | 200,772        | 144.20       | 2,208 B   | 4         |
| **Seal/Open RoundTrip** | 7,170          | 5.81         | 18,768 B  | 215       |

## KDF (Key Derivation Functions)

| Algorithm         | Operations/sec | Speed (MB/s)    | Memory/op    | Allocs/op |
|-------------------|----------------|-----------------|--------------|-----------|
| **HKDF-SHA256**   | 956,242        | <ins>29.97<ins> | 1,537 B      | 18        |
| **HKDF-BLAKE2b**  | 455,893        | 11.87           | 4,001 B      | 19        |
| **PBKDF2-SHA256** | 870            | 0.02            | 920 B        | 11        |
| **PBKDF2-SHA1**   | 406            | 0.01            | 832 B        | 11        |
| **Argon2id**      | 456            | 0.01            | 4,199,022 B  | 19        |
| **Scrypt**        | 19             | 0.00            | 33,560,440 B | 24        |

## MAC (Message Authentication Code)

| Algorithm       | Operations/sec | Speed (MB/s)       | Memory/op | Allocs/op |
|-----------------|----------------|--------------------|-----------|-----------|
| **Poly1305**    | 1,782,328      | <ins>3,059.40<ins> | 176 B     | 4         |
| **HMAC-SHA256** | 821,191        | 1,543.64           | 512 B     | 6         |
| **KMAC128**     | 24,081         | 41.10              | 1,032 B   | 15        |
| **KMAC256**     | 20,673         | 34.27              | 1,064 B   | 16        |

## Post-Quantum Cryptography

### Hybrid KEM

| Operation       | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|-----------------|----------------|--------------|-----------|-----------|
| **Encapsulate** | 15,826         | -            | 2,169 B   | 31        |
| **Decapsulate** | 15,982         | 0.40         | 1,945 B   | 28        |

### ML-KEM (Kyber)

| Algorithm      | Operation    | Operations/sec | ns/op   | Speed (MB/s) | Memory/op | Allocs/op |
|----------------|--------------|----------------|---------|--------------|-----------|-----------|
| **ML-KEM-512** | Encapsulate  | 6,448          | 155,085 | -            | 13,248 B  | 793       |
| **ML-KEM-512** | Decapsulate  | 4,691          | 213,172 | 0.15         | 15,552 B  | 1,050     |
| **ML-KEM-768** | Encapsulate  | 3,752          | 266,542 | -            | 22,560 B  | 1,565     |
| **ML-KEM-768** | Decapsulate  | 3,557          | 281,125 | 0.11         | 26,016 B  | 1,950     |
| **ML-KEM-1024** | Encapsulate  | 3,065          | 326,309 | -            | 34,704 B  | 2,593     |
| **ML-KEM-1024** | Decapsulate  | 2,452          | 407,897 | 0.08         | 39,056 B  | 3,106     |

### Envelope

| Operation | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|-----------|----------------|--------------|-----------|-----------|
| **Seal**  | 12,262         | 10.60        | 8,824 B   | 77        |
| **Open**  | 12,327         | 11.16        | 6,296 B   | 72        |

## Digital Signatures

| Algorithm       | Operation | Operations/sec | Speed (MB/s) | Memory/op | Allocs/op |
|-----------------|-----------|----------------|--------------|-----------|-----------|
| **Ed25519**     | Sign      | 57,078         | 48.98        | 64 B      | 1         |
| **Ed25519**     | Verify    | 27,109         | 23.24        | 0 B       | 0         |
| **ECDSA P-256** | Sign      | 33,120         | 28.52        | 7,132 B   | 81        |
| **ECDSA P-256** | Verify    | 20,851         | 17.95        | 976 B     | 17        |

## Stream Ciphers

| Algorithm     | Operations/sec | Speed (MB/s)     | Memory/op | Allocs/op |
|---------------|----------------|------------------|-----------|-----------|
| **XChaCha20** | 66,159         | <ins>226.16<ins> | 0 B       | 0         |
| **ChaCha20**  | 66,160         | 223.73           | 0 B       | 0         |

## XOF (Extendable-Output Functions)

| Algorithm      | Operations/sec | Speed (MB/s)     | Memory/op | Allocs/op |
|----------------|----------------|------------------|-----------|-----------|
| **Blake2bXOF** | 224,691        | <ins>191.58<ins> | 640 B     | 1         |
| **Blake2sXOF** | 145,125        | 122.37           | 320 B     | 1         |
| **XoodyakXOF** | 44,290         | 37.23            | 96 B      | 1         |
| **SHAKE128**   | 12,476         | 10.59            | 416 B     | 1         |
| **CSHAKE128**  | 12,070         | 10.30            | 864 B     | 10        |
| **CSHAKE256**  | 9,913          | 8.43             | 800 B     | 10        |
| **SHAKE256**   | 10,000         | 8.75             | 416 B     | 1         |

---

### Note

* All tests were executed using `go test -bench . -benchmem -count=1`
* Speeds are expressed in MB/s (megabytes per second)
* **Memory/op** indicates the number of bytes allocated per operation
* **Allocs/op** indicates the number of memory allocations per operation
