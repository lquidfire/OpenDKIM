# Ed25519-SHA256 Technical Implementation Notes

## RFC 8463 Specification Clarification

This document clarifies a common misunderstanding about how Ed25519-SHA256 works in DKIM.

---

## The Key RFC 8463 Statement

**RFC 8463, Section 3:**

> "The Ed25519-SHA256 signing algorithm computes a message hash as defined in Section 3 of [RFC6376] using SHA-256 [FIPS-180-4-2015] as the hash-alg. **It signs the hash with the PureEdDSA variant Ed25519**, as defined in RFC 8032, Section 5.1 [RFC8032]."

---

## What This Means

### Common Misconception ❌

"Ed25519 signs raw message data directly, while RSA signs a hash."

### Actual Behavior ✅

**Both RSA-SHA256 and Ed25519-SHA256 sign the same SHA-256 hash of canonicalized data.**

The algorithms differ only in **how** they sign that hash:

---

## The Complete Process

### RSA-SHA256 Process

```
1. Canonicalize headers and body per DKIM rules
2. Compute SHA-256 hash of canonicalized data
3. Sign the 32-byte SHA-256 hash using RSA
4. Output: ~256-byte RSA signature
```

### Ed25519-SHA256 Process (RFC 8463)

```
1. Canonicalize headers and body per DKIM rules
2. Compute SHA-256 hash of canonicalized data
3. Sign the 32-byte SHA-256 hash using PureEdDSA Ed25519
   (PureEdDSA internally applies SHA-512 to this hash as part of signing)
4. Output: 64-byte Ed25519 signature
```

### Key Insight

**The SHA-256 hash computed in step 2 is identical for both algorithms.**

The difference is **only** in step 3 (the cryptographic signing operation).

---

## Why Ed25519 Uses PureEdDSA

### What is PureEdDSA?

PureEdDSA is the Ed25519 signing algorithm where you provide a message, and Ed25519 internally:
1. Hashes the message with SHA-512 (as part of the signature algorithm)
2. Performs elliptic curve operations
3. Produces a 64-byte signature

### For DKIM Ed25519-SHA256

The "message" passed to PureEdDSA is the **SHA-256 hash** (32 bytes).

So the complete hashing chain is:
```
Canonical data → SHA-256 (DKIM layer) → SHA-512 (Ed25519 internal) → Signature
```

This is different from "HashEdDSA" where you would pass pre-hashed data and skip Ed25519's internal hashing.

---

## Implementation in OpenSSL

### Correct Implementation

```c
// For Ed25519-SHA256:

// 1. Compute SHA-256 hash of canonicalized data (DKIM layer)
unsigned char sha256_digest[32];
SHA256(canonicalized_data, data_len, sha256_digest);

// 2. Sign the SHA-256 digest using PureEdDSA
EVP_MD_CTX *ctx = EVP_MD_CTX_new();

// NULL for hash parameter = PureEdDSA mode
EVP_DigestSignInit(ctx, NULL, NULL, NULL, ed25519_private_key);

// Pass the SHA-256 digest as the "message" to Ed25519
unsigned char signature[64];
size_t sig_len = 64;
EVP_DigestSign(ctx, signature, &sig_len, sha256_digest, 32);

EVP_MD_CTX_free(ctx);
```

### What NOT to Do ❌

```c
// INCORRECT: Passing raw canonicalized data to Ed25519
EVP_DigestSign(ctx, signature, &sig_len, 
               canonicalized_data, data_len);  // Wrong!
```

This would be "HashEdDSA" mode and is NOT what RFC 8463 specifies.

---

## Why This Matters for Testing

### The Bug We Found

During Ed25519 implementation, we discovered a canonicalization bug where headers weren't being terminated with CRLF as required by RFC 6376.

**Why RSA tests didn't catch it:**
- Some RSA test vectors had been created with the same bug
- RSA was signing the incorrect hash, and verifying against incorrect expected signatures
- The bug was "baked into" the test expectations

**Why Ed25519 exposed it:**
- Ed25519 test vectors were freshly created from RFC 8463 Appendix A
- These vectors used correct canonicalization
- When Ed25519 failed but RSA passed, it revealed the canonicalization bug

**The key insight:** Both algorithms were affected by the bug. Ed25519 just had better test vectors.

---

## Verification Process

### Both Algorithms Verify the Same Way

**RSA-SHA256 Verification:**
```
1. Recompute SHA-256 hash of canonicalized data
2. Verify RSA signature against this hash
```

**Ed25519-SHA256 Verification:**
```
1. Recompute SHA-256 hash of canonicalized data
2. Verify Ed25519 signature against this hash (using PureEdDSA)
```

The SHA-256 hash in step 1 **must be identical** for both algorithms.

---

## Test Implications

### What the Tests Validate

The Ed25519 test suite validates:

1. **Correct SHA-256 computation**: Same hash as RSA for same input
2. **Proper canonicalization**: Headers with CRLF, body normalized correctly
3. **Ed25519 signature generation**: PureEdDSA signing of the SHA-256 hash
4. **Ed25519 signature verification**: PureEdDSA verification
5. **Chunk independence**: Hash computed correctly regardless of chunking

### Why Dual-Algorithm Tests Are Important

The dual-algorithm tests (t-test*DUAL.c) verify that RSA and Ed25519:
- Compute the same SHA-256 hash for the same message
- Both produce valid signatures (different values, but both verify)
- Handle canonicalization identically

This ensures the DKIM layer (canonicalization, hashing) is algorithm-agnostic, as it should be.

---

## Common Questions

### Q: Why does Ed25519 compute SHA-512 internally?

**A:** That's part of the Ed25519 signature algorithm itself (RFC 8032). When you sign a message with Ed25519, it internally computes SHA-512 hashes as part of the signature generation. This is independent of DKIM.

### Q: So there's SHA-256 and then SHA-512?

**A:** Yes:
- **SHA-256**: DKIM layer hashes the canonicalized message (RFC 6376)
- **SHA-512**: Ed25519 signature algorithm hashes during signing (RFC 8032)

The SHA-256 is what both RSA and Ed25519 sign. The SHA-512 is internal to Ed25519's signing process.

### Q: Why not just pass raw data to Ed25519?

**A:** Because RFC 8463 explicitly says "computes a message hash... using SHA-256" and then "signs the hash." This ensures:
- Consistency with RSA behavior (both sign the same hash)
- Compatibility with existing DKIM infrastructure
- Clear separation between DKIM layer (SHA-256) and crypto layer (Ed25519)

### Q: What's the difference between PureEdDSA and HashEdDSA?

**A:** 
- **PureEdDSA**: You give Ed25519 a message, it hashes it internally with SHA-512 and signs
- **HashEdDSA**: You give Ed25519 a pre-hashed message, it signs without internal hashing

RFC 8463 uses **PureEdDSA**, where the "message" is the SHA-256 hash.

---

## References

- **RFC 8463**: A New Cryptographic Signature Method for DKIM
  - Section 3: Ed25519-SHA256 Signing Algorithm
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA)
  - Section 5.1: PureEdDSA
- **RFC 6376**: DomainKeys Identified Mail (DKIM) Signatures
  - Section 3: Signing and Verification Algorithms
  - Section 3.7: Computing the Message Hash

---

## Conclusion

**Key Takeaway:** Ed25519-SHA256 in DKIM is not fundamentally different from RSA-SHA256 in terms of data processing. Both:

1. Canonicalize the message identically
2. Compute the same SHA-256 hash
3. Sign that hash (with different algorithms)

The Ed25519 test suite validates this equivalence and ensures that Ed25519 integrates correctly into the existing DKIM infrastructure without requiring special handling at the canonicalization or hashing layers.