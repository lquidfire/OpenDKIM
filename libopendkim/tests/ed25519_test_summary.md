# Ed25519 DKIM Test Suite

## Overview

This test suite provides comprehensive validation of Ed25519 signature support in libopendkim. The tests focus on Ed25519-specific behaviors, edge cases, and performance characteristics that differ from RSA implementations.

## Test Files

### Core Functionality Tests

#### t-test50ED25519.c - Core Signing & Verification
**Purpose**: Validate Ed25519 signing and verification across all canonicalization modes

**Tests**:
- Simple/simple canonicalization
- Simple/relaxed canonicalization  
- Relaxed/simple canonicalization
- Relaxed/relaxed canonicalization

**Key Validations**:
- Signature generation succeeds for all modes
- Verification succeeds for all modes
- Signature headers are properly formatted
- Algorithm detection works correctly

**Expected Results**: 4/4 tests pass (one for each canonicalization combination)

---

#### t-test51ED25519.c - Key Format Tests
**Purpose**: Validate Ed25519-specific key requirements and anomaly detection

**Tests**:
1. Valid Ed25519 key (32 bytes, base64 encoded)
2. Invalid short key (< 32 bytes) - should reject
3. Invalid long key (> 32 bytes) - should reject
4. Invalid base64 encoding - should reject
5. Signature format validation (always 64 bytes = 86 base64 chars)

**Key Validations**:
- 32-byte raw key format requirement
- Base64 encoding correctness
- Key size reporting (256 bits)
- Signature length consistency (64 bytes)
- Proper rejection of malformed keys

**Expected Results**: 5/5 tests pass

**Ed25519-Specific Requirements**:
- Keys must be exactly 32 bytes (no ASN.1 wrapping)
- Base64 encoding produces 44-45 characters
- Signatures are always 64 bytes (deterministic)
- Key size always reported as 256 bits

---

#### t-test52ED25519.c - DNS Record Tests  
**Purpose**: Validate Ed25519 DNS TXT record parsing and format requirements

**Tests**:
1. Valid DNS record with `k=ed25519` tag
2. DNS record without `k=` tag (should default to RSA or fail)
3. DNS record with `k=rsa` but Ed25519 signature (should fail)
4. DNS record with extra tags (t=s, n=note, etc.)

**Key Validations**:
- `k=ed25519` tag parsing
- Algorithm mismatch detection
- DNS tag order independence
- Extra tag tolerance

**Expected Results**: 4/4 tests pass

**DNS Record Format**:
```
selector._domainkey.example.com IN TXT "v=DKIM1; k=ed25519; p=<base64-key>"
```

---

### Edge Case Tests

#### t-test53ED25519.c - Edge Cases
**Purpose**: Test Ed25519 behavior with unusual but valid inputs

**Tests**:
1. Empty body handling
2. Very long headers (>1000 characters)
3. Various whitespace scenarios (tabs, multiple spaces, mixed)
4. Large messages (10KB body)
5. Binary-like content in body

**Key Validations**:
- Edge cases don't cause crashes
- Signatures remain valid for all edge cases
- Memory handling is correct
- Canonicalization handles extremes

**Expected Results**: 5/5 tests pass

**Critical Edge Cases**:
- Empty body should produce consistent hash
- Long headers should wrap correctly
- Whitespace normalization in relaxed mode
- Large messages don't overflow buffers
- Binary content doesn't break base64 encoding

---

### Performance Tests

#### t-test54ED25519.c - Performance Comparison
**Purpose**: Compare Ed25519 vs RSA performance characteristics

**Tests**:
1. Signing speed (100 iterations each algorithm)
2. Verification speed (100 iterations each algorithm)
3. Message size scaling (100B, 1KB, 10KB, 100KB)

**Metrics Collected**:
- Operations per second
- Average latency per operation
- Speedup factor (Ed25519 vs RSA)
- Memory usage patterns

**Expected Results**: 
- Ed25519 signing: 2-10x faster than RSA
- Ed25519 verification: 2-10x faster than RSA
- Ed25519 scales linearly with message size
- Smaller signature and key sizes

**Performance Targets** (typical):
```
Ed25519:
  - Signing:      ~1000-5000 ops/sec
  - Verification: ~1000-5000 ops/sec
  - Signature:    64 bytes
  - Key:          32 bytes

RSA-2048:
  - Signing:      ~200-1000 ops/sec
  - Verification: ~2000-10000 ops/sec
  - Signature:    256 bytes
  - Key:          256 bytes
```

---

## Test Execution

### Prerequisites

1. Run test setup to create keyfiles:
```bash
cd libopendkim/tests
./t-setup
```

2. Verify keyfile contains Ed25519 entries:
```bash
cat /var/tmp/testkeys | grep ed25519
```

Expected output:
```
ed25519-sha256._domainkey.example.com v=DKIM1; k=ed25519; p=<base64-key>
```

### Running Individual Tests

```bash
# Core signing/verification
./t-test50ED25519

# Key format validation
./t-test51ED25519

# DNS record parsing
./t-test52ED25519

# Edge cases
./t-test53ED25519

# Performance comparison
./t-test54ED25519
```

### Running All Ed25519 Tests

```bash
# Run all Ed25519-specific tests
for test in t-test5[0-4]ED25519; do
    echo "Running $test..."
    ./$test || echo "FAILED: $test"
done
```

### Expected Output

Each test should produce output like:
```
*** Ed25519 [Test Name] Tests ***

Testing [scenario]...
PASS: [description]

=== Test Results ===
Tests passed: X/X
SUCCESS: All tests passed
```

---

## Test Coverage Analysis

### What These Tests Cover

| Category | Coverage | Test File |
|----------|----------|-----------|
| Core functionality | All canonicalizations | t-test50ED25519.c |
| Key formats | Valid + invalid keys | t-test51ED25519.c |
| DNS parsing | k= tag variations | t-test52ED25519.c |
| Edge cases | Empty, large, binary | t-test53ED25519.c |
| Performance | Speed comparison | t-test54ED25519.c |

### What These Tests Do NOT Cover

- Interoperability with other DKIM implementations (see dual tests)
- Multi-signature scenarios (see t-test05DUAL.c)
- Real-world email scenarios (see dual test suite)
- Network-based DNS lookups (tests use file-based DNS)
- Cryptographic security properties (assumes correct Ed25519 library)

---

## Key Differences: Ed25519 vs RSA

### Algorithm Properties

| Property | Ed25519 | RSA-2048 |
|----------|---------|----------|
| Signature size | 64 bytes | ~256 bytes |
| Public key size | 32 bytes | ~256 bytes |
| Private key size | 32 bytes | ~1192 bytes |
| Deterministic | Yes | No (with padding) |
| Signing speed | Fast (constant time) | Slow (variable) |
| Verification speed | Fast (constant time) | Medium (variable) |

### DKIM-Specific Differences

1. **DNS Records**:
   - Ed25519 requires `k=ed25519` tag
   - Ed25519 keys are raw 32 bytes (no ASN.1)
   - RSA keys include ASN.1 structure

2. **Signature Format**:
   - Ed25519 signatures always 64 bytes
   - RSA signatures vary with key size

3. **Algorithm Tag**:
   - Ed25519: `a=ed25519-sha256`
   - RSA: `a=rsa-sha256`

4. **Signing Process** (per RFC 8463):
   - **Both algorithms**: Compute SHA-256 hash of canonicalized data
   - **RSA**: Signs the SHA-256 hash directly with RSA
   - **Ed25519**: Signs the SHA-256 hash with PureEdDSA (which internally uses SHA-512)
   - **Key point**: Both sign the same SHA-256 hash, just with different cryptographic algorithms

5. **Why Ed25519 Exposed Canonicalization Bugs**:
   - Ed25519 test vectors from RFC 8463 were freshly created with correct canonicalization
   - Some RSA tests had incorrect expected signatures that masked canonicalization bugs
   - When Ed25519 failed but RSA passed, it revealed that RSA tests were validating against incorrect signatures

---

## Common Failure Patterns

### 1. DNS Lookup Failures
**Symptom**: All tests fail with "key not found" errors

**Causes**:
- Keyfile not created by t-setup
- Keyfile path incorrect in KEYFILE constant
- Missing Ed25519 entry in keyfile

**Solution**:
```bash
./t-setup
cat /var/tmp/testkeys | grep ed25519
```

### 2. Key Format Errors
**Symptom**: "Invalid key" or "Key decode failed" errors

**Causes**:
- Key not exactly 32 bytes
- Base64 encoding incorrect
- ASN.1 wrapper included (should not be)

**Solution**: Regenerate keys ensuring raw 32-byte format

### 3. Algorithm Not Supported
**Symptom**: "Algorithm not supported" or DKIM_SIGN_ED25519SHA256 undefined

**Causes**:
- Library compiled without Ed25519 support
- Incorrect OpenSSL version (need 1.1.1+)
- Missing build flag

**Solution**: Rebuild with Ed25519 support:
```bash
./configure --enable-ed25519
make clean && make
```

### 4. Signature Verification Failures
**Symptom**: Signing succeeds but verification fails

**Causes**:
- Canonicalization mismatch
- Header manipulation between sign and verify
- DNS key doesn't match private key
- Known bug in simple canonicalization (see docs)

**Solution**: Use relaxed/relaxed canonicalization for Ed25519

---

## Integration with Existing Test Suite

### Relationship to Dual Algorithm Tests

These Ed25519-specific tests complement the dual-algorithm tests:

- **Dual tests** (t-test00DUAL.c, etc.): Cross-algorithm compatibility
- **Ed25519 tests** (t-test50ED25519.c, etc.): Algorithm-specific validation

Both test suites are needed for complete coverage.

### Relationship to Original RSA Tests

Original RSA tests remain unchanged. Ed25519 tests use similar patterns but focus on Ed25519-specific requirements.

---

## Future Enhancements

### Potential Additional Tests

1. **t-test55ED25519.c** - Interoperability
   - Test against known-good Ed25519 signatures from other implementations
   - Verify RFC 8463 test vectors
   - Cross-implementation compatibility

2. **t-test56ED25519.c** - Key Rotation
   - Test key rollover scenarios
   - Multiple selectors with different keys
   - Graceful handling of old vs new keys

3. **t-test57ED25519.c** - Error Handling
   - Corrupted signatures
   - Tampered messages
   - Invalid algorithm combinations

4. **t-test58ED25519.c** - Production Scenarios
   - Real email messages
   - Different email clients
   - Various MIME structures

---

## Success Criteria

### Minimum Requirements

All 18 tests across the 5 test files must pass:
- t-test50ED25519.c: 4/4 tests
- t-test51ED25519.c: 5/5 tests
- t-test52ED25519.c: 4/4 tests
- t-test53ED25519.c: 5/5 tests
- t-test54ED25519.c: Performance benchmarks (no pass/fail)

### Quality Indicators

- **Zero crashes**: No segfaults or memory errors
- **Consistent behavior**: Deterministic results across runs
- **Performance**: Ed25519 measurably faster than RSA
- **Compatibility**: Works with both file-based and DNS-based key lookup

---

## Troubleshooting

### Debug Mode

Enable debug output:
```bash
# Set environment variable
export DKIM_DEBUG=1

# Run test
./t-test50ED25519
```

### Valgrind Memory Check

Check for memory leaks:
```bash
valgrind --leak-check=full ./t-test50ED25519
```

### GDB Debugging

Debug failures:
```bash
gdb ./t-test50ED25519
(gdb) run
(gdb) backtrace
```

---

## References

- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA)
- **RFC 8463**: A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM)
- **RFC 6376**: DomainKeys Identified Mail (DKIM) Signatures
- **OpenSSL Ed25519 Documentation**: https://www.openssl.org/docs/man1.1.1/man7/Ed25519.html

---

## Changelog

### Version 1.0 (Current)
- Initial Ed25519 test suite
- 5 test files covering core functionality
- ~20 individual test cases
- Performance benchmarking included

### Planned Enhancements
- Interoperability tests with other implementations
- RFC 8463 test vector validation
- Extended edge case coverage
- Production scenario testing