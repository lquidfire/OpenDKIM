# Ed25519 DKIM Test Suite - Complete Documentation

## Quick Start

```bash
cd libopendkim/tests

# Setup test environment
./t-setup

# Run all Ed25519 tests
./run-ed25519-tests.sh

# Or run individual tests
./t-test50ED25519  # Core functionality
./t-test51ED25519  # Key formats
./t-test52ED25519  # DNS records
./t-test53ED25519  # Edge cases
./t-test54ED25519  # Performance
./t-test55ED25519  # Chunked processing
```

## Test Suite Overview

This comprehensive test suite validates Ed25519-SHA256 signature support in libopendkim, focusing on algorithm-specific behaviors that differ from RSA implementations.

### Total Test Coverage

| Test File | Tests | Focus Area | Status |
|-----------|-------|------------|--------|
| t-test50ED25519.c | 4 | Core signing/verification | ✓ Complete |
| t-test51ED25519.c | 5 | Key format validation | ✓ Complete |
| t-test52ED25519.c | 4 | DNS record parsing | ✓ Complete |
| t-test53ED25519.c | 5 | Edge cases | ✓ Complete |
| t-test54ED25519.c | Benchmarks | Performance comparison | ✓ Complete |
| t-test55ED25519.c | 7 | Chunked processing | ✓ Complete |
| **TOTAL** | **25+** | **All Ed25519 aspects** | **✓ Ready** |

---

## Detailed Test Descriptions

### t-test50ED25519.c - Core Signing & Verification (4 tests)

**Purpose**: Validate that Ed25519 signing and verification work correctly for all DKIM canonicalization combinations.

**Why This Matters**: Ed25519 operates on raw message data (not pre-hashed like RSA), so proper canonicalization is critical. Any byte-level differences will cause signature failures.

**Tests**:
1. **simple/simple** - No normalization, byte-for-byte preservation
2. **simple/relaxed** - Simple headers, relaxed body
3. **relaxed/simple** - Relaxed headers, simple body
4. **relaxed/relaxed** - Full whitespace normalization

**What Gets Tested**:
- Ed25519 signature generation
- Ed25519 signature verification
- Canonicalization consistency
- Signature header formatting
- Algorithm tag detection (a=ed25519-sha256)

**Expected Behavior**: All 4 canonicalization modes should pass. If simple/simple fails while others pass, this indicates a canonicalization bug (see known issues in project docs).

**Sample Output**:
```
*** Ed25519 Core Signing & Verification Tests ***

Testing Ed25519 with simple/simple canonicalization...
PASS: Ed25519 simple/simple verification succeeded
Testing Ed25519 with simple/relaxed canonicalization...
PASS: Ed25519 simple/relaxed verification succeeded
Testing Ed25519 with relaxed/simple canonicalization...
PASS: Ed25519 relaxed/simple verification succeeded
Testing Ed25519 with relaxed/relaxed canonicalization...
PASS: Ed25519 relaxed/relaxed verification succeeded

=== Test Results ===
Tests passed: 4/4
SUCCESS: All Ed25519 canonicalization tests passed
```

---

### t-test51ED25519.c - Key Format Tests (5 tests)

**Purpose**: Validate Ed25519-specific key requirements and ensure proper rejection of invalid keys.

**Why This Matters**: Ed25519 keys have strict format requirements (32 bytes, no ASN.1 wrapping) that differ from RSA. Invalid keys must be caught early to prevent security issues.

**Tests**:
1. **Valid key** (32 bytes) - Should accept and sign
2. **Short key** (< 32 bytes) - Should reject
3. **Long key** (> 32 bytes) - Should reject
4. **Invalid base64** - Should reject
5. **Signature format** - Should produce 64-byte signatures

**What Gets Tested**:
- Key size validation (must be exactly 32 bytes)
- Base64 decoding validation
- Key bit size reporting (256 bits)
- Signature size consistency (64 bytes)
- Error handling for malformed keys

**Ed25519 Key Format Requirements**:
```
Raw key:     32 bytes (256 bits)
Base64:      44 characters (without padding) or 45 (with =)
DNS format:  v=DKIM1; k=ed25519; p=<44-char-base64>
```

**Expected Behavior**: Valid keys accepted, all invalid keys rejected with appropriate error codes.

---

### t-test52ED25519.c - DNS Record Tests (4 tests)

**Purpose**: Validate proper parsing of Ed25519 DNS TXT records and detection of algorithm mismatches.

**Why This Matters**: DNS records specify the key type with `k=ed25519`. Mismatches between DNS records and signature algorithms must be detected to prevent security bypasses.

**Tests**:
1. **Valid DNS with k=ed25519** - Should work
2. **Missing k= tag** - Should default to RSA and fail/warn
3. **Wrong k=rsa tag** - Should detect mismatch and fail
4. **Extra DNS tags** (t=s, n=note) - Should ignore and work

**What Gets Tested**:
- k=ed25519 tag parsing
- Algorithm mismatch detection
- DNS tag order independence
- Tolerance for extra/unknown tags
- Proper DNS TXT record format

**DNS Record Examples**:
```dns
; Valid Ed25519 record
selector._domainkey.example.com. IN TXT (
    "v=DKIM1; k=ed25519; "
    "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" )

; Invalid - k=rsa with Ed25519 key
selector._domainkey.example.com. IN TXT (
    "v=DKIM1; k=rsa; "
    "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=" )
```

---

### t-test53ED25519.c - Edge Cases (5 tests)

**Purpose**: Ensure Ed25519 handles unusual but valid message formats without failures.

**Why This Matters**: Real-world email contains edge cases that must be handled correctly. Ed25519's raw data processing makes it sensitive to these cases.

**Tests**:
1. **Empty body** - Messages with no body content
2. **Very long headers** (>1000 chars) - Folded headers
3. **Whitespace variations** - Tabs, multiple spaces, mixed
4. **Large messages** (10KB body) - Memory and buffer handling
5. **Binary content** - Non-ASCII bytes in body

**What Gets Tested**:
- Empty body hash computation
- Header folding and wrapping
- Whitespace normalization in relaxed mode
- Memory allocation for large messages
- Binary data handling

**Critical Edge Cases**:
```
Empty body:         bh= hash of empty string
Long header:        Proper header folding (CRLF + space)
Whitespace:         Tabs → spaces, multiple → single (relaxed)
Large message:      No buffer overflows
Binary content:     Preserved in simple canonicalization
```

---

### t-test54ED25519.c - Performance Comparison (Benchmarks)

**Purpose**: Quantify Ed25519 performance advantages over RSA-2048.

**Why This Matters**: Performance is a key reason to adopt Ed25519. These benchmarks validate the expected improvements.

**Tests**:
1. **Signing speed** (100 iterations)
2. **Verification speed** (100 iterations)
3. **Message size scaling** (100B → 100KB)

**Metrics Collected**:
- Operations per second
- Average latency (microseconds)
- Speedup factor vs RSA
- Memory usage patterns

**Expected Performance** (typical hardware):
```
Operation          Ed25519      RSA-2048     Speedup
---------          -------      --------     -------
Signing            2-5ms        10-50ms      5-10x
Verification       2-5ms        3-10ms       2-3x
Signature size     64 bytes     256 bytes    4x smaller
Key size           32 bytes     256 bytes    8x smaller
```

**Sample Output**:
```
*** Ed25519 Performance Comparison Tests ***

=== Signing Performance ===
Testing Ed25519 signing speed (100 iterations)...
  Completed: 100/100 successful
  Total time: 234,567 μs
  Average per operation: 2,345.67 μs
  Operations per second: 426.32

Testing RSA-SHA256 signing speed (100 iterations)...
  Total time: 1,234,567 μs
  Average per operation: 12,345.67 μs
  Operations per second: 81.00

Signing speedup: 5.27x

=== Performance Summary ===
Ed25519 vs RSA-SHA256 (2048-bit):
  Signing:      5.27x faster
  Verification: 3.45x faster
```

---

### t-test55ED25519.c - Chunked Processing (7 tests)

**Purpose**: Validate Ed25519 signature stability when messages are delivered in chunks (simulating real MTA behavior).

**Why This Matters**: MTAs deliver messages incrementally. Ed25519 must produce identical signatures regardless of how the message is chunked during processing.

**Tests**:
1. **1-byte chunks** - Extreme fragmentation
2. **16-byte chunks** - Small chunks
3. **64-byte chunks** - Medium chunks
4. **1KB chunks** - Large chunks
5. **Mismatched chunks** - Sign with 10B, verify with 37B
6. **Byte-by-byte signing** - Sign 1 byte at a time, verify all at once
7. **Chunked headers** - Folded headers delivered in parts

**What Gets Tested**:
- Chunk size independence
- Signature determinism
- Buffer management
- State maintenance across chunks
- Header folding handling

**Critical Requirement**: The signature must be **identical** regardless of chunk boundaries. This is guaranteed by proper buffering and state management.

---

## Running the Tests

### Basic Execution

```bash
# Run all tests with summary
./run-ed25519-tests.sh

# Run only core tests (skip performance)
./run-ed25519-tests.sh --quick

# Run only performance benchmarks
./run-ed25519-tests.sh --perf-only

# Verbose output (show all test details)
./run-ed25519-tests.sh --verbose
```

### Individual Test Execution

```bash
# Run specific test
./t-test50ED25519

# Run with debugging
DKIM_DEBUG=1 ./t-test50ED25519

# Run with valgrind (memory check)
valgrind --leak-check=full ./t-test50ED25519

# Run with gdb (debugger)
gdb ./t-test50ED25519
```

### Using Make

```bash
# Build all Ed25519 tests
make check-ed25519

# Run performance benchmarks
make bench-ed25519

# Clean Ed25519 test binaries
make clean-local-ed25519
```

---

## Troubleshooting

### Problem: All tests fail with "key not found"

**Cause**: Test keyfile not created or Ed25519 keys missing

**Solution**:
```bash
./t-setup
cat /var/tmp/testkeys | grep -i ed25519
```

Expected keyfile entry:
```
ed25519-sha256._domainkey.example.com v=DKIM1; k=ed25519; p=<base64-key>
```

---

### Problem: "Algorithm not supported" errors

**Cause**: Library not compiled with Ed25519 support

**Solution**:
```bash
# Check if Ed25519 is enabled
./opendkim -V | grep -i ed25519

# Rebuild with Ed25519
./configure --enable-ed25519 --with-openssl=/usr
make clean && make
```

**Requirements**:
- OpenSSL 1.1.1 or later
- `--enable-ed25519` configure flag

---

### Problem: Simple canonicalization tests fail

**Cause**: Known bug in Ed25519 simple canonicalization (if applicable)

**Solution**: This is a known issue documented in the project. Use relaxed canonicalization for production:
```
c=relaxed/relaxed  # Recommended for Ed25519
```

**Workaround**: If you must use simple canonicalization, apply the canonicalization fix documented in the project knowledge.

---

### Problem: Performance tests show no speedup

**Cause**: System load, debug build, or hardware limitations

**Checks**:
```bash
# Check build flags
./opendkim -V | grep -i debug

# Check system load
top

# Check OpenSSL version
openssl version
```

**Solution**: Run on dedicated hardware, use release build, ensure OpenSSL 1.1.1+

---

## Success Criteria

### Minimum Pass Requirements

✓ All 25+ tests pass (except known issues)  
✓ No memory leaks (valgrind clean)  
✓ No segmentation faults  
✓ Ed25519 shows measurable performance advantage over RSA  

### Quality Indicators

✓ **Deterministic**: Same input → same signature every time  
✓ **Chunk-independent**: Signature unchanged regardless of chunking  
✓ **Compatible**: Works with relaxed/relaxed canonicalization  
✓ **Fast**: 2-10x faster than RSA for most operations  

---

## Integration with Existing Tests

### Relationship to Dual-Algorithm Tests

The Ed25519-specific tests (t-test50-55ED25519.c) complement the dual-algorithm tests (t-test00-06DUAL.c):

| Test Type | Purpose | Files |
|-----------|---------|-------|
| **Dual tests** | Cross-algorithm compatibility | t-test*DUAL.c |
| **Ed25519 tests** | Algorithm-specific validation | t-test*ED25519.c |

**Both test suites are needed** for complete Ed25519 validation.

### Test Execution Order

1. **Setup**: `./t-setup` (creates keys)
2. **Ed25519-specific**: `./run-ed25519-tests.sh` (validates Ed25519 features)
3. **Dual-algorithm**: Run dual tests (validates RSA/Ed25519 parity)
4. **Cleanup**: `./t-cleanup` (removes test files)

---

## Known Issues and Workarounds

### Issue #1: Simple Canonicalization May Fail

**Status**: Known bug (documented in project)

**Affected**: t-test50ED25519.c - simple/simple test

**Symptom**: Ed25519 fails simple/simple while RSA passes

**Cause**: Ed25519 uses raw data (not hashed), exposing canonicalization bugs that RSA's pre-hashing masks

**Workaround**: Use relaxed/relaxed canonicalization in production

**Fix**: Apply canonicalization patch (see project docs)

---

### Issue #2: DNS Lookup with File Backend

**Status**: Design limitation

**Affected**: All tests using DKIM_QUERY_FILE

**Behavior**: Tests use /var/tmp/testkeys instead of real DNS

**Impact**: DNS-specific issues (timeouts, NXDOMAIN, etc.) not tested

**Workaround**: Supplement with real DNS testing in staging environment

---

## Performance Benchmarking Guide

### Interpreting t-test54ED25519 Results

**Signing Performance**:
- Ed25519: Expect 1,000-5,000 ops/sec
- RSA-2048: Expect 200-1,000 ops/sec
- **Speedup**: 3-10x faster (varies by hardware)

**Verification Performance**:
- Ed25519: Expect 1,000-5,000 ops/sec
- RSA-2048: Expect 2,000-10,000 ops/sec
- **Speedup**: 1-3x faster (RSA verification is optimized)

**Message Size Scaling**:
- Both algorithms scale linearly with message size
- Ed25519 maintains consistent advantage across sizes

### Factors Affecting Performance

- **CPU**: Newer CPUs with crypto acceleration (AES-NI, etc.)
- **OpenSSL version**: 1.1.1+ has optimized Ed25519
- **System load**: Run on idle system for consistent results
- **Build flags**: Release build (-O2/-O3) vs debug (-g)

---

## Contributing

### Adding New Ed25519 Tests

1. **Create test file**: `t-test5XED25519.c`
2. **Follow naming convention**: `t-test5[0-9]ED25519`
3. **Add to Makefile**: Update `Makefile.ed25519`
4. **Document**: Add to this README
5. **Test**: Ensure it passes with existing suite

### Test Template

```c
/*
**  t-test5XED25519.c -- Brief description
**  
**  Detailed purpose and what gets tested
*/

#include "build-config.h"
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif

#include "../dkim.h"
#include "t-testdata.h"

int main(void)
{
    DKIM_LIB *lib;
    dkim_query_t qtype = DKIM_QUERY_FILE;
    uint64_t fixed_time = 1172620939;
    int tests_passed = 0;
    int tests_total = 0;

#ifdef USE_GNUTLS
    (void) gnutls_global_init();
#endif

    printf("*** Ed25519 [Test Name] Tests ***\n\n");

    lib = dkim_init(NULL, NULL);
    assert(lib != NULL);

    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_FIXEDTIME,
                        &fixed_time, sizeof fixed_time);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                        &qtype, sizeof qtype);
    (void) dkim_options(lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                        KEYFILE, strlen(KEYFILE));

    /* Run tests here */

    dkim_close(lib);

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, tests_total);

    return (tests_passed == tests_total) ? 0 : 1;
}
```

---

## References

- **RFC 8032**: EdDSA (Ed25519 specification)
- **RFC 8463**: Ed25519 for DKIM
- **RFC 6376**: DKIM base specification
- **Project Docs**: See ED25519_TEST_SUITE.md for detailed documentation

---

## Support

For issues, questions, or contributions related to the Ed25519 test suite:

1. Check this README first
2. Review ED25519_TEST_SUITE.md for details
3. Check project knowledge base
4. Report issues with full test output

---

**Last Updated**: Based on current implementation  
**Version**: 1.0  
**Status**: Production-ready