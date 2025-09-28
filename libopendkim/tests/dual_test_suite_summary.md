# Dual Algorithm DKIM Test Suite

This comprehensive test suite validates RSA-SHA256 and Ed25519-SHA256 DKIM implementations for real-world email interoperability. Unlike traditional crypto-focused tests, these tests emphasize practical email scenarios and cross-algorithm compatibility.

## Test Coverage Overview

### Core Functionality Tests

**t-test00NEWER.c** - Basic dual algorithm verification
- ✅ **PASSED** - Both algorithms sign and verify identical messages
- Tests: Basic signing, verification, relaxed/relaxed canonicalization
- Coverage: Fundamental algorithm compatibility

**t-test01DUAL.c** - Canonicalization compatibility  
- Tests: All 4 canonicalization combinations (simple/simple, simple/relaxed, relaxed/simple, relaxed/relaxed)
- Focus: Whitespace handling consistency between algorithms
- Expected: 8 tests (4 canonicalizations × 2 algorithms)

**t-test02DUAL.c** - Header handling
- Tests: Folded headers, multiple headers, header ordering, special characters
- Focus: Real email header scenarios and RFC compliance
- Expected: 8 tests (4 scenarios × 2 algorithms)

**t-test03DUAL.c** - Body processing
- Tests: Empty bodies, large bodies, binary content, line endings
- Focus: Message content handling across algorithms
- Expected: 12 tests (6 scenarios × 2 algorithms)

### Advanced Scenarios

**t-test04DUAL.c** - Chunked processing
- Tests: Various chunk sizes simulating MTA behavior
- Focus: Incremental message processing compatibility
- Expected: 10 tests (5 chunking patterns × 2 algorithms)

**t-test05DUAL.c** - Multiple signatures
- Tests: Messages with both RSA and Ed25519 signatures
- Focus: Dual-deployment strategy validation
- Expected: 2 tests (signature order variations)

**t-test06DUAL.c** - Interoperability edge cases
- Tests: Minimal messages, complex headers, real-world patterns
- Focus: Production email compatibility
- Expected: 10 tests (5 scenarios × 2 algorithms)

## Key Differences from Original Test Suite

### What These Tests Add

1. **Ed25519 Coverage** - First Ed25519 tests in the suite
2. **Cross-Algorithm Validation** - Both algorithms tested on identical content
3. **Real-World Focus** - Email scenarios vs crypto edge cases
4. **Interoperability Testing** - Production deployment validation

### What These Tests Replace/Extend

| Original Test | Our Enhancement | Improvement |
|---------------|-----------------|-------------|
| t-test00.c (RSA-SHA1 basic) | t-test00NEWER.c | Modern algorithms, dual testing |
| t-test01.c (RSA verification) | t-test01DUAL.c | All canonicalizations, both algorithms |
| t-test02.c (RSA simple/relaxed) | t-test02DUAL.c | Complex headers, both algorithms |
| Various body tests | t-test03DUAL.c | Comprehensive body scenarios |
| No chunked tests | t-test04DUAL.c | MTA simulation |
| No multi-sig tests | t-test05DUAL.c | Dual deployment |
| Limited edge cases | t-test06DUAL.c | Real-world interoperability |

## Strategic Value

### For Development
- **Algorithm Parity**: Ensures both algorithms behave identically
- **Regression Testing**: Catches differences introduced by changes
- **Performance Comparison**: Same workload, different algorithms

### For Deployment
- **Migration Confidence**: RSA→Ed25519 transition validation
- **Dual Signing**: Both algorithms can coexist
- **Compatibility Assurance**: Works with real email infrastructure

### For Standards Compliance
- **RFC 8463 Validation**: Ed25519 DKIM specification compliance
- **RFC 6376 Compatibility**: Traditional DKIM behavior preservation
- **Interoperability**: Cross-implementation compatibility

## Test Execution

### Prerequisites
```bash
# Run setup to create keyfiles
./t-setup

# Verify keyfile contains both algorithm entries
cat /var/tmp/testkeys | grep -E "(test\._domainkey|ed25519-sha256\._domainkey)"
```

### Running Individual Tests
```bash
# Basic dual algorithm test
./t-test00NEWER

# Canonicalization compatibility
./t-test01DUAL

# Header handling
./t-test02DUAL

# Body processing  
./t-test03DUAL

# Chunked processing
./t-test04DUAL

# Multiple signatures
./t-test05DUAL

# Interoperability
./t-test06DUAL
```

### Expected Results
- **Total Tests**: ~50 individual test cases
- **Success Rate**: 100% for compliant implementations
- **Failure Analysis**: Any failures indicate algorithm compatibility issues

## Implementation Notes

### Key Setup Requirements
- RSA key: Uses existing `KEY` and `SELECTOR` constants
- Ed25519 key: Uses `KEYED25519` and `SELECTORED25519` constants
- File-based DNS: Uses `KEYFILE` path with proper key format

### Common Failure Patterns
1. **DNS Lookup Issues**: Keyfile format or path problems
2. **Key Mismatches**: Private keys don't match public keys in keyfile
3. **Algorithm Detection**: Library doesn't recognize Ed25519
4. **Canonicalization Differences**: Algorithms handle whitespace differently

### Debugging Tools
- Debug tests included for DNS lookup verification
- Key matching validation scripts
- Step-by-step verification tracing

## Future Extensions

### Additional Test Scenarios
- **Performance benchmarking** between algorithms
- **Memory usage comparison** during processing
- **Signature size analysis** (Ed25519 vs RSA)
- **Error handling consistency** across algorithms

### Integration Testing
- **Mail server integration** with real MTAs
- **Multi-domain scenarios** with different selectors
- **Key rollover procedures** for both algorithms
- **DNSSEC validation** with Ed25519 keys

This test suite establishes the foundation for reliable dual-algorithm DKIM deployment and provides confidence in cross-algorithm compatibility for production email systems.