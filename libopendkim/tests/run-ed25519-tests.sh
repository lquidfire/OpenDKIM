#!/bin/bash
#
# run-ed25519-tests.sh - Execute Ed25519 DKIM test suite
#
# Usage: ./run-ed25519-tests.sh [options]
#
# Options:
#   -v, --verbose    Enable verbose output
#   -q, --quick      Run only core tests (skip performance)
#   -p, --perf-only  Run only performance tests
#   -h, --help       Show this help message

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERBOSE=0
QUICK=0
PERF_ONLY=0
TEST_DIR="$(cd "$(dirname "$0")" && pwd)"

# Test lists
CORE_TESTS=(
    "t-test50ED25519"  # Core signing/verification
    "t-test51ED25519"  # Key formats
    "t-test52ED25519"  # DNS records
)

EXTENDED_TESTS=(
    "t-test53ED25519"  # Edge cases
    "t-test55ED25519"  # Chunked processing
)

PERF_TESTS=(
    "t-test54ED25519"  # Performance comparison
)

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -q|--quick)
                QUICK=1
                shift
                ;;
            -p|--perf-only)
                PERF_ONLY=1
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
Usage: $0 [options]

Execute the Ed25519 DKIM test suite.

Options:
    -v, --verbose    Enable verbose output
    -q, --quick      Run only core tests (skip performance)
    -p, --perf-only  Run only performance tests
    -h, --help       Show this help message

Examples:
    $0                 # Run all tests
    $0 --quick         # Run core tests only
    $0 --perf-only     # Run performance benchmarks only
    $0 --verbose       # Run all tests with verbose output

EOF
}

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Check prerequisites
check_prereqs() {
    print_msg "$BLUE" "=== Checking Prerequisites ==="

    # Check if we're in the tests directory
    if [[ ! -f "t-testdata.h" ]]; then
        print_msg "$RED" "ERROR: Must be run from libopendkim/tests directory"
        exit 1
    fi

    # Check if t-setup has been run
    if [[ ! -f "/var/tmp/testkeys" ]]; then
        print_msg "$YELLOW" "WARNING: /var/tmp/testkeys not found"
        print_msg "$YELLOW" "Running t-setup to create test keys..."
        if [[ -x "./t-setup" ]]; then
            ./t-setup
            print_msg "$GREEN" "✓ Test keys created"
        else
            print_msg "$RED" "ERROR: t-setup not found or not executable"
            exit 1
        fi
    else
        print_msg "$GREEN" "✓ Test keyfile exists"
    fi

    # Check if Ed25519 keys are in keyfile
    if grep -q "ed25519" /var/tmp/testkeys 2>/dev/null; then
        print_msg "$GREEN" "✓ Ed25519 keys found in keyfile"
    else
        print_msg "$YELLOW" "WARNING: Ed25519 keys not found in keyfile"
        print_msg "$YELLOW" "Tests may fail if keys are not properly configured"
    fi

    echo
}

# Run a single test
run_test() {
    local test_name=$1
    local test_path="${TEST_DIR}/${test_name}"

    if [[ ! -x "$test_path" ]]; then
        print_msg "$YELLOW" "⊘ SKIP: $test_name (not found or not executable)"
        return 2
    fi

    print_msg "$BLUE" "▶ Running: $test_name"

    if [[ $VERBOSE -eq 1 ]]; then
        "$test_path"
        local result=$?
    else
        local output=$("$test_path" 2>&1)
        local result=$?

        if [[ $result -ne 0 ]]; then
            echo "$output"
        fi
    fi

    if [[ $result -eq 0 ]]; then
        print_msg "$GREEN" "✓ PASS: $test_name"
        return 0
    else
        print_msg "$RED" "✗ FAIL: $test_name (exit code: $result)"
        return 1
    fi
}

# Run test suite
run_test_suite() {
    local suite_name=$1
    shift
    local tests=("$@")
    local passed=0
    local failed=0
    local skipped=0

    print_msg "$BLUE" "\n=== $suite_name ==="

    for test in "${tests[@]}"; do
        run_test "$test"
        case $? in
            0) ((passed++)) ;;
            1) ((failed++)) ;;
            2) ((skipped++)) ;;
        esac
        echo
    done

    print_msg "$BLUE" "--- $suite_name Results ---"
    print_msg "$GREEN" "Passed:  $passed"
    if [[ $failed -gt 0 ]]; then
        print_msg "$RED" "Failed:  $failed"
    fi
    if [[ $skipped -gt 0 ]]; then
        print_msg "$YELLOW" "Skipped: $skipped"
    fi

    return $failed
}

# Main execution
main() {
    parse_args "$@"

    print_msg "$BLUE" "╔════════════════════════════════════════╗"
    print_msg "$BLUE" "║  Ed25519 DKIM Test Suite Runner       ║"
    print_msg "$BLUE" "╚════════════════════════════════════════╝"
    echo

    check_prereqs

    local total_failed=0

    if [[ $PERF_ONLY -eq 1 ]]; then
        # Run only performance tests
        run_test_suite "Performance Tests" "${PERF_TESTS[@]}"
        total_failed=$?
    else
        # Run core tests
        run_test_suite "Core Functionality Tests" "${CORE_TESTS[@]}"
        ((total_failed+=$?))

        if [[ $QUICK -eq 0 ]]; then
            # Run extended tests
            run_test_suite "Extended Tests" "${EXTENDED_TESTS[@]}"
            ((total_failed+=$?))

            # Run performance tests
            run_test_suite "Performance Tests" "${PERF_TESTS[@]}"
            # Don't count performance test failures in total
        fi
    fi

    # Print final summary
    echo
    print_msg "$BLUE" "╔════════════════════════════════════════╗"
    print_msg "$BLUE" "║  Final Test Summary                    ║"
    print_msg "$BLUE" "╚════════════════════════════════════════╝"

    if [[ $total_failed -eq 0 ]]; then
        print_msg "$GREEN" "✓ ALL TESTS PASSED"
        print_msg "$GREEN" "Ed25519 implementation is working correctly!"
        return 0
    else
        print_msg "$RED" "✗ $total_failed TEST(S) FAILED"
        print_msg "$RED" "Please review the failures above."
        return 1
    fi
}

# Run main with all arguments
main "$@"
exit $?
