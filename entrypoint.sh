#!/bin/sh
set -e

SERVER="127.0.0.1:5000"
PATH_ISSUING="/issuing"
MSG_TIMEOUT=10
SECRET="pass:SiemensIT"
REF="client1"
CLIENT_KEY="/tmp/client.key"
CERTOUT="/tmp/enrolled.crt"

COMMON_FLAGS="-server ${SERVER} \
  -msg_timeout ${MSG_TIMEOUT} \
  -unprotected_requests -unprotected_errors -ignore_keyusage \
  -secret ${SECRET} \
  -ref ${REF}"

echo "=== OpenSSL Version ==="
openssl version -a

# ---------------------------------------------------------------------------
# send_ir: Initial Request — enroll a new certificate using CMP IR.
#
# Usage:
#   ./entrypoint.sh send_ir [nonce_req_length] [nonce_seq_size]
#
# Arguments (all optional):
#   nonce_req_length  Length in bytes of the nonce to request (default: 32,
#                     pass 0 to let the server choose).
#   nonce_seq_size    Number of NonceRequest entries to include in the
#                     preceding genm (default: 1, must be >= 1).
#
# Examples:
#   ./entrypoint.sh send_ir            # 32-byte nonce, 1 NonceRequest entry
#   ./entrypoint.sh send_ir 32         # explicitly 32-byte nonce
#   ./entrypoint.sh send_ir 16 2       # 16-byte nonce, 2 NonceRequest entries
# ---------------------------------------------------------------------------
send_ir() {
    NONCE_LEN="${1:-32}"
    NONCE_SEQ="${2:-1}"

    echo ""
    echo "=== Generating client key ==="
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${CLIENT_KEY}"

    echo ""
    echo "=== Sending CMP IR to Mock CA ==="
    echo "    server            : ${SERVER}"
    echo "    nonce_req_length  : ${NONCE_LEN}"
    echo "    nonce_seq_size    : ${NONCE_SEQ}"
    echo "    certout           : ${CERTOUT}"

    openssl cmp \
        -cmd ir \
        ${COMMON_FLAGS} \
        -newkey "${CLIENT_KEY}" \
        -subject "/CN=test" \
        -rats \
        -path "issuing" \
        -nonce_req_length "${NONCE_LEN}" \
        -nonce_seq_size "${NONCE_SEQ}" \
        -certout "${CERTOUT}"
        -verbosity 8

    echo ""
    echo "=== IR completed successfully. Certificate stored at ${CERTOUT} ==="
}

# ---------------------------------------------------------------------------
# send_genm: General Message — send a standalone CMP genm (e.g. to fetch a
#            freshness nonce as defined in draft-ietf-lamps-attestation-freshness).
#
# Usage:
#   ./entrypoint.sh send_genm [nonce_req_length] [nonce_seq_size]
#
# Arguments (all optional):
#   nonce_req_length  Length in bytes of the nonce to request (default: 32,
#                     pass 0 to let the server choose).
#   nonce_seq_size    Number of NonceRequest entries to send (default: 1,
#                     must be >= 1).
#
# Examples:
#   ./entrypoint.sh send_genm            # 32-byte nonce, 1 NonceRequest entry
#   ./entrypoint.sh send_genm 32         # explicitly 32-byte nonce
#   ./entrypoint.sh send_genm 16 2       # 16-byte nonce, 2 NonceRequest entries
# ---------------------------------------------------------------------------
send_genm() {
    NONCE_LEN="${1:-32}"
    NONCE_SEQ="${2:-1}"

    echo ""
    echo "=== Sending CMP General Message (genm) to Mock CA ==="
    echo "    server            : ${SERVER}"
    echo "    nonce_req_length  : ${NONCE_LEN}"
    echo "    nonce_seq_size    : ${NONCE_SEQ}"

    openssl cmp \
        -cmd genm \
        ${COMMON_FLAGS} \
        -rats \
        -path "issuing" \
        -nonce_req_length ${NONCE_LEN} \
        -nonce_seq_size ${NONCE_SEQ}

    echo ""
    echo "=== genm completed successfully ==="
}

# ---------------------------------------------------------------------------
# run_tests: Run all CMP-related OpenSSL test cases.
#
# Usage:
#   ./entrypoint.sh test
#
# Runs every test recipe whose name matches "*cmp*" using the OpenSSL
# make test harness.  This covers:
#   65-test_cmp_asn      – ASN.1 encode/decode
#   65-test_cmp_ctx      – CMP_CTX API
#   65-test_cmp_hdr      – CMP header construction
#   65-test_cmp_msg      – CMP message building
#   65-test_cmp_protect  – message protection
#   65-test_cmp_server   – server-side logic
#   65-test_cmp_status   – status handling
#   65-test_cmp_vfy      – verification
#   65-test_cmp_client   – client integration
#   80-test_cmp_http     – HTTP transport
#   81-test_cmp_cli      – command-line interface
#   99-test_fuzz_cmp     – fuzz corpus replay
# ---------------------------------------------------------------------------
run_tests() {
    echo ""
    echo "=== Running all CMP test cases ==="
    cd /root/openssl
    make test TESTS="*cmp*"
    echo ""
    echo "=== All CMP tests finished ==="
}

# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------
COMMAND="${1:-}"
shift 2>/dev/null || true

case "${COMMAND}" in
    send_ir)
        send_ir "$@"
        ;;
    send_genm)
        send_genm "$@"
        ;;
    test)
        run_tests
        ;;
    "")
        echo "Usage: entrypoint.sh <command> [args...]"
        echo ""
        echo "Commands:"
        echo "  send_ir   [nonce_req_length] [nonce_seq_size]"
        echo "            Send a CMP Initial Request (ir) to enroll a new certificate."
        echo ""
        echo "  send_genm [nonce_req_length] [nonce_seq_size]"
        echo "            Send a CMP General Message (genm) to request a freshness nonce"
        echo "            as defined in draft-ietf-lamps-attestation-freshness."
        echo ""
        echo "  test"
        echo "            Run all CMP-related OpenSSL test cases (make test TESTS='*cmp*')."
        echo ""
        echo "If no command is given both scenarios are run in sequence."
        echo ""
        echo "Running both scenarios now..."
        send_genm
        send_ir
        ;;
    *)
        echo "Error: unknown command '${COMMAND}'"
        echo "Valid commands: send_ir, send_genm, test"
        exit 1
        ;;
esac

