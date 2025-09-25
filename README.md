# TLS Certificate Fuzzer

A penetration testing tool for testing TLS certificate handling vulnerabilities in server applications.

## ⚠️ Legal Notice

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for legitimate security testing by authorized penetration testers. Only use this tool on systems you own or have explicit written permission to test.

## Features

- Tests for format string vulnerabilities in certificate logging
- Tests for command injection vulnerabilities
- Tests for buffer overflow conditions
- Supports mutation of valid client certificates
- Comprehensive reporting of findings

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic usage (generates self-signed certificate):
```bash
python tls_cert_fuzzer.py target.example.com 443 -v
```

### With valid client certificate:
```bash
python tls_cert_fuzzer.py target.example.com 443 \
  -c /path/to/client.pem \
  -k /path/to/client_key.pem \
  -v -o results.json
```

### With CA certificate verification:
```bash
python tls_cert_fuzzer.py target.example.com 443 \
  -c client.pem \
  -k client_key.pem \
  --ca-cert ca.pem \
  -v
```

## Options

- `-c, --client-cert`: Path to valid client certificate (PEM format)
- `-k, --client-key`: Path to client private key (PEM format)
- `--ca-cert`: Path to CA certificate for server verification
- `-v, --verbose`: Enable verbose output
- `-o, --output`: Output JSON report file (default: fuzzing_report.json)
- `--timeout`: Connection timeout in seconds (default: 5)

## What It Tests

The fuzzer mutates the following certificate fields:
- Common Name (CN)
- Organization (O)
- Email Address
- Subject Alternative Name (SAN)

With these payload types:
- **Format strings**: `%s`, `%p`, `%n`, etc.
- **Command injection**: Shell metacharacters and command substitution
- **Buffer overflows**: Long strings and special encodings

## Output

Results are saved to a JSON report containing:
- Summary statistics
- Interesting findings (crashes, timeouts, unusual errors)
- Complete test results for analysis

## Responsible Disclosure

If you discover vulnerabilities using this tool:
1. Do not exploit them beyond validation
2. Report them to the vendor/owner immediately
3. Follow responsible disclosure practices
4. Allow reasonable time for patching

## License

MIT License - See LICENSE file for details