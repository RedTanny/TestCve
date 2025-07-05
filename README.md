# TestCVE

This project contains two main components:

## 1. Hash Generator and Server Communication
A simple C program that:
- Takes an input string (key)
- Generates a SHA256 hash using OpenSSL
- Sends the hash to a server using libcurl via an HTTP POST request (REST API style: `save=key`)

## 2. Certificate Verification Module
A comprehensive certificate verification module using OpenSSL's `X509_verify_cert` function that provides:
- Single certificate verification
- Certificate chain verification
- SSL client/server certificate verification
- Configurable verification options (purpose, time checking)
- Detailed error reporting

## Project Structure

```
TestCve/
├── main.c                 # Main hash generation and server communication program
├── Makefile              # Build configuration
├── README.md             # This file
├── verify/               # Certificate verification module
│   ├── cert_verify.h     # Header file for certificate verification functions
│   └── cert_verify.c     # Implementation of certificate verification using X509_verify_cert
└── tests/                # Test programs
    └── test_cert_verify.c # Test program for certificate verification functionality
```

## Requirements
- OpenSSL development libraries
- libcurl development libraries
- GCC or compatible C compiler

On Fedora/RedHat:
```
sudo dnf install openssl-devel libcurl-devel gcc
```

On Ubuntu/Debian:
```
sudo apt-get install libssl-dev libcurl4-openssl-dev build-essential
```

## Build
```
make
```

This will build both the main program (`TestCVE`) and the certificate verification test program (`test_cert_verify`).

## Usage

### Hash Generator and Server Communication
```
./TestCVE <key> <server_url>
```

- `<key>`: The input string to hash
- `<server_url>`: The URL of the server to send the hash to (e.g., `http://localhost:8080/save`)

Example:
```
./TestCVE mysecretkey http://localhost:8080/save
```

This will print the SHA256 hash and send it to the server as a POST request with the body `save=<hash>`.

### Certificate Verification Module

The certificate verification module is located in the `verify/` directory and provides several verification modes:

#### Basic Certificate Verification
```
./tests/test_cert_verify verify <cert_file> <ca_file> [ca_path]
```

#### Certificate Chain Verification
```
./tests/test_cert_verify chain <cert1> <cert2> ... <ca_file> [ca_path]
```

#### SSL Client Certificate Verification
```
./tests/test_cert_verify ssl-client <cert_file> <ca_file> [ca_path]
```

#### SSL Server Certificate Verification
```
./tests/test_cert_verify ssl-server <cert_file> <ca_file> [ca_path]
```

#### Verification Without Time Checking
```
./tests/test_cert_verify no-time-check <cert_file> <ca_file> [ca_path]
```

### Examples

```bash
# Verify a single certificate
./tests/test_cert_verify verify client.crt ca.crt

# Verify a certificate chain
./tests/test_cert_verify chain client.crt intermediate.crt ca.crt

# Verify as SSL client certificate
./tests/test_cert_verify ssl-client client.crt ca.crt /etc/ssl/certs

# Verify as SSL server certificate
./tests/test_cert_verify ssl-server server.crt ca.crt

# Verify without checking certificate validity time
./tests/test_cert_verify no-time-check expired.crt ca.crt
```

## Certificate Verification Features

The certificate verification module uses OpenSSL's `X509_verify_cert` function and provides:

- **Single Certificate Verification**: Verify a certificate against a CA bundle
- **Certificate Chain Verification**: Verify complete certificate chains
- **Purpose-Specific Verification**: Verify certificates for specific purposes (SSL client/server)
- **Flexible Time Checking**: Option to enable/disable certificate validity time checking
- **Detailed Error Reporting**: Comprehensive error messages with certificate details
- **Multiple CA Sources**: Support for both CA files and CA directories
- **Memory Management**: Proper cleanup of OpenSSL resources

## API Reference

### Functions

- `verify_certificate(cert_file, ca_file, ca_path)`: Basic certificate verification
- `verify_certificate_chain(cert_chain, cert_count, ca_file, ca_path)`: Chain verification
- `verify_certificate_with_options(cert_file, ca_file, ca_path, purpose, check_time)`: Advanced verification
- `print_verification_errors(ctx)`: Print detailed verification errors 