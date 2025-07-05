#ifndef CERT_VERIFY_H
#define CERT_VERIFY_H

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>

/**
 * Verify a certificate against a certificate store
 * @param cert_file Path to the certificate file to verify
 * @param ca_file Path to the CA certificate file (trusted certificates)
 * @param ca_path Path to directory containing CA certificates (optional, can be NULL)
 * @return 1 if verification successful, 0 if failed
 */
int verify_certificate(const char *cert_file, const char *ca_file, const char *ca_path);

/**
 * Verify a certificate chain
 * @param cert_chain Array of certificate files forming a chain
 * @param cert_count Number of certificates in the chain
 * @param ca_file Path to the CA certificate file
 * @param ca_path Path to directory containing CA certificates (optional, can be NULL)
 * @return 1 if verification successful, 0 if failed
 */
int verify_certificate_chain(const char **cert_chain, int cert_count, 
                           const char *ca_file, const char *ca_path);

/**
 * Verify certificate with additional verification options
 * @param cert_file Path to the certificate file to verify
 * @param ca_file Path to the CA certificate file
 * @param ca_path Path to directory containing CA certificates (optional, can be NULL)
 * @param purpose Purpose for verification (e.g., X509_PURPOSE_SSL_CLIENT, X509_PURPOSE_SSL_SERVER)
 * @param check_time Whether to check certificate validity time
 * @return 1 if verification successful, 0 if failed
 */
int verify_certificate_with_options(const char *cert_file, const char *ca_file, 
                                  const char *ca_path, int purpose, int check_time);

/**
 * Print verification errors to stderr
 * @param ctx X509_STORE_CTX containing verification context
 */
void print_verification_errors(X509_STORE_CTX *ctx);

#endif /* CERT_VERIFY_H */ 