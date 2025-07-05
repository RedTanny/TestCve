#include "cert_verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verify_certificate(const char *cert_file, const char *ca_file, const char *ca_path) {
    return verify_certificate_with_options(cert_file, ca_file, ca_path, 
                                         X509_PURPOSE_ANY, 1);
}

int verify_certificate_chain(const char **cert_chain, int cert_count, 
                           const char *ca_file, const char *ca_path) {
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    int ret = 0;
    
    if (!cert_chain || cert_count <= 0 || !ca_file) {
        fprintf(stderr, "Invalid parameters for certificate chain verification\n");
        return 0;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Create certificate store
    store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "Failed to create certificate store\n");
        goto cleanup;
    }
    
    // Load CA certificates
    if (!X509_STORE_load_locations(store, ca_file, ca_path)) {
        fprintf(stderr, "Failed to load CA certificates from %s\n", ca_file);
        goto cleanup;
    }
    
    // Create certificate chain
    chain = sk_X509_new_null();
    if (!chain) {
        fprintf(stderr, "Failed to create certificate chain\n");
        goto cleanup;
    }
    
    // Load all certificates in the chain
    for (int i = 0; i < cert_count; i++) {
        FILE *fp = fopen(cert_chain[i], "r");
        if (!fp) {
            fprintf(stderr, "Failed to open certificate file: %s\n", cert_chain[i]);
            goto cleanup;
        }
        
        X509 *temp_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        
        if (!temp_cert) {
            fprintf(stderr, "Failed to read certificate from: %s\n", cert_chain[i]);
            goto cleanup;
        }
        
        if (!sk_X509_push(chain, temp_cert)) {
            fprintf(stderr, "Failed to add certificate to chain\n");
            X509_free(temp_cert);
            goto cleanup;
        }
    }
    
    // Get the end-entity certificate (first in chain)
    cert = sk_X509_value(chain, 0);
    if (!cert) {
        fprintf(stderr, "No certificates in chain\n");
        goto cleanup;
    }
    
    // Create verification context
    ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create verification context\n");
        goto cleanup;
    }
    
    // Initialize verification context
    if (!X509_STORE_CTX_init(ctx, store, cert, chain)) {
        fprintf(stderr, "Failed to initialize verification context\n");
        goto cleanup;
    }
    
    // Perform verification
    ret = X509_verify_cert(ctx);
    if (ret != 1) {
        fprintf(stderr, "Certificate verification failed\n");
        print_verification_errors(ctx);
        ret = 0;
    } else {
        printf("Certificate chain verification successful\n");
        ret = 1;
    }
    
cleanup:
    if (ctx) X509_STORE_CTX_free(ctx);
    if (chain) sk_X509_pop_free(chain, X509_free);
    if (store) X509_STORE_free(store);
    
    EVP_cleanup();
    ERR_free_strings();
    
    return ret;
}

int verify_certificate_with_options(const char *cert_file, const char *ca_file, 
                                  const char *ca_path, int purpose, int check_time) {
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509 *cert = NULL;
    FILE *fp = NULL;
    int ret = 0;
    
    if (!cert_file || !ca_file) {
        fprintf(stderr, "Certificate file and CA file must be specified\n");
        return 0;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Create certificate store
    store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "Failed to create certificate store\n");
        goto cleanup;
    }
    
    // Load CA certificates
    if (!X509_STORE_load_locations(store, ca_file, ca_path)) {
        fprintf(stderr, "Failed to load CA certificates from %s\n", ca_file);
        goto cleanup;
    }
    
    // Set verification flags
    X509_STORE_set_flags(store, X509_V_FLAG_X509_STRICT);
    
    // Load the certificate to verify
    fp = fopen(cert_file, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open certificate file: %s\n", cert_file);
        goto cleanup;
    }
    
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) {
        fprintf(stderr, "Failed to read certificate from: %s\n", cert_file);
        goto cleanup;
    }
    
    // Create verification context
    ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create verification context\n");
        goto cleanup;
    }
    
    // Initialize verification context
    if (!X509_STORE_CTX_init(ctx, store, cert, NULL)) {
        fprintf(stderr, "Failed to initialize verification context\n");
        goto cleanup;
    }
    
    // Set verification purpose
    if (purpose != X509_PURPOSE_ANY) {
        X509_STORE_CTX_set_purpose(ctx, purpose);
    }
    
    // Set verification time (current time if check_time is true)
    if (check_time) {
        X509_STORE_CTX_set_time(ctx, 0, time(NULL));
    } else {
        // Disable time checking
        X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_NO_CHECK_TIME);
    }
    
    // Perform verification using X509_verify_cert
    ret = X509_verify_cert(ctx);
    if (ret != 1) {
        fprintf(stderr, "Certificate verification failed\n");
        print_verification_errors(ctx);
        ret = 0;
    } else {
        printf("Certificate verification successful\n");
        ret = 1;
    }
    
cleanup:
    if (ctx) X509_STORE_CTX_free(ctx);
    if (cert) X509_free(cert);
    if (store) X509_STORE_free(store);
    
    EVP_cleanup();
    ERR_free_strings();
    
    return ret;
}

void print_verification_errors(X509_STORE_CTX *ctx) {
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    
    fprintf(stderr, "Verification error at depth %d: %s\n", 
            depth, X509_verify_cert_error_string(err));
    
    if (cert) {
        X509_NAME *name = X509_get_subject_name(cert);
        char subject[256];
        X509_NAME_oneline(name, subject, sizeof(subject));
        fprintf(stderr, "Certificate subject: %s\n", subject);
    }
    
    // Print additional error information
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "OpenSSL error: %s\n", err_buf);
    }
} 