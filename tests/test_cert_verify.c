#include "../verify/cert_verify.h"
#include <stdio.h>
#include <stdlib.h>

void print_usage(const char *program_name) {
    printf("Usage: %s <command> [options]\n", program_name);
    printf("Commands:\n");
    printf("  verify <cert_file> <ca_file> [ca_path] - Verify a single certificate\n");
    printf("  chain <cert1> <cert2> ... <ca_file> [ca_path] - Verify certificate chain\n");
    printf("  ssl-client <cert_file> <ca_file> [ca_path] - Verify as SSL client certificate\n");
    printf("  ssl-server <cert_file> <ca_file> [ca_path] - Verify as SSL server certificate\n");
    printf("  no-time-check <cert_file> <ca_file> [ca_path] - Verify without time checking\n");
    printf("\nExamples:\n");
    printf("  %s verify client.crt ca.crt\n", program_name);
    printf("  %s chain client.crt intermediate.crt ca.crt\n", program_name);
    printf("  %s ssl-client client.crt ca.crt /etc/ssl/certs\n", program_name);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[1];
    int result = 0;
    
    if (strcmp(command, "verify") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: verify command requires cert_file and ca_file\n");
            return 1;
        }
        const char *cert_file = argv[2];
        const char *ca_file = argv[3];
        const char *ca_path = (argc > 4) ? argv[4] : NULL;
        
        printf("Verifying certificate: %s\n", cert_file);
        printf("Using CA file: %s\n", ca_file);
        if (ca_path) printf("Using CA path: %s\n", ca_path);
        
        result = verify_certificate(cert_file, ca_file, ca_path);
        
    } else if (strcmp(command, "chain") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Error: chain command requires at least 2 certificates and CA file\n");
            return 1;
        }
        
        int cert_count = argc - 4; // Subtract command, certificates, and CA file
        const char **cert_chain = (const char **)&argv[2];
        const char *ca_file = argv[argc - 2];
        const char *ca_path = (argc > 4) ? argv[argc - 1] : NULL;
        
        printf("Verifying certificate chain with %d certificates\n", cert_count);
        for (int i = 0; i < cert_count; i++) {
            printf("  Certificate %d: %s\n", i + 1, cert_chain[i]);
        }
        printf("Using CA file: %s\n", ca_file);
        if (ca_path) printf("Using CA path: %s\n", ca_path);
        
        result = verify_certificate_chain(cert_chain, cert_count, ca_file, ca_path);
        
    } else if (strcmp(command, "ssl-client") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: ssl-client command requires cert_file and ca_file\n");
            return 1;
        }
        const char *cert_file = argv[2];
        const char *ca_file = argv[3];
        const char *ca_path = (argc > 4) ? argv[4] : NULL;
        
        printf("Verifying SSL client certificate: %s\n", cert_file);
        printf("Using CA file: %s\n", ca_file);
        if (ca_path) printf("Using CA path: %s\n", ca_path);
        
        result = verify_certificate_with_options(cert_file, ca_file, ca_path, 
                                               X509_PURPOSE_SSL_CLIENT, 1);
        
    } else if (strcmp(command, "ssl-server") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: ssl-server command requires cert_file and ca_file\n");
            return 1;
        }
        const char *cert_file = argv[2];
        const char *ca_file = argv[3];
        const char *ca_path = (argc > 4) ? argv[4] : NULL;
        
        printf("Verifying SSL server certificate: %s\n", cert_file);
        printf("Using CA file: %s\n", ca_file);
        if (ca_path) printf("Using CA path: %s\n", ca_path);
        
        result = verify_certificate_with_options(cert_file, ca_file, ca_path, 
                                               X509_PURPOSE_SSL_SERVER, 1);
        
    } else if (strcmp(command, "no-time-check") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: no-time-check command requires cert_file and ca_file\n");
            return 1;
        }
        const char *cert_file = argv[2];
        const char *ca_file = argv[3];
        const char *ca_path = (argc > 4) ? argv[4] : NULL;
        
        printf("Verifying certificate (no time check): %s\n", cert_file);
        printf("Using CA file: %s\n", ca_file);
        if (ca_path) printf("Using CA path: %s\n", ca_path);
        
        result = verify_certificate_with_options(cert_file, ca_file, ca_path, 
                                               X509_PURPOSE_ANY, 0);
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    if (result) {
        printf("Certificate verification completed successfully\n");
        return 0;
    } else {
        printf("Certificate verification failed\n");
        return 1;
    }
} 