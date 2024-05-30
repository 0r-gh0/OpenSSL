#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 6969
#define HOST "127.0.0.1"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "key/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    int sock;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;

    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(HOST);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        while (1) {
            char buf[1024];
            printf("Enter a number or text (enter -1 to disconnect): ");
            fgets(buf, sizeof(buf), stdin);
            buf[strcspn(buf, "\n")] = 0; // Remove newline character

            if (SSL_write(ssl, buf, strlen(buf)) <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }

            if (strcmp(buf, "-1") == 0) {
                printf("Disconnecting...\n");
                break;
            }

            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes > 0) {
                buf[bytes] = 0;
                printf("Received: \"%s\"\n", buf);
            } else {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
