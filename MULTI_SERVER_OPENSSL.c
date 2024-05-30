#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/wait.h>

#define PORT 4433

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

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "key/certificate.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key/private_key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }

    /* Load and verify client certificates */
    if (SSL_CTX_load_verify_locations(ctx, "key/ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

void handle_client(SSL *ssl) {
    const int read_size = 1024;
    char buf[read_size];
    int bytes;

    while (1) {
        bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0) {
            buf[bytes] = 0;
            printf("Received from client: \"%s\"\n", buf);
            
            if (strcmp(buf, "-1") == 0) {
                printf("Client disconnected.\n");
                break;
            }

            int num;
            if (sscanf(buf, "%d", &num) == 1) {
                num += 5;
                sprintf(buf, "%d", num);
            }

            if (SSL_write(ssl, buf, strlen(buf)) <= 0) {
                ERR_print_errors_fp(stderr);
                break;
            }
        } else {
            ERR_print_errors_fp(stderr);
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void sigchld_handler(int signo) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char **argv) {
    int sock;
    struct sockaddr_in addr;
    SSL_CTX *ctx;

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
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, sigchld_handler); // Handle terminated child processes

    while (1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (fork() == 0) { // Child process
            close(sock);
            handle_client(ssl);
            close(client);
            exit(0);
        } else { // Parent process
            close(client);
        }
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
