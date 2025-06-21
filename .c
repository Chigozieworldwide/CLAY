#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>

#define BUFFER_SIZE 16384
#define TIMEOUT_SEC 5

// Global SSL context
static SSL_CTX *ctx = NULL;

__attribute__((constructor))
static void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(ctx);
    }
}

__attribute__((destructor))
static void cleanup_openssl() {
    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
}

int contains_key(const char *response, const char *key) {
    if (!response || !key) return 0;
    
    // Create search patterns
    const char *patterns[] = {
        "\"%s\"",   // "KEY"
        "'%s'",     // 'KEY'
        " %s ",     // space padded
        "\n%s\n",   // newline padded
        "key:%s",   // key:KEY
        "key=%s",   // key=KEY
        NULL
    };
    
    // Case insensitive check
    for (int i = 0; patterns[i]; i++) {
        char pattern[256];
        snprintf(pattern, sizeof(pattern), patterns[i], key);
        
        const char *ptr = response;
        while ((ptr = strstr(ptr, pattern))) {
            // Verify exact match
            if ((ptr == response || !isalnum(ptr[-1])) && 
                !isalnum(ptr[strlen(pattern)])) {
                return 1;
            }
            ptr++;
        }
    }
    
    return 0;
}

char* make_https_request(const char *host, const char *path, const char *key) {
    if (!ctx) {
        fprintf(stderr, "SSL context not initialized\n");
        return NULL;
    }

    SSL *ssl = NULL;
    int sockfd = -1;
    struct addrinfo hints, *result = NULL;
    char *response = NULL;
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int ret;
    if ((ret = getaddrinfo(host, "443", &hints, &result)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return NULL;
    }

    // Try each address
    struct addrinfo *rp;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;
        
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1) break;
        
        close(sockfd);
        sockfd = -1;
    }

    if (sockfd == -1) {
        perror("Could not connect");
        goto cleanup;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new failed\n");
        goto cleanup;
    }

    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, host);
    
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL_connect failed: %s\n", 
                ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }

    // Build request
    char request[1024];
    int req_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "X-Key: %s\r\n"
        "Connection: close\r\n\r\n",
        path, host, key);

    if (SSL_write(ssl, request, req_len) <= 0) {
        fprintf(stderr, "SSL_write failed\n");
        goto cleanup;
    }
    response = malloc(BUFFER_SIZE);
    if (!response) {
        perror("malloc failed");
        goto cleanup;
    }

    int total = 0, n;
    while ((n = SSL_read(ssl, response + total, BUFFER_SIZE - total - 1)) > 0) {
        total += n;
        if (total >= BUFFER_SIZE - 1) break;
    }

    if (n < 0) {
        fprintf(stderr, "SSL_read failed\n");
        free(response);
        response = NULL;
    } else if (!contains_key(response, key)) {
        free(response);
        response = NULL;
    } else {
        response[total] = '\0';
    }

cleanup:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sockfd != -1) close(sockfd);
    if (result) freeaddrinfo(result);
    
    return response;
}

void free_response(void *ptr) {
    free(ptr);
}
