#include <string.h>  
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h> 
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PROXY_HOST "127.0.0.1" 
#define PROXY_PORT "8080"   
#define TARGET_HOST "127.0.0.1" 
#define TARGET_PORT "443"  

// give IPV4 or IPV6  based on the family set in the sa
void *get_in_addr(struct sockaddr *sa){
	if(sa->sa_family == AF_INET){
		return &(((struct sockaddr_in*)sa)->sin_addr);	
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

SSL_CTX *create_SSL_context() {
    SSL_CTX *ctx;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int client_creation() {
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Connect to the proxy server
    if ((rv = getaddrinfo(PROXY_HOST, PROXY_PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }

        // Connect to the proxy server
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect to the proxy server\n");
        exit(EXIT_FAILURE);
    }

    // Print the IP address of the proxy server
    inet_ntop(p->ai_family, (void *)get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof(s));
    printf("client: connecting to proxy server at %s\n", s);

    // Free the addrinfo structure
    freeaddrinfo(servinfo);

    return sockfd;
}


void send_request(SSL *ssl, char *host, char *fileName, char *body, int isConnect) {
    char request[2048];

    if (isConnect) {
        sprintf(request, "CONNECT %s:%s HTTP/1.1\r\nHost: %s\r\n\r\n", TARGET_HOST, TARGET_PORT, TARGET_HOST);
    } else {
        if (body == NULL) {
            sprintf(request, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", fileName, host);
        } else {
            sprintf(request, "POST /%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %ld\r\n\r\n%s", fileName, host, strlen(body), body);
        }
    }

    if (SSL_write(ssl, request, strlen(request)) == -1) {
        perror("send");
        exit(EXIT_FAILURE);
    }

    printf("%s request sent to the %s\n", (isConnect ? "CONNECT" : (body == NULL ? "GET" : "POST")), (isConnect ? "proxy server" : "target server"));
}

void receive_message(SSL *ssl) {
    char buf[2048];
    int n;

    n = SSL_read(ssl, buf, sizeof(buf) - 1);
    buf[n] = '\0';

    printf("Client: received message:\n%s\n", buf);
}

void message_handler(SSL *ssl) {
    int req_method;
    while(1){
	    printf("Enter Request method\n0.CONNECT\n1.GET\n2.POST\n");
	    scanf("%d", &req_method);

	    if (req_method == 0) {
		send_request(ssl, TARGET_HOST, TARGET_PORT, NULL, 1); // CONNECT
		receive_message(ssl);
	    } else {
		char *fileName = "file.txt"; // Replace with your target file
		char *post_body = NULL;

		if (req_method == 2) {
		    post_body = "name=ajay"; // Replace with your POST body
		}

		send_request(ssl, TARGET_HOST, fileName, post_body, 0); // GET or POST
		receive_message(ssl);
	    }
    }
}

int main() {
    int sockfd;
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize SSL context
    ctx = create_SSL_context();

    // Create an SSL connection object
    ssl = SSL_new(ctx);

    // Create a TCP connection to the proxy server
    sockfd = client_creation();

    // Attach the SSL connection object to the socket file descriptor
    SSL_set_fd(ssl, sockfd);

    // Initiate SSL handshake
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    message_handler(ssl);

    // Clean up
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}

