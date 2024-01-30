#include <string.h>  
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SA struct sockaddr 
#define BACKLOG 10 
#define PORT "443"
#define NUM_FDS 10
#define FILE_DIR "/var/www/html/"

int flag = 0;

void send_response(SSL* ssl,const char* status, const char* content_type,const char* content);

void cleanup(SSL *ssl,struct pollfd* pollfds) {
    SSL_free(ssl);
    close(pollfds->fd);
    pollfds->fd *= -1;
}

SSL_CTX* create_SSL_context() {
    SSL_CTX* ctx;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "serverC.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "serverC.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

//send css is used to only the css file.
void send_css(SSL* ssl,char fileName[100]){
	 FILE *file = fopen(fileName, "r");
	 // open css file
	 if (file == NULL) {
		send_response(ssl, "404 Not Found", "text/html", "File Not Found");
		flag = 1;
		return;
	 }
	
	 //read data from the css file
	 char buffer[1024];
	 int bytesRead;
	 fread(buffer, 1, sizeof(buffer), file);
		
	 //send the data to the client
	 send_response(ssl, "200 OK", "text/css", buffer);
    	 fclose(file);
}

// defining HTTP header and send data to the client
void send_response(SSL* ssl,const char* status, const char* content_type,const char* content){
	char response[2048]; 
	sprintf(response, "HTTP/1.1 %s\r\nContent-Type: %s\r\n\r\n%s", status, content_type, content);
	SSL_write(ssl, response, strlen(response));
}

// handle saving of data into the file 
void store_data(SSL* ssl,char content[1024],char fileName[100]){
	    // Open a file for writing
	    FILE *file = fopen(fileName, "a"); // Open in append mode to append new data
	    if (file == NULL) {
		send_response(ssl, "500 Internal Server Error", "text/html", "Error opening file");
		flag = 1;
		return;
	    }

	    // Write the decoded data to the file
	    fprintf(file, "%s\n", content);

	    // Close the file
	    fclose(file);
}

// retrieve all data from the file in the list form
void getalldata(SSL* ssl,char content[1024],char fileName[100]){
	    // Open the file for reading
	    FILE *file = fopen(fileName, "r");
	    if (file == NULL) {
		send_response(ssl, "404 Not Found", "text/html", "File Not Found");
		flag = 1;
		return;
	    }

	    //get data from file
	    char line[100];
	    int len = 0;
	    while(fgets(line,100,file)){
		char line2[110];
	    	sprintf(line2,"<li>%s</li>",line);
		strcat(content,line2);
	    }
	    content[strlen(content) - 1] = '\0';
	    fclose(file);
}

//handling get request without query parameters
void handle_get_request(SSL* ssl,char fileName[100]) {
    char buff[1024];
    memset(buff,'\0',sizeof(buff));
	
    // get all data from the specified file
    getalldata(ssl,buff,fileName); 
    
    if(flag == 1)
	return;
    
    //create html content for displaying data
    char html_content[1150];
    sprintf(html_content,"<html><head><link rel=\"stylesheet\" href=\"styles.css\"></head><body><ul>%s</ul></body></html>",buff);
  
    send_response(ssl, "200 OK", "text/html", html_content);
}


// handle post request and get request with query parameters
void handle_post_request(SSL* ssl, char content[],char fileName[100]) {
    char* p;

    // replace '=' with ':'
    while((p = strstr(content,"=")) != NULL){
    	*p = ':';
    }
    char response_content[1024];
    store_data(ssl,content,fileName);
    if(flag == 1)
	return;
    // HTML  content
    sprintf(response_content, "<html><head><link rel=\"stylesheet\" href=\"styles.css\"></head><body><h1>Data is posted</h1><p>%s</p></body></html>", content);
    send_response(ssl, "200 OK", "text/html", response_content);
}


// Function to decode URL-encoded string to normal string
void url_decode(char *str) {
    int i, j = 0;
    char c;

    for (i = 0; str[i] != '\0'; ++i) {
        if (str[i] == '+') {
            str[j++] = ' ';
        } else if (str[i] == '%' && isxdigit(str[i + 1]) && isxdigit(str[i + 2])) {
            sscanf(&str[i + 1], "%2x", (unsigned int*)&c);
            str[j++] = c;
            i += 2;
        } else {
            str[j++] = str[i];
        }
    }

    str[j] = '\0';
}

//parsing of query parameters and store in content array
void parse_query_parameters(const char *query_string,char content[1024]) {
    char parameter[50];
    char value[50];
    content[0] = '\0';
    int len = 0;


    // Parse query parameters
    while (sscanf(query_string, "%49[^=]=%49[^&]", parameter, value) == 2) {
	char line2[101];
	memset(line2,'\0',sizeof(line2));
	sprintf(line2,"%s=%s\n",parameter,value);
        len += strlen(line2);
	strcat(content,line2);
	
        // Move to the next parameter
        query_string = strchr(query_string, '&');
        if (query_string == NULL) {
            break;
        }
        query_string++; // Skip the '&'
    }
    content[len-1] = '\0';
}

// give IPV4 or IPV6  based on the family set in the sa
void *get_in_addr(struct sockaddr *sa){
	if(sa->sa_family == AF_INET){
		return &(((struct sockaddr_in*)sa)->sin_addr);	
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// give PORT  based on the family set in the sa
int get_in_port(struct sockaddr *sa){
	if(sa->sa_family == AF_INET){
		return (((struct sockaddr_in*)sa)->sin_port);	
	}
	return (((struct sockaddr_in6*)sa)->sin6_port);
}

// this is the code for server creation. here i have used TCP instead of UDP because i need all the data without any loss. if we use UDP we
// have to implement those in the upper layers.
// this function will return socket descripter to the calling function.
int server_creation(){
	int sockfd;
	struct addrinfo hints,*servinfo,*p;
	int yes = 1;
	int rv;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;// my ip
	
	// set the address of the server with the port info.
	if((rv = getaddrinfo(NULL,PORT,&hints,&servinfo)) != 0){
		fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(rv));	
		return 1;
	}
	
	// loop through all the results and bind to the socket in the first we can
	for(p = servinfo; p!= NULL; p=p->ai_next){
		sockfd=socket(p->ai_family,p->ai_socktype,p->ai_protocol);
		if(sockfd==-1){ 
			perror("server: socket\n"); 
			continue; 
		} 
		
		// SO_REUSEADDR is used to reuse the same port even if it was already created by this.
		// this is needed when the program is closed due to some system errors then socket will be closed automaticlly after few
		// minutes in that case before the socket is closed if we rerun the program then we have use the already used port 	
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
			perror("setsockopt");
			exit(1);	
		}
		
		// it will help us to bind to the port.
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}
	}
	
	// server will be listening with maximum simultaneos connections of BACKLOG
	if(listen(sockfd,BACKLOG) == -1){ 
		perror("listen");
		exit(1); 
	} 
	return sockfd;
}

void connection_accepting(int sockfd, struct pollfd **pollfds, int *maxfds, int *numfds, SSL*** sslfds, SSL_CTX* ctx) {
    int connfd;
    struct sockaddr_storage their_addr;
    char s[INET6_ADDRSTRLEN];
    socklen_t sin_size;

    sin_size = sizeof(their_addr);
    connfd = accept(sockfd, (SA*)&their_addr, &sin_size);
    if (connfd == -1) {
        perror("accept");
        exit(1);
    }

    if (*numfds == *maxfds) {
        *pollfds = realloc(*pollfds, (*maxfds + NUM_FDS) * sizeof(struct pollfd));
        *sslfds = realloc(*sslfds, (*maxfds + NUM_FDS) * sizeof(SSL*));

        if (*pollfds == NULL || *sslfds == NULL) {
            perror("realloc");
            exit(1);
        }

        *maxfds += NUM_FDS;
    }
    // Printing the client name
    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s));
   
    
    (*numfds)++;

    ((*pollfds) + *numfds - 1)->fd = connfd;
    ((*pollfds) + *numfds - 1)->events = POLLIN;
    ((*pollfds) + *numfds - 1)->revents = 0;

    // Create a new SSL connection
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connfd);

    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(connfd);
        exit(1);
    }

    // Store the SSL structure pointer in the array
    (*sslfds)[*numfds - 1] = ssl;

    
    printf("\nserver: got connection from %s\n", s);
}


// handled different methods
void routing(char route[],char method[],SSL* ssl,char queryData[],char fileName[],char buff[],int query){
	// route based on the css	
	if(strstr(route,".css") != NULL){
		send_css(ssl,fileName);	
	}
	//query parameters given with GET
	else if(strcmp(method,"GET") == 0 && query == 1){ 
		handle_post_request(ssl,queryData,fileName);			
	}	
	//GET without query parameters		
	else if(strcmp(method,"GET") == 0){
		handle_get_request(ssl,fileName);			
	}
	//POST method 	
	else if(strcmp(method,"POST") == 0){		
		// content length extracted for POST 
		char* content_ptr = strstr(buff,"Content-Length:");	
		if(content_ptr != NULL){
			int content_length; 
			// content length extracted from HTTP message 
			sscanf(content_ptr, "Content-Length: %d", &content_length);
			content_ptr = strstr(buff,"\r\n\r\n"); //http header and message body are seperated using \r\n\r\n
			
			char content[content_length+1];
			//getting content from message body
			sscanf(content_ptr, "\r\n\r\n%[^\n]s", content);
			content[content_length] = '\0';

			//data is decoded 
			url_decode(content);
			
			//post method handler
			handle_post_request(ssl, content,fileName);
		}
		else {
			// Handle POST request without Content-Length header
			send_response(ssl, "411 Length Required", "text/plain", "Content-Length header is required for POST");
		}		
	}
	else{
		// Handle Non implemented methods
		send_response(ssl, "501 Not Implemented", "text/plain", "Method Not Implemented");
	}

}


//simple webserver with support to http methods such as get as well as post (basic functionalities)
void simple_webserver(SSL* ssl,struct pollfd* pollfds){
	int c = 0;
	flag = 0;
	char buff[1024];
	char method[10];// to store the method name
	// default route to be parsed
	char fileName[100] = "output.txt";
	char route[100];//route data
	char queryData[1024];// query parameters data in GET
	int query = 0;// whether query parametes is requested or not

	// receiving the message from the client either get request or post request
	c = SSL_read(ssl, buff, sizeof(buff));
	if (c <= 0) {
		if (c == 0) {
		    // Connection closed by the client
		    printf("\nClient closed connection\n");
		    cleanup(ssl, pollfds);
		    return;
		} else {
		    perror("SSL_read");
		    cleanup(ssl, pollfds);
		    exit(EXIT_FAILURE);
		}
	 }
	 
	buff[c] = '\0';

	printf("%s",buff);
	sscanf(buff, "%s /%s", method,route);
		

	// Different path other than default
	if(strcmp(route,"HTTP/1.1")){
		char* queryPointer = strstr(route,"?");
		// query parameters are not given
		if(queryPointer == NULL){
			strcpy(fileName,route);
		}
		else{
			//query parameters are given
			sscanf(route, "%[^?]s", fileName);
			query = 1;
			if (queryPointer != NULL) {
				// Move to the actual query string
				queryPointer++;

				// Parse query parameters
				parse_query_parameters(queryPointer,queryData);
			 }
		
		}
	}
	//query parameters given with default file
	else if(strcmp(route,"?")==0){
		char* queryPointer = strstr(route,"?");
		query = 1;
		if (queryPointer != NULL) {
			// Move to the actual query string
			queryPointer++;

			// Parse query parameters
			parse_query_parameters(queryPointer,queryData);
		}
	}
	
	char fileDirName[1000]=FILE_DIR;
	strcat(fileDirName,fileName);
	printf("The full path is %s\n",fileDirName);
	routing(route,method,ssl,queryData,fileDirName,buff,query);
	cleanup(ssl,pollfds);
	return;
}



int main(){ 
	int sockfd,connfd;
	nfds_t nfds = 0;
	struct pollfd *pollfds;
	int maxfds = 0;
	int numfds = 0;
	SSL** sslfds;
	
	//create SSL context
	SSL_CTX* ctx = create_SSL_context();
 
	
	//server creation .
	sockfd = server_creation();

	if((pollfds = malloc(NUM_FDS*sizeof(struct pollfd))) == NULL){
		perror("malloc");
		exit(1);
	}
	if((sslfds = malloc(NUM_FDS*sizeof(SSL*))) == NULL){
		perror("malloc");
		exit(1);
	}
	maxfds = NUM_FDS;
	
	
	pollfds -> fd = sockfd;
	pollfds -> events = POLLIN;
	pollfds -> revents = 0;
	numfds = 1;

	printf("server: waiting for connections...\n");
	 
	while(1){ 

		nfds = numfds;
		if(poll(pollfds,nfds,-1) == -1){
			perror("poll");
			exit(1);
		}
		
		for(int fd = 0; fd < nfds;fd++){
			if((pollfds + fd)->fd <= 0)
				continue;
			
			if(((pollfds + fd)->revents & POLLIN) == POLLIN){
				if((pollfds + fd)->fd == sockfd){
					connection_accepting(sockfd,&pollfds,&maxfds,&numfds,&sslfds,ctx);
				}
				else{
					simple_webserver(sslfds[fd],pollfds+fd);
				}
			}
		}
	} 
	SSL_CTX_free(ctx);
	close(sockfd); 
	return 0;
} 



