#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <memory.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <linux/if_alg.h>
#include <pthread.h>
#include <time.h>
#include <sys/times.h>

#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/modes.h>
#include <openssl/aes.h>


int bytes_recv;
int port;
int numRuns = 1;
int numRuns2 = 1;

double getCurrentValue();

#define u64 uint64_t
#define u32 uint32_t
#define u8 uint8_t

typedef struct {
    u64 hi, lo;
} u128;

typedef struct {
    /* Following 6 names follow names in GCM specification */
    union {
        u64 u[2];
        u32 d[4];
        u8 c[16];
        size_t t[16 / sizeof(size_t)];
    } Yi, EKi, EK0, len, Xi, H;
    /*
     * Relative position of Xi, H and pre-computed Htable is used in some
     * assembler modules, i.e. don't change the order!
     */
#if TABLE_BITS==8
    u128 Htable[256];
#else
    u128 Htable[16];
    void (*gmult) (u64 Xi[2], const u128 Htable[16]);
    void (*ghash) (u64 Xi[2], const u128 Htable[16], const u8 *inp,
                   size_t len);
#endif
    unsigned int mres, ares;
    block128_f block;
    void *key;
} gcm128_context_alias;

typedef struct {
    union {
        double align;
        AES_KEY ks;
    } ks;                       /* AES key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    gcm128_context_alias gcm;
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_AES_GCM_CTX;



#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN 4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif
#ifndef ALG_SET_PUBKEY
#define ALG_SET_PUBKEY 6
#endif

/* // Our pipe - a pair of file descriptors in an array - see pipe() */
/* static int pipefd[2]; */

/* //... */

/* ssize_t do_recvfile(int out_fd, int in_fd, off_t offset, size_t count) { */
/* 	ssize_t bytes, bytes_sent, bytes_in_pipe; */
/* 	size_t total_bytes_sent = 0; */

/* 	// Splice the data from in_fd into the pipe */
/* 	while (total_bytes_sent < count) { */
/* 		if ((bytes_sent = splice(in_fd, NULL, pipefd[1], NULL, */
/* 							count - total_bytes_sent, */
/* 							SPLICE_F_MORE | SPLICE_F_MOVE)) <= 0) { */
/* 			if (errno == EINTR || errno == EAGAIN) { */
/* 				// Interrupted system call/try again */
/* 				// Just skip to the top of the loop and try again */
/* 				continue; */
/* 			} */
/* 			perror("splice"); */
/* 			return -1; */
/* 		} */

/* 		// Splice the data from the pipe into out_fd */
/* 		bytes_in_pipe = bytes_sent; */
/* 		while (bytes_in_pipe > 0) { */
/* 			if ((bytes = splice(pipefd[0], NULL, out_fd, &offset, bytes_in_pipe, */
/* 							SPLICE_F_MORE | SPLICE_F_MOVE)) <= 0) { */
/* 				if (errno == EINTR || errno == EAGAIN) { */
/* 					// Interrupted system call/try again */
/* 					// Just skip to the top of the loop and try again */
/* 					continue; */
/* 				} */
/* 				perror("splice"); */
/* 				return -1; */
/* 			} */
/* 			bytes_in_pipe -= bytes; */
/* 		} */
/* 		total_bytes_sent += bytes_sent; */
/* 	} */
/* 	return total_bytes_sent; */
/* } */

/* //... */

/* // Setup the pipe at initialization time */
/* if ( pipe(pipefd) < 0 ) { */
/* 	perror("pipe"); */
/* 	exit(1); */
/* } */

/* //... */

/* // Send 'len' bytes from 'socket_fd' to 'offset' in 'file_fd' */
/* do_recvfile(file_fd, socket_fd, offset, len); */


int main_old(void) {
	int tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd == -1) {
		perror("socket error:");
		exit(-1);
	}

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "tls", /* this selects the hash logic in the kernel */
		.salg_name = "rfc4106(gcm(aes))" /* this is the cipher name */
	};

	if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		perror("AF_ALG: bind failed");
		close(tfmfd);
		exit(-1);
	}

	int opfd = accept(tfmfd, NULL, 0);
	if (opfd == -1) {
		perror("accept:");
		close(tfmfd);
		exit(-1);
	}

	// Load up the cmsg data
	struct cmsghdr *header = NULL;
	uint32_t *type = NULL;
	struct msghdr msg;

/* IV data */
	struct af_alg_iv *alg_iv = NULL;
	int ivsize = 8;
	uint32_t iv_msg_size = CMSG_SPACE(sizeof(*alg_iv) + ivsize);

	/* AEAD data */
	uint32_t *assoclen = NULL;
	uint32_t assoc_msg_size = CMSG_SPACE(sizeof(*assoclen));

	uint32_t bufferlen =
		CMSG_SPACE(sizeof(*type)) + /* Encryption / Decryption */
		iv_msg_size +/* IV */
		assoc_msg_size;/* AEAD associated data size */

	memset(&msg, 0, sizeof(msg));

	char* buffer = calloc(1, bufferlen);
	if (!buffer)
		return -ENOMEM;

	msg.msg_control = buffer;
	msg.msg_controllen = bufferlen;
	msg.msg_iov = NULL;
	msg.msg_iovlen = 0;

	/* encrypt/decrypt operation */
	header = CMSG_FIRSTHDR(&msg);
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void*)CMSG_DATA(header);
	*type = 1;

	/* set IV */
	header = CMSG_NXTHDR(&msg, header);
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_IV;
	header->cmsg_len = iv_msg_size;
	alg_iv = (void*)CMSG_DATA(header);
	alg_iv->ivlen = ivsize;
	memcpy(alg_iv->iv, "            ", ivsize);


	/* set AEAD information */
	/* Set associated data length */
	header = CMSG_NXTHDR(&msg, header);
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	header->cmsg_len = CMSG_LEN(sizeof(*assoclen));
	assoclen = (void*)CMSG_DATA(header);
	*assoclen = 13;

	int ret = sendmsg(opfd, &msg, 0);
	if (ret < 0) {
		perror("sendmsg");
		exit(-1);
	}

	return 0;
}

pthread_t server_thread;

int main_server(void);

void init(void);

int main(int argv, char* argc[]) {
	init();
	SSL_library_init();

	if (argv != 2) {
		printf("usage: ./tls port\n");
		exit(-1);
	}
	port = atoi(argc[1]);
	printf("Serving port %i\n", port);

	/* ---------------------------------------------------------- *
	 * These function calls initialize openssl for correct work.  *
	 * ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();/* load all error messages */

	int rc = pthread_create(&server_thread, NULL, main_server, NULL);
	if (rc) {
		printf("Error creating seraver %i\n", rc);
		exit(-1);
	}
	usleep(10000);

	main_tls_client();
	return 0;
}

/* ------------------------------------------------------------ *
 * file:        sslconnect.c                                    *
 * purpose:     Example code for building a SSL connection and  *
 *              retrieving the server certificate               *
 * author:      06/12/2012 Frank4DD                             *
 *                                                              *
 * gcc -lssl -lcrypto -o sslconnect sslconnect.c                *
 * ------------------------------------------------------------ */


/* ---------------------------------------------------------- *
 * First we need to make a standard TCP socket connection.    *
 * create_socket() creates a socket & TCP-connects to server. *
 * ---------------------------------------------------------- */
int create_socket(char[], BIO *);

int done = 0;
int server;

int main_tls_client() {

	char           dest_url[] = "https://localhost";
	BIO              *certbio = NULL;
	BIO               *outbio = NULL;
	X509                *cert = NULL;
	X509_NAME       *certname = NULL;
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	int server = 0;
	int ret, i;

	/* ---------------------------------------------------------- *
	 * Create the Input/Output BIO's.                             *
	 * ---------------------------------------------------------- */
	certbio = BIO_new(BIO_s_file());
	outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);


/* ---------------------------------------------------------- *
 * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
 * ---------------------------------------------------------- */
	method = SSLv23_client_method();

/* ---------------------------------------------------------- *
 * Try to create a new SSL context                            *
 * ---------------------------------------------------------- */
	if ( (ctx = SSL_CTX_new(method)) == NULL)
		BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

/* ---------------------------------------------------------- *
 * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
 * ---------------------------------------------------------- */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");

/* ---------------------------------------------------------- *
 * Create new SSL connection state object                     *
 * ---------------------------------------------------------- */
	ssl = SSL_new(ctx);

/* ---------------------------------------------------------- *
 * Make the underlying TCP socket connection                  *
 * ---------------------------------------------------------- */
	server = create_socket(dest_url, outbio);
	if(server != 0)
		BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", dest_url);

/* ---------------------------------------------------------- *
 * Attach the SSL session to the socket descriptor            *
 * ---------------------------------------------------------- */
	SSL_set_fd(ssl, server);

/* ---------------------------------------------------------- *
 * Try to SSL-connect here, returns 1 for success             *
 * ---------------------------------------------------------- */
	if ( SSL_connect(ssl) != 1 ) {
		BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", dest_url);
		exit(-1);
	}
	else
		BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);

/* ---------------------------------------------------------- *
 * Get the remote certificate into the X509 structure         *
 * ---------------------------------------------------------- */
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);
		exit(-1);
	}
	else
		BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", dest_url);

/* ---------------------------------------------------------- *
 * extract various certificate information                    *
	 * -----------------------------------------------------------*/
	certname = X509_NAME_new();
	certname = X509_get_subject_name(cert);

/* ---------------------------------------------------------- *
 * display the cert subject here                              *
 * -----------------------------------------------------------*/
	BIO_printf(outbio, "Displaying the certificate subject data:\n");
	X509_NAME_print_ex(outbio, certname, 0, 0);
	BIO_printf(outbio, "\n");

	clock_t start, end;
	double cpu_time_used;
	double cpu_start, cpu_end, cpu_used;

	int filefd = open("test.data", O_RDONLY);
	int bytes;
	int totalbytes = 0;
	bytes_recv = 0;
	char buf[4096];


	start = clock();
	cpu_start = getCurrentValue();

	do {
		bytes = read(filefd, buf, sizeof(buf));
		totalbytes += bytes;
		if (bytes > 0)
			SSL_write(ssl, buf, bytes);
	} while(bytes > 0);

	while (bytes_recv  + 4096 < totalbytes) {
		usleep(100);
		//printf("%i\n", bytes_recv);
	}

		end = clock();
		cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
		cpu_end = getCurrentValue();
		cpu_used = cpu_end - cpu_start;

		printf("Function time: %.02f, %f\n", cpu_time_used, cpu_used * cpu_time_used);

	sleep(2);
	int res = 0;
	char buf2[16000];
	int total_recv = 0;
	int cnt = 0;
	for (i = 0; i < numRuns; i++) {
		res = 0;
		total_recv = 0;
		cnt = 0;

		start = clock();
		cpu_start = getCurrentValue();

		//res = sendfile(opfd, filefd, 0, 16000);
		//printf("Sendfiled: %i of %i\n", res, totalbytes);
			res = SSL_read(ssl, buf2, 1);
			//printf("Receved: %i %i %i\n", res, total_recv, totalbytes);
			//printf("Recvd :%i\n", cnt++);
			//sleep(1);
			total_recv += res;
			if (res < 0)
				break;
		printf("Recvd: %i %i %i\n", res, total_recv, totalbytes);

		end = clock();
		cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
		cpu_end = getCurrentValue();
		cpu_used = cpu_end - cpu_start;

		printf("Function time: %.02f, %f\n", cpu_time_used, cpu_used * cpu_time_used);
	}

	close(filefd);
	filefd = open("test.data", O_RDONLY);

// USEr CRYPTO MODE
	int tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd == -1) {
		perror("socket error:");
		exit(-1);
	}

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "tls", /* this selects the hash logic in the kernel */
		.salg_name = "rfc4106(gcm(aes))" /* this is the cipher name */
	};

	if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		perror("AF_ALG: bind failed");
		close(tfmfd);
		exit(-1);
	}

	int opfd = accept(tfmfd, NULL, 0);
	if (opfd == -1) {
		perror("accept:");
		close(tfmfd);
		exit(-1);
	}

	if (setsockopt(tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 16)) {
		perror("AF_ALG: set authsize failed\n");
		exit(-1);
	}

	EVP_CIPHER_CTX * writeCtx = ssl->enc_write_ctx;
	EVP_CIPHER_CTX * readCtx = ssl->enc_read_ctx;

	EVP_AES_GCM_CTX* gcmWrite = (EVP_AES_GCM_CTX*)(writeCtx->cipher_data);
	EVP_AES_GCM_CTX* gcmRead = (EVP_AES_GCM_CTX*)(readCtx->cipher_data);

	unsigned char* writeKey = (unsigned char*)(gcmWrite->gcm.key);
	unsigned char* readKey = (unsigned char*)(gcmRead->gcm.key);

	int writeKeyLen = writeCtx->key_len;
	unsigned char* writeIV = gcmWrite->iv;
	unsigned char* readIV = gcmRead->iv;
	int writeIVLen = gcmWrite->ivlen;

	char keyiv[20];
	memcpy(keyiv, writeKey, 16);
	memcpy(keyiv + 16, writeIV, 4);

	if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, keyiv, 20)) {
		perror("AF_ALG: set write key failed\n");
		exit(-1);
	}

	memcpy(keyiv, readKey, 16);
	memcpy(keyiv + 16, readIV, 4);

	if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, keyiv, 20)) {
		perror("AF_ALG: set read key failed\n");
		exit(-1);
	}

	// Load up the cmsg data
	struct cmsghdr *header = NULL;
	uint32_t *type = NULL;
	struct msghdr msg;

/* IV data */
	struct af_alg_iv *alg_iv = NULL;
	int ivsize = 12;
	uint32_t iv_msg_size = CMSG_SPACE(sizeof(*alg_iv) + ivsize);

	/* AEAD data */
	uint32_t *assoclen = NULL;
	uint32_t assoc_msg_size = CMSG_SPACE(sizeof(*assoclen));

	uint32_t bufferlen =
		CMSG_SPACE(sizeof(*type)) + /* Encryption / Decryption */
		iv_msg_size +/* IV */
		assoc_msg_size;/* AEAD associated data size */

	memset(&msg, 0, sizeof(msg));

	char* buffer = calloc(1, bufferlen);
	if (!buffer)
		return -ENOMEM;

	msg.msg_control = buffer;
	msg.msg_controllen = bufferlen;
	msg.msg_iov = NULL;
	msg.msg_iovlen = 0;

	/* encrypt/decrypt operation */
	header = CMSG_FIRSTHDR(&msg);
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void*)CMSG_DATA(header);
	*type = server;


	/* set IV */
	header = CMSG_NXTHDR(&msg, header);
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_IV;
	header->cmsg_len = iv_msg_size;
	alg_iv = (void*)CMSG_DATA(header);
	alg_iv->ivlen = 8;
	uint64_t writeSeq;
	unsigned char* writeSeqNum = ssl->s3->write_sequence;
	memcpy(&writeSeq, writeSeqNum, sizeof(writeSeq));
	//uint64_t tmp = htobe64(writeSeq);
	//writeSeq = tmp;
	printf("write sequence number %li\n", writeSeq);

	memcpy(alg_iv->iv, &writeSeq, 8);


	/* set AEAD information */
	/* Set associated data length */
	header = CMSG_NXTHDR(&msg, header);
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	header->cmsg_len = CMSG_LEN(sizeof(*assoclen));
	assoclen = (void*)CMSG_DATA(header);
	*assoclen = 16 + 8;

	ret = sendmsg(opfd, &msg, MSG_MORE);
	if (ret < 0) {
		perror("sendmsg");
		exit(-1);
	}

	header = CMSG_FIRSTHDR(&msg);
	header = CMSG_NXTHDR(&msg, header);
	alg_iv = (void*)CMSG_DATA(header);
	uint64_t readSeq;
	unsigned char* readSeqNum = ssl->s3->read_sequence;
	memcpy(&readSeq, readSeqNum, sizeof(readSeq));
	uint64_t tmp = htobe64(readSeq);
	memcpy(alg_iv->iv, &readSeq, 8);
	printf("read sequence number %li %li\n", readSeq, tmp);

	ret = sendmsg(opfd, &msg, MSG_MORE);
	if (ret < 0) {
		perror("sendmsg recv");
		exit(-1);
	}
/*
	int pipes[2];
	if (pipe(pipes)) {
		perror("pipe");
		exit(-1);
	}
	long sp = splice(filefd, 0, pipes[1], 0, 1, 0);
	if (sp != 1) {
		perror("splice");
		exit(-1);
	}

	sp = splice(pipes[0], 0, opfd, 0, 1, 0);
*/
	off_t offset = 0;


	//sendfile(opfd, filefd, &offset, totalbytes);



	cpu_start = getCurrentValue();
	start = clock();

	sendfile(opfd, filefd, &offset, totalbytes);

	end = clock();
	cpu_end = getCurrentValue();
	cpu_used = cpu_end - cpu_start;
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

	printf("Function time: %.02f, %f\n", cpu_time_used, cpu_used * cpu_time_used);


	// Try some simple writes
	send(opfd, buf, 10, 0);
	send(opfd, buf, 100, 0);
	send(opfd, buf, 16000, 0);
	printf("Successful send\n");

	for ( i = 0; i < numRuns2; i++) {
		cpu_start = getCurrentValue();
		start = clock();


		res = 0;
		total_recv = 0;
		//res = sendfile(opfd, filefd, 0, 16000);
		//printf("Sendfiled: %i of %i\n", res, totalbytes);
		cnt = 0;
			res = recv(opfd, &buf2, 1, 0);
			//printf("Receved: %i %i %i\n", res, total_recv, totalbytes);
			//printf("Recvd :%i\n", cnt++);
			//sleep(1);
			total_recv += res;
			if (res < 0)
				break;
		printf("Recvd: %i %i %i\n", res, total_recv, totalbytes);


		end = clock();
		cpu_end = getCurrentValue();
		cpu_used = cpu_end - cpu_start;
		cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

		printf("Function time: %.02f, %f\n", cpu_time_used, cpu_used * cpu_time_used);
	}

	done = 1;
	while (recv(opfd, &buf2, 16000, MSG_DONTWAIT) > 0);
	pthread_kill(server_thread, SIGUSR1);
	close(server);


	/* while (bytes_recv + 4096 < totalbytes) { */
	/* 	usleep(100); */
	/* 	//printf("%i\n", bytes_recv); */
	/* } */
	/*
	if (sp != 16000) {

		perror("splice2");
		printf("%i\n", sp);
		exit(-1);
	}
	*/

	//char* databuf[16000];
	//sp = splice(opfd, 0, pipes[1], 0, 16000, 0);
	/* sp = read(opfd, databuf, 16000); */
	/* if (sp != 16000) { */
	/* 	perror("spliceout"); */
	/* 	exit(-1); */
	/* } */
	sleep(1);
	exit(-1);


// HACK CIPHER MODE

	if (EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(ssl->enc_write_ctx)) == EVP_CIPH_GCM_MODE)
	{
		printf("Can offload\n") ;

		unsigned char* writeIV = gcmWrite->iv;
		int writeIVLen = gcmWrite->ivlen;

		// 8 bytes each
		uint64_t writeSeq;
		unsigned char* writeSeqNum = ssl->s3->write_sequence;
		memcpy(&writeSeq, writeSeqNum, sizeof(writeSeq));
		uint64_t tmp = htobe64(writeSeq);
		writeSeq = tmp;

		/* Setsockopt to set the key inside the kernel */
		unsigned char *info = (unsigned char *)malloc(4 + 16 + 4 + 12 + 8);
		uint32_t keylen = writeKeyLen;
		printf("keylen: %i\n", keylen);
		memcpy(info, (unsigned char*)&keylen, sizeof(uint32_t));
		memcpy(info+4, writeKey, 16);
		uint32_t ivlen = writeIVLen;
		printf("IVLen: %i\n", ivlen);
		memcpy(info+4+16, (unsigned char*)&ivlen, sizeof(uint32_t));
		memcpy(info+4+16+4, writeIV, 12);
		memcpy(info+4+16+4+12, (unsigned char*)&writeSeq, sizeof(uint64_t));

		int z = setsockopt(server, SOL_SOCKET, 60,  /* Thats the tls offload sockopt */
				(void*)info, (socklen_t)4+16+4+12+8);
		if (z) {
			perror("AsyncSSLSocket setsockopt failed\n");
			exit(-1);
		}
	}

	close(filefd);
	bytes_recv = 0;
	sleep(1);
	filefd = open("test.data", O_RDONLY);

	cpu_start = getCurrentValue();
	start = clock();


	res = sendfile(server, filefd, 0, totalbytes);
	printf("Sendfiled: %i\n", res);

	while (bytes_recv != totalbytes) {
		usleep(100);
		//printf("%i\n", bytes_recv);
	}

	end = clock();
	cpu_end = getCurrentValue();
	cpu_used = cpu_end - cpu_start;
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

	printf("Function time: %.02f, %f\n", cpu_time_used, cpu_used * cpu_time_used);

/* ---------------------------------------------------------- *
 * Free the structures we don't need anymore                  *
 * -----------------------------------------------------------*/
	SSL_free(ssl);
	close(server);
	X509_free(cert);
	SSL_CTX_free(ctx);
	BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
	return(0);
}

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[], BIO *out) {
	int sockfd;
	char hostname[256] = "";
	char    portnum[6];
	sprintf(portnum, "%d", port);
	char      proto[6] = "";
	char      *tmp_ptr = NULL;
	int           port;
	struct hostent *host;
	struct sockaddr_in6 dest_addr;

	/* ---------------------------------------------------------- *
	 * Remove the final / from url_str, if there is one           *
	 * ---------------------------------------------------------- */
	if(url_str[strlen(url_str)] == '/')
		url_str[strlen(url_str)] = '\0';

	/* ---------------------------------------------------------- *
	 * the first : ends the protocol string, i.e. http            *
	 * ---------------------------------------------------------- */
	strncpy(proto, url_str, (strchr(url_str, ':')-url_str));

	/* ---------------------------------------------------------- *
	 * the hostname starts after the "://" part                   *
	 * ---------------------------------------------------------- */
	strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));

	/* ---------------------------------------------------------- *
	 * if the hostname contains a colon :, we got a port number   *
	 * ---------------------------------------------------------- */
	if(strchr(hostname, ':')) {
		tmp_ptr = strchr(hostname, ':');
		/* the last : starts the port number, if avail, i.e. 8443 */
		strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
		*tmp_ptr = '\0';
	}

	port = atoi(portnum);

	if ( (host = gethostbyname(hostname)) == NULL ) {
		BIO_printf(out, "Error: Cannot resolve hostname %s.\n",  hostname);
		abort();
	}

	/* ---------------------------------------------------------- *
	 * create the basic TCP socket                                *
	 * ---------------------------------------------------------- */
	sockfd = socket(AF_INET6, SOCK_STREAM, 0);

	memset(&(dest_addr), '\0', sizeof(dest_addr));
	dest_addr.sin6_family=AF_INET6;
	dest_addr.sin6_port=htons(port);
	//dest_addr.sin6_addr.s6_addr = inet_addr("::1");
	inet_pton(AF_INET6, "::1", &dest_addr.sin6_addr.s6_addr);


	//tmp_ptr = inet_ntoa(dest_addr.sin6_addr);

	/* ---------------------------------------------------------- *
	 * Try to make the host connect here                          *
	 * ---------------------------------------------------------- */
	if ( connect(sockfd, (struct sockaddr *) &dest_addr,
			sizeof(struct sockaddr_in6)) == -1 ) {
		perror("stuff");
		BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d.\n",
			hostname, hostname, port);
		exit(-1);
	}

	return sockfd;
}

// SERVER ///////////

#define FAIL    -1

/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/
int OpenListener(int port)
{   int sd;
	struct sockaddr_in6 addr;

	sd = socket(PF_INET6, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	memcpy(addr.sin6_addr.s6_addr, &in6addr_any, sizeof(in6addr_any));
	//addr.sin6_addr.s6_addr = in6addr_any;
	if ( bind(sd, &addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();/* create new server-method instance */
	ctx = SSL_CTX_new(method);/* create new context from method */
	SSL_CTX_set_cipher_list(ctx, "ECDH-ECDSA-AES128-GCM-SHA256");

	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);/* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared)                ---*/
/*---------------------------------------------------------------------*/
void Servlet(int client, SSL* ssl)/* Serve the connection -- threadable */
{   char buf[16000];
	char reply[1024];
	int sd, bytes;

	if ( SSL_accept(ssl) == FAIL )/* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);/* get any certificates */

		// Send a little data to test reads
		bytes = SSL_write(ssl, buf, 1);
		bytes = SSL_write(ssl, buf, 1);
		bytes = SSL_write(ssl, buf, 1);
		bytes = SSL_write(ssl, buf, 1);
	do {

		bytes = SSL_read(ssl, buf, sizeof(buf));/* get request */
			if ( bytes > 0 )
			{

			} else if (bytes == 0) {
				printf("Bytes recv: %i\n", bytes_recv);
			}
			else {
				printf("ERROR\n");
				ERR_print_errors_fp(stderr);
				break;
			}
			bytes_recv += bytes;
		} while (bytes > 0 && !done);
	}
	sd = SSL_get_fd(ssl);/* get socket connection */
	SSL_free(ssl);/* release SSL state */
	close(sd);/* close connection */
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL socket server.                              ---*/
/*---------------------------------------------------------------------*/
int main_server(void)
{
	SSL_CTX *ctx;

	done = 0;

	ctx = InitServerCTX();/* initialize SSL */
	LoadCertificates(ctx, "ca.crt", "ca.pem");/* load certs */

	server = OpenListener(port);/* create server socket */
	while (!done)
	{   struct sockaddr_in addr;
		int len = sizeof(addr);
		SSL *ssl;

		printf("Waiting for connection to server\n");
		int client = accept(server, &addr, &len);/* accept connection as usual */
		printf("Connection: %s:%d\n",
			inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx);         /* get new SSL state with context */
		SSL_set_fd(ssl, client);/* set connection socket to SSL state */
		Servlet(client, ssl);/* service connection */
	}
	close(server);/* close server socket */
	SSL_CTX_free(ctx);/* release context */
}

/* static clock_t lastCPU, lastSysCPU, lastUserCPU; */
/* static int numProcessors; */


/* void init(){ */
/*         FILE* file; */
/*         struct tms timeSample; */
/*         char line[128]; */


/*         lastCPU = times(&timeSample); */
/*         lastSysCPU = timeSample.tms_stime; */
/*         lastUserCPU = timeSample.tms_utime; */


/*         file = fopen("/proc/cpuinfo", "r"); */
/*         numProcessors = 0; */
/*         while(fgets(line, 128, file) != NULL){ */
/* 		if (strncmp(line, "processor", 9) == 0) numProcessors++; */
/*         } */
/*         fclose(file); */
/* } */


/* double getCurrentValue(){ */
/*         struct tms timeSample; */
/*         clock_t now; */
/*         double percent; */


/*         now = times(&timeSample); */
/*         if (now <= lastCPU || timeSample.tms_stime < lastSysCPU || */
/* 		timeSample.tms_utime < lastUserCPU){ */
/* 		//Overflow detection. Just skip this value. */
/* 		percent = -1.0; */
/*         } */
/*         else{ */
/* 		percent = (timeSample.tms_stime - lastSysCPU) + */
/* 			(timeSample.tms_utime - lastUserCPU); */
/* 		percent /= (now - lastCPU); */
/* 		percent /= numProcessors; */
/* 		percent *= 100; */
/*         } */
/*         lastCPU = now; */
/*         lastSysCPU = timeSample.tms_stime; */
/*         lastUserCPU = timeSample.tms_utime; */


/*         return percent; */
/* } */

static unsigned long long lastTotalUser, lastTotalUserLow, lastTotalSys, lastTotalIdle;


void init(){
        FILE* file = fopen("/proc/stat", "r");
        fscanf(file, "cpu %llu %llu %llu %llu", &lastTotalUser, &lastTotalUserLow,
		&lastTotalSys, &lastTotalIdle);
        fclose(file);
}


double getCurrentValue(){
        double percent;
        FILE* file;
        unsigned long long totalUser, totalUserLow, totalSys, totalIdle, total;


        file = fopen("/proc/stat", "r");
        fscanf(file, "cpu %llu %llu %llu %llu", &totalUser, &totalUserLow,
		&totalSys, &totalIdle);
        fclose(file);


        if (totalUser < lastTotalUser || totalUserLow < lastTotalUserLow ||
		totalSys < lastTotalSys || totalIdle < lastTotalIdle){
		//Overflow detection. Just skip this value.
		percent = -1.0;
        }
        else{
		total = (totalUser - lastTotalUser) + (totalUserLow - lastTotalUserLow) +
			(totalSys - lastTotalSys);
		percent = total;
		total += (totalIdle - lastTotalIdle);
		percent /= total;
		percent *= 100;
        }


        lastTotalUser = totalUser;
        lastTotalUserLow = totalUserLow;
        lastTotalSys = totalSys;
        lastTotalIdle = totalIdle;


        return percent;
}
