/**
 * @file client.c
 * @brief Simple CLI client for the Multithreaded File Processing Server
 *
 *
 * Sample usage:
 *   - ./client -f largefile.txt -p 2 -t uppercase
 *   - ./client -f urgent.doc -p 1 -t checksum
 *
 * @author Simone Iori
 * @date 14.09.2025
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

#define JSMN_HEADER
#include "jsmn.h"

#define BUF_SIZE 		8192
#define FILENAME_SIZE 	256


const char * get_filename(const char * path) {
	const char *base = strrchr(path, '/');
	base = base ? base + 1 : path;
	return base;
}


#define MIN(a,b)	( (a) < (b) ? (a) : (b) )
#define MAX(a,b)	( (a) > (b) ? (a) : (b) )

/**
 * @brief Parse a string value from a JSON string
 *
 * It looks for the provided key inside the JSON string,
 * and return the found value up to 'outsz' characters.
 *
 * @param s Pointer to the entire JSON string
 * @param key Key we are looking for
 * @param out Pointer to the parse value string, if found. If not found is NULL
 * @param outsz Size of the output buffer
 * @return Nothing
 */
static void parse_str_field(const char *s, const char *key, char *out, size_t outsz) {

	jsmn_parser parser;
	jsmntok_t tokens[20]; // Array to hold tokens

    jsmn_init(&parser);
    int ret = jsmn_parse(&parser, s, strlen(s), tokens, 30);

	const char *valPtr;
    int valLen;

    for (int i = 0; i < ret - 1; i++) {
	   if ((tokens[i].type == JSMN_STRING) && (tokens[i + 1].type == JSMN_STRING)) {
		   const char *keyPtr = s + tokens[i].start;
		   int keyLen = tokens[i].end - tokens[i].start;

		   if (strncmp(keyPtr, key, keyLen) == 0) {

			   valPtr = s + tokens[i + 1].start;
			   valLen = tokens[i + 1].end - tokens[i + 1].start;

			   int maxLen = MIN(outsz - 1, valLen);
			   strncpy (out, valPtr, maxLen);
			   out[maxLen] = '\0';
			   return;
		   }
	   }
    }

    out[0] = '\0';
}

/**
 * @brief Parse an integer value from a JSON string
 *
 * It looks for the provided key inside the JSON string,
 * and return the found value.
 *
 * @param s Pointer to the entire JSON string
 * @param key Key we are looking for
 * @return The parse value on success, -1 if value is not found.
 */
static int parse_int_field(const char *s, const char *key) {

	jsmn_parser parser;
	jsmntok_t tokens[20]; // Array to hold tokens

    jsmn_init(&parser);
    int ret = jsmn_parse(&parser, s, strlen(s), tokens, 30);

    for (int i = 0; i < ret - 1; i++) {
	   if ((tokens[i].type == JSMN_STRING) && (tokens[i + 1].type == JSMN_PRIMITIVE)) {
		   const char *keyPtr = s + tokens[i].start;
		   int keyLen = tokens[i].end - tokens[i].start;

		   if (strncmp(keyPtr, key, keyLen) == 0) {
			   const char *valPtr = s + tokens[i + 1].start;
			   return strtol (valPtr, NULL, 10);
		   }
	   }
    }

    return -1;
}


/**
 * @brief Helper method for connection
 *
 *
 * @param host Server address (textual format)
 * @param port Server port
 * @return On success, the file descriptor of the new socket is returned. On error, -1 is returned
 */
int connect_to(const char *host, int port) {

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { close(fd); return -1; }

    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) { close(fd); return -1; }

    return fd;
}


/**
 * @brief Compose and send a request as required
 *
 *
 * @param host Server address (textual format)
 * @param port Server port
 * @param filepath Requested filepath
 * @param transform Requested operation
 * @param priority Requested priority
 * @return On success, the file descriptor of the new socket is returned. On error, -1 is returned
 */
int send_request(const char *host, int ctrl_port, const char *filepath, const char *transform, int priority) {

    int data_port = ctrl_port + 1;								// Use consecutive ports
    int ctrl_fd = connect_to(host, ctrl_port);
    if (ctrl_fd < 0) { perror("connect control"); return -1; }

    // read assigned client id
    char buf[64];
    int r = recv(ctrl_fd, buf, sizeof(buf)-1, 0);
    if (r <= 0) { perror("recv client_id"); close(ctrl_fd); return -1; }

    buf[r] = 0;

    int client_id = parse_int_field(buf, "client_id");
    if (client_id == -1) { perror("no client_id"); close(ctrl_fd); return -1; }

    printf("CTRL IN: Server gave us client ID %d\n", client_id);

    // send metadata on control channel
	const char *fileName = get_filename(filepath);

	// format JSON command
    char ctrl_req[FILENAME_SIZE + 128];
    snprintf(ctrl_req, sizeof(ctrl_req), "{\"cmd\":\"request\",\"filename\":\"%s\",\"transform\":\"%s\",\"priority\":%d}\n",
    		fileName, transform, priority);

	// send command
    if (send(ctrl_fd, ctrl_req, strlen(ctrl_req), 0) < 0) { perror("send ctrl"); close(ctrl_fd); return -1; }

    printf("CTRL OUT: %s", ctrl_req);		// Here newline is not needed, the JSON already has it

    // wait the reply from the server
    while ((r = recv(ctrl_fd, buf, sizeof(buf)-1, 0)) > 0) {
        buf[r] = 0;
        printf("CTRL IN: %s\n", buf);

        char readStatus[20];
        parse_str_field(buf, "status", readStatus, sizeof(readStatus));

		if (strstr(readStatus, "ENQUEUED")) {
            //ok, we can go on
            break;
        }
		else if (strstr(readStatus, "BUSY")) {
            // nothing to do, server refused (it shouldn't happen...)
			close(ctrl_fd); return -1;
        }
		else if (strstr(readStatus, "UNKNOWN_CMD")) {
            // malformed request
			close(ctrl_fd); return -1;
        }
		else
		{
			close(ctrl_fd); return -1;
		}
	}


    // connect data channel
    int data_fd = connect_to(host, data_port);
    if (data_fd < 0) { perror("connect data"); close(ctrl_fd); return -1; }

    printf("DATA: Connection established on port %d\n", data_port);

    // send data header (JSON line) and then the raw file bytes
    struct stat st;
    if (stat(filepath, &st) != 0) { perror("stat file"); close(ctrl_fd); close(data_fd); return -1; }

    char header[FILENAME_SIZE + 128];
    snprintf(header, sizeof(header), "{\"client_id\":%d,\"filename\":\"%s\",\"filesize\":%ld}\n",
             client_id, fileName, (long)st.st_size);

    printf("DATA OUT: Sent header %s", header);		// Here newline is not needed, the JSON already has it

    if (send(data_fd, header, strlen(header), 0) < 0) { perror("send header"); close(ctrl_fd); close(data_fd); return -1; }

    FILE *f = fopen(filepath, "rb");
    if (!f) { perror("fopen"); close(ctrl_fd); close(data_fd); return -1; }

    char buf2[BUF_SIZE];
    size_t rr; int sentBytes = 0;
    while ((rr = fread(buf2, 1, sizeof(buf2), f)) > 0) {
        ssize_t w = send(data_fd, buf2, rr, 0);
        if (w <= 0) { perror("send file"); fclose(f); close(ctrl_fd); close(data_fd); return -1; }
        sentBytes += w;
    }
    fclose(f);

    printf("DATA OUT: Sent file payload (%d bytes)\n", sentBytes);

    // wait for reply on control channel. If server sends file result, read data channel accordingly
    while ((r = recv(ctrl_fd, buf, sizeof(buf)-1, 0)) > 0) {
        buf[r] = 0;
        printf("CTRL IN: %s\n", buf);

        char readResult[20];
        parse_str_field(buf, "result", readResult, sizeof(readResult));

        char statusResult[20];
        parse_str_field(buf, "status", statusResult, sizeof(statusResult));

        if (strstr(statusResult, "UPLOAD_COMPLETE")) {
        	//The server received the file
        	printf("CLIENT: Waiting while server is working...\n");
		}
        else if (strstr(readResult, "checksum")) {
        	int checksum = parse_int_field(buf, "value");
			printf("CLIENT: Calculated checksum: %08x\n", checksum);
            break;
        }
        else if (strstr(readResult, "file")) {

            // first read header line on data channel...
            char hdr[256]; int pos = 0;
            while (pos < (int)sizeof(hdr) - 1) {
                int q = recv(data_fd, hdr + pos, 1, 0);
                if (q <= 0) break;
                if (hdr[pos] == '\n') { hdr[pos] = 0; break; }
                pos += q;
            }
            hdr[pos] = 0;

            printf("DATA IN: Received header %s\n", hdr);

            // ...then get the raw bytes
            int filesize = parse_int_field(hdr, "filesize");
            if (filesize > 0) {
                char outname[512];
                snprintf(outname, sizeof(outname), "client_received_%s", fileName);
                FILE *of = fopen(outname, "wb");
                if (!of) { perror("open out"); break; }
                int remaining = filesize;
                int receivedBytes = 0;
                while (remaining > 0) {
                    int want = remaining < (int)sizeof(buf2) ? remaining : (int)sizeof(buf2);
                    int got = recv(data_fd, buf2, want, 0);
                    if (got <= 0) break;
                    fwrite(buf2, 1, got, of);
                    remaining -= got;
                    receivedBytes += got;
                }
                fclose(of);

                printf("DATA OUT: Received file payload (%d bytes)\n", receivedBytes);
                printf("CLIENT: Processed file saved to %s\n", outname);
            }
            break;
        }
    }


    close(ctrl_fd);
    close(data_fd);

    printf("CLIENT: Done, terminating... \n");

    return 0;
}


/**
 * @brief main
 *
 * It initializes variables and checks the arguments.
 * It then calls the send_request method.
 *
 */
int main(int argc, char **argv) {

    const char *host = "127.0.0.1";
    int port = 8080;
    const char *filepath = NULL;
    const char *transform = NULL;
    int priority = 2;

    // parse args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-host") == 0 && i + 1 < argc) host = argv[++i];
        else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) filepath = argv[++i];
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) transform = argv[++i];
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) priority = atoi(argv[++i]);
        else { fprintf(stderr, "Unknown arg %s\n", argv[i]); return 1; }
    }

    // Check params
    if (!filepath || !transform) {
        fprintf(stderr, "Usage: %s -f <file> -p <priority> -t <transform> [-host <host>] [-port <ctrl_port>]\n", argv[0]);
        return 1;
    }

    // Check that filename is not too long
	const char *fileName = get_filename(filepath);
    int filename_len = strlen(fileName);
    if (filename_len + 1 > FILENAME_SIZE){
    	fprintf(stdout, "Filename is too long (%d chars)\n", filename_len); return 1;
    }

    // Check that file exists
    struct stat st;
    if (stat(filepath, &st) != 0)	{
    	fprintf(stdout, "Bad filepath: %s\n", filepath); return 1;
    }

    printf("CLIENT: requesting \"%s\" elaboration on file \"%s\" (priority %d) \n",
    						transform, filepath, priority);


    return send_request(host, port, filepath, transform, priority);
}


