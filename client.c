/*
 client.c
 CLI:
   ./client -f <file> -p <priority> -t <transform> [-host <host>] [-port <control_port>]
 Defaults: host=127.0.0.1 port=8080 (data port is port+1)
 The program implements send_request() as requested:
   - opens persistent control and data connections
   - sends JSON metadata on control
   - streams file on data channel
   - waits for result via control and possible incoming file on data channel
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

#define BUFSZ 8192


jsmn_parser parser;
jsmntok_t tokens[20]; // Array to hold tokens



#define MIN(a,b)	( (a) < (b) ? (a) : (b) )
#define MAX(a,b)	( (a) > (b) ? (a) : (b) )

static void parse_str_field(const char *s, const char *key, char *out, size_t outsz) {

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

static int parse_int_field(const char *s, const char *key) {

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



/* helper to connect */
static int connect_to(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    return fd;
}

#define STATUS_SZ 	20
#define RESULT_SZ 	20

/* Compose and send a request as required. Public function name preserved */
int send_request(const char *host, int ctrl_port, const char *filename, const char *transform, int priority) {
    int data_port = ctrl_port + 1;
    int ctrl_fd = connect_to(host, ctrl_port);
    if (ctrl_fd < 0) { perror("connect control"); return -1; }

    /* read assigned client id */
    char buf[512];
    int r = recv(ctrl_fd, buf, sizeof(buf)-1, 0);
    if (r <= 0) { perror("recv client_id"); close(ctrl_fd); return -1; }
    buf[r] = 0;
    int client_id = parse_int_field(buf, "client_id");
    if (client_id == -1) { perror("no client_id"); close(ctrl_fd); return -1; }

    /* send metadata on control channel */
    const char *base = strrchr(filename, '/'); base = base ? base + 1 : filename;
    char ctrl_req[512];
    snprintf(ctrl_req, sizeof(ctrl_req), "{\"cmd\":\"request\",\"filename\":\"%s\",\"transform\":\"%s\",\"priority\":%d}\n",
             base, transform, priority);
    if (send(ctrl_fd, ctrl_req, strlen(ctrl_req), 0) < 0) { perror("send ctrl"); close(ctrl_fd); return -1; }


    // wait for ack
    while ((r = recv(ctrl_fd, buf, sizeof(buf)-1, 0)) > 0) {
        buf[r] = 0;
        printf("CTRL: %s", buf);

        char readStatus[20];
        parse_str_field(buf, "status", readStatus, sizeof(readStatus));

		if (strstr(readStatus, "ENQUEUED")) {
            //ok, we can go on
            break;
        }
		else if (strstr(readStatus, "BUSY")) {
            // nothing to do, server refused (shouldn't happen)
			printf("server busy"); close(ctrl_fd); return -1;
        }
		else if (strstr(readStatus, "UNKNOWN_CMD")) {
            // malformed request
			printf("malformed request"); close(ctrl_fd); return -1;
        }
		else
		{
			printf("unknown error: %s\r\n", readStatus); close(ctrl_fd); return -1;
		}
	}


    /* connect data channel */
    int data_fd = connect_to(host, data_port);
    if (data_fd < 0) { perror("connect data"); close(ctrl_fd); return -1; }

    /* send data header (JSON line) then file bytes */
    struct stat st;
    if (stat(filename, &st) != 0) { perror("stat file"); close(ctrl_fd); close(data_fd); return -1; }
    char header[512];
    snprintf(header, sizeof(header), "{\"client_id\":%d,\"filename\":\"%s\",\"filesize\":%ld}\n",
             client_id, base, (long)st.st_size);
    if (send(data_fd, header, strlen(header), 0) < 0) { perror("send header"); close(ctrl_fd); close(data_fd); return -1; }
    FILE *f = fopen(filename, "rb");
    if (!f) { perror("fopen"); close(ctrl_fd); close(data_fd); return -1; }
    char buf2[BUFSZ];
    size_t rr;
    while ((rr = fread(buf2, 1, sizeof(buf2), f)) > 0) {
        ssize_t w = send(data_fd, buf2, rr, 0);
        if (w <= 0) { perror("send file"); fclose(f); close(ctrl_fd); close(data_fd); return -1; }
    }
    fclose(f);


    /* wait for responses on control. If server sends file result, read data channel accordingly */
    while ((r = recv(ctrl_fd, buf, sizeof(buf)-1, 0)) > 0) {
        buf[r] = 0;
        printf("CTRL: %s", buf);

        char readResult[RESULT_SZ];
        parse_str_field(buf, "result", readResult, RESULT_SZ);

        if (strstr(readResult, "checksum")) {
        	int checksum = parse_int_field(buf, "value");
			printf("Checksum: %08x", checksum);
            break;
        }
        else if (strstr(readResult, "file")) {

            /* first read header line on data channel */
            char hdr[256]; int pos = 0;
            while (pos < (int)sizeof(hdr) - 1) {
                int q = recv(data_fd, hdr + pos, 1, 0);
                if (q <= 0) break;
                if (hdr[pos] == '\n') { hdr[pos] = 0; break; }
                pos += q;
            }
            hdr[pos] = 0;
            /* parse filesize */
            int filesize = 0;
            char *fp = strstr(hdr, "\"filesize\"");
            if (fp) { char *col = strchr(fp, ':'); if (col) filesize = atoi(col+1); }
            if (filesize > 0) {
                char outname[512];
                snprintf(outname, sizeof(outname), "client_received_%s", base);
                FILE *of = fopen(outname, "wb");
                if (!of) { perror("open out"); break; }
                int remaining = filesize;
                while (remaining > 0) {
                    int want = remaining < (int)sizeof(buf2) ? remaining : (int)sizeof(buf2);
                    int got = recv(data_fd, buf2, want, 0);
                    if (got <= 0) break;
                    fwrite(buf2, 1, got, of);
                    remaining -= got;
                }
                fclose(of);
                printf("Saved processed file to %s\n", outname);
            }
            break;
        }
    }


    close(ctrl_fd);
    close(data_fd);

    //Clean pending carriage returns...
	printf("\r\n");

    return 0;
}

/* Simple CLI that calls send_request */
int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 8080;
    const char *filepath = NULL;
    const char *transform = NULL;
    int priority = 2;


    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-host") == 0 && i + 1 < argc) host = argv[++i];
        else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) filepath = argv[++i];
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) transform = argv[++i];
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) priority = atoi(argv[++i]);
        else { fprintf(stderr, "Unknown arg %s\n", argv[i]); return 1; }
    }
    if (!filepath || !transform) {
        fprintf(stderr, "Usage: %s -f <file> -p <priority> -t <transform> [-host <host>] [-port <ctrl_port>]\n", argv[0]);
        return 1;
    }

    //Check that file exists
    struct stat st;
    if (stat(filepath, &st) != 0)	{
    	fprintf(stdout, "Bad filepath: %s\n", filepath); return 1;
    }


    return send_request(host, port, filepath, transform, priority);
}


