#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// #include <openssl/hmac.h> // need to add -lssl to compile

#define BUF_LEN 1024

/** Warning: This is a very weak supplied shared key...as a result it is not
 * really something you'd ever want to use again :)
 */

static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9, 0x9b, 0x28,
		0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

/**
 * Structure to hold all relevant state
 **/
typedef struct nc_args {
	struct sockaddr_in destaddr; //destination/server address
	unsigned short port; //destination/listen port
	unsigned short listen; //listen flag
	int n_bytes; //number of bytes to send
	int offset; //file offset
	int verbose; //verbose output info
	int message_mode; // retrieve input to send via command line
	char * message; // if message_mode is activated, this will store the message
	char * filename; //input/output file
} nc_args_t;

/**
 * usage(FILE * file) -> void
 *
 * Write the usage info for netcat_part to the give file pointer.
 */
void usage(FILE * file) {
	fprintf(file,
			"netcat_part [OPTIONS]  dest_ip [file] \n"
					"\t -h           \t\t Print this help screen\n"
					"\t -v           \t\t Verbose output\n"
					"\t -m \"MSG\"   \t\t Send the message specified on the command line. \n"
					"                \t\t Warning: if you specify this option, you do not specify a file. \n"
					"\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
					"\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
					"\t -o offset    \t\t Offset into file to start sending\n"
					"\t -l           \t\t Listen on port instead of connecting and write output to file\n"
					"                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n");
}

/**
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function use getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return results
 **/
void parse_args(nc_args_t * nc_args, int argc, char * argv[]) {
	int ch;
	struct hostent * hostinfo;
	//set defaults
	nc_args->n_bytes = 0;
	nc_args->offset = 0;
	nc_args->listen = 0;
	nc_args->port = 6767;
	nc_args->verbose = 0;
	nc_args->message_mode = 0;

	while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1) {
		switch (ch) {
		case 'h': //help
			usage(stdout);
			exit(0);
			break;
		case 'l': //listen
			nc_args->listen = 1;

			break;
		case 'p': //port
			nc_args->port = atoi(optarg);
			break;
		case 'o': //offset
			nc_args->offset = atoi(optarg);
			break;
		case 'n': //bytes
			nc_args->n_bytes = atoi(optarg);
			break;
		case 'v':
			nc_args->verbose = 1;
			break;
		case 'm':
			nc_args->message_mode = 1;
			nc_args->message = malloc(strlen(optarg) + 1);
			strncpy(nc_args->message, optarg, strlen(optarg) + 1);
			break;
		default:
			fprintf(stderr, "ERROR: Unknown option '-%c'\n", ch);
			usage(stdout);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 2 && nc_args->message_mode == 0) {
		fprintf(stderr, "ERROR: Require ip and file\n");
		usage(stderr);
		exit(1);
	} else if (argc != 1 && nc_args->message_mode == 1) {
		fprintf(stderr,
				"ERROR: Require ip send/recv from when in message mode\n");
		usage(stderr);
		exit(1);
	}

	if (!(hostinfo = gethostbyname(argv[0]))) {
		fprintf(stderr, "ERROR: Invalid host name %s", argv[0]);
		usage(stderr);
		exit(1);
	}

	nc_args->destaddr.sin_family = hostinfo->h_addrtype;
	bcopy((char *) hostinfo->h_addr,
	(char *) &(nc_args->destaddr.sin_addr.s_addr),
	hostinfo->h_length);

	nc_args->destaddr.sin_port = htons(nc_args->port);

	/* Save file name if not in message mode */
	if (nc_args->message_mode == 0) {
		nc_args->filename = malloc(strlen(argv[1]) + 1);
		strncpy(nc_args->filename, argv[1], strlen(argv[1]) + 1);
	}
	return;
}
char* sendMesssageWithHash(char * message) { // function to calculate hash and to append hash and hash length to the original message

	unsigned char * digest;
	digest = HMAC(EVP_sha1(), key, strlen(key), (const unsigned char*) message,
			strlen(message), NULL, NULL);
	char digest_to_char[40]; //array of 40 bytes as hash sent calculated by SHA is of 40 bytes.
	int i = 0;
	for (i = 0; i < 20; i++) {
		sprintf(&digest_to_char[i * 2], "%02x", (unsigned int) digest[i]); // copy digest to char array. This will be used to append hash with message.
	}

	fprintf(stdout, "HMAC digest Computed: %s\n\n", digest_to_char); //append and send
	message[strlen(message) + strlen(digest_to_char)] = '\0';
	strncat(message, digest_to_char, 40); //concatenate original string with hash and hash length
	strncat(message, "40", 2);

	fprintf(stdout,
			"The Message (Msg+Digest+DLength) Sent to Server is: %s\n\n",
			message);
	return message;

}

void nc_client(nc_args_t * nc_args) {

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "Socket initialization failed");
		exit(1);
	}
	if (nc_args->verbose) {                                      // verbose mode
		fprintf(stdout, "Client Socket Made. Will Start Connecting.\n");
	}
	nc_args->destaddr.sin_addr.s_addr = INADDR_ANY;
	int connect_check = connect(sockfd, (struct sockaddr *) &nc_args->destaddr,
			sizeof(struct sockaddr_in));
	if (connect_check < 0) {
		fprintf(stderr, "Failed to connect server Check Port/IP\n");
		usage(stderr);
		exit(1);
	}
	if (nc_args->verbose) {                                      // verbose mode
		fprintf(stdout,
				"Client Is Connected To Socket. Will Start Sending Data.\n");
	}
	if (nc_args->message_mode == 1) {
		//message mode = 1
		char * sendDataForMessage;
		sendDataForMessage = sendMesssageWithHash(nc_args->message);
		send(sockfd, sendDataForMessage, BUF_LEN, 0);
	} else {
		if (nc_args->verbose) {                                   //verbose mode
			fprintf(stdout, "Client Is Reading File To Start Sending Data.\n");
		}
		FILE * f;

		f = fopen(nc_args->filename, "r");
		if (f == NULL) {
			fprintf(stderr, "File Initialization Failed Check File Name\n");
			usage(stderr);
			exit(1);
		}
		char ch;
		char buf[BUF_LEN];
		char * sendData;
		char send_selectedBytes[BUF_LEN]; // used to send the selected no. of bytes selected by user
		int i = 0;                                    // inner loop variable
		long int size_of_file;                        // size of file

		if (nc_args->n_bytes == 0 && nc_args->offset != 0)    // only offset
				{
			fseek(f, 0L, SEEK_END);             // point to end , full file mode
			size_of_file = ftell(f) - nc_args->offset;
		} else if (nc_args->n_bytes != 0 && nc_args->offset == 0) // only no. of bytes
				{
			size_of_file = nc_args->n_bytes;
		} else if (nc_args->n_bytes != 0 && nc_args->offset != 0)  // both
				{
			size_of_file = nc_args->n_bytes;

		} else {
			fseek(f, 0L, SEEK_END);             // point to end , full file mode
			size_of_file = ftell(f);
		}

		//no. times loop should be run
		double loopNumber = ceil((float) size_of_file / 982);
		int j = 1;
		for (j = 0; j < loopNumber; j++) {

			if (nc_args->n_bytes == 0 && nc_args->offset != 0)    // only offset
					{
				fseek(f, nc_args->offset + 982 * j, SEEK_SET);
			} else if (nc_args->n_bytes != 0 && nc_args->offset == 0) //only no of bytes.
					{
				fseek(f, 982 * j, SEEK_SET);

			} else if (nc_args->n_bytes != 0 && nc_args->offset != 0) //both

					{
				fseek(f, nc_args->offset + 982 * j, SEEK_SET); // only bytes

			} else                 // full file
			{
				fseek(f, 982 * j, SEEK_SET); //point to multiple of 982 data to send.. as sending file of 982 bytes
			}
			memset(buf, '\0', sizeof(char) * BUF_LEN);   //clearing buf

			while ((ch = fgetc(f)) != EOF && strlen(buf) != 982) {
				buf[i] = ch;
				i++;
			}
			i = 0;
			if (nc_args->verbose) {    //verbose mode
				fprintf(stdout,
						"Will Start Sending Data After Computing Digest, Offset and Bytes To Be Transmitted.\n");
			}
			if (nc_args->n_bytes != 0 && nc_args->offset == 0) { // only no. of bytes specified
				if (j == loopNumber - 1) {
					buf[nc_args->n_bytes % 982] = '\0';
				}
				sendData = sendMesssageWithHash(buf);
				send(sockfd, sendData, BUF_LEN, 0);

			} else if (nc_args->n_bytes != 0 && nc_args->offset != 0) { // both no. of bytes and offset specified

				if (j == loopNumber - 1) {
					if (nc_args->n_bytes > 982) {
						buf[(nc_args->n_bytes - 982) % 982] = '\0';
					} else {
						buf[(nc_args->n_bytes)] = '\0';
					}
				}
				sendData = sendMesssageWithHash(buf);
				send(sockfd, sendData, BUF_LEN, 0);
			} else if (nc_args->n_bytes == 0 && nc_args->offset != 0) { // only offset specified
				sendData = sendMesssageWithHash(buf);
				send(sockfd, sendData, BUF_LEN, 0);
			} else {                                      // normal sending file
				sendData = sendMesssageWithHash(buf);
				sendData[BUF_LEN] = '\0';
				int bytes_transmitted = send(sockfd, sendData, BUF_LEN, 0);
			}
		}
		fclose(f);
		close(sockfd);
		memset(buf, '\0', sizeof(char) * BUF_LEN);

		if (nc_args->verbose) {
			fprintf(stdout,
					"Computing Offset and Bytes To Be Transmitted Done And Data Sent :-)\n");
		}

	}
	return;
}
void nc_server(nc_args_t * nc_args) {

	struct sockaddr_in client;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "Socket initialization failed");
		exit(1);
	}
	if (nc_args->verbose) {
		fprintf(stdout, "Server Socket Made. Will Start Binding.\n");
	}
	int bind_check = bind(sockfd, (struct sockaddr *) &nc_args->destaddr,
			sizeof(struct sockaddr_in));
	if (bind_check == -1) {
		fprintf(stderr, "Bind Process failed..!!");
		exit(1);
	}
	if (nc_args->verbose) {
		fprintf(stdout, "Binding Done Moving To Listen State.\n");
	}
	int listen_check = listen(sockfd, 5);
	if (listen_check < 0) {
		fprintf(stderr, "Cannot listen on port..Port already in use..!!");
		exit(1);
	}
	if (nc_args->verbose) {
		fprintf(stdout, "Server In Listen Mode. Will Start Accepting Data.\n");
	}
	int size_of_struct = sizeof(struct sockaddr_in);
	FILE * f;
	int client_accept = accept(sockfd, (struct sockaddr *) &client,
			&size_of_struct);
	if (client_accept < 0) {
		fprintf(stderr, "Accept function failed %d\n", client_accept);
		exit(1);

	}
	if (nc_args->verbose) {
		fprintf(stdout, "Server Accepting Data. Bytes will be received\n");
	}

	f = fopen(nc_args->filename, "w");
	if (f == NULL) {
		fprintf(stderr, "File Initialization Failed Check File Name\n");
		usage(stderr);
		exit(1);
	}
	char buf[BUF_LEN];
	int bytes_receieved = 1;

	memset(buf, '\0', sizeof(char) * BUF_LEN);
	while (bytes_receieved) {

		memset(buf, '\0', sizeof(char) * BUF_LEN);
		bytes_receieved = recv(client_accept, buf, BUF_LEN, 0);
		buf[BUF_LEN] = '\0';
		if (strlen(buf) == 0) {
			break;
		}

		if (bytes_receieved == -1) {
			fprintf(stderr, "Server could not receive data sent by client. \n");
			exit(1);
		}
		if (nc_args->verbose) {
			fprintf(stdout, "Server Received Data. Server Will Process It.\n");
		}
		int no_bytes_received = strlen(buf);

		buf[no_bytes_received] = '\0'; // to prevent garbage value getting printed after buf array of 1024 bytes.
		fprintf(stdout, "Message Received From Client Is: %s\n\n", buf);

		char hash_value[40];   // array to store hash sent from sever.
//		printf("%d\n",strlen(buf));
		int validMessageLength = strlen(buf) - 42; // validMessage Length is Length of original message sent.
		char validMessage[validMessageLength];
		int c = 0;
		for (c = 0; c < 40; c++) {
			hash_value[c] = buf[strlen(buf) - 42 + c];
		}
		hash_value[40] = '\0';  // to prevent garbage getting printed
		fprintf(stdout, "Hash Value Sent From Client Is: %s\n\n", hash_value);
		int j;
		for (j = 0; j < validMessageLength; j++) { //validMessage is the original message
			validMessage[j] = buf[j];

		}
		validMessage[validMessageLength] = '\0';
		fprintf(stdout, "Message Sent By Client Is: %s\n\n", validMessage);

		fprintf(stdout, "Hash Length Sent By Client Is : %c%c\n\n",
				buf[strlen(buf) - 2], buf[strlen(buf) - 1]);

		fputs(validMessage, f); // to write data from validMessage buffer to the file
		if (nc_args->verbose) {
			fprintf(stdout, "Bytes are received. And written to a file.\n");
		}

		if (nc_args->verbose) {
			fprintf(stdout, "Server Is Doing a Hash Check.\n");
		}

		unsigned char * digestServer;
		digestServer = HMAC(EVP_sha1(), key, strlen(key),
				(const unsigned char*) validMessage, //calculate hash on server side
				strlen(validMessage), NULL, NULL);
		char digest_to_char[40];
		int i = 0;
		for (i = 0; i < 20; i++) {

			sprintf(&digest_to_char[i * 2], "%02x",
					(unsigned int) digestServer[i]);
		}

		fprintf(stdout, "HMAC digest Computed At Server: %s\n\n",
				digest_to_char);
		if (strcmp(hash_value, digest_to_char) == 0) {    // Compare hash value
			fprintf(stdout, "Hash Equal!! Message Is Authentic..!!\n");
		}
	}
	fclose(f);  //Close the file pointer
	close(client_accept); // Close the socket connection
}
int main(int argc, char * argv[]) {
	nc_args_t nc_args;
	parse_args(&nc_args, argc, argv);
	if (nc_args.listen == 1) {
		fprintf(stdout, "You are a Server..!!\n\n");
		nc_server(&nc_args);
	} else {
		fprintf(stdout, "You are in Client mode..!!\n\n");
		nc_client(&nc_args);
	}
	return 0;
}

