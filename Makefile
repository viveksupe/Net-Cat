OBJS = netcat_part
CC = gcc

all: netcat_part

netcat_part: 
	$(CC) -lssl -lm -lcrypto netcat_part.c -o netcat_part

clean:
	rm -rf $(OBJS)


