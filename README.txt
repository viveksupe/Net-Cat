Project 1: netcat_part
-----------------------

Name: Vivek Supe		
uname: vsupe

Name: Jay Modi	
uname: jmmodi

------------------------

This is a partial version of netcat which accepts messages entered by user and also takes in file as input message in client mode. Also all messages sent via the client are saved on server on a text file. We break the file sent by the client into chunks of 1024 bytes and send it to the server. We also compute HMAC using SHA1 on both sides ie client and server for each chunk of 1024 bytes. Thus checking the integrity of transmission of the 1024 byte chunk. 

Guide:

1 - Type WIN:"echo %cd%: or for LINUX:"pwd" so check current directory. Now we use "cd" to change directory to the folder which has the Makefile & C File.
2 - We compile the file. To do so we have to get into current directory where the code is based and type "make" command.
3 - Once the code has compiled we can go ahead with running the program. So do so we first understand the flags used.
netcat_part [OPTIONS]  dest_ip [file]
                     -h           Print this help screen
                     -v           Verbose output
                     -m "MSG"     Send the message specified on the command line. Warning: if you specify this option, you do not specify a file.   	  
                     -p port      Set the port to connect on (dflt: 6767)
                     -n bytes     Number of bytes to send, defaults whole file
                     -o offset    Offset into file to start sending\n"
                     -l           Listen on port instead of connecting and write output to file and dest_ip refers to which ip to bind to (dflt: localhost)

Some valid commands are:
Client:
1 - Client mentioning port message and the IP to send data  $ ./netcat_part -p <Portno> -m "<Your Message>" <yourIP>
2 - Client sending a file on a specific IP and Port number  $ ./netcat_part -p <Portno> <YourIP> <Filename>
3 - Client can also specify number of bytes to send and also the offset  $ ./netcat_part -o <OffsetNo> -n <FirstNBytes> -p <Portno> <YourIP> <Filename>

Server:
1 - Server wants to listen on specific IP and Port and write bytes to file $ ./netcat_part -p <Portno> -l <YourIP> <Filename>
                                                                 
Output:


