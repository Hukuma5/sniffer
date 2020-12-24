#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream>

int main(int argc, char *argv[]) {
    if (argc > 1 && *(argv[1]) == '-') {
         exit(1);
    }

    // Create a socket
    int s0 = socket(AF_INET, SOCK_STREAM, 0);
    if (s0 < 0) {
        perror("Cannot create a socket"); exit(1);
    }

    // Fill in the address of server
    struct sockaddr_in peeraddr;
    memset(&peeraddr, 0, sizeof(peeraddr));
    const char* peerHost = "localhost";
    if (argc > 1)
        peerHost = argv[1];

    // Resolve the server address (convert from symbolic name to IP number)
    //struct hostent *host = gethostbyname(peerHost);
    struct hostent *host = gethostbyname("0.0.0.0");
    if (host == NULL) {
        perror("Cannot define host address"); exit(1);
    }
    peeraddr.sin_family = AF_INET;
    short peerPort = 80;
    if (argc >= 3)
        peerPort = (short) atoi(argv[2]);
    peeraddr.sin_port = htons(peerPort);

    // Print a resolved address of server (the first IP of the host)
    printf(
            "peer addr = %d.%d.%d.%d, port %d\n",
            host->h_addr_list[0][0] & 0xff,
            host->h_addr_list[0][1] & 0xff,
            host->h_addr_list[0][2] & 0xff,
            host->h_addr_list[0][3] & 0xff,
            (int) peerPort
    );

    // Write resolved IP address of a server to the address structure
    memmove(&(peeraddr.sin_addr.s_addr), host->h_addr_list[0], 4);

    // Connect to a remote server
    int res = connect(s0, (struct sockaddr*) &peeraddr, sizeof(peeraddr));
    if (res < 0) {
        perror("Cannot connect"); exit(1);
    }
    printf("Write your login: \n");
    char User_name[20];
    std::cin>>User_name;
    write(s0, User_name, 20);
    printf("Connected. Reading a server command\n");
for(;;) {
    char buffer[1024];
    char command[1024];
    res = read(s0, buffer, 1024);
    if (res < 0) {
        perror("Read error");
        exit(1);
    }
    res = read(s0, command, 1024);
    std::string BUFFER = buffer;
    std::string COMMAND = command;
    //printf("Received:\n%s", buffer);
    //printf("Received command:\n%s", command);

    //write(s0, "Thanks! Bye-bye...\r\n", 20);
    if (BUFFER == User_name) {
        printf("Received:\n%s\n", buffer);
        printf("Received command:\n%s", command);
        if (COMMAND == "close") {
            close(s0);
            return 0;
        }
        if (COMMAND == "start") {
            std::cout << "\nstarting process\n";
        } else {
            std::cout << "wrong command from server";
            write (s0, "wrong command from server", 25);
        }
    }
}
}

