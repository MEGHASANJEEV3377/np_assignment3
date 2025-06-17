#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#define MAX_NICKNAME_LENGTH 12
#define MAX_MESSAGE_LENGTH 255
#define MAX_BUFFER_SIZE 2048
#define GREETING "HELLO 1\n"

int read_line(int fd, char *buffer, size_t maxlen) {
    size_t total = 0;
    char ch;
    while (total < maxlen - 1) {
        ssize_t n = recv(fd, &ch, 1, 0);
        if (n == 1) {
            buffer[total++] = ch;
            if (ch == '\n') break;
        } else if (n == 0) {
            break;
        } else {
            return -1;
        }
    }
    buffer[total] = '\0';
    return total;
}

void exit_with_error(const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    fflush(stderr);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "ERROR: Usage: %s <IP:PORT> <nickname>\n", argv[0]);
        fflush(stderr);
        exit(EXIT_FAILURE);
    }

    char *address = argv[1];
    char *colon = strrchr(address, ':');
    if (!colon) {
        exit_with_error("Invalid address format. Use IP:PORT");
    }

    *colon = '\0';
    char *ip = address;
    char *port_str = colon + 1;

    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        exit_with_error("Invalid port number");
    }

    if (strlen(argv[2]) > MAX_NICKNAME_LENGTH) {
        exit_with_error("Nickname too long (max 12 characters)");
    }

    regex_t regex;
    if (regcomp(&regex, "^[A-Za-z0-9_]+$", REG_EXTENDED | REG_NOSUB) != 0) {
        exit_with_error("Regex compile failed");
    }
    if (regexec(&regex, argv[2], 0, NULL, 0) != 0) {
        regfree(&regex);
        exit_with_error("Invalid nickname. Only A-Z, a-z, 0-9, _ allowed");
    }
    regfree(&regex);

    char nickname[MAX_NICKNAME_LENGTH + 1];
    strncpy(nickname, argv[2], MAX_NICKNAME_LENGTH);
    nickname[MAX_NICKNAME_LENGTH] = '\0';

    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portnum[6];
    snprintf(portnum, sizeof(portnum), "%d", port);
    if (getaddrinfo(ip, portnum, &hints, &res) != 0) {
        exit_with_error("Failed to resolve address");
    }

    int sockfd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sockfd);
        sockfd = -1;
    }
    freeaddrinfo(res);

    if (sockfd == -1) {
        exit_with_error("Unable to connect to server");
    }

    printf("Connected to server at %s:%d\n", ip, port);
    fflush(stdout);

    char buffer[MAX_BUFFER_SIZE];
    if (read_line(sockfd, buffer, sizeof(buffer)) <= 0 || strcmp(buffer, GREETING) != 0) {
        close(sockfd);
        exit_with_error("Invalid server greeting");
    }

    char nick_cmd[MAX_NICKNAME_LENGTH + 8];
    snprintf(nick_cmd, sizeof(nick_cmd), "NICK %.*s\n", MAX_NICKNAME_LENGTH, nickname);
    if (send(sockfd, nick_cmd, strlen(nick_cmd), 0) <= 0) {
        close(sockfd);
        exit_with_error("Failed to send nickname");
    }

    if (read_line(sockfd, buffer, sizeof(buffer)) <= 0 || strncmp(buffer, "OK", 2) != 0) {
        close(sockfd);
        exit_with_error("Nickname rejected by server");
    }

    struct termios oldt, newt;
    int termios_enabled = 0;

    // Only modify terminal if STDIN is a TTY
    if (isatty(STDIN_FILENO)) {
        if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
            newt = oldt;
            newt.c_lflag &= ~(ICANON | ECHO);
            if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) == 0) {
                termios_enabled = 1;
            }
        }
    }

    // Enable non-blocking STDIN
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    fd_set readfds;
    char input_buffer[MAX_BUFFER_SIZE] = {0};
    int input_len = 0;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        FD_SET(STDIN_FILENO, &readfds);
        int maxfd = sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO;

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (FD_ISSET(sockfd, &readfds)) {
            if (read_line(sockfd, buffer, sizeof(buffer)) <= 0) {
                printf("\nDisconnected from server.\n");
                fflush(stdout);
                break;
            }
            if (strncmp(buffer, "MSG ", 4) == 0) {
                char sender[MAX_NICKNAME_LENGTH + 1], msg[MAX_MESSAGE_LENGTH + 1];
                if (sscanf(buffer + 4, "%12s %[^\n]", sender, msg) == 2 && strcmp(sender, nickname) != 0) {
                    printf("%s: %s\n", sender, msg);
                    fflush(stdout);
                }
            } else if (strncmp(buffer, "ERROR ", 6) == 0) {
                fprintf(stderr, "Server error: %s\n", buffer + 6);
                fflush(stderr);
            }
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            ssize_t bytes_read = read(STDIN_FILENO, input_buffer + input_len, MAX_MESSAGE_LENGTH - input_len);
            if (bytes_read > 0) {
                input_len += bytes_read;
                char *newline = memchr(input_buffer, '\n', input_len);
                if (newline) {
                    *newline = '\0';

                    char trimmed[MAX_MESSAGE_LENGTH + 1];
                    snprintf(trimmed, sizeof(trimmed), "%.*s", MAX_MESSAGE_LENGTH, input_buffer);

                    char message_to_send[MAX_BUFFER_SIZE];
                    if (strncmp(trimmed, "MSG ", 4) == 0 || strncmp(trimmed, "QUIT", 4) == 0) {
                        snprintf(message_to_send, sizeof(message_to_send), "%.*s\n", MAX_MESSAGE_LENGTH, trimmed);
                    } else {
                        snprintf(message_to_send, sizeof(message_to_send),
                                 "MSG %.*s\n",
                                 MAX_MESSAGE_LENGTH, trimmed);
                    }

                    if (send(sockfd, message_to_send, strlen(message_to_send), 0) < 0) {
                        perror("send");
                        break;
                    }

                    input_len = 0;
                    memset(input_buffer, 0, sizeof(input_buffer));
                }
            }
        }
    }

    // Restore terminal settings
    if (termios_enabled) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }

    close(sockfd);
    printf("Client terminated.\n");
    fflush(stdout);
    return 0;
}
