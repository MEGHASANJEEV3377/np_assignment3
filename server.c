#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define MAX_CLIENTS 100
#define MAX_NICKNAME_LENGTH 12
#define MAX_MESSAGE_LENGTH 255
#define MAX_LINE_LENGTH 512
#define GREETING "HELLO 1\n"
#define OK_RESPONSE "OK\n"

typedef struct {
    int fd;
    int ready;
    char nickname[MAX_NICKNAME_LENGTH + 1];
} Client;

Client clients[MAX_CLIENTS];
int listener_fd = -1;
regex_t nick_regex;

void shutdown_server() {
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].fd != -1) {
            close(clients[i].fd);
        }
    }
    if (listener_fd != -1) close(listener_fd);
    regfree(&nick_regex);
    printf("Server shut down.\n");
    fflush(stdout);
}

void signal_handler(int sig) {
    (void)sig;
    shutdown_server();
    exit(0);
}

void broadcast_message(const char* from, const char* msg, int exclude_fd) {
    char out[MAX_LINE_LENGTH];
    snprintf(out, sizeof(out), "MSG %s %s\n", from, msg);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].fd != -1 && clients[i].ready && clients[i].fd != exclude_fd) {
            send(clients[i].fd, out, strlen(out), 0);
        }
    }
}

int read_line(int fd, char* buffer, size_t maxlen) {
    size_t len = 0;
    char c;
    while (len < maxlen - 1) {
        ssize_t r = recv(fd, &c, 1, 0);
        if (r == 1) {
            buffer[len++] = c;
            if (c == '\n') break;
        } else if (r == 0) {
            return 0;
        } else {
            return -1;
        }
    }
    buffer[len] = '\0';
    return len;
}

int add_client(int fd) {
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].fd == -1) {
            clients[i].fd = fd;
            clients[i].ready = 0;
            clients[i].nickname[0] = '\0';
            return i;
        }
    }
    return -1;
}

void remove_client(int index) {
    if (clients[index].fd != -1) close(clients[index].fd);
    clients[index].fd = -1;
    clients[index].ready = 0;
    clients[index].nickname[0] = '\0';
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "ERROR: Usage: %s <IP:PORT>\n", argv[0]);
        fflush(stderr);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (regcomp(&nick_regex, "^[A-Za-z0-9_]+$", REG_EXTENDED | REG_NOSUB) != 0) {
        fprintf(stderr, "ERROR: Regex compile failed.\n");
        fflush(stderr);
        return 1;
    }

    char* sep = strrchr(argv[1], ':');
    if (!sep) {
        fprintf(stderr, "ERROR: Invalid format. Use IP:PORT\n");
        fflush(stderr);
        return 1;
    }

    *sep = '\0';
    char* ip = argv[1];
    char* port = sep + 1;

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(ip, port, &hints, &res) != 0) {
        perror("ERROR: getaddrinfo");
        return 1;
    }

    for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
        listener_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener_fd < 0) continue;
        int opt = 1;
        setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (bind(listener_fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(listener_fd);
        listener_fd = -1;
    }
    freeaddrinfo(res);

    if (listener_fd < 0) {
        fprintf(stderr, "ERROR: Socket bind failed.\n");
        fflush(stderr);
        return 1;
    }

    if (listen(listener_fd, 10) < 0) {
        perror("ERROR: listen");
        return 1;
    }

    for (int i = 0; i < MAX_CLIENTS; ++i) clients[i].fd = -1;

    printf("Server listening on %s:%s\n", ip, port);
    fflush(stdout);

    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(listener_fd, &readfds);
        int maxfd = listener_fd;

        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i].fd != -1) {
                FD_SET(clients[i].fd, &readfds);
                if (clients[i].fd > maxfd) maxfd = clients[i].fd;
            }
        }

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("ERROR: select");
            break;
        }

        if (FD_ISSET(listener_fd, &readfds)) {
            struct sockaddr_storage addr;
            socklen_t len = sizeof(addr);
            int newfd = accept(listener_fd, (struct sockaddr*)&addr, &len);
            if (newfd >= 0) {
                int idx = add_client(newfd);
                if (idx >= 0) {
                    send(newfd, GREETING, strlen(GREETING), 0);
                } else {
                    const char *full = "ERROR Server full\n";
                    send(newfd, full, strlen(full), 0);
                    close(newfd);
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i].fd != -1 && FD_ISSET(clients[i].fd, &readfds)) {
                char buf[MAX_LINE_LENGTH];
                int len = read_line(clients[i].fd, buf, sizeof(buf));
                if (len <= 0) {
                    remove_client(i);
                    continue;
                }

                if (!clients[i].ready) {
                    if (strncmp(buf, "NICK ", 5) == 0) {
                        char* nick = buf + 5;
                        nick[strcspn(nick, "\n")] = 0;
                        if (strlen(nick) > MAX_NICKNAME_LENGTH || regexec(&nick_regex, nick, 0, NULL, 0) != 0) {
                            const char *err = "ERROR Invalid nickname\n";
                            send(clients[i].fd, err, strlen(err), 0);
                            remove_client(i);
                        } else {
                            strncpy(clients[i].nickname, nick, MAX_NICKNAME_LENGTH);
                            clients[i].nickname[MAX_NICKNAME_LENGTH] = '\0';
                            clients[i].ready = 1;
                            send(clients[i].fd, OK_RESPONSE, strlen(OK_RESPONSE), 0);
                        }
                    } else {
                        const char *err = "ERROR Expecting NICK\n";
                        send(clients[i].fd, err, strlen(err), 0);
                        remove_client(i);
                    }
                } else {
                    if (strncmp(buf, "MSG ", 4) == 0) {
                        char* msg = buf + 4;
                        msg[strcspn(msg, "\n")] = 0;
                        if (strlen(msg) > MAX_MESSAGE_LENGTH) {
                            const char *err = "ERROR Message too long\n";
                            send(clients[i].fd, err, strlen(err), 0);
                        } else {
                            broadcast_message(clients[i].nickname, msg, clients[i].fd);
                        }
                    } else {
                        const char *err = "ERROR Unknown command\n";
                        send(clients[i].fd, err, strlen(err), 0);
                    }
                }
            }
        }
    }

    shutdown_server();
    return 0;
}
