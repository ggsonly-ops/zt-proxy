#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "http.h"
#include "policy.h"
#include "tls.h"

#define BUF_SIZE 16384
#define MAX_EVENTS 256
#define HANDSHAKE_TIMEOUT 10   /* seconds to finish headers / connect / ClientHello */
#define IDLE_TIMEOUT 60

enum state { READ_REQUEST, CONNECTING, WAIT_CLIENT_HELLO, RELAY };

struct conn;

struct endpoint {
    struct conn *conn;
    int fd;
};

struct conn {
    struct endpoint client;
    struct endpoint upstream;
    enum state state;
    char to_upstream[BUF_SIZE];
    size_t to_upstream_len;
    char to_client[BUF_SIZE];
    size_t to_client_len;
    int upstream_closed;
    int closed;
    struct request req;
    struct user *user;
    char client_ip[INET6_ADDRSTRLEN];
    int status;
    size_t bytes_up, bytes_down;
    time_t deadline;
    struct conn *prev, *next;
};

static int epoll_fd;
static struct conn *all_conns;
static struct conn *dead_conns;   /* freed after each epoll batch, since later events may point at them */

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void set_nonblocking(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

static void log_conn(struct conn *conn)
{
    char when[32];
    time_t wall = time(NULL);
    strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%S", localtime(&wall));
    printf("%s %s user=%s %s %s:%d status=%d up=%zu down=%zu\n", when, conn->client_ip,
           conn->user ? conn->user->name : "-", conn->req.method[0] ? conn->req.method : "-",
           conn->req.host[0] ? conn->req.host : "-", conn->req.port, conn->status,
           conn->bytes_up, conn->bytes_down);
    fflush(stdout);
}

static void close_conn(struct conn *conn)
{
    log_conn(conn);
    close(conn->client.fd);
    if (conn->upstream.fd >= 0)
        close(conn->upstream.fd);
    if (conn->prev)
        conn->prev->next = conn->next;
    else
        all_conns = conn->next;
    if (conn->next)
        conn->next->prev = conn->prev;
    conn->closed = 1;
    conn->next = dead_conns;
    dead_conns = conn;
}

/* Recomputes what each socket should wait for. Level-triggered keeps this simple. */
static void update_interest(struct conn *conn)
{
    struct epoll_event event = { 0 };

    event.data.ptr = &conn->client;
    if (conn->state != CONNECTING && conn->to_upstream_len < BUF_SIZE)
        event.events |= EPOLLIN;
    if (conn->to_client_len > 0)
        event.events |= EPOLLOUT;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->client.fd, &event);

    if (conn->upstream.fd < 0)
        return;
    event.events = 0;
    event.data.ptr = &conn->upstream;
    if (conn->state == CONNECTING) {
        event.events = EPOLLOUT;
    } else if (conn->state == RELAY) {
        if (!conn->upstream_closed && conn->to_client_len < BUF_SIZE)
            event.events |= EPOLLIN;
        if (conn->to_upstream_len > 0)
            event.events |= EPOLLOUT;
    }
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->upstream.fd, &event);
}

static void reject(struct conn *conn, int status)
{
    const char *reason = status == 400 ? "Bad Request"
                       : status == 403 ? "Forbidden"
                       : status == 407 ? "Proxy Authentication Required"
                       : status == 429 ? "Too Many Requests"
                       : "Bad Gateway";
    char response[256];
    int len = snprintf(response, sizeof response,
                       "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", status, reason,
                       status == 407 ? "Proxy-Authenticate: Basic realm=\"zt-proxy\"\r\n" : "");
    if (write(conn->client.fd, response, (size_t)len) < 0) {
        /* client is gone anyway */
    }
    conn->status = status;
    close_conn(conn);
}

static int start_upstream_connect(struct conn *conn)
{
    char port[8];
    snprintf(port, sizeof port, "%d", conn->req.port);
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *result;
    /* getaddrinfo blocks the loop; fine for a small proxy, see README */
    if (getaddrinfo(conn->req.host, port, &hints, &result) != 0)
        return -1;

    int fd = socket(result->ai_family, SOCK_STREAM, 0);
    if (fd < 0) {
        freeaddrinfo(result);
        return -1;
    }
    set_nonblocking(fd);
    int rc = connect(fd, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    conn->upstream.fd = fd;
    struct epoll_event event = { .events = EPOLLOUT, .data.ptr = &conn->upstream };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
    conn->state = CONNECTING;
    return 0;
}

static void handle_request(struct conn *conn)
{
    int parsed = parse_request(conn->to_upstream, conn->to_upstream_len, &conn->req);
    if (parsed == 0)
        return;
    if (parsed < 0) {
        reject(conn, 400);
        return;
    }

    conn->user = authenticate(conn->req.auth);
    if (!conn->user) {
        reject(conn, 407);
        return;
    }
    if (is_blocked(conn->user, conn->req.host)) {
        reject(conn, 403);
        return;
    }
    if (!take_token(conn->user, now_seconds())) {
        reject(conn, 429);
        return;
    }

    size_t body_len = conn->to_upstream_len - conn->req.header_len;
    if (strcmp(conn->req.method, "CONNECT") == 0) {
        /* keep only bytes the client sent after the CONNECT headers */
        memmove(conn->to_upstream, conn->to_upstream + conn->req.header_len, body_len);
        conn->to_upstream_len = body_len;
    } else {
        char rewritten[BUF_SIZE];
        int len = build_forward_request(conn->to_upstream, &conn->req, rewritten, sizeof rewritten);
        if (len < 0 || (size_t)len + body_len > BUF_SIZE) {
            reject(conn, 400);
            return;
        }
        memmove(rewritten + len, conn->to_upstream + conn->req.header_len, body_len);
        memcpy(conn->to_upstream, rewritten, (size_t)len + body_len);
        conn->to_upstream_len = (size_t)len + body_len;
    }

    if (start_upstream_connect(conn) < 0)
        reject(conn, 502);
}

/* The CONNECT line names a host, but only the ClientHello says where TLS is really going.
   Both must agree and both must pass policy, otherwise the tunnel is dropped. */
static void check_client_hello(struct conn *conn)
{
    char server_name[256];
    int found = extract_sni((unsigned char *)conn->to_upstream, conn->to_upstream_len, server_name,
                            sizeof server_name);
    if (found == 0 && conn->to_upstream_len < BUF_SIZE)
        return;
    if (found <= 0 || strcasecmp(server_name, conn->req.host) != 0 || is_blocked(conn->user, server_name)) {
        conn->status = 403;
        close_conn(conn);
        return;
    }
    conn->state = RELAY;
    conn->status = 200;
}

/* returns -1 if the conn was closed */
static int flush(int fd, char *buf, size_t *len, size_t *counter)
{
    ssize_t sent = write(fd, buf, *len);
    if (sent < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    memmove(buf, buf + sent, *len - (size_t)sent);
    *len -= (size_t)sent;
    *counter += (size_t)sent;
    return 0;
}

static void on_client_event(struct conn *conn, unsigned events)
{
    if (events & EPOLLOUT) {
        if (flush(conn->client.fd, conn->to_client, &conn->to_client_len, &conn->bytes_down) < 0) {
            close_conn(conn);
            return;
        }
        if (conn->upstream_closed && conn->to_client_len == 0) {
            close_conn(conn);
            return;
        }
    }

    if (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
        ssize_t got = read(conn->client.fd, conn->to_upstream + conn->to_upstream_len,
                           BUF_SIZE - conn->to_upstream_len);
        if (got <= 0) {
            if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                return;
            close_conn(conn);
            return;
        }
        conn->to_upstream_len += (size_t)got;

        if (conn->state == READ_REQUEST) {
            handle_request(conn);
            return;
        }
        if (conn->state == WAIT_CLIENT_HELLO) {
            check_client_hello(conn);
            return;
        }
        conn->deadline = time(NULL) + IDLE_TIMEOUT;
    }
}

static void on_upstream_event(struct conn *conn, unsigned events)
{
    if (conn->state == CONNECTING) {
        int error = 0;
        socklen_t error_len = sizeof error;
        getsockopt(conn->upstream.fd, SOL_SOCKET, SO_ERROR, &error, &error_len);
        if (error != 0) {
            reject(conn, 502);
            return;
        }
        if (strcmp(conn->req.method, "CONNECT") == 0) {
            const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            memcpy(conn->to_client, ok, strlen(ok));
            conn->to_client_len = strlen(ok);
            conn->state = WAIT_CLIENT_HELLO;
            if (conn->to_upstream_len > 0)
                check_client_hello(conn);
        } else {
            conn->state = RELAY;
            conn->status = 200;
        }
        return;
    }

    if (events & EPOLLOUT) {
        if (flush(conn->upstream.fd, conn->to_upstream, &conn->to_upstream_len, &conn->bytes_up) < 0) {
            close_conn(conn);
            return;
        }
    }

    if (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
        ssize_t got = read(conn->upstream.fd, conn->to_client + conn->to_client_len,
                           BUF_SIZE - conn->to_client_len);
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if (got <= 0) {
            /* upstream finished: send what is left to the client, then close */
            conn->upstream_closed = 1;
            if (conn->to_client_len == 0)
                close_conn(conn);
            return;
        }
        conn->to_client_len += (size_t)got;
        conn->deadline = time(NULL) + IDLE_TIMEOUT;
    }
}

static void accept_clients(int listen_fd)
{
    for (;;) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof addr;
        int fd = accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
        if (fd < 0)
            return;
        set_nonblocking(fd);

        struct conn *conn = calloc(1, sizeof *conn);
        if (!conn) {
            close(fd);
            continue;
        }
        conn->client = (struct endpoint){ conn, fd };
        conn->upstream = (struct endpoint){ conn, -1 };
        conn->state = READ_REQUEST;
        conn->deadline = time(NULL) + HANDSHAKE_TIMEOUT;
        if (addr.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr, conn->client_ip, sizeof conn->client_ip);
        else
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr, conn->client_ip, sizeof conn->client_ip);

        conn->next = all_conns;
        if (all_conns)
            all_conns->prev = conn;
        all_conns = conn;

        struct epoll_event event = { .events = EPOLLIN, .data.ptr = &conn->client };
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
    }
}

/* drops slow handshakes (slowloris) and idle tunnels */
static void expire_conns(void)
{
    time_t now = time(NULL);
    struct conn *conn = all_conns;
    while (conn) {
        struct conn *next = conn->next;
        if (now > conn->deadline) {
            if (conn->state != RELAY)
                conn->status = 408;
            close_conn(conn);
        }
        conn = next;
    }
}

static int open_listener(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                                .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(fd, 512) < 0) {
        perror("listen");
        exit(1);
    }
    set_nonblocking(fd);
    return fd;
}

int main(int argc, char **argv)
{
    int port = 8080;
    const char *users_path = "config/users.conf";
    const char *rules_path = "config/rules.conf";
    int opt;
    while ((opt = getopt(argc, argv, "p:u:r:l:")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 'u': users_path = optarg; break;
        case 'r': rules_path = optarg; break;
        case 'l': set_rate_limit(atof(optarg)); break;
        default:
            fprintf(stderr, "usage: %s [-p port] [-u users.conf] [-r rules.conf] [-l requests_per_sec]\n", argv[0]);
            return 1;
        }
    }

    if (load_users(users_path) <= 0 || load_rules(rules_path) < 0) {
        fprintf(stderr, "could not load %s / %s\n", users_path, rules_path);
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    int listen_fd = open_listener(port);
    epoll_fd = epoll_create1(0);
    struct epoll_event listen_event = { .events = EPOLLIN, .data.ptr = NULL };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &listen_event);
    fprintf(stderr, "zt-proxy listening on :%d\n", port);

    struct epoll_event events[MAX_EVENTS];
    time_t last_sweep = time(NULL);
    for (;;) {
        int ready = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        for (int i = 0; i < ready; i++) {
            struct endpoint *endpoint = events[i].data.ptr;
            if (!endpoint) {
                accept_clients(listen_fd);
                continue;
            }
            struct conn *conn = endpoint->conn;
            if (conn->closed)
                continue;
            if (endpoint == &conn->client)
                on_client_event(conn, events[i].events);
            else
                on_upstream_event(conn, events[i].events);
            if (!conn->closed)
                update_interest(conn);
        }
        while (dead_conns) {
            struct conn *next = dead_conns->next;
            free(dead_conns);
            dead_conns = next;
        }
        if (time(NULL) != last_sweep) {
            expire_conns();
            last_sweep = time(NULL);
        }
    }
}
