#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "policy.h"
#include "tls.h"

static int failures;

#define CHECK(cond)                                                    \
    do {                                                               \
        if (!(cond)) {                                                 \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);     \
            failures++;                                                \
        }                                                              \
    } while (0)

static void test_parse_connect(void)
{
    const char *raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
                      "Proxy-Authorization: Basic YWxpY2U6YWxpY2UxMjM=\r\n\r\n";
    struct request req;
    CHECK(parse_request(raw, strlen(raw), &req) == 1);
    CHECK(strcmp(req.method, "CONNECT") == 0);
    CHECK(strcmp(req.host, "example.com") == 0);
    CHECK(req.port == 443);
    CHECK(strcmp(req.auth, "Basic YWxpY2U6YWxpY2UxMjM=") == 0);
    CHECK(req.header_len == strlen(raw));
}

static void test_parse_http_and_rewrite(void)
{
    const char *raw = "GET http://site.test:8000/a/b?x=1 HTTP/1.1\r\nHost: site.test:8000\r\n"
                      "Proxy-Authorization: Basic abc\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n";
    struct request req;
    CHECK(parse_request(raw, strlen(raw), &req) == 1);
    CHECK(strcmp(req.host, "site.test") == 0);
    CHECK(req.port == 8000);
    CHECK(strcmp(req.path, "/a/b?x=1") == 0);

    char out[1024];
    int len = build_forward_request(raw, &req, out, sizeof out);
    CHECK(len > 0);
    out[len] = '\0';
    CHECK(strncmp(out, "GET /a/b?x=1 HTTP/1.1\r\n", 23) == 0);
    CHECK(strstr(out, "Proxy-Authorization") == NULL);    /* credentials never leave the proxy */
    CHECK(strstr(out, "Proxy-Connection") == NULL);
    CHECK(strstr(out, "Accept: */*\r\n") != NULL);
    CHECK(strstr(out, "Connection: close\r\n\r\n") != NULL);
}

static void test_parse_bad_and_partial(void)
{
    struct request req;
    const char *partial = "GET http://a.test/ HTTP/1.1\r\nHost: a";
    CHECK(parse_request(partial, strlen(partial), &req) == 0);
    const char *origin_form = "GET /index.html HTTP/1.1\r\n\r\n";
    CHECK(parse_request(origin_form, strlen(origin_form), &req) == -1);
    const char *bad_port = "CONNECT a.test:99999 HTTP/1.1\r\n\r\n";
    CHECK(parse_request(bad_port, strlen(bad_port), &req) == -1);
    char huge[MAX_HEADER + 10];
    memset(huge, 'A', sizeof huge);
    CHECK(parse_request(huge, sizeof huge, &req) == -1);
}

/* builds a minimal TLS 1.2 ClientHello carrying the given server name */
static size_t make_client_hello(unsigned char *buf, const char *name)
{
    size_t name_len = strlen(name);
    unsigned char body[512];
    size_t n = 0;
    body[n++] = 0x03; body[n++] = 0x03;                 /* version */
    memset(body + n, 0x11, 32); n += 32;                /* random */
    body[n++] = 0;                                      /* session id */
    body[n++] = 0; body[n++] = 2; body[n++] = 0x13; body[n++] = 0x01;   /* one cipher */
    body[n++] = 1; body[n++] = 0;                       /* null compression */
    size_t ext_len = 4 + 5 + name_len;
    body[n++] = (unsigned char)(ext_len >> 8); body[n++] = (unsigned char)ext_len;
    body[n++] = 0; body[n++] = 0;                       /* server_name */
    body[n++] = (unsigned char)((5 + name_len) >> 8);
    body[n++] = (unsigned char)(5 + name_len);
    body[n++] = (unsigned char)((3 + name_len) >> 8); body[n++] = (unsigned char)(3 + name_len);
    body[n++] = 0;                                      /* host_name */
    body[n++] = (unsigned char)(name_len >> 8); body[n++] = (unsigned char)name_len;
    memcpy(body + n, name, name_len); n += name_len;

    size_t i = 0;
    buf[i++] = 0x16; buf[i++] = 0x03; buf[i++] = 0x01;
    buf[i++] = (unsigned char)((n + 4) >> 8); buf[i++] = (unsigned char)(n + 4);
    buf[i++] = 0x01; buf[i++] = 0; buf[i++] = (unsigned char)(n >> 8); buf[i++] = (unsigned char)n;
    memcpy(buf + i, body, n);
    return i + n;
}

static void test_sni(void)
{
    unsigned char hello[600];
    size_t len = make_client_hello(hello, "www.example.com");
    char name[256];
    CHECK(extract_sni(hello, len, name, sizeof name) == 1);
    CHECK(strcmp(name, "www.example.com") == 0);
    CHECK(extract_sni(hello, len - 10, name, sizeof name) == 0);   /* incomplete record */
    const unsigned char plain[] = "GET / HTTP/1.1\r\n";
    CHECK(extract_sni(plain, sizeof plain, name, sizeof name) == -1);
    hello[50] = 0xFF;   /* corrupt the extensions length */
    CHECK(extract_sni(hello, len, name, sizeof name) == -1);
}

static void test_policy(void)
{
    CHECK(load_users("config/users.conf") == 2);
    CHECK(load_rules("config/rules.conf") == 3);

    struct user *alice = authenticate("Basic YWxpY2U6YWxpY2UxMjM=");   /* alice:alice123 */
    struct user *bob = authenticate("Basic Ym9iOmJvYjEyMw==");         /* bob:bob123 */
    CHECK(alice != NULL && strcmp(alice->group, "engineering") == 0);
    CHECK(bob != NULL && strcmp(bob->group, "interns") == 0);
    CHECK(authenticate("Basic YWxpY2U6d3Jvbmc=") == NULL);              /* alice:wrong */
    CHECK(authenticate("Bearer abc") == NULL);
    CHECK(authenticate("") == NULL);

    CHECK(is_blocked(alice, "malware.test"));
    CHECK(is_blocked(alice, "cdn.MALWARE.test"));
    CHECK(!is_blocked(alice, "notmalware.test"));
    CHECK(!is_blocked(alice, "social.example"));    /* only interns are blocked */
    CHECK(is_blocked(bob, "m.social.example"));

    set_rate_limit(5);
    int allowed = 0;
    for (int i = 0; i < 10; i++)
        allowed += take_token(alice, 100.0);
    CHECK(allowed == 5);                  /* burst of 5, then throttled */
    CHECK(take_token(alice, 100.5) == 1); /* half a second refills 2.5 tokens */
}

int main(void)
{
    test_parse_connect();
    test_parse_http_and_rewrite();
    test_parse_bad_and_partial();
    test_sni();
    test_policy();
    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
