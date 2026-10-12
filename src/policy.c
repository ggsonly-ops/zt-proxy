#include "policy.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define MAX_USERS 256
#define MAX_RULES 1024

struct rule {
    char group[64];     /* "*" means every user */
    char domain[256];
};

static struct user users[MAX_USERS];
static int user_count;
static struct rule rules[MAX_RULES];
static int rule_count;
static double rate_per_sec = 20.0;

void set_rate_limit(double requests_per_sec) { rate_per_sec = requests_per_sec; }

static int skip_line(const char *line) { return line[0] == '#' || line[0] == '\n' || line[0] == '\0'; }

int load_users(const char *path)
{
    FILE *file = fopen(path, "r");
    if (!file)
        return -1;
    char line[512];
    while (fgets(line, sizeof line, file) && user_count < MAX_USERS) {
        if (skip_line(line))
            continue;
        struct user *user = &users[user_count];
        /* name:sha256hex:group */
        if (sscanf(line, "%63[^:]:%64[0-9a-f]:%63s", user->name, user->password_hash, user->group) == 3
            && strlen(user->password_hash) == 64) {
            user->tokens = -1;  /* filled on first request */
            user_count++;
        } else {
            fprintf(stderr, "skipping bad user line: %s", line);
        }
    }
    fclose(file);
    return user_count;
}

int load_rules(const char *path)
{
    FILE *file = fopen(path, "r");
    if (!file)
        return -1;
    char line[512];
    while (fgets(line, sizeof line, file) && rule_count < MAX_RULES) {
        if (skip_line(line))
            continue;
        struct rule *rule = &rules[rule_count];
        /* <group|*> <domain> */
        if (sscanf(line, "%63s %255s", rule->group, rule->domain) == 2)
            rule_count++;
    }
    fclose(file);
    return rule_count;
}

static int base64_decode(const char *in, char *out, size_t out_cap)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned buffer = 0;
    int bits = 0;
    size_t used = 0;
    for (; *in && *in != '='; in++) {
        const char *found = strchr(alphabet, *in);
        if (!found)
            return -1;
        buffer = (buffer << 6) | (unsigned)(found - alphabet);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (used + 1 >= out_cap)
                return -1;
            out[used++] = (char)((buffer >> bits) & 0xFF);
        }
    }
    out[used] = '\0';
    return (int)used;
}

static void sha256_hex(const char *text, char hex[65])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)text, strlen(text), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hex + 2 * i, "%02x", digest[i]);
}

struct user *authenticate(const char *auth_header)
{
    if (strncasecmp(auth_header, "Basic ", 6) != 0)
        return NULL;
    char decoded[256];
    if (base64_decode(auth_header + 6, decoded, sizeof decoded) < 0)
        return NULL;
    char *colon = strchr(decoded, ':');
    if (!colon)
        return NULL;
    *colon = '\0';

    char hash[65];
    sha256_hex(colon + 1, hash);
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].name, decoded) == 0)
            return CRYPTO_memcmp(users[i].password_hash, hash, 64) == 0 ? &users[i] : NULL;
    }
    return NULL;
}

static int domain_matches(const char *host, const char *domain)
{
    size_t host_len = strlen(host), domain_len = strlen(domain);
    if (host_len == domain_len)
        return strcasecmp(host, domain) == 0;
    /* sub.example.com matches example.com, but notexample.com does not */
    return host_len > domain_len
        && host[host_len - domain_len - 1] == '.'
        && strcasecmp(host + host_len - domain_len, domain) == 0;
}

int is_blocked(const struct user *user, const char *host)
{
    for (int i = 0; i < rule_count; i++) {
        int applies = strcmp(rules[i].group, "*") == 0 || strcmp(rules[i].group, user->group) == 0;
        if (applies && domain_matches(host, rules[i].domain))
            return 1;
    }
    return 0;
}

int take_token(struct user *user, double now)
{
    if (user->tokens < 0) {
        user->tokens = rate_per_sec;
        user->last_refill = now;
    }
    user->tokens += (now - user->last_refill) * rate_per_sec;
    if (user->tokens > rate_per_sec)
        user->tokens = rate_per_sec;   /* burst size = one second of budget */
    user->last_refill = now;
    if (user->tokens < 1.0)
        return 0;
    user->tokens -= 1.0;
    return 1;
}
