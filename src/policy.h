#ifndef POLICY_H
#define POLICY_H

struct user {
    char name[64];
    char password_hash[65];   /* hex SHA-256 */
    char group[64];
    double tokens;            /* token bucket for rate limiting */
    double last_refill;
};

int load_users(const char *path);
int load_rules(const char *path);
void set_rate_limit(double requests_per_sec);

/* Checks a "Basic <base64>" Proxy-Authorization value. NULL if invalid. */
struct user *authenticate(const char *auth_header);

/* 1 if the user's group (or everyone) is denied this host or a parent domain */
int is_blocked(const struct user *user, const char *host);

/* 1 if the user still has budget for a new request */
int take_token(struct user *user, double now);

#endif
