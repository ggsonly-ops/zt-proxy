# zt-proxy

A small zero-trust web gateway in C. It is an HTTP/HTTPS forward proxy that checks **who** is asking and **where** the traffic is really going before it lets anything through.

Every request must carry user credentials. Policy is per user group, not per IP. For HTTPS, the proxy reads the server name from the TLS ClientHello (without decrypting anything) and drops the tunnel if it does not match the host the client asked for.

One thread, one `epoll` loop, non-blocking sockets. Under 900 lines of C.

## What it does

| Feature | How |
|---|---|
| HTTP forwarding | Parses `GET http://host/path`, rewrites it to origin form, strips `Proxy-Authorization` and hop-by-hop headers before forwarding |
| HTTPS tunneling | `CONNECT host:443`, then relays encrypted bytes both ways |
| Authentication | `Proxy-Authorization: Basic`, passwords stored as SHA-256, compared in constant time. Missing or wrong → `407` |
| Per-group policy | `rules.conf` blocks a domain and all its subdomains for a group or everyone (`sub.bad.test` matches `bad.test`, `notbad.test` does not) → `403` |
| SNI check | The ClientHello's server name must equal the `CONNECT` host and must also pass policy. Stops a client from opening a tunnel to an allowed host and then talking TLS to a blocked one |
| Rate limiting | Token bucket per user (`-l` requests/sec, burst of one second) → `429` |
| Timeouts | 10 s to finish headers, connect and send the ClientHello (slowloris defence) → `408`. Idle tunnels close after 60 s |
| Backpressure | Fixed 16 KB buffer per direction. A full buffer stops reading from that side until the other side drains it |
| Access log | One line per connection: time, client IP, user, method, host, status, bytes up/down |

## Build and run

Needs Linux, gcc and OpenSSL's libcrypto (`libssl-dev`), used only for SHA-256.

```bash
make
./zt-proxy -p 8080 -u config/users.conf -r config/rules.conf -l 20
```

Add a user (prompts for the password):

```bash
tools/adduser.sh carol engineering
```

## Try it

The sample config has `alice` (engineering, password `alice123`) and `bob` (interns, password `bob123`).

```bash
curl -x http://127.0.0.1:8080 https://example.com                          # 407, no credentials
curl -x http://127.0.0.1:8080 -U alice:alice123 https://example.com        # 200
curl -x http://127.0.0.1:8080 -U alice:alice123 http://malware.test        # 403, blocked for everyone
curl -x http://127.0.0.1:8080 -U bob:bob123 https://social.example         # blocked for interns only

# CONNECT says example.com, but the ClientHello says evil.test → tunnel dropped
openssl s_client -connect example.com:443 -proxy 127.0.0.1:8080 \
  -proxy_user alice -proxy_pass pass:alice123 -servername evil.test
```

## Tests

```bash
make test
```

Unit tests for the HTTP parser and rewriter, the ClientHello parser (complete, truncated, corrupted and non-TLS input), authentication, domain matching and the token bucket. They are built with AddressSanitizer and UBSan.

I also ran the proxy itself under ASan against a local HTTP server and an `openssl s_server`, covering auth failures, blocked hosts, a dead upstream (`502`), an SNI mismatch, rate limiting and a half-sent request. ASan reported nothing.

## Benchmark

`wrk` on a 2-vCPU Linux VM, with the proxy, a small Go origin server and `wrk` all sharing those two cores. The proxy adds `Connection: close`, so every request opens a fresh client connection and a fresh upstream connection.

| Setup | Requests/sec | p99 latency |
|---|---|---|
| wrk → origin directly, 100 connections | 31,074 | 9.4 ms |
| wrk → zt-proxy → origin, 100 connections | 15,124 | 12.9 ms |
| wrk → zt-proxy → origin, 1,000 connections | 11,454 | 143 ms |

No socket errors in any run. Going through the proxy halves throughput, which is expected since it does twice the connection setup and every byte is copied through it.

## Design notes and limits

- **Level-triggered epoll.** Interest is recomputed after every event from the buffer state, so there is no "missed edge" class of bug. Edge-triggered would save some `epoll_ctl` calls.
- **Closed connections are freed after the epoll batch,** because a later event in the same batch can still point at them.
- **DNS is blocking.** `getaddrinfo` stalls the loop while it resolves. A real gateway would use an async resolver or a resolver thread.
- **One request per connection** for plain HTTP. This keeps the policy check simple: a client cannot reuse a connection to reach a second host without being checked again.
- **No TLS inspection.** Only the unencrypted ClientHello is read. Full inspection would need the proxy to act as its own CA.
- IPv6 literals in `CONNECT` (`[::1]:443`) are not parsed. A ClientHello split across several TLS records is rejected.

## Layout

```
src/main.c     event loop, connection state machine, timeouts, logging
src/http.c     request parsing and rewriting
src/tls.c      ClientHello SNI extraction
src/policy.c   users, rules, auth, token bucket
tests/test.c   unit tests
config/        sample users and rules
```
