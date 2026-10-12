CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -O2
LDLIBS  = -lcrypto
SRC     = src/http.c src/tls.c src/policy.c

zt-proxy: src/main.c $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

test: tests/test.c $(SRC)
	$(CC) $(CFLAGS) -g -fsanitize=address,undefined -Isrc -o tests/run_tests $^ $(LDLIBS)
	./tests/run_tests

clean:
	rm -f zt-proxy tests/run_tests

.PHONY: test clean
