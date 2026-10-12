#ifndef TLS_H
#define TLS_H

#include <stddef.h>

/* Reads the server name out of a TLS ClientHello without decrypting anything.
   1 = found (written to out), 0 = need more bytes, -1 = not TLS or no SNI */
int extract_sni(const unsigned char *buf, size_t len, char *out, size_t out_cap);

#endif
