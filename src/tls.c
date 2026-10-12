#include "tls.h"

#include <string.h>

static unsigned read_u16(const unsigned char *p) { return (unsigned)(p[0] << 8 | p[1]); }

int extract_sni(const unsigned char *buf, size_t len, char *out, size_t out_cap)
{
    if (len < 5)
        return 0;
    if (buf[0] != 0x16)                 /* record type must be handshake */
        return -1;
    size_t record_len = read_u16(buf + 3);
    if (len < 5 + record_len)
        return 0;

    const unsigned char *pos = buf + 5;
    const unsigned char *end = pos + record_len;

    if (end - pos < 4 || pos[0] != 0x01) /* ClientHello */
        return -1;
    pos += 4;                           /* handshake type + 3-byte length */

    if (end - pos < 2 + 32 + 1)
        return -1;
    pos += 2 + 32;                      /* client version + random */
    pos += 1 + pos[0];                  /* session id */

    if (end - pos < 2)
        return -1;
    pos += 2 + read_u16(pos);           /* cipher suites */

    if (end - pos < 1)
        return -1;
    pos += 1 + pos[0];                  /* compression methods */

    if (end - pos < 2)
        return -1;
    const unsigned char *ext_end = pos + 2 + read_u16(pos);
    pos += 2;
    if (ext_end > end)
        return -1;

    while (ext_end - pos >= 4) {
        unsigned type = read_u16(pos);
        unsigned ext_len = read_u16(pos + 2);
        pos += 4;
        if (ext_end - pos < ext_len)
            return -1;

        if (type == 0x0000) {           /* server_name */
            /* list length (2), name type (1), name length (2), name */
            if (ext_len < 5 || pos[2] != 0x00)
                return -1;
            size_t name_len = read_u16(pos + 3);
            if (name_len + 5 > ext_len || name_len == 0 || name_len >= out_cap)
                return -1;
            memcpy(out, pos + 5, name_len);
            out[name_len] = '\0';
            return 1;
        }
        pos += ext_len;
    }
    return -1;
}
