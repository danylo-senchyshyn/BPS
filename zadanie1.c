#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static void die(void) {
    fputs("chyba", stdout);
    exit(1);
}

static uint64_t fnv1a64(const unsigned char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) {
        h ^= (uint64_t)(*s++);
        h *= 1099511628211ULL;
    }
    if (h == 0) h = 0x9e3779b97f4a7c15ULL;
    return h;
}

static uint64_t xorshift64star(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

int main(int argc, char **argv) {
    int opt;
    int do_encrypt = 0, do_decrypt = 0;
    const char *password = NULL;
    const char *in_path = NULL;
    const char *out_path = NULL;

    while ((opt = getopt(argc, argv, "sdp:i:o:")) != -1) {
        switch (opt) {
            case 's': do_encrypt = 1; break;
            case 'd': do_decrypt = 1; break;
            case 'p': password = optarg; break;
            case 'i': in_path = optarg; break;
            case 'o': out_path = optarg; break;
            default: die();
        }
    }

    if ((do_encrypt + do_decrypt) != 1) die();
    if (!password || !in_path || !out_path) die();
    if (optind != argc) die();

    FILE *fin = fopen(in_path, "rb");
    if (!fin) die();

    FILE *fout = fopen(out_path, "wb");
    if (!fout) {
        fclose(fin);
        die();
    }

    uint64_t state = fnv1a64((const unsigned char *)password);

    unsigned char buf[8192];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        size_t i = 0;
        while (i < n) {
            uint64_t r = xorshift64star(&state);
            for (int k = 0; k < 8 && i < n; k++, i++) {
                buf[i] ^= (unsigned char)((r >> (8 * k)) & 0xFF);
            }
        }

        if (fwrite(buf, 1, n, fout) != n) {
            fclose(fin);
            fclose(fout);
            die();
        }
    }

    if (ferror(fin)) {
        fclose(fin);
        fclose(fout);
        die();
    }

    if (fclose(fin) != 0) {
        fclose(fout);
        die();
    }
    if (fclose(fout) != 0) die();

    return 0;
}
