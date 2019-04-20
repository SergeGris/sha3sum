
#include <stdnoreturn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <locale.h>

#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <progname.h>
#include <fadvise.h>

#define ROL64(a, offset) ((offset != 0) ? ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64 - offset))) : a)
#define index(x, y) (((x) % 5) + 5 * ((y) % 5))
#define SHA3ROUNDS 24

typedef unsigned int uint;

/* Rho Offsets */
static uint RO[SHA3ROUNDS];

/* Round Constants */
static const uint64_t RC[SHA3ROUNDS] =
{
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* --------------------------------------------------------------------------- */

void
init_RO(void)
{
    uint newX, newY;

    RO[index(0, 0)] = 0;
    uint x = 1;
    uint y = 0;
    for (uint t = 0; t < SHA3ROUNDS; ++t) {
        RO[index(x, y)] = ((t + 1) * (t + 2) / 2) % 64;
        newX = (0 * x + 1 * y) % 5;
        newY = (2 * x + 3 * y) % 5;
        x = newX;
        y = newY;
    }
}

static void
theta(uint64_t *A)
{
    uint64_t C[5], D[5];

    for (uint x = 0; x < 5; ++x) {
        C[x] = 0;
        for (uint y = 0; y < 5; ++y) {
            C[x] ^= A[index(x, y)];
        }
    }
    for (uint x = 0; x < 5; ++x) {
        D[x] = ROL64(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
    }
    for (uint x = 0; x < 5; ++x) {
        for (uint y = 0; y < 5; ++y) {
            A[index(x, y)] ^= D[x];
        }
    }
}

static void
rho(uint64_t *A)
{
    init_RO();
    
    for (uint x = 0; x < 5; ++x) {
        for (uint y = 0; y < 5; ++y) {
            A[index(x, y)] = ROL64(A[index(x, y)], RO[index(x, y)]);
        }
    }
}

static void
pi(uint64_t *A)
{
    uint64_t tempA[25];

    for (uint x = 0; x < 5; ++x) {
        for (uint y = 0; y < 5; ++y) {
            tempA[index(x, y)] = A[index(x, y)];
        }
    }
    for (uint x = 0; x < 5; ++x) {
        for (uint y = 0; y < 5; ++y) {
            A[index(0 * x + 1 * y, 2 * x + 3 * y)] = tempA[index(x, y)];
        }
    }
}

static void
chi(uint64_t *A)
{
    uint64_t C[5];

    for (uint y = 0; y < 5; ++y) {
        for (uint x = 0; x < 5; ++x) {
            C[x] = A[index(x, y)] ^ ((~A[index(x + 1, y)]) & A[index(x + 2, y)]);
        }
        for (uint x = 0; x < 5; ++x) {
            A[index(x, y)] = C[x];
        }
    }
}

static void
iota(uint64_t *A, uint indexRound)
{
    A[index(0, 0)] ^= RC[indexRound];
}

static void
keccakf(void *state)
{
    for (uint i = 0; i < SHA3ROUNDS; ++i) {
        theta(state);
        rho(state);
        pi(state);
        chi(state);
        iota(state, i);
    }
}

#define Plen 200

static void
xorin(uint8_t *dest, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        dest[i] ^= src[i];
    }
}
static void
setout(const uint8_t *src, uint8_t *dest, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        dest[i] = src[i];
    }
}

/* The sponge-based hash construction.  */
static void
hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen, size_t rate, uint8_t delim)
{
    if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
        return;
    }
    uint8_t a[Plen];
    bzero(a, Plen * sizeof(uint8_t));

    while (inlen >= rate) {
        xorin(a, in, rate);
        keccakf(a);
        in += rate;
        inlen -= rate;
    }

    a[inlen] ^= delim;
    a[rate - 1] ^= 0x80;

    xorin(a, in, inlen);

    keccakf(a);

    while (outlen >= rate) {
        setout(a, out, rate);
        keccakf(a);
        out += rate;
        outlen -= rate;
    }
    setout(a, out, outlen);
    bzero(a, Plen * sizeof(uint8_t));
}

/* Helper macros to define SHA-3 and SHAKE instances.  */
#define defsha3(bits)                                                               \
    void                                                                            \
    sha3_##bits(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)       \
    {                                                                               \
        if (outlen > (bits / 8)) {                                                  \
            return;                                                                 \
        }                                                                           \
        hash(out, outlen, in, inlen, Plen - (bits / 4), 0x06);                      \
    }


/* FIPS202 SHA3 FOFs */
defsha3(224)
static const size_t SHA3_224_BLOCK  = 28;
static const char  *SHA3_224_STRING = "SHA3-224";

defsha3(256)
static const size_t SHA3_256_BLOCK  = 32;
static const char  *SHA3_256_STRING = "SHA3-256";

defsha3(384)
static const size_t SHA3_384_BLOCK  = 48;
static const char  *SHA3_384_STRING = "SHA3-384";

defsha3(512)
static const size_t SHA3_512_BLOCK  = 64;
static const char  *SHA3_512_STRING = "SHA3-512";

/* FIPS202 SHAKE VOFs */
static const char  *SHAKE_STRING = "SHAKE";
static       int    shake_lenght = 0;

void
shake(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    hash(out, outlen, in, inlen, Plen - (shake_lenght / 4), 0x1f);
}

bool streq(const char *s1, const char *s2)
{
    return !strcmp(s1, s2);
}
bool strneq(const char *s1, const char *s2, size_t n)
{
    return !strncmp(s1, s2, n);
}

noreturn static void
usage(int errcode)
{
    if (errcode != EXIT_SUCCESS) {
        fprintf(stderr, "Try '%s --help' for more information.\n",
                program_name);
        exit(errcode);
    }

    fprintf(stdout, "Usage: %s [OPTION]... [FILE]...\n", program_name);
    fputs("With no FILE, or when FILE is -, read standard input.\n\n", stdout);
    fputs("  --<algo>               hash algorithm (sha3-256 is default):\n"
          "                         [sha3-224 | sha3-256 | sha3-384 | sha3-512]\n"
          "                         [shake-128 | shake-256]\n", stdout);
    fputs("  -l, --length <length>  digest length in bits, must not exceed the maximum for\n"
          "                         the selected algorithm\n", stdout);
    fputs("  --tag                  create a BSD-style checksum\n", stdout);
    fputs("  -b, --binary           read in binary mode\n", stdout);
    fputs("  -t, --text             read in text mode\n", stdout);
    fputs("  -z, --zero             end each output line with NUL, not newline,\n"
          "                         and disable file name escaping\n", stdout);
    fputs("  --help                 display this help and exit\n", stdout);

    exit(EXIT_SUCCESS);
}

typedef void (*hashf)(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

static size_t      BLOCK     = 32;
static hashf       hash_algo = sha3_256;
static const char *hash_name = "SHA3-256";

static bool is_opts_ended  = false;
static bool prefix_tag     = false;
static bool binary         = false;
static bool ignore_missing = false;

/* Line delimiter.  */
static unsigned char delim = '\n';

enum
{
    END_OPTIONS = 1,
    HELP_OPTION,
    LENGHT_OPTION,
    TAG_OPTION,
    BINARY_OPTION,
    TEXT_OPTION,
    ZERO_OPTION,
    IGNORE_MISSING_OPTION,

    SHA3_224_OPTION,
    SHA3_256_OPTION,
    SHA3_384_OPTION,
    SHA3_512_OPTION,

    SHAKE_OPTION
};

int
is_option(char *str)
{
    if (streq(str, "--")) {
        return END_OPTIONS;
    }
    if (streq(str, "--help")) {
        return HELP_OPTION;
    }
    if (streq(str, "--length") || streq(str, "-l")) {
        return LENGHT_OPTION;
    }
    if (streq(str, "--tag")) {
        return TAG_OPTION;
    }
    if (streq(str, "--binary") || streq(str, "-b")) {
        return BINARY_OPTION;
    }
    if (streq(str, "--text") || streq(str, "-t")) {
        return TEXT_OPTION;
    }
    if (streq(str, "--zero") || streq(str, "-z")) {
        return ZERO_OPTION;
    }
    if (streq(str, "--ignore-missing")) {
        return IGNORE_MISSING_OPTION;
    }

    if (streq(str, "--sha3-224")) {
        return SHA3_224_OPTION;
    }
    if (streq(str, "--sha3-256")) {
        return SHA3_256_OPTION;
    }
    if (streq(str, "--sha3-384")) {
        return SHA3_384_OPTION;
    }
    if (streq(str, "--sha3-512")) {
        return SHA3_512_OPTION;
    }

    size_t len = strlen("--shake-");
    if (strneq(str, "--shake-", len)) {
        if (str[len] == '\0') {
            fprintf(stderr, "%s: missing length\n", program_name);
            exit(EXIT_FAILURE);
        }
        str += len;
        shake_lenght = atoi(str);
        if (shake_lenght % 8 != 0) {
            fprintf(stderr, "%s: SHAKE length must be divided by 8 without remainder\n", program_name);
            exit(EXIT_FAILURE);
        }
        return SHAKE_OPTION;
    }

    return 0;
}

/* If ESCAPE is true, then translate each NEWLINE byte to the string, "\\n",
   and each backslash to "\\\\".  */
static void
print_filename(char const *file, bool escape)
{
    if (!escape) {
        fputs (file, stdout);
        return;
    }

    while (*file) {
        switch (*file)
        {
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;

        default:
            putchar(*file);
            break;
        }
        file++;
    }
}

void
hash_file(char *filename)
{
    FILE *fp;
    uint8_t *in  = malloc(BLOCK * sizeof(uint8_t));
    uint8_t *out = malloc(BLOCK * sizeof(uint8_t));
    size_t bytesread;

    if (streq(filename, "-")) {
        fp = stdin;
    }
    else {
        fp = fopen(filename, binary ? "rb" : "r");
        if (fp == NULL) {
            if (ignore_missing) {
                return;
            }
            else {
                fprintf(stderr, "%s: unable to open \u2018%s\u2019\n", program_name, filename);
                exit(EXIT_FAILURE);
            }
        }
    }

    fadvise(fp, FADVISE_SEQUENTIAL);

    while ((bytesread = fread(in, sizeof(char), BLOCK, fp)) != 0) {
        hash_algo(out, BLOCK, in, bytesread);
    }

    /* We don't really need to escape, and hence detect, the '\\'
       char, and not doing so should be both forwards and backwards
       compatible, since only escaped lines would have a '\\' char at
       the start. However just in case users are directly comparing
       against old (hashed) outputs, in the presence of files
       containing '\\' characters, we decided to not simplify the
       output in this case.  */
    bool needs_escape = (strchr(filename, '\\') || strchr(filename, '\n')) && delim == '\n';

    if (prefix_tag) {
        fputs(hash_name, stdout);

        if (shake_lenght != 0) {
            fprintf(stdout, "-%i", shake_lenght);
        }

        fputs(" (", stdout);
        print_filename(filename, needs_escape);
        fputs(") = ", stdout);
    }

    /* Output a leading backslash if the file name contains
       a newline or backslash.  */
    if (!prefix_tag && needs_escape) {
        putchar('\\');
    }

    for (size_t i = 0; i < BLOCK; ++i) {
        printf("%02x", out[i]);
    }

    if (!prefix_tag) {
        putchar(' ');

        putchar(binary ? '*' : ' ');

        printf(filename, needs_escape);
    }
    
    putchar(delim);

    if (fp != stdin) {
        fclose(fp);
    }

    free(out);
    free(in);
}

void
parseopt(int argc, char **argv)
{
#define F (hashf)

    for (int i = 1; i < argc; ++i) {
        int opt;
        if (!is_opts_ended) {
            switch (opt = is_option(argv[i]))
            {
            case END_OPTIONS:
                is_opts_ended = true;
                break;
            case HELP_OPTION:
                usage(EXIT_SUCCESS);

            case TAG_OPTION:
                prefix_tag = true;
                binary = true;
                break;
            case BINARY_OPTION:
                binary = true;
                break;
            case TEXT_OPTION:
                binary = false;
                break;
            case ZERO_OPTION:
                delim = '\0';
                break;
            case IGNORE_MISSING_OPTION:
                ignore_missing = true;
                break;

            case SHA3_224_OPTION:
                hash_algo = F sha3_224;
                BLOCK     = SHA3_224_BLOCK;
                hash_name = SHA3_224_STRING;
                break;
            case SHA3_256_OPTION:
                hash_algo = F sha3_256;
                BLOCK     = SHA3_256_BLOCK;
                hash_name = SHA3_256_STRING;
                break;
            case SHA3_384_OPTION:
                hash_algo = F sha3_384;
                BLOCK     = SHA3_384_BLOCK;
                hash_name = SHA3_384_STRING;
                break;
            case SHA3_512_OPTION:
                hash_algo = F sha3_512;
                BLOCK     = SHA3_512_BLOCK;
                hash_name = SHA3_512_STRING;
                break;

            case SHAKE_OPTION:
                hash_algo = F shake;
                BLOCK     = shake_lenght / 8;
                hash_name = SHAKE_STRING;
                break;
            }
        }
    }

    if (prefix_tag && !binary) {
        fprintf(stderr, "%s: \u2018--tag\u2019 does not support \u2018--text\u2019 mode.\n", program_name);
        exit(EXIT_FAILURE);
    }

#undef F
}

int
main(int argc, char **argv)
{
    set_program_name(argv[0]);
    setlocale(LC_ALL, "");

    /* TODO:
       atexit(close_stdout); */

    /* Line buffer stdout to ensure lines are written atomically and immediately
       so that processes running in parallel do not intersperse their output.  */
    setvbuf(stdout, NULL, _IOLBF, 0);

    parseopt(argc, argv);

    if (argc == 1) {
        hash_file("-");
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        if (!is_option(argv[i])) {
            hash_file(argv[i]);
        }
    }

    return EXIT_SUCCESS;
}

