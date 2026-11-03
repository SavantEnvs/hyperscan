// Writes starter seeds for fuzz_deserialize_scan: u16le database length, a serialized database, then bytes to scan.
// Databases are compiled for a generic platform so they deserialize on any host.
//   clang++ gen_seeds.cc -I<hyperscan>/src <build>/lib/libhs.a -lcrypto -o gen_seeds && ./gen_seeds <outdir>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "hs.h"

struct Seed { const char *name; const char *pattern; unsigned flags; unsigned mode; const char *payload; };

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const Seed seeds[] = {
        {"block_literal", "foobar", 0, HS_MODE_BLOCK, "xx foobar yy"},
        {"block_singlematch", "ab+c", HS_FLAG_SINGLEMATCH, HS_MODE_BLOCK, "abbbc abc"},
        {"block_alt_caseless", "(?:cat|dog|bird)s?", HS_FLAG_CASELESS, HS_MODE_BLOCK, "Cats and DOG and birds"},
        {"block_repeat", "a[0-9]{3,40}z", HS_FLAG_DOTALL, HS_MODE_BLOCK, "a12345z a1z a123456789012345678901234567890123456789z"},
        {"block_dotstar", "^foo.*bar", HS_FLAG_MULTILINE, HS_MODE_BLOCK, "foo bar\nfoo baz bar"},
        {"block_utf8", "caf\\xc3\\xa9+", HS_FLAG_UTF8, HS_MODE_BLOCK, "caf\xc3\xa9\xc3\xa9 cafe"},
        {"vectored_literal", "needle", 0, HS_MODE_VECTORED, "hay needle hay"},
        {"stream_literal", "hello world", 0, HS_MODE_STREAM, "say hello world now"},
        {"stream_repeat", "x(abc){2,6}y", 0, HS_MODE_STREAM, "xabcabcabcy"},
        {"stream_dotstar", "foo.*bar.*baz", 0, HS_MODE_STREAM, "foo 1 bar 2 baz"},
        {"stream_som", "a.{1,10}b", HS_FLAG_SOM_LEFTMOST, HS_MODE_STREAM | HS_MODE_SOM_HORIZON_LARGE, "a123456b ab"},
    };
    hs_platform_info_t plat = {};
    plat.tune = HS_TUNE_FAMILY_GENERIC;
    plat.cpu_features = 0;
    for (const Seed &s : seeds) {
        hs_database_t *db = nullptr;
        hs_compile_error_t *err = nullptr;
        if (hs_compile(s.pattern, s.flags, s.mode, &plat, &db, &err) != HS_SUCCESS) {
            fprintf(stderr, "%s: compile failed: %s\n", s.name, err->message);
            return 1;
        }
        char *bytes = nullptr;
        size_t len = 0;
        if (hs_serialize_database(db, &bytes, &len) != HS_SUCCESS) return 1;
        std::string path = std::string(argv[1]) + "/" + s.name;
        FILE *f = fopen(path.c_str(), "wb");
        if (len > 0xffff) return 1;
        fputc(len & 0xff, f);
        fputc(len >> 8, f);
        fwrite(bytes, 1, len, f);
        fwrite(s.payload, 1, strlen(s.payload), f);
        fclose(f);
        free(bytes);
        hs_free_database(db);
    }
    return 0;
}
