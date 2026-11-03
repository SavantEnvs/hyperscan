// Fuzzes hs_deserialize_database and the runtime over a serialized database plus scan data.
// Input = u16 little-endian database length, the serialized database, then the bytes to scan.
// Serialized databases are trusted input (doc/dev-reference/serialization.rst): the two HMACs are
// NOT forged, so a mutated database is rejected by the integrity check (the real surface) and only
// databases that pass (the seeds) reach the scan, where the scanned bytes are what the fuzzer varies.
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "hs.h"

namespace {

int on_match(unsigned int, unsigned long long, unsigned long long, unsigned int, void *ctx) {
    ++*static_cast<unsigned *>(ctx);
    return 0;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return -1;
    }
    const size_t db_len = static_cast<size_t>(data[0]) | (static_cast<size_t>(data[1]) << 8);
    if (db_len == 0 || db_len > size - 2) {
        return -1;
    }

    // Exactly sized heap copy so ASan catches any read past the end of the blob.
    char *blob = static_cast<char *>(malloc(db_len));
    memcpy(blob, data + 2, db_len);
    hs_database_t *db = nullptr;
    const hs_error_t rc = hs_deserialize_database(blob, db_len, &db);
    free(blob);
    if (rc != HS_SUCCESS) {
        return -1;
    }

    char *info = nullptr;
    if (hs_database_info(db, &info) == HS_SUCCESS) {
        free(info);
    }

    hs_scratch_t *scratch = nullptr;
    if (hs_alloc_scratch(db, &scratch) == HS_SUCCESS) {
        unsigned matches = 0;
        const unsigned len = static_cast<unsigned>(size - 2 - db_len);
        const unsigned half = len / 2;
        char *buf = static_cast<char *>(malloc(len ? len : 1));
        memcpy(buf, data + 2 + db_len, len);

        hs_scan(db, buf, len, 0, scratch, on_match, &matches);

        const char *parts[2] = {buf, buf + half};
        const unsigned lens[2] = {half, len - half};
        hs_scan_vector(db, parts, lens, 2, 0, scratch, on_match, &matches);

        hs_stream_t *stream = nullptr;
        if (hs_open_stream(db, 0, &stream) == HS_SUCCESS) {
            hs_scan_stream(stream, buf, half, 0, scratch, on_match, &matches);
            hs_scan_stream(stream, buf + half, len - half, 0, scratch, on_match, &matches);
            hs_close_stream(stream, scratch, on_match, &matches);
        }
        free(buf);
        hs_free_scratch(scratch);
    }
    hs_free_database(db);
    return 0;
}
