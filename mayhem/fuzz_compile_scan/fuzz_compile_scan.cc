// Fuzzes Hyperscan's compiler and every scan mode: the input picks the mode, pattern flags,
// extended parameters (or literal patterns) and the data to scan.
#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "hs.h"

namespace {

int on_match(unsigned int, unsigned long long, unsigned long long, unsigned int, void *ctx) {
    ++*static_cast<unsigned *>(ctx);
    return 0;
}

void scan_db(const hs_database_t *db, unsigned mode, const std::vector<uint8_t> &data) {
    hs_scratch_t *scratch = nullptr;
    if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
        return;
    }
    unsigned matches = 0;
    const char *buf = reinterpret_cast<const char *>(data.data());
    const unsigned len = static_cast<unsigned>(data.size());
    const unsigned half = len / 2;

    if (mode & HS_MODE_BLOCK) {
        hs_scan(db, buf, len, 0, scratch, on_match, &matches);
    } else if (mode & HS_MODE_VECTORED) {
        const char *parts[2] = {buf, buf + half};
        const unsigned lens[2] = {half, len - half};
        hs_scan_vector(db, parts, lens, 2, 0, scratch, on_match, &matches);
    } else {
        hs_stream_t *stream = nullptr;
        if (hs_open_stream(db, 0, &stream) == HS_SUCCESS) {
            hs_scan_stream(stream, buf, half, 0, scratch, on_match, &matches);

            hs_stream_t *copy = nullptr;
            if (hs_copy_stream(&copy, stream) == HS_SUCCESS) {
                hs_close_stream(copy, scratch, on_match, &matches);
            }

            size_t need = 0;
            hs_compress_stream(stream, nullptr, 0, &need);
            if (need) {
                std::vector<char> blob(need);
                size_t used = 0;
                if (hs_compress_stream(stream, blob.data(), blob.size(), &used) == HS_SUCCESS) {
                    hs_stream_t *restored = nullptr;
                    if (hs_expand_stream(db, &restored, blob.data(), used) == HS_SUCCESS) {
                        hs_scan_stream(restored, buf + half, len - half, 0, scratch, on_match, &matches);
                        hs_close_stream(restored, scratch, on_match, &matches);
                    }
                }
            }

            hs_scan_stream(stream, buf + half, len - half, 0, scratch, on_match, &matches);
            hs_close_stream(stream, scratch, on_match, &matches);
        }
    }
    hs_free_scratch(scratch);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    static const unsigned kModes[] = {
        HS_MODE_BLOCK,
        HS_MODE_VECTORED,
        HS_MODE_STREAM,
        HS_MODE_STREAM | HS_MODE_SOM_HORIZON_LARGE,
        HS_MODE_STREAM | HS_MODE_SOM_HORIZON_MEDIUM,
        HS_MODE_STREAM | HS_MODE_SOM_HORIZON_SMALL,
        HS_MODE_BLOCK | HS_MODE_SOM_HORIZON_LARGE,
        HS_MODE_VECTORED | HS_MODE_SOM_HORIZON_LARGE,
    };
    const unsigned mode = kModes[fdp.ConsumeIntegralInRange<unsigned>(0, 7)];
    const bool literal = fdp.ConsumeBool();
    const unsigned npat = fdp.ConsumeIntegralInRange<unsigned>(1, 3);

    std::vector<std::string> exprs;
    std::vector<unsigned> flags;
    std::vector<unsigned> ids;
    std::vector<hs_expr_ext_t> exts;
    std::vector<size_t> lens;
    bool use_ext = false;
    for (unsigned i = 0; i < npat; i++) {
        flags.push_back(fdp.ConsumeIntegral<uint16_t>() & 0x7ff);
        ids.push_back(i + 1);
        std::string e = fdp.ConsumeRandomLengthString(96);
        if (!literal) {
            e = e.substr(0, e.find('\0'));
        }
        lens.push_back(e.size());
        exprs.push_back(e);

        hs_expr_ext_t ext = {};
        ext.flags = fdp.ConsumeIntegral<uint8_t>() & 0x1f;
        ext.min_offset = fdp.ConsumeIntegralInRange<unsigned long long>(0, 64);
        ext.max_offset = fdp.ConsumeIntegralInRange<unsigned long long>(0, 128);
        ext.min_length = fdp.ConsumeIntegralInRange<unsigned long long>(0, 32);
        ext.edit_distance = fdp.ConsumeIntegralInRange<unsigned>(0, 3);
        ext.hamming_distance = fdp.ConsumeIntegralInRange<unsigned>(0, 3);
        use_ext |= ext.flags != 0;
        exts.push_back(ext);
    }
    const std::vector<uint8_t> input = fdp.ConsumeRemainingBytes<uint8_t>();

    std::vector<const char *> cexprs;
    std::vector<const hs_expr_ext_t *> cexts;
    for (unsigned i = 0; i < npat; i++) {
        cexprs.push_back(exprs[i].c_str());
        cexts.push_back(use_ext ? &exts[i] : nullptr);
    }

    hs_database_t *db = nullptr;
    hs_compile_error_t *err = nullptr;
    hs_error_t rc;
    if (literal) {
        rc = hs_compile_lit_multi(cexprs.data(), flags.data(), ids.data(), lens.data(), npat, mode,
                                  nullptr, &db, &err);
    } else if (use_ext) {
        rc = hs_compile_ext_multi(cexprs.data(), flags.data(), ids.data(), cexts.data(), npat, mode,
                                  nullptr, &db, &err);
    } else {
        rc = hs_compile_multi(cexprs.data(), flags.data(), ids.data(), npat, mode, nullptr, &db, &err);
    }
    if (rc != HS_SUCCESS) {
        hs_free_compile_error(err);
        if (!literal) {
            hs_expr_info_t *info = nullptr;
            hs_compile_error_t *ierr = nullptr;
            if (hs_expression_info(cexprs[0], flags[0], &info, &ierr) == HS_SUCCESS) {
                free(info);
            } else {
                hs_free_compile_error(ierr);
            }
        }
        return -1;
    }

    char *dbinfo = nullptr;
    if (hs_database_info(db, &dbinfo) == HS_SUCCESS) {
        free(dbinfo);
    }
    size_t dbsize = 0;
    hs_database_size(db, &dbsize);

    scan_db(db, mode, input);

    char *blob = nullptr;
    size_t blob_len = 0;
    if (hs_serialize_database(db, &blob, &blob_len) == HS_SUCCESS) {
        hs_database_t *copy = nullptr;
        if (hs_deserialize_database(blob, blob_len, &copy) == HS_SUCCESS) {
            scan_db(copy, mode, input);
            hs_free_database(copy);
        }
        free(blob);
    }
    hs_free_database(db);
    return 0;
}
