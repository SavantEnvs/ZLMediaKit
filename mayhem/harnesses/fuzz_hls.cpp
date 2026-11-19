// HLS playlists as the HLS pull client (HlsPlayer) downloads them: HlsParser::parse of master and
// media m3u8 (EXTM3U, EXTINF, EXT-X-STREAM-INF, sequence, target duration, byte ranges, program
// date time) with segment URL resolution against the playlist URL.
#include "fuzz_common.h"
#include "Http/HlsParser.h"

using namespace mediakit;

namespace {
class HlsFuzzParser : public HlsParser {
public:
    size_t _urls = 0;

protected:
    bool onParsed(bool is_m3u8_inner, int64_t sequence, const std::map<int, ts_segment> &ts_list) override {
        for (auto &pr : ts_list) {
            _urls += pr.second.url.size();
        }
        return true;
    }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    HlsFuzzParser parser;
    try {
        parser.parse("http://127.0.0.1:80/live/stream/hls.m3u8?token=1", std::string((const char *)data, size));
        (void)parser.isM3u8();
        (void)parser.isLive();
        (void)parser.getTotalDuration();
        (void)parser.getSequence();
    } catch (std::exception &) {
    }
    return 0;
}
