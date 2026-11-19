// HTTP/1.x over TCP as HttpSession (requests) and HttpClient (responses) read it:
// HttpRequestSplitter header/body framing with Content-Length, Parser (start line, headers, url
// and query args), the session's URL decoding (strCoding::UrlDecodePath/Component), and chunked
// transfer-encoding bodies (HttpChunkedSplitter) on responses.
#include "fuzz_common.h"
#include "Http/HttpRequestSplitter.h"
#include "Http/HttpChunkedSplitter.h"
#include "Common/Parser.h"
#include "Common/strCoding.h"
#include "Util/util.h"
#include "Common/macros.h"

using namespace mediakit;

namespace {
class HttpFuzzSplitter : public HttpRequestSplitter {
public:
    explicit HttpFuzzSplitter(bool response) : _response(response) {}
    size_t _body = 0;

protected:
    ssize_t onRecvHeader(const char *data, size_t len) override {
        _chunked.reset();
        _parser.parse(data, len);
        if (!_response) {
            // HttpSession::onRecvHeader + urlDecode
            CHECK(_parser.url()[0] == '/');
            _parser.setUrl(strCoding::UrlDecodePath(_parser.url()));
            for (auto &pr : _parser.getUrlArgs()) {
                (void)strCoding::UrlDecodeComponent(pr.second);
            }
            (void)Parser::parseArgs(_parser.params());
            (void)_parser["Origin"];
            (void)_parser.fullUrl();
        } else {
            (void)_parser.status();
            (void)_parser.statusStr();
            (void)_parser["Location"];
            if (toolkit::strToLower(std::string(_parser["Transfer-Encoding"])) == "chunked") {
                _chunked = std::make_shared<HttpChunkedSplitter>([this](const char *data, size_t len) { _body += len; });
                return -1; // body of unknown length, fed to the chunked splitter
            }
        }
        auto &len_str = _parser["Content-Length"];
        if (len_str.empty()) {
            return 0;
        }
        // Cap the declared body so one input can't ask for gigabytes of buffering.
        int64_t content_len = atoll(len_str.data());
        return content_len < 0 ? 0 : std::min<int64_t>(content_len, 1 << 20);
    }
    void onRecvContent(const char *data, size_t len) override {
        if (_chunked) {
            _chunked->input(data, len);
        } else {
            _body += len;
        }
    }

private:
    bool _response;
    Parser _parser;
    std::shared_ptr<HttpChunkedSplitter> _chunked;
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return -1;
    }
    // Byte 0, bit 0: parse as responses (HttpClient side) instead of requests (HttpSession side).
    HttpFuzzSplitter splitter(data[0] & 1);
    try {
        auto buf = fuzz::socketCopy(data + 1, size - 1);
        splitter.input(buf.data(), size - 1);
    } catch (std::exception &) {
    }
    return 0;
}
