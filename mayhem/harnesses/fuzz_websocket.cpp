// WebSocket frames (WebSocket-FLV/TS playback, the HTTP API's ws endpoints, the ws client):
// WebSocketSplitter::decode header parsing (FIN/opcode, 7/16/64-bit lengths, masking key),
// payload unmasking and reassembly across reads, then re-encoding each decoded message.
#include "fuzz_common.h"
#include "Http/WebSocketSplitter.h"

using namespace mediakit;

namespace {
class WsFuzzSplitter : public WebSocketSplitter {
public:
    size_t _payload = 0;
    size_t _encoded = 0;

protected:
    void onWebSocketDecodeHeader(const WebSocketHeader &header) override { _msg.clear(); }
    void onWebSocketDecodePayload(const WebSocketHeader &header, const uint8_t *ptr, size_t len, size_t recved) override {
        _payload += len;
        if (_msg.size() < (1 << 16)) {
            _msg.append((const char *)ptr, len);
        }
    }
    void onWebSocketDecodeComplete(const WebSocketHeader &header) override {
        // Echo it back the way WebSocketSession answers PING/CLOSE frames.
        WebSocketHeader out = header;
        out._mask_flag = false;
        encode(out, std::make_shared<toolkit::BufferString>(_msg));
    }
    void onWebSocketEncodeData(toolkit::Buffer::Ptr buffer) override { _encoded += buffer->size(); }

private:
    std::string _msg;
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return -1;
    }
    // Byte 0 picks the read size, so frames split across socket reads are exercised.
    size_t chunk = 1 + data[0] * 7;
    // decode() unmasks in place: give it a private, exact-size copy.
    std::vector<uint8_t> buf(data + 1, data + size);
    WsFuzzSplitter ws;
    try {
        size_t off = 0;
        while (off < buf.size()) {
            size_t len = std::min(chunk, buf.size() - off);
            ws.decode(buf.data() + off, len);
            off += len;
        }
    } catch (std::exception &) {
    }
    return 0;
}
