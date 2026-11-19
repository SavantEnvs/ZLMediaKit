// RTMP over TCP as a server (RtmpSession) or client (RtmpPlayer/RtmpPusher) sees it: C0C1/C2
// (simple + complex digest handshake) or S0S1S2, then chunk stream parsing (basic/message headers,
// extended timestamps, chunk size / ack / user-control messages), and the per-message handling a
// session does: AMF command/data decoding and RtmpDemuxer for audio/video.
#include "fuzz_common.h"
#include "Rtmp/RtmpProtocol.h"
#include "Rtmp/RtmpDemuxer.h"
#include "Rtmp/amf.h"

using namespace mediakit;

namespace {
class RtmpFuzzProtocol : public RtmpProtocol {
public:
    RtmpFuzzProtocol() { _demuxer.setTrackListener(&_sink); }
    void client() {
        startClientSession([]() {}, true);
    }
    fuzz::TrackSink _sink;

protected:
    void onSendRawData(toolkit::Buffer::Ptr buffer) override { _sent += buffer->size(); }
    void onRtmpChunk(RtmpPacket::Ptr packet) override {
        switch (packet->type_id) {
        case MSG_CMD:
        case MSG_CMD3: {
            // RtmpSession::onRtmpChunk -> onProcessCmd: method name, transaction id, arguments.
            AMFDecoder dec(packet->buffer, packet->type_id == MSG_CMD3 ? 3 : 0);
            std::string method = dec.load<std::string>();
            (void)dec.load<double>();
            for (int i = 0; i < 16 && dec.remain(); ++i) {
                (void)dec.load<AMFValue>().to_string();
            }
            break;
        }
        case MSG_DATA:
        case MSG_DATA3: {
            AMFDecoder dec(packet->buffer, packet->type_id == MSG_DATA3 ? 3 : 0);
            std::string type = amfLoadLeadingString(dec);
            if (type == "@setDataFrame") {
                (void)dec.load<std::string>();
            }
            if (dec.remain()) {
                _demuxer.loadMetaData(dec.load<AMFValue>());
            }
            break;
        }
        case MSG_AUDIO:
        case MSG_VIDEO:
            _demuxer.inputRtmp(packet);
            break;
        default:
            break;
        }
    }

private:
    size_t _sent = 0;
    RtmpDemuxer _demuxer;
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return -1;
    }
    // Byte 0, bit 0: act as the client (expects S0S1S2) instead of the server (expects C0C1).
    bool client = data[0] & 1;
    ++data;
    --size;
    RtmpFuzzProtocol proto;
    auto buf = fuzz::socketCopy(data, size);
    try {
        if (client) {
            proto.client();
        }
        // Deliver the stream in TCP-sized pieces so partial-chunk reassembly is exercised.
        size_t off = 0;
        while (off < size) {
            size_t len = std::min<size_t>(size - off, 4096);
            proto.onParseRtmp(buf.data() + off, len);
            off += len;
        }
    } catch (std::exception &) {
        // RtmpProtocol rejects malformed streams by throwing; the session closes the socket.
    }
    proto._sink.inspect();
    return 0;
}
