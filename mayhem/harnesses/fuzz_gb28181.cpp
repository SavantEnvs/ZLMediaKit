// GB28181 / RTP-proxy ingest (RtpSession over TCP): RtpSplitter framing (2-byte length, RTSP '$'
// interleave, EHOME header detection), then what RtpProcess does per packet: isRtp check and
// GB28181Process::inputRtp -> payload-type dispatch, RtpReceiver sorting, MPEG-PS/TS demux
// (libmpeg via DecoderImp) or direct H264/H265/Opus/G711 RTP decoding, and track creation.
#include "fuzz_common.h"
#include "Rtp/RtpSplitter.h"
#include "Rtp/GB28181Process.h"
#include "Rtsp/Rtsp.h"

using namespace mediakit;

namespace {
class GbFuzzSplitter : public RtpSplitter {
public:
    GbFuzzSplitter() : _process(MediaInfo("rtp://127.0.0.1/rtp/fuzz"), &_sink) {}
    fuzz::TrackSink _sink;
    GB28181Process _process;

protected:
    void onRtpPacket(const char *data, size_t len) override {
        if (!isRtp(data, len)) {
            return; // RtpProcess::inputRtp ignores non-RTP data
        }
        try {
            _process.inputRtp(false, data, len);
        } catch (std::exception &) {
            // A bad packet throws out of the session's read handler.
        }
    }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    GbFuzzSplitter splitter;
    try {
        auto buf = fuzz::socketCopy(data, size);
        splitter.input(buf.data(), size);
        splitter._process.flush();
    } catch (std::exception &) {
    }
    splitter._sink.inspect();
    return 0;
}
