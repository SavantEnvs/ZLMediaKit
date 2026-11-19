// RTSP over TCP as RtspSession/RtspPlayer reads it: RtspSplitter request/response framing with
// Content-Length bodies and '$'-interleaved RTP/RTCP, Parser (start line, headers, url args), the
// request URL (RtspUrl), SDP bodies (SdpParser) and the codec tracks built from them
// (Factory::getTrackBySdp -> each ext-codec plugin's fmtp/config parsing).
#include "fuzz_common.h"
#include "Rtsp/RtspSplitter.h"
#include "Rtsp/Rtsp.h"
#include "Rtcp/Rtcp.h"
#include "Common/Parser.h"
#include "Extension/Factory.h"

using namespace mediakit;

namespace {
class RtspFuzzSplitter : public RtspSplitter {
public:
    RtspFuzzSplitter() { enableRecvRtp(true); }
    fuzz::TrackSink _sink;

protected:
    void onWholeRtspPacket(Parser &parser) override {
        (void)parser.method();
        (void)parser.fullUrl();
        (void)Parser::parseArgs(parser.params());
        (void)parser["CSeq"];
        (void)parser["Session"];
        (void)parser["Transport"];
        try {
            RtspUrl url;
            url.parse(parser.fullUrl());
        } catch (std::exception &) {
        }
        if (parser.content().empty()) {
            return;
        }
        SdpParser sdp(parser.content());
        (void)sdp.toString();
        (void)sdp.getControlUrl(parser.fullUrl());
        for (auto &track : sdp.getAvailableTrack()) {
            auto t = Factory::getTrackBySdp(track);
            if (t) {
                _sink.addTrack(t);
            }
        }
    }
    void onRtpPacket(const char *data, size_t len) override {
        // data[1] is the interleaved channel: odd channels carry RTCP (RtspSession::onRtpPacket).
        if (len < 4 || !(data[1] & 1)) {
            return;
        }
        std::string copy(data + 4, len - 4);
        for (auto rtcp : RtcpHeader::loadFromBytes((char *)copy.data(), copy.size())) {
            (void)rtcp->dumpString();
        }
    }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    RtspFuzzSplitter splitter;
    try {
        auto buf = fuzz::socketCopy(data, size);
        splitter.input(buf.data(), size);
    } catch (std::exception &) {
    }
    splitter._sink.inspect();
    return 0;
}
