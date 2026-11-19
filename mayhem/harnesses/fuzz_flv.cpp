// FLV byte stream (HTTP-FLV / FLV file ingest): FlvSplitter tag parsing, AMF0/AMF3 script data
// (amfLoadLeadingString, AMFDecoder), then RtmpDemuxer metadata + audio/video tag decoding into
// codec tracks (H264/H265/AAC/Opus/AV1 ... config and frame parsing).
#include "fuzz_common.h"
#include "Rtmp/FlvSplitter.h"
#include "Rtmp/RtmpDemuxer.h"

using namespace mediakit;

namespace {
class FlvFuzzSplitter : public FlvSplitter {
public:
    FlvFuzzSplitter() { _demuxer.setTrackListener(&_sink); }
    fuzz::TrackSink _sink;

protected:
    bool onRecvMetadata(const AMFValue &metadata) override {
        (void)metadata.to_string();
        _demuxer.loadMetaData(metadata);
        return true;
    }
    void onRecvRtmpPacket(RtmpPacket::Ptr packet) override { _demuxer.inputRtmp(packet); }

private:
    RtmpDemuxer _demuxer;
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FlvFuzzSplitter splitter;
    auto buf = fuzz::socketCopy(data, size);
    try {
        // Feed in two chunks so the splitter's buffering across reads is exercised as well.
        size_t half = size / 2;
        splitter.input(buf.data(), half);
        splitter.input(buf.data() + half, size - half);
    } catch (std::exception &) {
        // Malformed streams are rejected by throwing; a session would drop the connection.
    }
    splitter._sink.inspect();
    return 0;
}
