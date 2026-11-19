// MPEG program stream (GB28181 PS payload, PS-over-RTP after reassembly): DecoderImp with the
// libmpeg PS demuxer, stream/track setup and FrameMerger into codec tracks (SPS/VPS parsing).
#include "fuzz_common.h"
#include "Rtp/Decoder.h"

using namespace mediakit;

#ifndef FUZZ_DECODER_TYPE
#define FUZZ_DECODER_TYPE DecoderImp::decoder_ps
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz::TrackSink sink;
    auto decoder = DecoderImp::createDecoder(FUZZ_DECODER_TYPE, &sink);
    if (!decoder) {
        return 0;
    }
    // RTP payloads sit at the end of a ZLToolKit buffer (spare byte, see socketCopy).
    auto buf = fuzz::socketCopy(data, size);
    try {
        // Deliver in packet-sized pieces, like successive RTP payloads.
        size_t off = 0;
        while (off < size) {
            size_t len = std::min<size_t>(size - off, 1400);
            decoder->input((const uint8_t *)buf.data() + off, len);
            off += len;
        }
        decoder->flush();
    } catch (std::exception &) {
    }
    sink.inspect();
    return 0;
}
