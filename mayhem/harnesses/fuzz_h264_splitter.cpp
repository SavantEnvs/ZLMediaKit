// Annex-B elementary streams through the public C API (mk_h264_splitter_*, used by SDK users to
// push raw H264/H265 from cameras/files): start-code search and frame grouping in H264Splitter,
// then each frame into an H264/H265 Track (NAL splitting, SPS/PPS/VPS parsing -> width/height/fps).
#include "fuzz_common.h"
#include "mk_h264_splitter.h"
#include "Extension/Factory.h"

using namespace mediakit;

namespace {
struct Ctx {
    CodecId codec;
    Track::Ptr track;
    uint64_t dts = 0;
};

void API_CALL on_frame(void *user_data, mk_h264_splitter splitter, const char *frame, int size) {
    auto ctx = static_cast<Ctx *>(user_data);
    try {
        auto f = Factory::getFrameFromPtr(ctx->codec, (char *)frame, size, ctx->dts, ctx->dts);
        ctx->dts += 40;
        if (f && ctx->track) {
            (void)f->keyFrame();
            (void)f->configFrame();
            ctx->track->inputFrame(f);
        }
    } catch (std::exception &) {
    }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return -1;
    }
    // Byte 0: bit 0 selects H265 (the API's is_h265 flag); the upper bits pick a read size.
    Ctx ctx;
    ctx.codec = (data[0] & 1) ? CodecH265 : CodecH264;
    ctx.track = Factory::getTrackByCodecId(ctx.codec);
    size_t chunk = 1 + (data[0] >> 1) * 37;
    ++data;
    --size;
    auto buf = fuzz::socketCopy(data, size);
    auto splitter = mk_h264_splitter_create(on_frame, &ctx, ctx.codec == CodecH265);
    size_t off = 0;
    while (off < size) {
        size_t len = std::min(chunk, size - off);
        mk_h264_splitter_input_data(splitter, buf.data() + off, (int)len);
        off += len;
    }
    mk_h264_splitter_release(splitter);
    if (ctx.track) {
        auto video = std::dynamic_pointer_cast<VideoTrack>(ctx.track);
        (void)ctx.track->ready();
        if (video) {
            (void)video->getVideoWidth();
            (void)video->getVideoHeight();
            (void)video->getVideoFps();
        }
    }
    return 0;
}
