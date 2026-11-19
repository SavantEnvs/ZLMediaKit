// MPEG transport stream (HLS segments, SRT/RTP MP2T payloads): DecoderImp with the libmpeg TS
// demuxer (PAT/PMT/PES), stream/track setup and FrameMerger into codec tracks.
#include "Rtp/Decoder.h"
#define FUZZ_DECODER_TYPE DecoderImp::decoder_ts
#include "fuzz_mpeg_ps.cpp"
