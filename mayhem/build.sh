#!/usr/bin/env bash
#
# mayhem/build.sh — build ZLMediaKit's fuzz harnesses and its gating unit tests.
#
# Runs in the commit image as `mayhem` in /mayhem. Uses the base image's build contract
# (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/DEBUG_FLAGS/STANDALONE_FUZZ_MAIN).
#   1) the project (ZLMediaKit + ext-codec + srt + webrtc + mk_api + ZLToolKit + media-server libs)
#      with the sanitizers + SanCov, CMake build type "Fuzz"  -> build/fuzz, release/linux/Fuzz
#   2) every harness in mayhem/harnesses twice: libFuzzer binary + -standalone reproducer
#      -> build/fuzzers/<name>{,-standalone}
#   3) upstream's gating ctest programs with upstream's normal Release flags
#      -> build/test, release/linux/Release (mayhem/test.sh runs them)
# All of build/ and release/ are gitignored upstream, so `git clean -ffdX` resets them.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

for sub in 3rdpart/ZLToolKit/src 3rdpart/media-server/libmov 3rdpart/jsoncpp/include; do
  [ -d "$sub" ] || { echo "missing submodule content: $sub (check out with submodules)" >&2; exit 1; }
done

# Options shared by both builds: the libraries only (no MediaServer/player apps); WebRTC needs
# OpenSSL + libsrtp2 (apt); SCTP (usrsctp) is not packaged and stays off. Upstream's CMake wires in
# ccache when it finds one — CCACHE_FOUND=OFF keeps the build cache-neutral (the grader owns ccache).
COMMON_OPTS=(
  -DENABLE_SERVER=OFF -DENABLE_PLAYER=OFF -DENABLE_API=ON -DENABLE_API_STATIC_LIB=ON
  -DENABLE_OBJCOPY=OFF -DDISABLE_REPORT=ON -DENABLE_WEBRTC=ON -DENABLE_SCTP=OFF
  -DENABLE_SRT=ON -DENABLE_MP4=ON -DENABLE_HLS=ON -DENABLE_RTPPROXY=ON -DENABLE_OPENSSL=ON
  -DCCACHE_FOUND=OFF
)

# 1) Instrumented project build. Custom build type "Fuzz": no -DNDEBUG (upstream's asserts stay
#    live) and no CMake default -O3; -O1 keeps it fast enough to fuzz.
#    Three UBSan checks are relaxed because they fire on (nearly) every valid stream, which would
#    leave the fuzzer stuck on one report instead of exploring:
#    `shift-base` (all code) — signed left shifts that overflow: ZLToolKit's av_base64_decode on every
#      SDP sprop-parameter-sets, libmpeg's PS/PES timestamp parsing for any SCR/PTS >= 2^30. (C++20
#      defines these shifts; shift-exponent and all other checks stay on.)
#    `null` + `object-size` (C only = the vendored ireader media-server libflv/libmov/libmpeg; at -O1
#      both report it) — libmov's
#      MOV_READER_FROM_MOV container_of() forms a member access off a null base in every
#      mov_reader_box() call. Real null dereferences still SEGV.
#    ASan and every other UBSan check stay on and halting.
FUZZ_CXXFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1"
FUZZ_CFLAGS="$FUZZ_CXXFLAGS"
case " $SANITIZER_FLAGS " in
  *undefined*) FUZZ_CXXFLAGS="$FUZZ_CXXFLAGS -fno-sanitize=shift-base"
               FUZZ_CFLAGS="$FUZZ_CFLAGS -fno-sanitize=null,object-size,shift-base" ;;
esac
cmake -S . -B build/fuzz -DCMAKE_BUILD_TYPE=Fuzz -DENABLE_TESTS=OFF "${COMMON_OPTS[@]}" \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CXXFLAGS"
cmake --build build/fuzz -j"$MAYHEM_JOBS"

LIBDIR="$SRC/release/linux/Fuzz"
DEFS=(-DDISABLE_REPORT -DENABLE_HLS -DENABLE_MP4 -DENABLE_OPENSSL -DENABLE_RTPPROXY -DENABLE_SRT
      -DENABLE_VERSION -DENABLE_WEBRTC -DHAVE_MMSG_HDR -DHAVE_RECVMMSG_API -DHAVE_SENDMMSG_API
      -DSOCKET_DEFAULT_BUF_SIZE=262144)
INCS=(-I"$SRC/build/fuzz" -I"$SRC/3rdpart" -I"$SRC" -I"$SRC/src" -I"$SRC/srt" -I"$SRC/webrtc"
      -I"$SRC/api/include" -I"$SRC/3rdpart/ZLToolKit/src" -I"$SRC/3rdpart/jsoncpp/include"
      -I"$SRC/3rdpart/media-server/libflv/include" -I"$SRC/3rdpart/media-server/libmov/include"
      -I"$SRC/3rdpart/media-server/libmpeg/include" -I"$SRC/mayhem/harnesses")
# ext-codec registers its codec plugins from static initializers: link it whole.
LIBS=(-Wl,--start-group "$LIBDIR/libmk_api.a" "$LIBDIR/libwebrtc.a" "$LIBDIR/libsrt.a" "$LIBDIR/libzlmediakit.a"
      -Wl,--whole-archive "$LIBDIR/libext-codec.a" -Wl,--no-whole-archive
      "$LIBDIR/libflv.a" "$LIBDIR/libmov.a" "$LIBDIR/libmpeg.a" "$LIBDIR/libjsoncpp.a"
      "$SRC/build/fuzz/3rdpart/ZLToolKit/lib/libZLToolKit.a" -Wl,--end-group
      -lsrtp2 -lssl -lcrypto -lpthread -ldl)

OUT="$SRC/build/fuzzers"
mkdir -p "$OUT"
HCFLAGS=($FUZZ_CXXFLAGS -std=c++11 "${DEFS[@]}" "${INCS[@]}")
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

build_one() {
  local name="$1"
  $CXX "${HCFLAGS[@]}" -c "mayhem/harnesses/$name.cpp" -o "$OUT/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$OUT/lsan_off.o" "${LIBS[@]}" -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/$name.o" "$OUT/standalone_main.o" "$OUT/lsan_off.o" "${LIBS[@]}" -fsanitize=fuzzer-no-link -o "$OUT/$name-standalone"
}
FUZZERS=(fuzz_flv fuzz_amf fuzz_rtmp_protocol fuzz_rtsp fuzz_rtp fuzz_gb28181 fuzz_mpeg_ps fuzz_mpeg_ts
         fuzz_h264_splitter fuzz_srt fuzz_rtcp fuzz_http fuzz_websocket fuzz_hls fuzz_mp4
         fuzz_webrtc_sdp fuzz_stun)
pids=()
for f in "${FUZZERS[@]}"; do
  build_one "$f" &
  pids+=($!)
  if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
done
for p in "${pids[@]}"; do wait "$p"; done
for f in "${FUZZERS[@]}"; do [ -x "$OUT/$f" ] && [ -x "$OUT/$f-standalone" ] || { echo "missing $f" >&2; exit 1; }; done

# 3) Upstream's gating tests (tests/CMakeLists.txt GATING_TESTS), upstream's Release flags.
cmake -S . -B build/test -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON "${COMMON_OPTS[@]}" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build/test -j"$MAYHEM_JOBS" --target \
  test_av1_rtmp test_amf test_hls_cookie_data test_sortor test_rtx_twcc test_webrtc_regression
