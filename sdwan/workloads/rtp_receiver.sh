#!/bin/sh
set -eu

SDP="${1:-/opt/sdwan/workloads/rtp-video.sdp}"
OUTPUT="${2:-/tmp/received-video.mkv}"

# Decode the real RTP/H.264 stream and record it. The file provides a visible
# end-to-end artefact while FFmpeg logs packet/decode errors for the experiment.
exec ffmpeg \
  -hide_banner \
  -loglevel info \
  -protocol_whitelist file,udp,rtp \
  -fflags +genpts \
  -i "$SDP" \
  -map 0:v:0 \
  -c copy \
  -y "$OUTPUT"
