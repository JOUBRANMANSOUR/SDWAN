#!/bin/sh
set -eu

DESTINATION="${1:-10.2.0.10}"
PORT="${2:-5004}"

# A single H.264 elementary video stream is used because FFmpeg's RTP muxer
# supports one stream per RTP output. Audio, when required, must use a second
# RTP port and a matching multi-media SDP file.
exec ffmpeg \
  -hide_banner \
  -loglevel warning \
  -re \
  -f lavfi \
  -i 'testsrc=size=640x360:rate=25' \
  -an \
  -c:v libx264 \
  -preset ultrafast \
  -tune zerolatency \
  -pix_fmt yuv420p \
  -g 50 \
  -b:v 1200k \
  -payload_type 96 \
  -f rtp \
  "rtp://${DESTINATION}:${PORT}?pkt_size=1200"
