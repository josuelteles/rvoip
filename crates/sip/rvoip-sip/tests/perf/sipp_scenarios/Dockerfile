# The `local-sipp` image the dockerized runners in this directory expect.
#
# `run_comparison_dockerized.sh` has always required this image and told the
# caller to "build it first" without saying how; this is the how.
#
#   docker build -t local-sipp crates/sip/rvoip-sip/tests/perf/sipp_scenarios
#
# Debian's `sip-tester` package is sipp with TLS, SCTP and PCAP compiled in,
# which is what the scenarios here assume.
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends sip-tester ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["sipp"]
