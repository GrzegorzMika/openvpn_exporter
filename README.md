# openvpn_exporter

<!-- [![github-actions](https://github.com/theohbrothers/openvpn_exporter/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/theohbrothers/openvpn_exporter/actions/workflows/ci.yml)
[![github-release](https://img.shields.io/github/v/release/theohbrothers/openvpn_exporter?style=flat-square)](https://github.com/theohbrothers/openvpn_exporter/releases/)
[![docker-image-size](https://img.shields.io/docker/image-size/theohbrothers/openvpn_exporter/latest)](https://hub.docker.com/r/theohbrothers/openvpn_exporter)
[![codecov](https://codecov.io/gh/theohbrothers/openvpn_exporter/branch/master/graph/badge.svg)](https://codecov.io/gh/theohbrothers/openvpn_exporter)
[![go-report-card](https://goreportcard.com/badge/github.com/theohbrothers/openvpn_exporter)](https://goreportcard.com/report/github.com/theohbrothers/openvpn_exporter) -->

This repository provides code for a simple Prometheus metrics exporter
for [OpenVPN](https://openvpn.net/). Right now it can parse files
generated by OpenVPN's `--status`, having one of the following formats:

* Client statistics,
* Server statistics with `--status-version 2` (comma delimited),
* Server statistics with `--status-version 3` (tab delimited).

As it is not uncommon to run multiple instances of OpenVPN on a single
system (e.g., multiple servers, multiple clients or a mixture of both),
this exporter can be configured to scrape and export the status of
multiple status files, using the `-openvpn.status_paths` command line
flag. Paths need to be comma separated. Metrics for all status files are
exported over TCP port 9176.

Please refer to this utility's `main()` function for a full list of
supported command line flags.

## Exposed metrics example

### Client statistics

For clients status files, the exporter generates metrics that may look
like this:

```
openvpn_client_auth_read_bytes_total{status_path="..."} 3.08854782e+08
openvpn_client_post_compress_bytes_total{status_path="..."} 4.5446864e+07
openvpn_client_post_decompress_bytes_total{status_path="..."} 2.16965355e+08
openvpn_client_pre_compress_bytes_total{status_path="..."} 4.538819e+07
openvpn_client_pre_decompress_bytes_total{status_path="..."} 1.62596168e+08
openvpn_client_tcp_udp_read_bytes_total{status_path="..."} 2.92806201e+08
openvpn_client_tcp_udp_write_bytes_total{status_path="..."} 1.97558969e+08
openvpn_client_tun_tap_read_bytes_total{status_path="..."} 1.53789941e+08
openvpn_client_tun_tap_write_bytes_total{status_path="..."} 3.08764078e+08
openvpn_status_update_time_seconds{status_path="..."} 1.490092749e+09
openvpn_up{status_path="..."} 1
```

### Server statistics

For server status files (both version 2 and 3), the exporter generates
metrics that may look like this:

```
openvpn_server_client_received_bytes_total{common_name="...",connection_time="...",real_address="...",status_path="...",username="...",virtual_address="..."} 139583
openvpn_server_client_sent_bytes_total{common_name="...",connection_time="...",real_address="...",status_path="...",username="...",virtual_address="..."} 710764
openvpn_server_route_last_reference_time_seconds{common_name="...",real_address="...",status_path="...",virtual_address="..."} 1.493018841e+09
openvpn_status_update_time_seconds{status_path="..."} 1.490089154e+09
openvpn_up{status_path="..."} 1
openvpn_server_connected_clients 1
```

## Usage

```sh
  -ignore.individuals
        If ignoring metrics for individuals
  -openvpn.status_paths string
        Paths at which OpenVPN places its status files. (default "examples/client.status,examples/server2.status,examples/server3.status")
  -version
        Show version information and exit
  -web.listen-address string
        Address to listen on for web interface and telemetry. (default ":9176")
  -web.telemetry-path string
        Path under which to expose metrics. (default "/metrics")
  -openvpn.version string
         Version of the OpenVPN which is used. Currently 2.3 and 2.4 are supported. (default "2.3")
```

E.g:

```sh
openvpn_exporter -openvpn.status_paths /etc/openvpn/server.status
```

## Docker

To use with docker, the `openvpn` server status file must be mounted in the container.

```sh
docker run --rm \
  -p 9176:9176 \
  -v /etc/openvpn/server.status:/server.status:ro \
  gregmika/openvpn_exporter:latest -openvpn.status_paths /server.status
```

Metrics should be available at http://localhost:9176/metrics.

<!-- ## Get a standalone executable binary

You can download the pre-compiled binaries from the
[releases page](https://github.com/theohbrothers/openvpn_exporter/releases). -->

## Development

Requires `make`, `docker`, and `docker-compose` if you want all `make` commands to be working.

Requires [`go`](https://golang.org/doc/install) only if you are developing.

```sh
# Print usage
make help

# Build
make build # Defaults to linux amd64
make build GOOS=linux GOARCH=arm64 # For arm64

# Build docker image
make build-image # Defaults to linux amd64
make build-image GOOS=linux GOARCH=arm64 # For arm64

# Build multiarch docker images
make buildx-image # Build
make buildx-image REGISTRY=xxx REGISTRY_USER=xxx BUILDX_PUSH=true BUILDX_TAG_LATEST=true # Build and push

# Start a shell in a container
make shell

# Test
make test

# Cleanup
make clean
```
