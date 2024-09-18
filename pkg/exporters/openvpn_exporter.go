package exporters

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/prometheus/client_golang/prometheus"
)

type OpenvpnServerHeader struct {
	LabelColumns []string
	Metrics      []OpenvpnServerHeaderField
}

type OpenvpnServerHeaderField struct {
	Column    string
	Desc      *prometheus.Desc
	ValueType prometheus.ValueType
}

type OpenVPNExporter struct {
	statusPaths                 []string
	openvpnUpDesc               *prometheus.Desc
	openvpnStatusUpdateTimeDesc *prometheus.Desc
	openvpnConnectedClientsDesc *prometheus.Desc
	openvpnClientDescs          map[string]*prometheus.Desc
	openvpnServerHeaders        map[string]OpenvpnServerHeader
}

func NewOpenVPNExporter(statusPaths []string, ignoreIndividuals bool, version string) (*OpenVPNExporter, error) {
	// Metrics exported both for client and server statistics.
	openvpnUpDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "up"),
		"Whether scraping OpenVPN's metrics was successful.",
		[]string{"status_path"}, nil)
	openvpnStatusUpdateTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "status_update_time_seconds"),
		"UNIX timestamp at which the OpenVPN statistics were updated.",
		[]string{"status_path"}, nil)

	// Metrics specific to OpenVPN servers.
	openvpnConnectedClientsDesc := prometheus.NewDesc(
		prometheus.BuildFQName("openvpn", "", "server_connected_clients"),
		"Number Of Connected Clients",
		[]string{"status_path"}, nil)

	// Metrics specific to OpenVPN clients.
	openvpnClientDescs := map[string]*prometheus.Desc{
		"TUN/TAP read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tun_tap_read_bytes_total"),
			"Total amount of TUN/TAP traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"TUN/TAP write bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tun_tap_write_bytes_total"),
			"Total amount of TUN/TAP traffic written, in bytes.",
			[]string{"status_path"}, nil),
		"TCP/UDP read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tcp_udp_read_bytes_total"),
			"Total amount of TCP/UDP traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"TCP/UDP write bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "tcp_udp_write_bytes_total"),
			"Total amount of TCP/UDP traffic written, in bytes.",
			[]string{"status_path"}, nil),
		"Auth read bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "auth_read_bytes_total"),
			"Total amount of authentication traffic read, in bytes.",
			[]string{"status_path"}, nil),
		"pre-compress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "pre_compress_bytes_total"),
			"Total amount of data before compression, in bytes.",
			[]string{"status_path"}, nil),
		"post-compress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "post_compress_bytes_total"),
			"Total amount of data after compression, in bytes.",
			[]string{"status_path"}, nil),
		"pre-decompress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "pre_decompress_bytes_total"),
			"Total amount of data before decompression, in bytes.",
			[]string{"status_path"}, nil),
		"post-decompress bytes": prometheus.NewDesc(
			prometheus.BuildFQName("openvpn", "client", "post_decompress_bytes_total"),
			"Total amount of data after decompression, in bytes.",
			[]string{"status_path"}, nil),
	}

	serverHeaderClientLabels, serverHeaderClientLabelColumns, serverHeaderRoutingLabels, serverHeaderRoutingLabelColumns := getLabels(ignoreIndividuals, version)

	openvpnServerHeaders := map[string]OpenvpnServerHeader{
		"CLIENT_LIST": {
			LabelColumns: serverHeaderClientLabelColumns,
			Metrics: []OpenvpnServerHeaderField{
				{
					Column: "Bytes Received",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "client_received_bytes_total"),
						"Amount of data received over a connection on the VPN server, in bytes.",
						serverHeaderClientLabels, nil),
					ValueType: prometheus.CounterValue,
				},
				{
					Column: "Bytes Sent",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "client_sent_bytes_total"),
						"Amount of data sent over a connection on the VPN server, in bytes.",
						serverHeaderClientLabels, nil),
					ValueType: prometheus.CounterValue,
				},
			},
		},
		"ROUTING_TABLE": {
			LabelColumns: serverHeaderRoutingLabelColumns,
			Metrics: []OpenvpnServerHeaderField{
				{
					Column: "Last Ref (time_t)",
					Desc: prometheus.NewDesc(
						prometheus.BuildFQName("openvpn", "server", "route_last_reference_time_seconds"),
						"Time at which a route was last referenced, in seconds.",
						serverHeaderRoutingLabels, nil),
					ValueType: prometheus.GaugeValue,
				},
			},
		},
	}

	return &OpenVPNExporter{
		statusPaths:                 statusPaths,
		openvpnUpDesc:               openvpnUpDesc,
		openvpnStatusUpdateTimeDesc: openvpnStatusUpdateTimeDesc,
		openvpnConnectedClientsDesc: openvpnConnectedClientsDesc,
		openvpnClientDescs:          openvpnClientDescs,
		openvpnServerHeaders:        openvpnServerHeaders,
	}, nil
}

// Converts OpenVPN status information into Prometheus metrics. This
// function automatically detects whether the file contains server or
// client metrics. For server metrics, it also distinguishes between the
// version 2 and 3 file formats.
func (e *OpenVPNExporter) collectStatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric) error {
	reader := bufio.NewReader(file)
	buf, _ := reader.Peek(18)
	if bytes.HasPrefix(buf, []byte("TITLE,")) {
		// Server version 2.3 statistics, using format version 2.
		return e.collectServer23StatusFromReader(statusPath, reader, ch, ",")
	} else if bytes.HasPrefix(buf, []byte("TITLE\t")) {
		// Server version 2.3 statistics, using format version 3. The only
		// difference compared to version 2 is that it uses tabs
		// instead of spaces.
		return e.collectServer23StatusFromReader(statusPath, reader, ch, "\t")
	} else if bytes.HasPrefix(buf, []byte("OpenVPN STATISTICS")) {
		// Client statistics.
		return e.collectClientStatusFromReader(statusPath, reader, ch)
	} else if bytes.HasPrefix(buf, []byte("OpenVPN CLIENT LIS")) {
		// Server version 2.4 statistics.
		// We check by OpenVPN CLIENT LIS instead of OpenVPN CLIENT LIST due to the peek value in reader to keep the backward
		return e.collectServer24StatusFromReader(statusPath, reader, ch, ",")
	} else {
		return fmt.Errorf("unexpected file contents: %q", buf)
	}
}

func (e *OpenVPNExporter) collectStatusFromFile(statusPath string, ch chan<- prometheus.Metric) error {
	conn, err := os.Open(statusPath)
	if err != nil {
		return fmt.Errorf("failed to open status file %s: %s", statusPath, err)
	}
	defer conn.Close()
	return e.collectStatusFromReader(statusPath, conn, ch)
}

func (e *OpenVPNExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.openvpnUpDesc
}

func (e *OpenVPNExporter) Collect(ch chan<- prometheus.Metric) {
	for _, statusPath := range e.statusPaths {
		if err := e.collectStatusFromFile(statusPath, ch); err == nil {
			ch <- prometheus.MustNewConstMetric(
				e.openvpnUpDesc,
				prometheus.GaugeValue,
				1.0,
				statusPath)
		} else {
			log.Printf("Failed to scrape showq socket: %s", err)
			ch <- prometheus.MustNewConstMetric(
				e.openvpnUpDesc,
				prometheus.GaugeValue,
				0.0,
				statusPath)
		}
	}
}
