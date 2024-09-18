package exporters

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Converts OpenVPN client status information into Prometheus metrics.
func (e *OpenVPNExporter) collectClientStatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		if fields[0] == "END" && len(fields) == 1 {
			// Stats footer.
		} else if fields[0] == "OpenVPN STATISTICS" && len(fields) == 1 {
			// Stats header.
		} else if fields[0] == "Updated" && len(fields) == 2 {
			// Time at which the statistics were updated.
			location, _ := time.LoadLocation("Local")
			timeParser, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", fields[1], location)
			if err != nil {
				return fmt.Errorf("failed to parse updated time: %v", err)
			}
			ch <- prometheus.MustNewConstMetric(
				e.openvpnStatusUpdateTimeDesc,
				prometheus.GaugeValue,
				float64(timeParser.Unix()),
				statusPath)
		} else if desc, ok := e.openvpnClientDescs[fields[0]]; ok && len(fields) == 2 {
			// Traffic counters.
			value, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return fmt.Errorf("failed to parse traffic counter value: %v", err)
			}
			ch <- prometheus.MustNewConstMetric(
				desc,
				prometheus.CounterValue,
				value,
				statusPath)
		} else {
			return fmt.Errorf("unsupported key: %q", fields[0])
		}
	}
	return scanner.Err()
}

// Converts OpenVPN server version 2.3 status information into Prometheus metrics.
func (e *OpenVPNExporter) collectServer23StatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric, separator string) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	headersFound := map[string][]string{}
	// counter of connected client
	numberConnectedClient := 0

	recordedMetrics := map[OpenvpnServerHeaderField][]string{}

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), separator)
		if fields[0] == "END" && len(fields) == 1 {
			// Stats footer.
		} else if fields[0] == "GLOBAL_STATS" {
			// Global server statistics.
		} else if fields[0] == "HEADER" && len(fields) > 2 {
			// Column names for CLIENT_LIST and ROUTING_TABLE.
			headersFound[fields[1]] = fields[2:]
		} else if fields[0] == "TIME" && len(fields) == 3 {
			// Time at which the statistics were updated.
			timeStartStats, err := strconv.ParseFloat(fields[2], 64)
			if err != nil {
				return err
			}
			ch <- prometheus.MustNewConstMetric(
				e.openvpnStatusUpdateTimeDesc,
				prometheus.GaugeValue,
				timeStartStats,
				statusPath)
		} else if fields[0] == "TITLE" && len(fields) == 2 {
			// OpenVPN version number.
		} else if header, ok := e.openvpnServerHeaders[fields[0]]; ok {
			if fields[0] == "CLIENT_LIST" {
				numberConnectedClient++
			}
			// Entry that depends on a preceding HEADERS directive.
			columnNames, ok := headersFound[fields[0]]
			if !ok {
				return fmt.Errorf("%s should be preceded by HEADERS", fields[0])
			}
			if len(fields) != len(columnNames)+1 {
				return fmt.Errorf("HEADER for %s describes a different number of columns", fields[0])
			}

			// Store entry values in a map indexed by column name.
			columnValues := map[string]string{}
			for _, column := range header.LabelColumns {
				columnValues[column] = ""
			}
			for i, column := range columnNames {
				columnValues[column] = fields[i+1]
			}

			// Extract columns that should act as entry labels.
			labels := []string{statusPath}
			for _, column := range header.LabelColumns {
				labels = append(labels, columnValues[column])
			}

			// Export relevant columns as individual metrics.
			for _, metric := range header.Metrics {
				if columnValue, ok := columnValues[metric.Column]; ok {
					if l := recordedMetrics[metric]; !subslice(labels, l) {
						value, err := strconv.ParseFloat(columnValue, 64)
						if err != nil {
							return err
						}
						ch <- prometheus.MustNewConstMetric(
							metric.Desc,
							metric.ValueType,
							value,
							labels...)
						recordedMetrics[metric] = append(recordedMetrics[metric], labels...)
					} else {
						log.Printf("Metric entry with same labels: %s, %s", metric.Column, labels)
					}
				}
			}
		} else {
			return fmt.Errorf("unsupported key: %q", fields[0])
		}
	}
	// add the number of connected client
	ch <- prometheus.MustNewConstMetric(
		e.openvpnConnectedClientsDesc,
		prometheus.GaugeValue,
		float64(numberConnectedClient),
		statusPath)
	return scanner.Err()
}

// Converts OpenVPN server version 2.4 status information into Prometheus metrics.
func (e *OpenVPNExporter) collectServer24StatusFromReader(statusPath string, file io.Reader, ch chan<- prometheus.Metric, separator string) error {
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	headersFound := map[string][]string{}
	// counter of connected client
	numberConnectedClient := 0

	recordedMetrics := map[OpenvpnServerHeaderField][]string{}
	currentSection := ""

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), separator)
		if fields[0] == "END" && len(fields) == 1 {
			// Stats footer.
		} else if fields[0] == "OpenVPN CLIENT LIST" {
			currentSection = "CLIENT_LIST"
			// OpenVPN client list.
		} else if fields[0] == "GLOBAL STATS" && len(fields) == 1 {
			currentSection = "GLOBAL STATS"
			// Global server statistics.
		} else if fields[0] == "OpenVPN CLIENT LIST" && len(fields) == 1 {
			currentSection = "CLIENT_LIST"
			// OpenVPN client list.
		} else if fields[0] == "ROUTING TABLE" && len(fields) == 1 {
			currentSection = "ROUTING_TABLE"
			// Routing table.
		} else if fields[0] == "Virtual Address" && len(fields) > 2 {
			// Column names for ROUTING_TABLE.
			headersFound["ROUTING_TABLE"] = fields
		} else if fields[0] == "Common Name" && len(fields) > 2 {
			// Column names for CLIENT_LIST.
			headersFound["CLIENT_LIST"] = fields
		} else if fields[0] == "Updated" && len(fields) == 2 {
			// Time at which the statistics were updated.
			parsedTime, err := time.Parse(time.ANSIC, fields[1])
			if err != nil {
				return fmt.Errorf("failed to parse updated time: %v", err)
			}

			ch <- prometheus.MustNewConstMetric(
				e.openvpnStatusUpdateTimeDesc,
				prometheus.GaugeValue,
				float64(parsedTime.UTC().Unix()),
				statusPath)
		} else if header, ok := e.openvpnServerHeaders[currentSection]; ok {
			if currentSection == "CLIENT_LIST" {
				numberConnectedClient++
			}
			// Entry that depends on a preceding HEADERS directive.
			columnNames, ok := headersFound[currentSection]
			if !ok {
				return fmt.Errorf("failed to find column names for %s", currentSection)
			}
			if len(fields) != len(columnNames) {
				return fmt.Errorf("%s describes a different number of columns", currentSection)
			}

			// Store entry values in a map indexed by column name.
			columnValues := map[string]string{}
			for _, column := range header.LabelColumns {
				columnValues[column] = ""
			}
			for i, column := range columnNames {
				columnValues[column] = fields[i]
			}

			// Extract columns that should act as entry labels.
			labels := []string{statusPath}
			for _, column := range header.LabelColumns {
				labels = append(labels, columnValues[column])
			}

			// Export relevant columns as individual metrics.
			for _, metric := range header.Metrics {
				if columnValue, ok := columnValues[metric.Column]; ok {
					if l := recordedMetrics[metric]; !subslice(labels, l) {
						value, err := strconv.ParseFloat(columnValue, 64)
						if err != nil {
							return err
						}
						ch <- prometheus.MustNewConstMetric(
							metric.Desc,
							metric.ValueType,
							value,
							labels...)
						recordedMetrics[metric] = append(recordedMetrics[metric], labels...)
					} else {
						log.Printf("Metric entry with same labels: %s, %s", metric.Column, labels)
					}
				}
			}
		} else if currentSection == "GLOBAL STATS" {
			continue
		} else {
			return fmt.Errorf("unsupported key: %q", fields[0])
		}
	}
	// add the number of connected client
	ch <- prometheus.MustNewConstMetric(
		e.openvpnConnectedClientsDesc,
		prometheus.GaugeValue,
		float64(numberConnectedClient),
		statusPath)
	return scanner.Err()
}
