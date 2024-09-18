// Copyright 2017 Kumina, https://kumina.nl/
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/kumina/openvpn_exporter/pkg/exporters"
	"github.com/kumina/openvpn_exporter/pkg/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	var (
		listenAddress      = flag.String("web.listen-address", ":9176", "Address to listen on for web interface and telemetry.")
		metricsPath        = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		openvpnStatusPaths = flag.String("openvpn.status_paths", "examples/version-2.3/client.status,examples/version-2.3/server2.status,examples/version-2.3/server3.status", "Paths at which OpenVPN places its status files.")
		ignoreIndividuals  = flag.Bool("ignore.individuals", false, "If ignoring metrics for individuals")
		openvpnVersion     = flag.String("openvpn.version", "2.3", "Version of OpenVPN to use (e.g., 2.3)")
		showVersion        = flag.Bool("version", false, "Show version information and exit")
	)
	flag.Parse()

	log.Println(version.GetVersion())
	if *showVersion {
		os.Exit(0)
	}

	if !isValidOpenVPNVersion(*openvpnVersion) {
		log.Fatal("openvpn.version must be specified, currently supported versions are 2.3 and 2.4")
	}

	log.Printf("Starting OpenVPN Exporter\n")
	log.Printf("Listen address: %v\n", *listenAddress)
	log.Printf("Metrics path: %v\n", *metricsPath)
	log.Printf("openvpn.status_path: %v\n", *openvpnStatusPaths)
	log.Printf("OpenVPN Version: %v\n", *openvpnVersion)
	log.Printf("Ignore Individuals: %v\n", *ignoreIndividuals)

	exporter, err := exporters.NewOpenVPNExporter(strings.Split(*openvpnStatusPaths, ","), *ignoreIndividuals, *openvpnVersion)
	if err != nil {
		panic(err)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`
			<html>
			<head><title>OpenVPN Exporter</title></head>
			<body>
			<h1>OpenVPN Exporter</h1>
			<p><a href='` + *metricsPath + `'>Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			log.Printf("Error writing HTML: %v", err)
		}
	})
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}

func isValidOpenVPNVersion(version string) bool {
	return version == "2.3" || version == "2.4"
}
