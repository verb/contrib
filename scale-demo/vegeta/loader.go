/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	vegeta "github.com/tsenart/vegeta/lib"
)

var (
	host       = flag.String("host", "", "The host to load test")
	port       = flag.Int("port", 80, "The port to load test")
	paths      = flag.String("paths", "/", "A comma separated list of URL paths to load test")
	rate       = flag.Int("rate", 0, "The QPS to send")
	resultsDir = flag.String("results", "", "If set, a directory in which to save results")
	duration   = flag.Duration("duration", 10*time.Second, "The duration of the load test")
	addr       = flag.String("address", "localhost:8080", "The address to serve on")
	workers    = flag.Int("workers", 10, "The number of workers to use")
)

// HTTPReporter outputs metrics over HTTP
type HTTPReporter struct {
	sync.Mutex
	metrics *vegeta.Metrics
}

func (h *HTTPReporter) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	metrics := h.GetMetrics()

	res.WriteHeader(http.StatusOK)
	reporter := vegeta.NewJSONReporter(metrics)
	reporter.Report(res)
}

// GetMetrics returns the current metrics for this reporter
func (h *HTTPReporter) GetMetrics() *vegeta.Metrics {
	h.Lock()
	defer h.Unlock()
	return h.metrics
}

// SetMetrics sets the current metrics for this reporter
func (h *HTTPReporter) SetMetrics(metrics *vegeta.Metrics) {
	h.Lock()
	defer h.Unlock()
	h.metrics = metrics
}

type output struct {
	encoder *json.Encoder
	file    *os.File
	name    string
}

func (o *output) close() {
	if o.file != nil {
		o.file.Close()
		os.Rename(o.file.Name(), o.name)
	}
}

func (o *output) rotate() error {
	o.close()

	o.name = path.Join(*resultsDir, fmt.Sprintf("results-%d.json", time.Now().Unix()))
	file, err := os.Create(o.name + ".tmp")
	if err != nil {
		return err
	}

	o.file, o.encoder = file, json.NewEncoder(file)
	return nil
}

func main() {
	flag.Parse()

	var serviceIP string
	ips, err := net.LookupIP(*host)
	if err != nil {
		fmt.Printf("Error looking up %s: %v\n", *host, err)
		os.Exit(2)
	}
	for _, ip := range ips {
		ipv4 := ip.To4()
		if ipv4 != nil {
			serviceIP = ipv4.String()
			break
		}
	}
	if len(serviceIP) == 0 {
		fmt.Printf("Failed to find suitable IP address: %v", ips)
		os.Exit(2)
	}

	headers := http.Header{"Host": []string{*host}}
	host := serviceIP
	if *port != 80 {
		host = fmt.Sprintf("%s:%d", host, *port)
	}
	var targets []vegeta.Target
	for _, path := range strings.Split(*paths, ",") {
		path = strings.TrimPrefix(path, "/")
		targets = append(targets, vegeta.Target{
			Method: "GET",
			URL:    fmt.Sprintf("http://%s/%s", host, path),
			Header: headers,
		})
	}
	targeter := vegeta.NewStaticTargeter(targets...)
	attacker := vegeta.NewAttacker(vegeta.Workers(uint64(*workers)))

	reporter := &HTTPReporter{}
	go http.ListenAndServe(*addr, reporter)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	out := &output{}
	defer out.close()
	for len(stop) == 0 {
		metrics := &vegeta.Metrics{}
		if *resultsDir != "" {
			if err := out.rotate(); err != nil {
				fmt.Fprintln(os.Stderr, "Error opening results file:", err)
				os.Exit(3)
			}
		}
		for res := range attacker.Attack(targeter, uint64(*rate), *duration) {
			metrics.Add(res)
			if out.encoder != nil {
				out.encoder.Encode(res)
			}
			if len(stop) > 0 {
				break
			}
		}
		metrics.Close()
		reporter.SetMetrics(metrics)
	}
}
