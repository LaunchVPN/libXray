package xray

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/libxray/nodep"
	"github.com/xtls/xray-core/infra/conf"
)

func TestReadPingOutboundsIgnoresOtherRootFields(t *testing.T) {
	xrayJSON := `{
		// These fields are deliberately invalid for the full Xray schema.
		"inbounds": "ignored",
		"routing": 42,
		"dns": false,
		"outbounds": [
			{"protocol": "freedom", "tag": "proxy"}
		]
	}`

	outbounds, err := readPingOutbounds(xrayJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 1 {
		t.Fatalf("outbounds = %d, want 1", len(outbounds))
	}
	if outbounds[0].Tag != "proxy" {
		t.Fatalf("tag = %q, want proxy", outbounds[0].Tag)
	}
}

func TestPreparePingOutboundsPreservesRealityClientConfig(t *testing.T) {
	xrayJSON := `{
		"outbounds": [{
			"tag": "proxy",
			"protocol": "vless",
			"settings": {
				"address": "example.com",
				"port": 443,
				"id": "41b20a0c-b56f-4bb8-97e1-e5ceb0ab1ba4",
				"encryption": "none"
			},
			"streamSettings": {
				"network": "xhttp",
				"xhttpSettings": {
					"host": "example.com",
					"path": "/xhttp",
					"mode": "auto"
				},
				"security": "reality",
				"realitySettings": {
					"fingerprint": "chrome",
					"serverName": "example.com",
					"password": "itSUyWpOsw4n3_Rc-hK0r_ryzTBGRqHdrPJI-OFuAwM"
				}
			}
		}]
	}`

	outbounds, err := readPingOutbounds(xrayJSON)
	if err != nil {
		t.Fatal(err)
	}
	prepared, targetTag, err := preparePingOutbounds(outbounds, "proxy", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 1 {
		t.Fatalf("outbounds = %d, want 1", len(prepared))
	}
	if targetTag != "__libxray_ping_0_0" {
		t.Fatalf("target tag = %q", targetTag)
	}
}

func TestPreparePingOutboundsSelectsAndRewritesDependencies(t *testing.T) {
	outbounds := []conf.OutboundDetourConfig{
		{
			Protocol: "blackhole",
			Tag:      "unused",
		},
		{
			Protocol: "not-a-protocol",
			Tag:      "unused",
		},
		{
			Protocol: "freedom",
			Tag:      "proxy",
			StreamSetting: &conf.StreamConfig{
				SocketSettings: &conf.SocketConfig{DialerProxy: "fragment"},
			},
		},
		{
			Protocol: "freedom",
			Tag:      "fragment",
		},
	}

	prepared, targetTag, err := preparePingOutbounds(outbounds, "", 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 2 {
		t.Fatalf("prepared outbounds = %d, want 2", len(prepared))
	}
	if targetTag != "__libxray_ping_7_0" {
		t.Fatalf("target tag = %q", targetTag)
	}
	if prepared[0].Tag != targetTag {
		t.Fatalf("root tag = %q, want %q", prepared[0].Tag, targetTag)
	}
	if prepared[1].Tag != "__libxray_ping_7_1" {
		t.Fatalf("dependency tag = %q", prepared[1].Tag)
	}
	if got := prepared[0].StreamSetting.SocketSettings.DialerProxy; got != prepared[1].Tag {
		t.Fatalf("dialerProxy = %q, want %q", got, prepared[1].Tag)
	}
	for _, outbound := range prepared {
		if outbound.Tag == "unused" {
			t.Fatal("unrelated outbound was included")
		}
	}
}

func TestPreparePingOutboundsRejectsRemovedProxySettings(t *testing.T) {
	outbounds, err := readPingOutbounds(`{"outbounds":[
		{"protocol":"freedom","tag":"proxy","proxySettings":{"tag":"transport"}},
		{"protocol":"freedom","tag":"transport"}
	]}`)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = preparePingOutbounds(outbounds, "proxy", 1)
	if err == nil || !strings.Contains(err.Error(), "proxySettings") {
		t.Fatalf("expected Xray-core to reject proxySettings, got %v", err)
	}
}

func TestPreparePingOutboundsRejectsDependencyCycle(t *testing.T) {
	outbounds := []conf.OutboundDetourConfig{
		{
			Protocol: "freedom",
			Tag:      "proxy",
			StreamSetting: &conf.StreamConfig{
				SocketSettings: &conf.SocketConfig{DialerProxy: "next"},
			},
		},
		{
			Protocol: "freedom",
			Tag:      "next",
			StreamSetting: &conf.StreamConfig{
				SocketSettings: &conf.SocketConfig{DialerProxy: "proxy"},
			},
		},
	}

	_, _, err := preparePingOutbounds(outbounds, "", 0)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("error = %v, want dependency cycle", err)
	}
}

func TestPingBatchRunsRequestsConcurrently(t *testing.T) {
	requestStarted := make(chan struct{}, 2)
	releaseRequests := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		requestStarted <- struct{}{}
		<-releaseRequests
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	config := `{"outbounds":[{"protocol":"freedom","tag":"proxy"}]}`
	type batchResult struct {
		results []PingBatchResult
		err     error
	}
	done := make(chan batchResult, 1)
	go func() {
		results, err := PingBatch(
			[]PingBatchItem{
				{XrayJSON: config},
				{XrayJSON: config},
			},
			2,
			server.URL,
			false,
		)
		done <- batchResult{results: results, err: err}
	}()

	for range 2 {
		select {
		case <-requestStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("requests did not run concurrently")
		}
	}
	close(releaseRequests)

	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if len(result.results) != 2 {
		t.Fatalf("results = %d, want 2", len(result.results))
	}
	for index := range result.results {
		if !result.results[index].Success {
			t.Fatalf(
				"result %d failed: %s",
				index,
				result.results[index].Error,
			)
		}
	}
}

func warmServer(firstDelay time.Duration) (*httptest.Server, *atomic.Int32) {
	var requests, connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if requests.Add(1) == 1 {
			select {
			case <-time.After(firstDelay):
			case <-request.Context().Done():
			}
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	return server, &connections
}

func TestPingBatchWarmTimesSecondRequestOnOneConnection(t *testing.T) {
	const firstDelay = 300 * time.Millisecond
	server, connections := warmServer(firstDelay)
	defer server.Close()

	results, err := PingBatch(
		[]PingBatchItem{{XrayJSON: `{"outbounds":[{"protocol":"freedom"}]}`}},
		2,
		server.URL,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Success {
		t.Fatalf("warm probe failed: %s", results[0].Error)
	}
	if results[0].Delay >= firstDelay.Milliseconds() {
		t.Fatalf("delay = %d, want the second request only", results[0].Delay)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections = %d, want 1", got)
	}
}

func TestPingBatchTimesOutWithinOneTimeout(t *testing.T) {
	for _, warm := range []bool{false, true} {
		t.Run(fmt.Sprintf("warm=%t", warm), func(t *testing.T) {
			server, _ := warmServer(5 * time.Second)
			defer server.Close()

			start := time.Now()
			results, err := PingBatch(
				[]PingBatchItem{{XrayJSON: `{"outbounds":[{"protocol":"freedom"}]}`}},
				1,
				server.URL,
				warm,
			)
			if err != nil {
				t.Fatal(err)
			}
			if results[0].Success || results[0].Delay != nodep.PingDelayTimeout {
				t.Fatalf("result = %+v, want a timeout", results[0])
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("batch took %s, want one timeout", elapsed)
			}
		})
	}
}

func TestPingBatchKeepsPerItemConfigErrorsInInputOrder(t *testing.T) {
	results, err := PingBatch(
		[]PingBatchItem{
			{XrayJSON: "not JSON"},
			{XrayJSON: `{"outbounds":[]}`},
		},
		1,
		"https://example.com",
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	for index, result := range results {
		if result.Success {
			t.Fatalf("result %d unexpectedly succeeded", index)
		}
		if result.Delay != 10000 {
			t.Fatalf("result %d delay = %d, want 10000", index, result.Delay)
		}
		if result.Error == "" {
			t.Fatalf("result %d has no error", index)
		}
	}
	if results[0].Error == "" {
		t.Fatal("first result should contain a JSON parsing error")
	}
	if results[1].Error != "ping config has no outbounds" {
		t.Fatalf("second result error = %q, want empty outbounds error", results[1].Error)
	}
}

func TestValidatePingBatchRequest(t *testing.T) {
	tests := []struct {
		name      string
		items     []PingBatchItem
		timeout   int
		targetURL string
		errorText string
	}{
		{
			name:      "empty configs",
			timeout:   1,
			targetURL: "https://example.com",
			errorText: "configs are empty",
		},
		{
			name:      "invalid URL",
			items:     []PingBatchItem{{}},
			timeout:   1,
			targetURL: "example.com",
			errorText: "absolute HTTP",
		},
		{
			name: "too many configs",
			items: []PingBatchItem{
				{},
				{},
				{},
				{},
				{},
				{},
			},
			timeout:   1,
			targetURL: "https://example.com",
			errorText: "more than 5 configs",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePingBatchRequest(
				test.items,
				test.timeout,
				test.targetURL,
			)
			if err == nil || !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("error = %v, want %q", err, test.errorText)
			}
		})
	}
}

func TestValidatePingBatchRequestAcceptsFiveConfigs(t *testing.T) {
	err := validatePingBatchRequest(
		[]PingBatchItem{
			{},
			{},
			{},
			{},
			{},
		},
		1,
		"https://example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
}

func ExamplePingBatch() {
	results, _ := PingBatch(
		[]PingBatchItem{{XrayJSON: `{"outbounds":[{"protocol":"freedom"}]}`}},
		5,
		"https://cp.cloudflare.com/",
		true,
	)
	fmt.Println(len(results))
}

// heldServer holds each request until release, which a failed test also calls
// so that closing the server does not wait on held handlers.
func heldServer(t *testing.T) (url string, started chan struct{}, release func()) {
	started = make(chan struct{}, 16)
	held := make(chan struct{})
	release = sync.OnceFunc(func() { close(held) })
	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		started <- struct{}{}
		<-held
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(release)
	return server.URL, started, release
}

func probeOnce(url string) ([]PingBatchResult, error) {
	return PingBatch(
		[]PingBatchItem{{XrayJSON: `{"outbounds":[{"protocol":"freedom"}]}`}},
		5,
		url,
		false,
	)
}

func TestPingBatchCallsOverlap(t *testing.T) {
	url, started, release := heldServer(t)

	const calls = 15
	errs := make(chan error, calls)
	for range calls {
		go func() {
			results, err := probeOnce(url)
			if err == nil && !results[0].Success {
				err = fmt.Errorf("probe failed: %s", results[0].Error)
			}
			errs <- err
		}()
	}
	for range calls {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("pingBatch calls did not overlap")
		}
	}
	release()
	for range calls {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestManagedCoreWaitsForPingBatch(t *testing.T) {
	for name, operation := range map[string]func() error{
		"runXray": func() error {
			defer func() { _ = StopXray() }()
			return RunXray(minimalConfig)
		},
		"testXray": func() error { return TestXray(minimalConfig) },
	} {
		t.Run(name, func(t *testing.T) {
			url, started, release := heldServer(t)

			probed := make(chan []PingBatchResult, 1)
			go func() {
				results, _ := probeOnce(url)
				probed <- results
			}()
			<-started

			finished := make(chan error, 1)
			go func() { finished <- operation() }()
			select {
			case err := <-finished:
				t.Fatalf("%s ran beside a probe: %v", name, err)
			case <-time.After(300 * time.Millisecond):
			}
			release()
			if results := <-probed; len(results) != 1 || !results[0].Success {
				t.Fatalf("probe = %+v, want a success", results)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPingBatchThroughSharedDialerStateRunsAlone(t *testing.T) {
	url, started, release := heldServer(t)

	held := make(chan error, 1)
	go func() {
		_, err := probeOnce(url)
		held <- err
	}()
	<-started

	chained := make(chan []PingBatchResult, 1)
	go func() {
		results, _ := PingBatch(
			[]PingBatchItem{{XrayJSON: `{"outbounds":[
				{"protocol":"freedom","tag":"proxy","streamSettings":{"sockopt":{"dialerProxy":"hop"}}},
				{"protocol":"freedom","tag":"hop"}
			]}`}},
			5,
			url,
			false,
		)
		chained <- results
	}()
	select {
	case <-started:
		t.Fatal("a dialerProxy chain was measured beside another probe")
	case <-time.After(300 * time.Millisecond):
	}
	release()
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if results := <-chained; len(results) != 1 || !results[0].Success {
		t.Fatalf("chained probe = %+v, want a success", results)
	}
}
