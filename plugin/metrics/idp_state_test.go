package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rashpile/go-envoy-oauth/plugin/metrics"
)

// findGaugeValue returns the value of the gauge series matching name+labels.
// Returns NaN-equivalent 0.0 and false if not found.
func findGaugeValue(t *testing.T, reg *prometheus.Registry, name string, wantLabels map[string]string) (float64, bool) {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("reg.Gather(): %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
	metricLoop:
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			for k, v := range wantLabels {
				if labels[k] != v {
					continue metricLoop
				}
			}
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

// TestIDPStateGauge_OneActiveSeriesPerProvider — HLTH-02, D-08: exactly one
// state series has value 1.0 per provider at any time.
func TestIDPStateGauge_OneActiveSeriesPerProvider(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics.RegisterOAuthFlowMetrics(reg)

	metrics.UpdateIDPState("kc", "degraded")

	for _, state := range []string{"ready", "degraded", "down"} {
		want := 0.0
		if state == "degraded" {
			want = 1.0
		}
		got, ok := findGaugeValue(t, reg, "envoy_oauth_idp_state", map[string]string{"idp": "kc", "state": state})
		if !ok {
			t.Errorf("no series envoy_oauth_idp_state{idp=kc,state=%s}", state)
			continue
		}
		if got != want {
			t.Errorf("envoy_oauth_idp_state{idp=kc,state=%s} = %v, want %v", state, got, want)
		}
	}
}

// TestUpdateIDPState_SyncsIDPUp — D-08 backward-compat: ready|degraded => up=1, down => up=0.
func TestUpdateIDPState_SyncsIDPUp(t *testing.T) {
	cases := []struct {
		stateLabel string
		wantUp     float64
	}{
		{"ready", 1.0},
		{"degraded", 1.0},
		{"down", 0.0},
	}
	for _, tc := range cases {
		reg := prometheus.NewRegistry()
		metrics.RegisterOAuthFlowMetrics(reg)

		metrics.UpdateIDPState("kc", tc.stateLabel)

		got, ok := findGaugeValue(t, reg, "envoy_oauth_idp_up", map[string]string{"idp": "kc"})
		if !ok {
			t.Fatalf("state=%s: no envoy_oauth_idp_up{idp=kc} series", tc.stateLabel)
		}
		if got != tc.wantUp {
			t.Errorf("state=%s: envoy_oauth_idp_up{idp=kc} = %v, want %v", tc.stateLabel, got, tc.wantUp)
		}
	}
}
