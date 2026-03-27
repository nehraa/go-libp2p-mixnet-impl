package main

import "testing"

func TestResolveNetworkConditionPreset(t *testing.T) {
	condition, err := resolveNetworkCondition("3g", -1, -1, -1, -1)
	if err != nil {
		t.Fatalf("resolveNetworkCondition(3g) returned error: %v", err)
	}
	if condition.Name != "3g" || condition.LatencyMS != 200 || condition.JitterMS != 10 || condition.PacketLossPct != 1.0 || condition.BandwidthMbps != 2 {
		t.Fatalf("unexpected 3g condition: %+v", condition)
	}
}

func TestResolveNetworkConditionOverrides(t *testing.T) {
	condition, err := resolveNetworkCondition("satellite", 300, 5, 3.5, 7)
	if err != nil {
		t.Fatalf("resolveNetworkCondition(satellite overrides) returned error: %v", err)
	}
	if condition.LatencyMS != 300 || condition.JitterMS != 5 || condition.PacketLossPct != 3.5 || condition.BandwidthMbps != 7 {
		t.Fatalf("overrides not applied: %+v", condition)
	}
}

func TestResolveNetworkConditionRejectsInvalidPacketLoss(t *testing.T) {
	if _, err := resolveNetworkCondition("custom", 0, 0, 100, 0); err == nil {
		t.Fatal("expected invalid packet loss to be rejected")
	}
}
