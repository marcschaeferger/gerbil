package telemetry

import (
	"context"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var background = context.Background()

func addCounter(counter metric.Int64Counter, value int64, attrs ...attribute.KeyValue) {
	if counter == nil || value == 0 {
		return
	}
	counter.Add(background, value, metric.WithAttributes(attrs...))
}

func recordHistogram(hist metric.Float64Histogram, value float64, attrs ...attribute.KeyValue) {
	if hist == nil {
		return
	}
	hist.Record(background, value, metric.WithAttributes(attrs...))
}

func normalizeResult(result string) string {
	switch strings.ToLower(result) {
	case "success":
		return "success"
	case "failure":
		return "failure"
	default:
		return "unknown"
	}
}

func normalizeLower(value, fallback string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func RecordWGHandshake(ifname, peer, result string, dur time.Duration) {
	attrs := []attribute.KeyValue{
		attrIfname.String(ifname),
		attrPeer.String(shortPeer(peer)),
		attrResult.String(normalizeResult(result)),
	}
	addCounter(inst.wgHandshakes, 1, attrs...)
	if dur > 0 {
		recordHistogram(inst.wgHandshakeLatency, dur.Seconds(), attrs[:2]...)
	}
}

func RecordWGPeerRTT(ifname, peer string, dur time.Duration) {
	if dur <= 0 {
		return
	}
	attrs := []attribute.KeyValue{
		attrIfname.String(ifname),
		attrPeer.String(shortPeer(peer)),
	}
	recordHistogram(inst.wgPeerRTT, dur.Seconds(), attrs...)
}

func RecordWGBytes(ifname, peer string, rxDelta, txDelta int64) {
	attrs := []attribute.KeyValue{
		attrIfname.String(ifname),
		attrPeer.String(shortPeer(peer)),
	}
	addCounter(inst.wgBytesReceived, rxDelta, attrs...)
	addCounter(inst.wgBytesTransmitted, txDelta, attrs...)
}

func RecordKeyRotation(ifname, reason string) {
	addCounter(inst.keyRotation, 1, attrIfname.String(ifname), attrReason.String(normalizeLower(reason, "unknown")))
}

func RecordNetlinkEvent(eventType string) {
	addCounter(inst.netlinkEvents, 1, attrEvent.String(normalizeLower(eventType, "unknown")))
}

func RecordNetlinkError(component, errorType string) {
	addCounter(inst.netlinkErrors, 1,
		attrComponent.String(normalizeLower(component, "unknown")),
		attrErrorType.String(normalizeLower(errorType, "unknown")),
	)
}

func RecordSyncDuration(component string, d time.Duration) {
	if d <= 0 {
		return
	}
	recordHistogram(inst.syncDuration, d.Seconds(), attrComponent.String(normalizeLower(component, "unknown")))
}

func RecordKernelModuleLoad(result string) {
	addCounter(inst.kernelModuleLoads, 1, attrResult.String(normalizeResult(result)))
}

func RecordFirewallApplied(chain, result string) {
	addCounter(inst.firewallRulesApplied, 1,
		attrChain.String(chain),
		attrResult.String(normalizeResult(result)),
	)
}

func RecordConfigReload(result string) {
	addCounter(inst.configReloads, 1, attrResult.String(normalizeResult(result)))
}

func IncRestartCount() {
	addCounter(inst.restartCount, 1)
}

func RecordAuthFailure(peer, reason string) {
	addCounter(inst.authFailures, 1,
		attrPeer.String(shortPeer(peer)),
		attrReason.String(normalizeLower(reason, "unknown")),
	)
}

func RecordACLDenied(ifname, peer, policy string) {
	addCounter(inst.aclDenied, 1,
		attrIfname.String(ifname),
		attrPeer.String(shortPeer(peer)),
		attrPolicy.String(normalizeLower(policy, "unknown")),
	)
}

func RecordRemoteConfigFetch(result string, d time.Duration) {
	if d < 0 {
		return
	}
	recordHistogram(inst.remoteConfigFetch, d.Seconds(), attrResult.String(normalizeResult(result)))
}

func RecordRemoteConfigError(errorType string) {
	addCounter(inst.remoteConfigErrors, 1, attrErrorType.String(normalizeLower(errorType, "unknown")))
}

func RecordSNIHandshake(result, errorType string) {
	attrs := []attribute.KeyValue{
		attrResult.String(normalizeResult(result)),
		attrErrorType.String(normalizeLower(errorType, "none")),
	}
	addCounter(inst.sniTLSHandshakes, 1, attrs...)
}

func RecordSNIBackendConnect(d time.Duration, backend string) {
	if d <= 0 {
		return
	}
	recordHistogram(inst.sniBackendConnect, d.Seconds(), attrBackend.String(backend))
}

func AddSNIProxyBytes(direction string, n int64) {
	addCounter(inst.sniProxyBytes, n, attrDirection.String(normalizeLower(direction, "unknown")))
}

func RecordSNIRoutingCacheEvent(event string) {
	addCounter(inst.sniRoutingCacheEvents, 1, attrEvent.String(normalizeLower(event, "unknown")))
}

func RecordRelayPacket(direction, action string) {
	addCounter(inst.relayPackets, 1,
		attrDirection.String(normalizeLower(direction, "unknown")),
		attrAction.String(normalizeLower(action, "unknown")),
	)
}

func RecordRelaySocketError(errorType string) {
	addCounter(inst.relaySocketErrors, 1, attrErrorType.String(normalizeLower(errorType, "unknown")))
}

func RecordHolepunchAttempt(result, reason string) {
	attrs := []attribute.KeyValue{
		attrResult.String(normalizeResult(result)),
	}
	if reason != "" {
		attrs = append(attrs, attrReason.String(normalizeLower(reason, "unknown")))
	}
	addCounter(inst.holepunchAttempts, 1, attrs...)
}

func RecordHolepunchLatency(d time.Duration) {
	if d <= 0 {
		return
	}
	recordHistogram(inst.holepunchLatency, d.Seconds())
}

func RecordBandwidthReportCycle(result string) {
	addCounter(inst.bandwidthReportCycles, 1, attrResult.String(normalizeResult(result)))
}

func RecordNotifyEvent(result string) {
	addCounter(inst.notifyEvents, 1, attrResult.String(normalizeResult(result)))
}

func RecordProxyProtocolInjected(enabled string) {
	value := "false"
	if strings.ToLower(enabled) == "true" {
		value = "true"
	}
	addCounter(inst.proxyProtocolInjected, 1, attrEnabled.String(value))
}

func RecordWGApplyDuration(phase string, d time.Duration) {
	if d <= 0 {
		return
	}
	recordHistogram(inst.wireguardApply, d.Seconds(), attrPhase.String(normalizeLower(phase, "unknown")))
}
