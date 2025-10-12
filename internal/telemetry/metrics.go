package telemetry

import (
	"log"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

type instrumentation struct {
	wgInterfaceUp          metric.Int64ObservableGauge
	wgPeersTotal           metric.Int64ObservableGauge
	wgPeerConnected        metric.Int64ObservableGauge
	allowedIPsCount        metric.Int64ObservableGauge
	workQueueDepth         metric.Int64ObservableGauge
	certExpiryDays         metric.Float64ObservableGauge
	sniActiveConnections   metric.Int64ObservableGauge
	sniRoutingCacheEntries metric.Int64ObservableGauge

	wgHandshakes          metric.Int64Counter
	wgBytesReceived       metric.Int64Counter
	wgBytesTransmitted    metric.Int64Counter
	keyRotation           metric.Int64Counter
	netlinkEvents         metric.Int64Counter
	netlinkErrors         metric.Int64Counter
	kernelModuleLoads     metric.Int64Counter
	firewallRulesApplied  metric.Int64Counter
	configReloads         metric.Int64Counter
	restartCount          metric.Int64Counter
	authFailures          metric.Int64Counter
	aclDenied             metric.Int64Counter
	remoteConfigErrors    metric.Int64Counter
	sniTLSHandshakes      metric.Int64Counter
	sniProxyBytes         metric.Int64Counter
	sniRoutingCacheEvents metric.Int64Counter
	relayPackets          metric.Int64Counter
	relaySocketErrors     metric.Int64Counter
	holepunchAttempts     metric.Int64Counter
	bandwidthReportCycles metric.Int64Counter
	notifyEvents          metric.Int64Counter
	proxyProtocolInjected metric.Int64Counter
	remoteConfigFetch     metric.Float64Histogram
	wgHandshakeLatency    metric.Float64Histogram
	wgPeerRTT             metric.Float64Histogram
	syncDuration          metric.Float64Histogram
	sniBackendConnect     metric.Float64Histogram
	holepunchLatency      metric.Float64Histogram
	wireguardApply        metric.Float64Histogram
}

var (
	providerMu    sync.Mutex
	meterProvider metric.MeterProvider = noop.NewMeterProvider()
	meter                              = meterProvider.Meter("gerbil")
	inst          instrumentation
	attrIfname    = attribute.Key("ifname")
	attrPeer      = attribute.Key("peer")
	attrResult    = attribute.Key("result")
	attrErrorType = attribute.Key("error_type")
	attrDirection = attribute.Key("direction")
	attrAction    = attribute.Key("action")
	attrBackend   = attribute.Key("backend")
	attrEvent     = attribute.Key("event")
	attrComponent = attribute.Key("component")
	attrPhase     = attribute.Key("phase")
	attrQueue     = attribute.Key("queue")
	attrPolicy    = attribute.Key("policy")
	attrChain     = attribute.Key("chain")
	attrReason    = attribute.Key("reason")
	attrCertName  = attribute.Key("cert_name")
	attrEnabled   = attribute.Key("enabled")
)

func configureMeterProvider(mp metric.MeterProvider) error {
	providerMu.Lock()
	defer providerMu.Unlock()

	meterProvider = mp
	meter = mp.Meter("gerbil")

	var err error
	inst, err = createInstruments(meter)
	if err != nil {
		return err
	}
	return initCollectors(meter)
}

func createInstruments(m metric.Meter) (instrumentation, error) {
	var err error
	i := instrumentation{}

	if i.wgInterfaceUp, err = m.Int64ObservableGauge("gerbil_wg_interface_up", metric.WithDescription("WireGuard interface state (1 if up).")); err != nil {
		return i, err
	}
	if i.wgPeersTotal, err = m.Int64ObservableGauge("gerbil_wg_peers_total", metric.WithDescription("Total WireGuard peers configured.")); err != nil {
		return i, err
	}
	if i.wgPeerConnected, err = m.Int64ObservableGauge("gerbil_wg_peer_connected", metric.WithDescription("WireGuard peer connected flag.")); err != nil {
		return i, err
	}
	if i.allowedIPsCount, err = m.Int64ObservableGauge("gerbil_allowed_ips_count", metric.WithDescription("Allowed IPs configured per peer.")); err != nil {
		return i, err
	}
	if i.workQueueDepth, err = m.Int64ObservableGauge("gerbil_workqueue_depth", metric.WithDescription("Depth of internal work queues.")); err != nil {
		return i, err
	}
	if i.certExpiryDays, err = m.Float64ObservableGauge("gerbil_certificate_expiry_days", metric.WithDescription("TLS certificate validity in days.")); err != nil {
		return i, err
	}
	if i.sniActiveConnections, err = m.Int64ObservableGauge("gerbil_sni_active_connections", metric.WithDescription("Active SNI proxy connections.")); err != nil {
		return i, err
	}
	if i.sniRoutingCacheEntries, err = m.Int64ObservableGauge("gerbil_sni_routing_cache_entries", metric.WithDescription("Entries in SNI routing cache.")); err != nil {
		return i, err
	}

	if i.wgHandshakes, err = m.Int64Counter("gerbil_wg_handshakes_total", metric.WithDescription("WireGuard handshake attempts.")); err != nil {
		return i, err
	}
	if i.wgBytesReceived, err = m.Int64Counter("gerbil_wg_bytes_received_total", metric.WithDescription("Bytes received per peer."), metric.WithUnit("By")); err != nil {
		return i, err
	}
	if i.wgBytesTransmitted, err = m.Int64Counter("gerbil_wg_bytes_transmitted_total", metric.WithDescription("Bytes transmitted per peer."), metric.WithUnit("By")); err != nil {
		return i, err
	}
	if i.keyRotation, err = m.Int64Counter("gerbil_key_rotation_total", metric.WithDescription("Key rotation events.")); err != nil {
		return i, err
	}
	if i.netlinkEvents, err = m.Int64Counter("gerbil_netlink_events_total", metric.WithDescription("Netlink events processed.")); err != nil {
		return i, err
	}
	if i.netlinkErrors, err = m.Int64Counter("gerbil_netlink_errors_total", metric.WithDescription("Netlink error events.")); err != nil {
		return i, err
	}
	if i.kernelModuleLoads, err = m.Int64Counter("gerbil_kernel_module_loads_total", metric.WithDescription("Kernel module load attempts.")); err != nil {
		return i, err
	}
	if i.firewallRulesApplied, err = m.Int64Counter("gerbil_firewall_rules_applied_total", metric.WithDescription("Firewall rule applications.")); err != nil {
		return i, err
	}
	if i.configReloads, err = m.Int64Counter("gerbil_config_reloads_total", metric.WithDescription("Configuration reload results.")); err != nil {
		return i, err
	}
	if i.restartCount, err = m.Int64Counter("gerbil_restart_count_total", metric.WithDescription("Process restart count.")); err != nil {
		return i, err
	}
	if i.authFailures, err = m.Int64Counter("gerbil_auth_failures_total", metric.WithDescription("Authentication failures.")); err != nil {
		return i, err
	}
	if i.aclDenied, err = m.Int64Counter("gerbil_acl_denied_total", metric.WithDescription("ACL denied operations.")); err != nil {
		return i, err
	}
	if i.remoteConfigErrors, err = m.Int64Counter("gerbil_remote_config_errors_total", metric.WithDescription("Remote configuration errors.")); err != nil {
		return i, err
	}
	if i.sniTLSHandshakes, err = m.Int64Counter("gerbil_sni_tls_handshakes_total", metric.WithDescription("SNI TLS handshakes.")); err != nil {
		return i, err
	}
	if i.sniProxyBytes, err = m.Int64Counter("gerbil_sni_proxy_bytes_total", metric.WithDescription("SNI proxy bytes transferred."), metric.WithUnit("By")); err != nil {
		return i, err
	}
	if i.sniRoutingCacheEvents, err = m.Int64Counter("gerbil_sni_routing_cache_events_total", metric.WithDescription("SNI routing cache events.")); err != nil {
		return i, err
	}
	if i.relayPackets, err = m.Int64Counter("gerbil_relay_packets_total", metric.WithDescription("UDP relay packets processed.")); err != nil {
		return i, err
	}
	if i.relaySocketErrors, err = m.Int64Counter("gerbil_relay_socket_errors_total", metric.WithDescription("Relay socket errors.")); err != nil {
		return i, err
	}
	if i.holepunchAttempts, err = m.Int64Counter("gerbil_holepunch_attempts_total", metric.WithDescription("Hole punch attempts.")); err != nil {
		return i, err
	}
	if i.bandwidthReportCycles, err = m.Int64Counter("gerbil_bandwidth_report_cycles_total", metric.WithDescription("Bandwidth report cycles.")); err != nil {
		return i, err
	}
	if i.notifyEvents, err = m.Int64Counter("gerbil_notify_events_total", metric.WithDescription("Notify webhook results.")); err != nil {
		return i, err
	}
	if i.proxyProtocolInjected, err = m.Int64Counter("gerbil_proxy_protocol_injected_total", metric.WithDescription("Proxy protocol injection count.")); err != nil {
		return i, err
	}
	if i.remoteConfigFetch, err = m.Float64Histogram("gerbil_remote_config_fetch_seconds", metric.WithDescription("Remote configuration fetch latency."), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(LatencyBucketsSeconds...)); err != nil {
		return i, err
	}
	if i.wgHandshakeLatency, err = m.Float64Histogram("gerbil_wg_handshake_latency_seconds", metric.WithDescription("WireGuard handshake latency."), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(LatencyBucketsSeconds...)); err != nil {
		return i, err
	}
	if i.wgPeerRTT, err = m.Float64Histogram("gerbil_wg_peer_rtt_seconds", metric.WithDescription("WireGuard peer RTT."), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(LatencyBucketsSeconds...)); err != nil {
		return i, err
	}
	if i.syncDuration, err = m.Float64Histogram("gerbil_sync_duration_seconds", metric.WithDescription("Sync duration."), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(LatencyBucketsSeconds...)); err != nil {
		return i, err
	}
	if i.sniBackendConnect, err = m.Float64Histogram("gerbil_sni_backend_connect_seconds", metric.WithDescription("SNI backend connect latency."), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(LatencyBucketsSeconds...)); err != nil {
		return i, err
	}
	if i.holepunchLatency, err = m.Float64Histogram("gerbil_holepunch_latency_seconds", metric.WithDescription("Hole punch latency."), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(LatencyBucketsSeconds...)); err != nil {
		return i, err
	}
	if i.wireguardApply, err = m.Float64Histogram("gerbil_wireguard_apply_seconds", metric.WithDescription("WireGuard apply latency."), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(LatencyBucketsSeconds...)); err != nil {
		return i, err
	}

	return i, nil
}

func shortPeer(pk string) string {
	if len(pk) <= 0 {
		return ""
	}
	cleaned := make([]rune, 0, len(pk))
	for _, r := range pk {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			cleaned = append(cleaned, r)
		}
	}
	if len(cleaned) == 0 {
		return "unknown"
	}
	max := 12
	if len(cleaned) < max {
		max = len(cleaned)
	}
	trimmed := string(cleaned[:max])
	// Format as colon separated pairs for readability if we have even length.
	out := make([]rune, 0, len(trimmed)+len(trimmed)/2)
	for i, r := range trimmed {
		if i > 0 && i%2 == 0 {
			out = append(out, ':')
		}
		out = append(out, r)
	}
	return string(out)
}

func init() {
	var err error
	inst, err = createInstruments(meter)
	if err != nil {
		log.Printf("telemetry: failed to create instruments: %v", err)
		return
	}
	if err := initCollectors(meter); err != nil {
		log.Printf("telemetry: failed to init collectors: %v", err)
	}
}
