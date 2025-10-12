package telemetry

import (
	"context"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/metric"
)

// WireGuardPeerSnapshot represents the observable state of a WireGuard peer.
type WireGuardPeerSnapshot struct {
	PublicKey  string
	Connected  bool
	AllowedIPs int
}

// WireGuardSnapshot represents a WireGuard interface and its peers.
type WireGuardSnapshot struct {
	Interface string
	Up        bool
	Peers     []WireGuardPeerSnapshot
}

// WireGuardSnapshotter collects the current WireGuard state.
type WireGuardSnapshotter func(ctx context.Context) ([]WireGuardSnapshot, error)

// WorkQueueDepth describes the depth of an internal work queue.
type WorkQueueDepth struct {
	Queue string
	Depth int64
}

// WorkQueueCollector reports queue depths.
type WorkQueueCollector func(ctx context.Context) ([]WorkQueueDepth, error)

// CertificateExpiry contains certificate lifetime metadata.
type CertificateExpiry struct {
	Name      string
	Interface string
	Days      float64
}

// CertificateCollector collects certificate expirations.
type CertificateCollector func(ctx context.Context) ([]CertificateExpiry, error)

// SNIStats represents the state of the SNI proxy internals.
type SNIStats struct {
	ActiveConnections map[string]int64
	RoutingCache      int64
}

// SNIStatsProvider retrieves current SNI stats.
type SNIStatsProvider func(ctx context.Context) (SNIStats, error)

var (
	wireguardSnapshotter atomic.Value

	workqueueMu         sync.RWMutex
	workqueueCollectors []WorkQueueCollector

	certificateCollector atomic.Value
	sniStatsProvider     atomic.Value
)

// SetWireGuardSnapshotter registers the WireGuard snapshot provider.
func SetWireGuardSnapshotter(fn WireGuardSnapshotter) {
	wireguardSnapshotter.Store(fn)
}

// RegisterWorkQueueCollector registers a callback that reports work queue depths.
func RegisterWorkQueueCollector(fn WorkQueueCollector) {
	workqueueMu.Lock()
	defer workqueueMu.Unlock()
	workqueueCollectors = append(workqueueCollectors, fn)
}

// SetCertificateCollector registers the certificate expiry collector.
func SetCertificateCollector(fn CertificateCollector) {
	certificateCollector.Store(fn)
}

// SetSNIStatsProvider registers the SNI stats provider.
func SetSNIStatsProvider(fn SNIStatsProvider) {
	sniStatsProvider.Store(fn)
}

func initCollectors(m metric.Meter) error {
	_, err := m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		observeWireGuard(ctx, o)
		observeWorkQueues(ctx, o)
		observeCertificates(ctx, o)
		observeSNI(ctx, o)
		return nil
	}, inst.wgInterfaceUp, inst.wgPeersTotal, inst.wgPeerConnected, inst.allowedIPsCount, inst.workQueueDepth, inst.certExpiryDays, inst.sniActiveConnections, inst.sniRoutingCacheEntries)
	return err
}

func observeWireGuard(ctx context.Context, o metric.Observer) {
	val := wireguardSnapshotter.Load()
	if val == nil {
		return
	}
	fn, ok := val.(WireGuardSnapshotter)
	if !ok || fn == nil {
		return
	}
	snapshots, err := fn(ctx)
	if err != nil {
		return
	}
	for _, snap := range snapshots {
		attrs := metric.WithAttributes(attrIfname.String(snap.Interface))
		var up int64
		if snap.Up {
			up = 1
		}
		o.ObserveInt64(inst.wgInterfaceUp, up, attrs)
		o.ObserveInt64(inst.wgPeersTotal, int64(len(snap.Peers)), attrs)
		for _, peer := range snap.Peers {
			peerAttrs := metric.WithAttributes(
				attrIfname.String(snap.Interface),
				attrPeer.String(shortPeer(peer.PublicKey)),
			)
			var connected int64
			if peer.Connected {
				connected = 1
			}
			o.ObserveInt64(inst.wgPeerConnected, connected, peerAttrs)
			o.ObserveInt64(inst.allowedIPsCount, int64(peer.AllowedIPs), peerAttrs)
		}
	}
}

func observeWorkQueues(ctx context.Context, o metric.Observer) {
	workqueueMu.RLock()
	collectors := append([]WorkQueueCollector(nil), workqueueCollectors...)
	workqueueMu.RUnlock()
	for _, collector := range collectors {
		if collector == nil {
			continue
		}
		depths, err := collector(ctx)
		if err != nil {
			continue
		}
		for _, depth := range depths {
			o.ObserveInt64(inst.workQueueDepth, depth.Depth, metric.WithAttributes(attrQueue.String(depth.Queue)))
		}
	}
}

func observeCertificates(ctx context.Context, o metric.Observer) {
	val := certificateCollector.Load()
	if val == nil {
		return
	}
	fn, ok := val.(CertificateCollector)
	if !ok || fn == nil {
		return
	}
	expiries, err := fn(ctx)
	if err != nil {
		return
	}
	for _, expiry := range expiries {
		o.ObserveFloat64(inst.certExpiryDays, expiry.Days, metric.WithAttributes(
			attrCertName.String(expiry.Name),
			attrIfname.String(expiry.Interface),
		))
	}
}

func observeSNI(ctx context.Context, o metric.Observer) {
	val := sniStatsProvider.Load()
	if val == nil {
		return
	}
	fn, ok := val.(SNIStatsProvider)
	if !ok || fn == nil {
		return
	}
	stats, err := fn(ctx)
	if err != nil {
		return
	}
	for backend, active := range stats.ActiveConnections {
		o.ObserveInt64(inst.sniActiveConnections, active, metric.WithAttributes(attrBackend.String(backend)))
	}
	o.ObserveInt64(inst.sniRoutingCacheEntries, stats.RoutingCache)
}
