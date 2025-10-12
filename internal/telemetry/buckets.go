package telemetry

// LatencyBucketsSeconds defines histogram buckets shared by latency metrics.
var LatencyBucketsSeconds = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
