package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// Config controls telemetry initialisation.
type Config struct {
	ServiceName    string
	ServiceVersion string
	InstanceID     string
	Environment    string
	Exporter       string // "prom" or "otlp"
	Prometheus     PromConfig
	OTLP           OTLPConfig
}

// PromConfig defines the Prometheus exporter options.
type PromConfig struct {
	Addr string
	Path string
}

// OTLPConfig defines the OTLP/HTTP exporter options.
type OTLPConfig struct {
	Endpoint string
	Insecure bool
	Headers  map[string]string
}

var (
	initOnce     sync.Once
	initErr      error
	shutdownFunc = func(context.Context) error { return nil }
)

// Init configures the global MeterProvider and exporters.
func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	initOnce.Do(func() {
		shutdownFunc, initErr = initProvider(ctx, cfg)
	})
	return shutdownFunc, initErr
}

func initProvider(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	exporter := strings.ToLower(strings.TrimSpace(cfg.Exporter))
	if exporter == "" {
		exporter = "prom"
	}

	res, err := buildResource(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("telemetry: build resource: %w", err)
	}

	var (
		reader metric.Reader
		srv    *http.Server
		stop   func(context.Context) error
	)

	switch exporter {
	case "otlp":
		reader, stop, err = buildOTLPExporter(ctx, cfg)
	case "prom", "prometheus":
		reader, srv, err = buildPrometheusExporter(cfg)
	default:
		return nil, fmt.Errorf("telemetry: unsupported exporter %q", exporter)
	}
	if err != nil {
		return nil, err
	}

	mp := metric.NewMeterProvider(
		metric.WithReader(reader),
		metric.WithResource(res),
	)

	if err := configureMeterProvider(mp); err != nil {
		_ = mp.Shutdown(ctx)
		if stop != nil {
			_ = stop(ctx)
		}
		return nil, fmt.Errorf("telemetry: configure meter: %w", err)
	}
	otel.SetMeterProvider(mp)

	shutdown := func(ctx context.Context) error {
		var errs []error
		if stop != nil {
			if err := stop(ctx); err != nil {
				errs = append(errs, err)
			}
		}
		if srv != nil {
			shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs = append(errs, err)
			}
		}
		if err := mp.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
		if len(errs) == 0 {
			return nil
		}
		return errors.Join(errs...)
	}

	return shutdown, nil
}

func buildResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	var attrs []attribute.KeyValue
	if cfg.ServiceName != "" {
		attrs = append(attrs, semconv.ServiceNameKey.String(cfg.ServiceName))
	}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersionKey.String(cfg.ServiceVersion))
	}
	if cfg.InstanceID != "" {
		attrs = append(attrs, semconv.ServiceInstanceIDKey.String(cfg.InstanceID))
	}
	if cfg.Environment != "" {
		attrs = append(attrs, semconv.DeploymentEnvironmentKey.String(cfg.Environment))
	}
	return resource.New(ctx,
		resource.WithOS(),
		resource.WithProcess(),
		resource.WithContainer(),
		resource.WithHost(),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attrs...),
	)
}

func buildPrometheusExporter(cfg Config) (metric.Reader, *http.Server, error) {
	registry := promclient.NewRegistry()
	exporter, err := prometheus.New(
		prometheus.WithoutTargetInfo(),
		prometheus.WithoutUnits(),
		prometheus.WithRegisterer(registry),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("telemetry: create prometheus exporter: %w", err)
	}

	addr := cfg.Prometheus.Addr
	if addr == "" {
		addr = ":9464"
	}
	path := cfg.Prometheus.Path
	if path == "" {
		path = "/metrics"
	}

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("telemetry: prometheus server error: %v", err)
		}
	}()

	return exporter, srv, nil
}

func buildOTLPExporter(ctx context.Context, cfg Config) (metric.Reader, func(context.Context) error, error) {
	endpoint := cfg.OTLP.Endpoint
	if endpoint == "" {
		endpoint = "http://otel-collector:4318"
	}
	options := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(endpoint)}
	if cfg.OTLP.Insecure {
		options = append(options, otlpmetrichttp.WithInsecure())
	}
	if len(cfg.OTLP.Headers) > 0 {
		options = append(options, otlpmetrichttp.WithHeaders(cfg.OTLP.Headers))
	}

	exporter, err := otlpmetrichttp.New(ctx, options...)
	if err != nil {
		return nil, nil, fmt.Errorf("telemetry: create otlp exporter: %w", err)
	}

	reader := metric.NewPeriodicReader(exporter)
	stop := func(ctx context.Context) error { return exporter.Shutdown(ctx) }
	return reader, stop, nil
}
