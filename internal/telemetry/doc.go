// Package telemetry provides application specific metrics helpers for Gerbil.
//
// The package mirrors the structure used by Pangolin's Newt client while
// adapting instrument names and semantics to Gerbil's runtime. All helpers
// abstract OpenTelemetry primitives away from the rest of the codebase so
// callers interact with small domain specific functions only.
package telemetry
