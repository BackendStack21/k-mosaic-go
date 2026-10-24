// Deprecated: the 1.x design is broken (the KEM shared secret is recoverable
// from public data and signatures are forgeable). Use
// github.com/BackendStack21/k-mosaic-go/v2 instead.
module github.com/BackendStack21/k-mosaic-go

go 1.21

require golang.org/x/crypto v0.31.0

require golang.org/x/sys v0.28.0 // indirect

retract (
	[v1.0.0, v1.0.4] // Broken by design: KEM shared secret recoverable, signatures forgeable. Use /v2.
	v1.0.5 // Contains only the retractions and deprecation notice.
)
