// Package policy defines the serializable, content-addressed form of a Keycard
// policy bundle — a Cedar schema, a set of Cedar policies, and a manifest —
// along with the codecs that read and write it.
//
// The package is a pure format layer with no service, database, or engine
// dependencies. Encoding computes content digests from the supplied bytes;
// decoding re-computes them from the archive so callers receive trustworthy
// SHAs regardless of what a producer claimed.
//
// A [Bundle] is encoded and decoded via the [BundleCodec] interface. The only
// built-in codec is [TarGZipCodec], registered automatically at package init.
// Use [CodecFor] to look up a codec by media type.
//
// The [Manifest.Digest] method returns a JCS-canonical (RFC 8785) SHA-256 that
// commits to the schema and every policy by content hash. It is the value to
// attest, to serve as the bundle ETag, and that a consumer reproduces to verify
// the bundle it holds is the one that was signed.
package policy
