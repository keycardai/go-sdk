// Package policy defines the serializable, content-addressed form of a Keycard
// policy bundle — a Cedar schema, a set of Cedar policies, and a manifest — and
// the operations that read, write, validate, and evaluate it.
//
// A [Bundle] is the in-memory form. It is encoded to and decoded from a byte
// stream by media type: [Bundle.Encode] and [DecodeBundle] use the codec
// registered for a [MediaType]. The only built-in codec handles [MediaTypeTarGzip]
// (a tar+gzip archive) and is registered at package init; use [CodecFor] to look
// one up directly. Encoding computes content digests from the supplied bytes;
// decoding recomputes them from the archive, so callers receive trustworthy SHAs
// regardless of what a producer claimed.
//
// A bundle can also be expanded onto a filesystem: [LoadBundle] reads one from an
// io/fs.FS and [Bundle.Unload] writes one to a [WriteFS] — use [OsDirFS] for the
// OS filesystem or [VFS] for an in-memory tree.
//
// [Bundle.Digest] returns the bundle's attestable identity: a JCS-canonical
// (RFC 8785) SHA-256 that commits to the schema and every policy by content hash,
// recomputed from the bundle's own bytes. It is the value to attest, to serve as
// the bundle ETag, and that a consumer reproduces to verify the bundle it holds is
// the one that was signed.
//
// The package uses cedar-go for the Cedar layer: [Bundle.Validate] checks the
// schema and policies for syntactic validity and reports action UIDs referenced by
// policies but absent from the schema, and [Bundle.PolicySet] parses the policies
// into a cedar-go PolicySet for evaluation.
package policy
