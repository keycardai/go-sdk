package policy

import "errors"

// Structural decode errors. The codec validates archive structure only; content
// authority and SHA reconciliation are the ingest layer's concern. All are
// wrapped with %w so callers can match them with errors.Is.
var (
	// ErrMissingBundle is returned by Encode when the bundle argument is nil.
	ErrMissingBundle = errors.New("policy: bundle missing")

	// ErrMalformedArchive is returned by Decode when the archive is not a valid
	// gzip-compressed tar stream.
	ErrMalformedArchive = errors.New("policy: malformed archive")

	// ErrMissingManifest is returned by Decode when manifest.json is absent.
	ErrMissingManifest = errors.New("policy: missing manifest.json")

	// ErrInvalidManifest is returned by Decode when manifest.json cannot be
	// parsed or contains contradictory policy entries.
	ErrInvalidManifest = errors.New("policy: invalid manifest.json")

	// ErrMissingVersion is returned when the manifest's schema version field is empty.
	ErrMissingVersion = errors.New("policy: missing schema version")

	// ErrUnexpectedEntry is returned by Decode when the archive contains a tar
	// entry that does not belong in a policy bundle.
	ErrUnexpectedEntry = errors.New("policy: unexpected entry")

	// ErrDuplicateEntry is returned by Decode when the archive contains more than
	// one entry for the same path.
	ErrDuplicateEntry = errors.New("policy: duplicate entry")

	// ErrBundleTooLarge is returned by Decode when the decompressed archive
	// content exceeds the codec's size limit.
	ErrBundleTooLarge = errors.New("policy: decompressed size exceeds limit")

	// ErrUnknownMediaType is returned when no codec is registered for the media type.
	ErrUnknownMediaType = errors.New("policy: unknown media type")

	// ErrOrphanPolicy is returned by LoadBundle when a policies/ file has no
	// matching manifest entry.
	ErrOrphanPolicy = errors.New("policy: orphan policy file")

	// ErrInvalidSchema is returned by Validate when the Cedar schema is
	// syntactically invalid.
	ErrInvalidSchema = errors.New("policy: invalid schema")

	// ErrInvalidPolicy is returned by Validate when a Cedar policy is
	// syntactically invalid.
	ErrInvalidPolicy = errors.New("policy: invalid policy")
)
