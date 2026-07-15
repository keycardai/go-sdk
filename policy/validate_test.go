package policy

import (
	"errors"
	"testing"
)

func TestPolicySet(t *testing.T) {
	b := &Bundle{
		Manifest: Manifest{Schema: SchemaRef{Version: "2026-02-14"}},
		Policies: map[string][]byte{
			"pol_a": []byte(`@id("a")
permit(principal, action, resource);`),
			"pol_b": []byte(`@id("b")
forbid(principal, action, resource);`),
		},
	}
	ps, err := b.PolicySet()
	if err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
	count := 0
	for range ps.All() {
		count++
	}
	if count != 2 {
		t.Errorf("policy count = %d, want 2", count)
	}
}

func TestPolicySet_InvalidPolicy(t *testing.T) {
	b := &Bundle{
		Manifest: Manifest{Schema: SchemaRef{Version: "2026-02-14"}},
		Policies: map[string][]byte{"pol_bad": []byte(`this is not cedar !!!`)},
	}
	if _, err := b.PolicySet(); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("got %v, want ErrInvalidPolicy", err)
	}
}

func TestPolicySet_Nil(t *testing.T) {
	var b *Bundle
	if _, err := b.PolicySet(); !errors.Is(err, ErrMissingBundle) {
		t.Errorf("got %v, want ErrMissingBundle", err)
	}
}

func TestValidate_ValidBundle(t *testing.T) {
	b := sampleBundle()
	result, err := b.Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !result.Valid() {
		t.Errorf("expected Valid()=true, got UnknownActions=%v", result.UnknownActions)
	}
}

// sampleSchema declares only action "any", so a policy scoped to a different
// action UID is an unknown action.
func TestValidate_UnknownAction(t *testing.T) {
	b := &Bundle{
		Manifest: Manifest{Schema: SchemaRef{Version: "2026-02-14"}, TargetType: TargetTypeUser},
		Schema:   []byte(sampleSchema),
		Policies: map[string][]byte{
			"pol_x": []byte(`permit(principal, action == Keycard::Action::"other", resource);`),
		},
	}
	result, err := b.Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Valid() {
		t.Error("expected Valid()=false for unknown action reference")
	}
	found := false
	for _, uid := range result.UnknownActions {
		if uid == `Keycard::Action::"other"` {
			found = true
		}
	}
	if !found {
		t.Errorf("expected UnknownActions to contain Keycard::Action::\"other\", got %v", result.UnknownActions)
	}
}

func TestValidate_InvalidSchema(t *testing.T) {
	b := &Bundle{
		Manifest: Manifest{Schema: SchemaRef{Version: "2026-02-14"}, TargetType: TargetTypeUser},
		Schema:   []byte(`this is not valid cedar schema !!!`),
		Policies: map[string][]byte{},
	}
	_, err := b.Validate()
	if !errors.Is(err, ErrInvalidSchema) {
		t.Errorf("got %v, want ErrInvalidSchema", err)
	}
}

func TestValidate_InvalidPolicy(t *testing.T) {
	b := &Bundle{
		Manifest: Manifest{Schema: SchemaRef{Version: "2026-02-14"}, TargetType: TargetTypeUser},
		Schema:   []byte(sampleSchema),
		Policies: map[string][]byte{
			"pol_bad": []byte(`this is not valid cedar policy !!!`),
		},
	}
	_, err := b.Validate()
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("got %v, want ErrInvalidPolicy", err)
	}
}

func TestValidate_NilBundle(t *testing.T) {
	var b *Bundle
	_, err := b.Validate()
	if !errors.Is(err, ErrMissingBundle) {
		t.Errorf("got %v, want ErrMissingBundle", err)
	}
}

// A bundle with only wildcard action scopes (action) has no specific action
// UIDs to check, so Validate must succeed with no unknown actions.
func TestValidate_WildcardActionScope(t *testing.T) {
	b := &Bundle{
		Manifest: Manifest{Schema: SchemaRef{Version: "2026-02-14"}, TargetType: TargetTypeUser},
		Schema:   []byte(sampleSchema),
		Policies: map[string][]byte{
			"pol_all": []byte(`permit(principal, action, resource);`),
		},
	}
	result, err := b.Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !result.Valid() {
		t.Errorf("wildcard action scope must not produce unknown actions: got %v", result.UnknownActions)
	}
}
