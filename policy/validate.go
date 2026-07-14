package policy

import (
	"fmt"
	"sort"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	cedarschema "github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/types"
)

// ValidationResult reports the outcome of Bundle.Validate.
type ValidationResult struct {
	// UnknownActions lists action entity UIDs referenced by policies but absent
	// from the schema's action declarations. Non-empty is a warning, not a hard
	// error: the caller decides whether to reject the bundle.
	UnknownActions []string
}

// Valid reports whether the bundle passed validation with no warnings.
func (r *ValidationResult) Valid() bool { return len(r.UnknownActions) == 0 }

// Validate validates the bundle's schema and all Cedar policies for syntactic
// correctness, and cross-references action UIDs in policy scopes against the
// schema's action declarations. It returns ErrInvalidSchema if the schema
// cannot be parsed, ErrInvalidPolicy if any policy cannot be parsed, or a nil
// error with a ValidationResult whose UnknownActions field lists any action
// UIDs present in policies but absent from the schema.
func (b *Bundle) Validate() (*ValidationResult, error) {
	if b == nil {
		return nil, ErrMissingBundle
	}

	var sch cedarschema.Schema
	if err := sch.UnmarshalCedar(b.Schema); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSchema, err)
	}
	resolved, err := sch.Resolve()
	if err != nil {
		return nil, fmt.Errorf("%w: resolve: %v", ErrInvalidSchema, err)
	}

	known := make(map[types.EntityUID]struct{}, len(resolved.Actions))
	for uid := range resolved.Actions {
		known[uid] = struct{}{}
	}

	unknownSet := make(map[types.EntityUID]struct{})
	for id, content := range b.Policies {
		ps, err := cedar.NewPolicySetFromBytes(id, content)
		if err != nil {
			return nil, fmt.Errorf("%w: policy %q: %v", ErrInvalidPolicy, id, err)
		}
		for _, p := range ps.All() {
			collectUnknownActions(p.AST().Action, known, unknownSet)
		}
	}

	var result ValidationResult
	for uid := range unknownSet {
		result.UnknownActions = append(result.UnknownActions, uid.String())
	}
	sort.Strings(result.UnknownActions)

	return &result, nil
}

// collectUnknownActions inspects the action scope of a policy and adds any
// action UIDs that are not in known to unknown.
func collectUnknownActions(scope ast.IsActionScopeNode, known, unknown map[types.EntityUID]struct{}) {
	switch s := scope.(type) {
	case ast.ScopeTypeEq:
		if _, ok := known[s.Entity]; !ok {
			unknown[s.Entity] = struct{}{}
		}
	case ast.ScopeTypeIn:
		if _, ok := known[s.Entity]; !ok {
			unknown[s.Entity] = struct{}{}
		}
	case ast.ScopeTypeInSet:
		for _, e := range s.Entities {
			if _, ok := known[e]; !ok {
				unknown[e] = struct{}{}
			}
		}
	// ScopeTypeAll (action wildcard) has no specific UID to check.
	}
}
