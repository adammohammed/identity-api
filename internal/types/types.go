// Package types defines all non-http types used in the STS.
package types

import (
	"context"
	"encoding/json"

	"github.com/google/cel-go/cel"
	"github.com/google/uuid"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/prototext"

	"go.infratographer.com/identity-api/internal/celutils"
	v1 "go.infratographer.com/identity-api/pkg/api/v1"
)

// Issuer represents a token issuer.
type Issuer struct {
	// TenantID represents the ID of the tenant the issuer belongs to.
	TenantID string
	// ID represents the ID of the issuer in identity-api.
	ID string
	// Name represents the human-readable name of the issuer.
	Name string
	// URI represents the issuer URI as found in the "iss" claim of a JWT.
	URI string
	// JWKSURI represents the URI where the issuer's JWKS lives. Must be accessible by identity-api.
	JWKSURI string
	// ClaimMappings represents a map of claims to a CEL expression that will be evaluated
	ClaimMappings ClaimsMapping
}

// ToV1Issuer converts an issuer to an API issuer.
func (i Issuer) ToV1Issuer() (v1.Issuer, error) {
	claimsMappingRepr, err := i.ClaimMappings.Repr()
	if err != nil {
		return v1.Issuer{}, err
	}

	out := v1.Issuer{
		ID:            uuid.MustParse(i.ID),
		Name:          i.Name,
		URI:           i.URI,
		JWKSURI:       i.JWKSURI,
		ClaimMappings: claimsMappingRepr,
	}

	return out, nil
}

// IssuerUpdate represents an update operation on an issuer.
type IssuerUpdate struct {
	Name          *string
	URI           *string
	JWKSURI       *string
	ClaimMappings ClaimsMapping
}

// IssuerService represents a service for managing issuers.
type IssuerService interface {
	CreateIssuer(ctx context.Context, iss Issuer) (*Issuer, error)
	GetIssuerByID(ctx context.Context, id string) (*Issuer, error)
	GetIssuerByURI(ctx context.Context, uri string) (*Issuer, error)
	UpdateIssuer(ctx context.Context, id string, update IssuerUpdate) (*Issuer, error)
	DeleteIssuer(ctx context.Context, id string) error
}

// ClaimsMapping represents a map of claims to a CEL expression that will be evaluated
type ClaimsMapping map[string]*cel.Ast

// NewClaimsMapping creates a ClaimsMapping from the given map of CEL expressions.
func NewClaimsMapping(exprs map[string]string) (ClaimsMapping, error) {
	out := make(ClaimsMapping, len(exprs))

	for k, v := range exprs {
		ast, err := celutils.ParseCEL(v)
		if err != nil {
			return nil, err
		}

		out[k] = ast
	}

	return out, nil
}

// Repr produces a representation of the claim map using human-readable CEL expressions.
func (c ClaimsMapping) Repr() (map[string]string, error) {
	out := make(map[string]string, len(c))

	for k, v := range c {
		var err error

		out[k], err = cel.AstToString(v)
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

// MarshalJSON implements the json.Marshaler interface.
func (c ClaimsMapping) MarshalJSON() ([]byte, error) {
	out := make(map[string][]byte, len(c))

	for k, v := range c {
		expr, err := cel.AstToCheckedExpr(v)
		if err != nil {
			return nil, err
		}

		b, err := prototext.Marshal(expr)
		if err != nil {
			return nil, err
		}

		out[k] = b
	}

	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (c *ClaimsMapping) UnmarshalJSON(data []byte) error {
	in := make(map[string][]byte)
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}

	out := make(ClaimsMapping, len(in))

	for k, v := range in {
		var expr exprpb.CheckedExpr

		err := prototext.Unmarshal(v, &expr)
		if err != nil {
			return err
		}

		out[k] = cel.CheckedExprToAst(&expr)
	}

	*c = out

	return nil
}

// BuildClaimsMappingFromMap builds a ClaimsMapping from a map of strings.
func BuildClaimsMappingFromMap(in map[string]*exprpb.CheckedExpr) ClaimsMapping {
	out := make(ClaimsMapping, len(in))

	for k, v := range in {
		out[k] = cel.CheckedExprToAst(v)
	}

	return out
}

// UserInfo contains information about the user from the source OIDC provider.
// As defined in https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type UserInfo struct {
	ID      uuid.UUID `json:"-"`
	Name    string    `json:"name,omitempty"`
	Email   string    `json:"email,omitempty"`
	Issuer  string    `json:"iss"`
	Subject string    `json:"sub"`
}

// UserInfoService defines the storage class for storing User
// information related to the subject tokens.
type UserInfoService interface {
	// LookupUserInfoByClaims returns the User information object for a issuer, subject pair.
	LookupUserInfoByClaims(ctx context.Context, iss, sub string) (*UserInfo, error)

	// LookupUserInfoByID returns the user info for a STS user ID
	LookupUserInfoByID(ctx context.Context, id string) (*UserInfo, error)

	// StoreUserInfo stores the userInfo into the storage backend.
	StoreUserInfo(ctx context.Context, userInfo UserInfo) (*UserInfo, error)

	// FetchUserInfoFromIssuer uses the rawToken to make a userinfo endpoint request
	// and unpacks it into the UserInfo type.
	FetchUserInfoFromIssuer(ctx context.Context, iss, rawToken string) (*UserInfo, error)
}
