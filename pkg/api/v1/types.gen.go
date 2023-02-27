// Package v1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.5-0.20230118012357-f4cf8f9a5703 DO NOT EDIT.
package v1

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	openapi_types "github.com/deepmap/oapi-codegen/pkg/types"
	"github.com/getkin/kin-openapi/openapi3"
)

// CreateIssuer defines model for CreateIssuer.
type CreateIssuer struct {
	// ClaimMappings CEL expressions mapping token claims to other claims
	ClaimMappings *map[string]string `json:"claim_mappings,omitempty"`

	// JwksUri JWKS URI
	JWKSURI string `json:"jwks_uri"`

	// Name A human-readable name for the issuer
	Name string `json:"name"`

	// Uri URI for the issuer. Must match the "iss" claim value in incoming JWTs
	URI string `json:"uri"`
}

// CreateOAuthClient defines model for CreateOAuthClient.
type CreateOAuthClient struct {
	// Name A human-readable name for the client
	Name string `json:"name"`
}

// DeleteResponse defines model for DeleteResponse.
type DeleteResponse struct {
	// Success Always true.
	Success bool `json:"success"`
}

// Issuer defines model for Issuer.
type Issuer struct {
	// ClaimMappings CEL expressions mapping token claims to other claims
	ClaimMappings map[string]string `json:"claim_mappings"`

	// Id ID of the issuer
	ID openapi_types.UUID `json:"id"`

	// JwksUri JWKS URI
	JWKSURI string `json:"jwks_uri"`

	// Name A human-readable name for the issuer
	Name string `json:"name"`

	// Uri URI for the issuer.
	// Must match the "iss" claim value in incoming JWTs
	URI string `json:"uri"`
}

// IssuerUpdate defines model for IssuerUpdate.
type IssuerUpdate struct {
	// ClaimMappings CEL expressions mapping token claims to other claims
	ClaimMappings *map[string]string `json:"claim_mappings,omitempty"`

	// JwksUri JWKS URI
	JWKSURI *string `json:"jwks_uri,omitempty"`

	// Name A human-readable name for the issuer
	Name *string `json:"name,omitempty"`

	// Uri URI for the issuer.
	// Must match the "iss" claim value in incoming JWTs
	URI *string `json:"uri,omitempty"`
}

// OAuthClient defines model for OAuthClient.
type OAuthClient struct {
	// Audience Grantable audiences
	Audience []string `json:"audience"`

	// Id OAuth 2.0 Client ID
	ID openapi_types.UUID `json:"id"`

	// Name Description of Client
	Name string `json:"name"`

	// Scope Grantable scopes
	Scope string `json:"scope"`

	// Secret OAuth2.0 Client Secret
	Secret string `json:"secret"`
}

// UpdateIssuerJSONRequestBody defines body for UpdateIssuer for application/json ContentType.
type UpdateIssuerJSONRequestBody = IssuerUpdate

// CreateOAuthClientJSONRequestBody defines body for CreateOAuthClient for application/json ContentType.
type CreateOAuthClientJSONRequestBody = CreateOAuthClient

// CreateIssuerJSONRequestBody defines body for CreateIssuer for application/json ContentType.
type CreateIssuerJSONRequestBody = CreateIssuer

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/+xYXW/bNhT9KwS3hw1Qbbd981saD4G6FSviBH1IgoKmri2mEsnyw6lh6L8Pl5Ri2ZKd",
	"xtuKutsbTZGX955z7ge8plyVWkmQztLxmlqeQ8nC8twAc5Ba68Hgb22UBuMEhK+8YKL8WDKthVyEHZZl",
	"wgklWfF+66RbaaBjap0RckGrhGZguREaz9IxPf/tDwJftAFrhZKW1CaJU59AkvCMJU4R5XIw9W+aNFbV",
	"7B64Q6v3D5/sR28EPrn9wtsPv0/J9WW6uVX7ktAvLxbqhWQl1MfwVJXQuLNr54zkvmTyhQGWsVkBBI+R",
	"uTLE5UBEBCrpxtvr1PVlunN1QN5560jJHM/D9i0V1t7SGDNZssIDEZIIyVWJCL39cGWfiCnEUyXUwGcv",
	"DGR0fBODi161ULurkprxP8+8y88LAdJ1aT8GGR5tdZDp8wvdmEABDi7BaiUtdH2wnnOwtseN4oGtLHHG",
	"w2Dz3EypApjsvNeYwSdPRuUi64adToiab2twrkzJHB1T70X2hEbSyY+RPrfy2+RPALQ/iZJdwWy0da0z",
	"5uD/OnrSQqgSerA6Mp8JkLwn5gvDpAvBNmfwReGg7Oe23mDGsNW+vA+ukFeDEYn+kHRyVOr3szTZ/MLy",
	"cr6niCfUcqUPRhwO2N6rwA24PZG1ApvGc091kHZm2ubKIyeNp3eBRyHnqvvwFLg3wq3IVciaKZil4EB+",
	"mV5NfyXvmGQLKNGhs/cpEZYwGVaoP1LiV1TT9GpKuJJzsfCGoV0bmpFwBex/Yds2TegSjI0+jQajwUtE",
	"S2mQTAs6pq8Ho8FrmlDNXB70M2RaDJcvh7HV2uE6LtJJFWPEhoorFGvwKc0CxbjfVjSaNKwEB8bS8U2/",
	"4nhLbQK30Y0G+TFtnqZtcrAnJ/V0iY4cVmlV3eHlOACEAF+NRqFaKunqzGNaF4KHYIb3Ft1bt+z/bGBO",
	"x/Sn4Wa8Hdaz7XBnvghy2JFBHA3mviCtYwm1viyZWTXQBQFsw+cYFvGbdpmIXWARdb5NwAW4/xz67YCP",
	"gv4Cgcf0xRiwOrGZ8u6RilZBHOwnpEoecyZ2DTtci+wrsiVt2tNBquJIFi1j061t9jIWGPgBMsUcyBQI",
	"qVLj8SBc7MsLsQRJ0kmbp4jv4ZyJZ96sgsqfxcMitITTIqFW3FHgX9RFqkZgtjqAtsZ5qYt3HFyPk72P",
	"Q++/hvhnD9a9UdnqHwa7Htar7QEDXay+U6Kjxy2u+1lulT0HkoVRIS7SSdVMD2GuVbYn97p/EDynZdlc",
	"+SIjMyAz5WWGAnG5sKRxoF8nra/fnVq6eHxjyfztZhojCLpRbMPV13XOHgnVzfQpCT2nnETjqBYe7jb1",
	"RchTFUw70U+jvLRkcrC8VNVfAQAA//+ldyAwURYAAA==",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
