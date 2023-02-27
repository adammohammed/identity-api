package types

import (
	"github.com/google/uuid"
	v1 "go.infratographer.com/identity-api/pkg/api/v1"
)

// OAuthClient is an OAuth 2.0 Client
type OAuthClient struct {
	ID       string
	TenantID string
	Name     string
	Secret   string
	Audience []string
	Scope    string
}

func (c OAuthClient) ToV1OAuthClient() (v1.OAuthClient, error) {
	var client v1.OAuthClient

	client.ID = uuid.MustParse(c.ID)
	client.Name = c.Name
	client.Secret = c.Secret
	client.Audience = c.Audience
	client.Scope = c.Scope

	return client, nil
}
