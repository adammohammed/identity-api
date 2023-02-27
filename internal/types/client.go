package types

// OAuthClient is an OAuth 2.0 Client
type OAuthClient struct {
	ID       string
	TenantID string
	Name     string
	Secret   string
	Audience []string
	Scope    string
}
