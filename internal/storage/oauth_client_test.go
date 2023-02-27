package storage

import "go.infratographer.com/identity-api/internal/types"

var _ types.OAuthClientStore = &oauthClientStore{}
