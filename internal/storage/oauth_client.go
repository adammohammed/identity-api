package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/ory/fosite"
	"go.infratographer.com/identity-api/internal/types"
)

var oauthClientCols = struct {
	ID       string
	TenantID string
	Name     string
	Secret   string
	Audience string
	Scope    string
}{
	ID:       "id",
	TenantID: "tenant_id",
	Name:     "name",
	Secret:   "secret",
	Audience: "audience",
	Scope:    "scope",
}

var (
	oauthClientColumns = []string{
		oauthClientCols.TenantID,
		oauthClientCols.Name,
		oauthClientCols.Secret,
		oauthClientCols.Audience,
		oauthClientCols.Scope,
	}
	oauthClientColumnsStr = strings.Join(oauthClientColumns, ", ")
)

type oauthClientStore struct {
	db     *sql.DB
	hasher fosite.Hasher
}

func newOAuthClientStore(config Config, db *sql.DB) (*oauthClientStore, error) {
	return &oauthClientStore{
		db: db,
		hasher: &fosite.BCrypt{
			Config: &fosite.Config{
				HashCost: fosite.DefaultBCryptWorkFactor,
			},
		},
	}, nil
}

// CreateOAuthClient implements types.OAuthClientStore
func (s *oauthClientStore) CreateOAuthClient(ctx context.Context, client types.OAuthClient) (types.OAuthClient, error) {
	var emptyModel types.OAuthClient
	tx, err := getContextTx(ctx)
	if err != nil {
		return emptyModel, err
	}

	q := `
        INSERT INTO oauth_clients (
           %s
        ) VALUES
        ($1, $2, $3, $4, $5) RETURNING id;
       `
	q = fmt.Sprintf(q, oauthClientColumnsStr)

	hashedSecret, err := s.hasher.Hash(ctx, []byte(client.Secret))
	if err != nil {
		return emptyModel, err
	}

	client.Secret = string(hashedSecret)

	row := tx.QueryRowContext(
		ctx,
		q,
		client.TenantID,
		client.Name,
		client.Secret,
		strings.Join(client.Audience, " "),
		client.Scope,
	)

	err = row.Scan(&client.ID)
	if err != nil {
		return emptyModel, err
	}

	return client, nil
}

// DeleteOAuthClient implements types.OAuthClientStore
func (*oauthClientStore) DeleteOAuthClient(ctx context.Context, clientID string) error {
	tx, err := getContextTx(ctx)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM oauth_clients WHERE id = $1;`, clientID)

	return err
}

// LookupOAuthClientByID implements types.OAuthClientStore
func (s *oauthClientStore) LookupOAuthClientByID(ctx context.Context, clientID string) (*types.OAuthClient, error) {
	q := fmt.Sprintf(`SELECT %s FROM oauth_clients WHERE id = $1`, oauthClientColumnsStr)

	var row *sql.Row

	tx, err := getContextTx(ctx)

	switch err {
	case nil:
		row = tx.QueryRowContext(ctx, q, clientID)
	case ErrorMissingContextTx:
		row = s.db.QueryRowContext(ctx, q, clientID)
	default:
		return nil, err
	}

	var model types.OAuthClient
	var aud string
	err = row.Scan(
		&model.TenantID,
		&model.Name,
		&model.Secret,
		&aud,
		&model.Scope,
	)

	switch err {
	case nil:
	case sql.ErrNoRows:
		return nil, types.ErrOAuthClientNotFound
	default:
		return nil, err
	}

	model.ID = clientID
	model.Audience = strings.Fields(aud)

	return &model, nil
}
