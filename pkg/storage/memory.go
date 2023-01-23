package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cockroachdb/cockroach-go/v2/testserver"

	"go.infratographer.com/identity-manager-sts/internal/types"
	v1 "go.infratographer.com/identity-manager-sts/pkg/api/v1"
)

type memoryEngine struct {
	*memoryIssuerService
	crdb testserver.TestServer
}

func (eng *memoryEngine) Shutdown() {
	eng.crdb.Stop()
}

func buildIssuerFromSeed(seed SeedIssuer) (v1.Issuer, error) {
	claimMappings, err := v1.BuildClaimsMappingFromMap(seed.ClaimMappings)
	if err != nil {
		return v1.Issuer{}, err
	}

	out := v1.Issuer{
		ID:            seed.ID,
		Name:          seed.Name,
		URI:           seed.URI,
		JWKSURI:       seed.JWKSURI,
		ClaimMappings: claimMappings,
	}

	return out, nil
}

// memoryIssuerService represents an in-memory issuer service.
type memoryIssuerService struct {
	db *sql.DB
}

// newMemoryEngine creates a new in-memory storage engine.
func newMemoryIssuerService(config Config) (*memoryIssuerService, error) {
	svc := &memoryIssuerService{db: config.db}

	err := svc.createTables()
	if err != nil {
		return nil, err
	}

	for _, seed := range config.SeedData.Issuers {
		iss, err := buildIssuerFromSeed(seed)
		if err != nil {
			return nil, err
		}

		err = svc.insertIssuer(iss)
		if err != nil {
			return nil, err
		}
	}

	return svc, nil
}

// GetByURI looks up the given issuer by URI, returning the issuer if one exists.
func (s *memoryIssuerService) GetByURI(ctx context.Context, uri string) (*v1.Issuer, error) {
	row := s.db.QueryRow(`SELECT id, name, uri, jwksuri, mappings FROM issuers WHERE uri = $1;`, uri)

	var iss v1.Issuer

	var mapping string

	err := row.Scan(&iss.ID, &iss.Name, &iss.URI, &iss.JWKSURI, &mapping)

	if errors.Is(err, sql.ErrNoRows) {
		err := v1.ErrorIssuerNotFound{
			URI: uri,
		}

		return nil, err
	} else if err != nil {
		return nil, err
	}

	c := v1.ClaimsMapping{}

	err = c.UnmarshalJSON([]byte(mapping))
	if err != nil {
		return nil, err
	}

	iss.ClaimMappings = c

	return &iss, nil
}

func (s *memoryIssuerService) createTables() error {
	stmt := `
        CREATE TABLE IF NOT EXISTS issuers (
            id       uuid PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
            uri      STRING NOT NULL,
            name     STRING NOT NULL,
            jwksuri  STRING NOT NULL,
            mappings STRING,
            UNIQUE (uri)
        );
        `
	_, err := s.db.Exec(stmt)

	return err
}

func (s *memoryIssuerService) insertIssuer(iss v1.Issuer) error {
	q := `
        INSERT INTO issuers (
            id, name, uri, jwksuri, mappings
        ) VALUES
        ($1, $2, $3, $4, $5);
        `

	mappings, err := iss.ClaimMappings.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		q,
		iss.ID,
		iss.Name,
		iss.URI,
		iss.JWKSURI,
		string(mappings),
	)

	return err
}

func inMemoryCRDB() (testserver.TestServer, error) {
	ts, err := testserver.NewTestServer()
	if err != nil {
		return nil, err
	}

	if err := ts.Start(); err != nil {
		return nil, err
	}

	return ts, nil
}

type memoryUserInfoService struct {
	db         *sql.DB
	httpClient *http.Client
}

type userInfoServiceOpt func(*memoryUserInfoService)

func newUserInfoService(config Config, opts ...userInfoServiceOpt) (*memoryUserInfoService, error) {
	s := &memoryUserInfoService{
		db:         config.db,
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(s)
	}

	err := s.createTables()

	return s, err
}

// WithHTTPClient allows configuring the HTTP client used by
// memoryUserInfoService to call out to userinfo endpoints.
func WithHTTPClient(client *http.Client) func(svc *memoryUserInfoService) {
	return func(svc *memoryUserInfoService) {
		svc.httpClient = client
	}
}

func (s *memoryUserInfoService) createTables() error {
	_, err := s.db.Exec(`
        CREATE TABLE IF NOT EXISTS user_info (
            id    UUID PRIMARY KEY NOT NULL DEFAULT gen_random_uuid(),
            name  STRING,
            email STRING,
            sub   STRING NOT NULL,
            iss_id   UUID NOT NULL REFERENCES issuers(id),
            UNIQUE (iss_id, sub)
        )`)

	return err
}

// LookupByClaims fetches UserInfo from the store.
// This does not make an HTTP call with the subject token, so for this
// data to be available, the data must have already be fetched and
// stored.
func (s memoryUserInfoService) LookupByClaims(ctx context.Context, iss, sub string) (*types.UserInfo, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT ui.name, ui.email, ui.sub, i.uri FROM user_info ui
        JOIN issuers i ON
           ui.iss_id = i.id
        WHERE
           i.uri = $1 AND ui.sub = $2
        `, iss, sub)

	var ui types.UserInfo

	err := row.Scan(&ui.Name, &ui.Email, &ui.Subject, &ui.Issuer)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, types.ErrUserInfoNotFound
	}

	return &ui, err
}

// StoreUserInfo is used to store user information by issuer and
// subject pairs. UserInfo is unique to issuer/subject pairs.
func (s memoryUserInfoService) StoreUserInfo(ctx context.Context, userInfo types.UserInfo) error {
	row := s.db.QueryRowContext(ctx, `
        SELECT id FROM issuers WHERE uri = $1
        `, userInfo.Issuer)

	var issuerID string

	err := row.Scan(&issuerID)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
        INSERT INTO user_info (name, email, sub, iss_id) VALUES (
            $1, $2, $3, $4
	)`, userInfo.Name, userInfo.Email, userInfo.Subject, issuerID)

	return err
}

// FetchUserInfoFromIssuer uses the subject access token to retrieve
// information from the OIDC /userinfo endpoint.
func (s memoryUserInfoService) FetchUserInfoFromIssuer(ctx context.Context, iss, rawToken string) (*types.UserInfo, error) {
	endpoint, err := url.JoinPath(iss, "userinfo")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", rawToken))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"unexpected response code %d from request: %w",
			resp.StatusCode,
			types.ErrFetchUserInfo,
		)
	}

	var ui types.UserInfo

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&ui)
	if err != nil {
		return nil, err
	}

	return &ui, nil
}
