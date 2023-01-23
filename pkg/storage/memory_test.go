package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/cockroachdb/cockroach-go/v2/testserver"
	"github.com/stretchr/testify/assert"

	"go.infratographer.com/identity-manager-sts/internal/types"
	v1 "go.infratographer.com/identity-manager-sts/pkg/api/v1"
)

func TestMemoryIssuerService(t *testing.T) {
	db, _ := testserver.NewDBForTest(t)
	t.Parallel()

	type testResult struct {
		iss *v1.Issuer
		err error
	}

	type testCase struct {
		name    string
		input   string
		checkFn func(*testing.T, testResult)
	}

	issuer := v1.Issuer{
		ID:            "e495a393-ae79-4a02-a78d-9798c7d9d252",
		Name:          "Example",
		URI:           "https://example.com/",
		JWKSURI:       "https://example.com/.well-known/jwks.json",
		ClaimMappings: v1.ClaimsMapping{},
	}

	testCases := []testCase{
		{
			name:  "NotFound",
			input: "https://evil.biz/",
			checkFn: func(t *testing.T, res testResult) {
				expErr := v1.ErrorIssuerNotFound{
					URI: "https://evil.biz/",
				}

				assert.ErrorIs(t, expErr, res.err)
			},
		},
		{
			name:  "Success",
			input: "https://example.com/",
			checkFn: func(t *testing.T, res testResult) {
				assert.Nil(t, res.err)
				assert.Equal(t, &issuer, res.iss)
			},
		},
	}

	config := Config{
		db: db,
		SeedData: SeedData{
			Issuers: []SeedIssuer{
				{
					ID:      issuer.ID,
					Name:    issuer.Name,
					URI:     issuer.URI,
					JWKSURI: issuer.JWKSURI,
				},
			},
		},
	}

	issSvc, err := newMemoryIssuerService(config)
	assert.Nil(t, err)

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			iss, err := issSvc.GetByURI(context.Background(), testCase.input)

			result := testResult{
				iss: iss,
				err: err,
			}

			testCase.checkFn(t, result)
		})
	}
}

func TestUserInfoStore(t *testing.T) {
	t.Parallel()

	db, _ := testserver.NewDBForTest(t)

	tr := &recordingTransport{}
	httpClient := &http.Client{
		Transport: tr,
	}

	issuer := v1.Issuer{
		ID:            "e495a393-ae79-4a02-a78d-9798c7d9d252",
		Name:          "Example",
		URI:           "https://example.com/",
		JWKSURI:       "https://example.com/.well-known/jwks.json",
		ClaimMappings: v1.ClaimsMapping{},
	}

	config := Config{
		db: db,
		SeedData: SeedData{
			Issuers: []SeedIssuer{
				{
					ID:      issuer.ID,
					Name:    issuer.Name,
					URI:     issuer.URI,
					JWKSURI: issuer.JWKSURI,
				},
			},
		},
	}

	_, err := newMemoryIssuerService(config)
	assert.Nil(t, err)

	svc, err := newUserInfoService(config, WithHTTPClient(httpClient))
	assert.NoError(t, err)

	ctx := context.Background()
	user := types.UserInfo{
		Name:    "Maliketh",
		Email:   "mal@iketh.co",
		Issuer:  issuer.URI,
		Subject: "sub0|malikadmin",
	}

	tests := map[string]func(t *testing.T){
		"LoadUserAfterStore": func(t *testing.T) {
			err := svc.StoreUserInfo(ctx, user)
			assert.NoError(t, err)
			out, err := svc.LookupByClaims(ctx, user.Issuer, user.Subject)
			assert.NoError(t, err)
			assert.Equal(t, user, *out)
		},
		"LoadUserFails": func(t *testing.T) {
			_, err := svc.LookupByClaims(ctx, "", user.Subject)
			assert.ErrorIs(t, err, types.ErrUserInfoNotFound)
		},
		"FetchUserInfoFromIssuer": func(t *testing.T) {
			_, err := svc.FetchUserInfoFromIssuer(ctx, "https://someidp.com", "supersecrettoken")
			assert.ErrorIs(t, err, errFakeHTTP)

			assert.Equal(t, "https://someidp.com/userinfo", tr.req.URL.String())
			assert.Equal(t, "Bearer supersecrettoken", tr.req.Header.Get("authorization"))
			assert.Equal(t, http.MethodGet, tr.req.Method)
		},

		"FetchUserInfoBadIssuer": func(t *testing.T) {
			_, err = svc.FetchUserInfoFromIssuer(ctx, "://", "supersecrettoken")
			assert.ErrorContains(t, err, "missing protocol scheme")
		},
		"FetchUserInfoWithResponse": func(t *testing.T) {
			jsonBody := `{"name": "adam", "email": "ad@am.com", "sub": "super-admin", "iss": "https://woo.com"}`
			ft := &fakeTransport{
				body: jsonBody,
			}
			// copy this struct so we can override the transport
			// without affecting other tests in parallel
			msvc := &memoryUserInfoService{
				db:         svc.db,
				httpClient: &http.Client{Transport: ft},
			}

			info, err := msvc.FetchUserInfoFromIssuer(ctx, "https://someidp.com", "rawSecrets")
			assert.NoError(t, err)
			expected := types.UserInfo{
				Name:    "adam",
				Email:   "ad@am.com",
				Subject: "super-admin",
				Issuer:  "https://woo.com",
			}

			assert.Equal(t, expected, *info)
		},
	}

	for name, testCase := range tests {
		tcase := testCase

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tcase(t)
		})
	}
}

type recordingTransport struct {
	req *http.Request
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.req = req
	// Just error out to prevent making the network call, but we
	// can ensure the request is built properly
	return nil, errFakeHTTP
}

type fakeTransport struct {
	req  *http.Request
	body string
}

func (ft *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ft.req = req
	resp := http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
	}

	r := io.NopCloser(bytes.NewReader([]byte(ft.body)))
	resp.Body = r

	return &resp, nil
}

var errFakeHTTP = errors.New("error to stop http client from making a network call")
