package oauth2

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"
	"go.infratographer.com/identity-api/internal/fositex"
	"go.infratographer.com/identity-api/internal/storage"
	"go.infratographer.com/identity-api/internal/types"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
)

var _ fosite.TokenEndpointHandler = &ClientCredentialsGrantHandler{}

type ClientCredentialsConfigurator interface {
	fosite.ScopeStrategyProvider
	fosite.AudienceStrategyProvider
	fosite.AccessTokenLifespanProvider
	fosite.AccessTokenIssuerProvider
	fositex.UserInfoAudienceProvider
	fositex.SigningKeyProvider
}

type ClientCredentialsGrantHandler struct {
	*oauth2.HandleHelper
	types.UserInfoService
	storage.TransactionManager
	Config ClientCredentialsConfigurator
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.4.2
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {

	client := request.GetClient()
	for _, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	request.GrantAudience(c.Config.GetUserInfoAudience(ctx))

	// The client MUST authenticate with the authorization server as described in Section 3.2.1.
	// This requirement is already fulfilled because fosite requires all token requests to be authenticated as described
	// in https://tools.ietf.org/html/rfc6749#section-3.2.1
	if client.IsPublic() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'client_credentials'."))
	}
	// if the client is not public, he has already been authenticated by the access request handler.

	atLifespan := fosite.GetEffectiveLifespan(client, fosite.GrantTypeClientCredentials, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	session := request.GetSession().(*oauth2.JWTSession)

	headers := jwt.Headers{}
	headers.Add("kid", c.Config.GetSigningKey(ctx).KeyID)

	session.JWTClaims = &jwt.JWTClaims{}
	session.JWTClaims.Add("client_id", request.GetClient().GetID())

	session.JWTHeader = &headers
	session.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan))

	dbCtx, err := c.BeginContext(ctx)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithHint("could not start transaction"))
	}

	userInfo := types.UserInfo{
		Issuer:  c.Config.GetAccessTokenIssuer(ctx),
		Subject: request.GetClient().GetID(),
	}

	uiWithId, err := c.StoreUserInfo(dbCtx, userInfo)
	if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithHintf("unable to create user info for client: %v", err))
	}

	if err := c.CommitContext(dbCtx); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithHintf("unable to store userinfo for client: %v", err))
	}

	session.JWTClaims.Subject = fmt.Sprintf("urn:infratographer:user/%s", uiWithId.ID)

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.4.3
func (c *ClientCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeClientCredentials, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	return c.IssueAccessToken(ctx, atLifespan, request, response)
}

func (c *ClientCredentialsGrantHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *ClientCredentialsGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	return requester.GetGrantTypes().ExactOne("client_credentials")
}

func NewClientCredentialsHandlerFactory(config fosite.Configurator, strage any, strategy any) any {
	return &ClientCredentialsGrantHandler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  strage.(oauth2.AccessTokenStorage),
			Config:              config,
		},
		UserInfoService:    strage.(types.UserInfoService),
		TransactionManager: strage.(storage.TransactionManager),
		Config:             config.(ClientCredentialsConfigurator),
	}
}
