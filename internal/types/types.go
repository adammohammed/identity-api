// Package types defines all non-http types used in the STS.
package types

import (
	"context"
	"errors"
)

// UserInfo stores information about the user based on issuer/subject
// pairs.
type UserInfo struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
}

// ErrUserInfoNotFound is returned if we attempt to fetch user info
// from the storage backend and no info exists for that user
var ErrUserInfoNotFound = errors.New("user info does not exist")

// ErrFetchUserInfo occurs when we fail to successfully hit the user
// info endpoint for a subject token.
var ErrFetchUserInfo = errors.New("could not fetch user info")

// UserInfoService defines the storage class for storing User
// information related to the subject tokens.
type UserInfoService interface {
	// LookupByClaims returns the User information object for a issuer, subject pair.
	LookupByClaims(ctx context.Context, iss, sub string) (*UserInfo, error)

	// StoreUserInfo stores the userInfo into the storage backend.
	StoreUserInfo(ctx context.Context, userInfo UserInfo) error

	// FetchUserInfoFromIssuer uses the rawToken to make a userinfo endpoint request
	// and unpacks it into the UserInfo type.
	FetchUserInfoFromIssuer(ctx context.Context, iss, rawToken string) (*UserInfo, error)
}
