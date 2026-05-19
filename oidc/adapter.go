package oidc

import (
	"orion-auth-backend/oauth"
)

// IDTokenAdapter adapts oidc.Service to the oauth.IDTokenGenerator interface.
type IDTokenAdapter struct {
	service *Service
}

func NewIDTokenAdapter(service *Service) *IDTokenAdapter {
	return &IDTokenAdapter{service: service}
}

func (a *IDTokenAdapter) GenerateIDToken(claims oauth.IDTokenClaims) (string, error) {
	return a.service.GenerateIDToken(IDTokenClaims{
		UserID:            claims.UserID,
		ClientID:          claims.ClientID,
		Scopes:            claims.Scopes,
		Nonce:             claims.Nonce,
		AuthTime:          claims.AuthTime,
		ATHash:            claims.ATHash,
		CHash:             claims.CHash,
		SHash:             claims.SHash,
		TTL:               claims.TTL,
		RequestedClaims:   claims.RequestedClaims,
		ACR:               claims.ACR,
		AMR:               claims.AMR,
		SubjectType:       claims.SubjectType,
		SectorIdentifier:  claims.SectorIdentifier,
		ExtraClaims:       claims.ExtraClaims,
		EncryptionJWKSURI: claims.EncryptionJWKSURI,
		EncryptionAlg:     claims.EncryptionAlg,
		EncryptionEnc:     claims.EncryptionEnc,
	})
}

// AccessTokenJWTSignerAdapter satisfies oauth.AccessTokenJWTSigner.
type AccessTokenJWTSignerAdapter struct {
	service *Service
}

func NewAccessTokenJWTSignerAdapter(service *Service) *AccessTokenJWTSignerAdapter {
	return &AccessTokenJWTSignerAdapter{service: service}
}

func (a *AccessTokenJWTSignerAdapter) GenerateAccessTokenJWT(claims oauth.AccessTokenJWTClaims, signingAlg string) (string, string, error) {
	return a.service.GenerateAccessTokenJWT(AccessTokenClaims{
		UserID:      claims.UserID,
		ClientID:    claims.ClientID,
		Scopes:      claims.Scopes,
		Audience:    claims.Audience,
		TTL:         claims.TTL,
		ExtraClaims: claims.ExtraClaims,
	}, signingAlg)
}

func (a *AccessTokenJWTSignerAdapter) ValidateAccessTokenJWT(tokenString string) (map[string]any, error) {
	claims, err := a.service.ValidateAccessTokenJWT(tokenString)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(claims))
	for k, v := range claims {
		out[k] = v
	}
	return out, nil
}
