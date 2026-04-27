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
		UserID:           claims.UserID,
		ClientID:         claims.ClientID,
		Scopes:           claims.Scopes,
		Nonce:            claims.Nonce,
		AuthTime:         claims.AuthTime,
		ATHash:           claims.ATHash,
		CHash:            claims.CHash,
		SHash:            claims.SHash,
		TTL:              claims.TTL,
		RequestedClaims:  claims.RequestedClaims,
		ACR:              claims.ACR,
		AMR:              claims.AMR,
		SubjectType:      claims.SubjectType,
		SectorIdentifier: claims.SectorIdentifier,
		ExtraClaims:      claims.ExtraClaims,
	})
}
