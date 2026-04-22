package audit

// User actions
const (
	ActionUserRegistered  = "user.registered"
	ActionUserLogin       = "user.login"
	ActionUserLoginFailed = "user.login_failed"
	ActionUserUpdated     = "user.updated"
	ActionUserDeleted     = "user.deleted"
	ActionPasswordChanged = "user.password_changed"
	ActionPasswordReset   = "user.password_reset"
	ActionEmailVerified   = "user.email_verified"
)

// Session actions
const (
	ActionSessionRevoked     = "session.revoked"
	ActionSessionsRevokedAll = "session.revoked_all"
)

// OAuth client actions
const (
	ActionClientCreated       = "client.created"
	ActionClientUpdated       = "client.updated"
	ActionClientDeleted       = "client.deleted"
	ActionClientSecretRotated = "client.secret_rotated"
)

// OAuth flow actions
const (
	ActionOAuthConsentGranted = "oauth.consent_granted"
	ActionTokenRevoked        = "oauth.token_revoked"
)

// RBAC actions
const (
	ActionRoleCreated            = "role.created"
	ActionRoleUpdated            = "role.updated"
	ActionRoleDeleted            = "role.deleted"
	ActionRolePermissionsUpdated = "role.permissions_updated"
	ActionRoleAssigned           = "role.assigned"
	ActionRoleRemoved            = "role.removed"
)

// MFA actions
const (
	ActionMFAEnrolled = "mfa.enrolled"
	ActionMFADisabled = "mfa.disabled"
)

// Invitation actions
const (
	ActionInvitationCreated = "invitation.created"
	ActionSettingsUpdated   = "settings.updated"
)

// Federation actions
const (
	ActionFederationProviderCreated = "federation.provider_created"
	ActionFederationProviderUpdated = "federation.provider_updated"
	ActionFederationProviderDeleted = "federation.provider_deleted"
)

// Resource actions
const (
	ActionResourceCreated           = "resource.created"
	ActionResourceUpdated           = "resource.updated"
	ActionResourceDeleted           = "resource.deleted"
	ActionResourcePermissionAdded   = "resource.permission_added"
	ActionResourcePermissionRemoved = "resource.permission_removed"
	ActionClientPermissionsUpdated  = "resource.client_permissions_updated"
)

// Policy actions
const (
	ActionPolicyCreated = "policy.created"
	ActionPolicyUpdated = "policy.updated"
	ActionPolicyDeleted = "policy.deleted"
	ActionPolicyDenied  = "policy.denied"
)
