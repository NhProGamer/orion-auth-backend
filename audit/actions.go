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
	ActionFederationLoginSucceeded  = "federation.login_succeeded"
	ActionFederationLoginFailed     = "federation.login_failed"
	ActionFederationAccountLinked   = "federation.account_linked"
	ActionFederationAccountUnlinked = "federation.account_unlinked"
	ActionFederationUserProvisioned = "federation.user_provisioned"
	ActionFederationLinkConfirmFail = "federation.link_confirm_failed"
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

// M2M actions (changes performed by services on users via /api/v1/m2m/users/*).
// The audit log always carries the caller `client_id` in ClientID, and the
// affected user in metadata.target_user_id.
const (
	ActionM2MUserCreated        = "m2m.user.created"
	ActionM2MUserUpdated        = "m2m.user.updated"
	ActionM2MUserDeleted        = "m2m.user.deleted"
	ActionM2MUserPasswordSet    = "m2m.user.password_set"
	ActionM2MUserUnlocked       = "m2m.user.unlocked"
	ActionM2MUserMFAReset       = "m2m.user.mfa_reset"
	ActionM2MUserRoleAssigned   = "m2m.user.role_assigned"
	ActionM2MUserRoleRemoved    = "m2m.user.role_removed"
	ActionM2MUserSessionRevoked = "m2m.user.session_revoked"
	ActionM2MUserPasskeyRemoved = "m2m.user.passkey_removed"
	ActionM2MUserLinkRemoved    = "m2m.user.linked_account_removed"
)

// Account self-service actions (user-initiated changes on their own account).
const (
	ActionAccountProfileUpdated         = "account.profile_updated"
	ActionAccountEmailChangeRequested   = "account.email_change_requested"
	ActionAccountEmailChanged           = "account.email_changed"
	ActionAccountPasswordChanged        = "account.password_changed"
	ActionAccountMFADisabled            = "account.mfa_disabled"
	ActionAccountMFABackupCodesReissued = "account.mfa_backup_codes_regenerated"
	ActionAccountPasskeyAdded           = "account.passkey_added"
	ActionAccountPasskeyRenamed         = "account.passkey_renamed"
	ActionAccountPasskeyRemoved         = "account.passkey_removed"
	ActionAccountLinkedAccountRemoved   = "account.linked_account_removed"
	ActionAccountDeletionRequested      = "account.deletion_requested"
	ActionAccountDeletionCancelled      = "account.deletion_cancelled"
	ActionAccountDeleted                = "account.deleted"
	ActionAccountReauthIssued           = "account.reauth_issued"
	ActionAccountReauthFailed           = "account.reauth_failed"
)
