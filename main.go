package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"orion-auth-backend/account"
	"orion-auth-backend/audit"
	"orion-auth-backend/m2m"
	"orion-auth-backend/model"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"orion-auth-backend/client"
	"orion-auth-backend/config"
	"orion-auth-backend/crypto"
	"orion-auth-backend/database"
	_ "orion-auth-backend/docs"
	"orion-auth-backend/email"
	emailtemplates "orion-auth-backend/email/templates"
	"orion-auth-backend/federation"
	"orion-auth-backend/invitation"
	"orion-auth-backend/mfa"
	"orion-auth-backend/middleware"
	"orion-auth-backend/oauth"
	"orion-auth-backend/oidc"
	"orion-auth-backend/passkey"
	"orion-auth-backend/password"
	"orion-auth-backend/policy"
	"orion-auth-backend/rbac"
	"orion-auth-backend/reauth"
	"orion-auth-backend/regform"
	"orion-auth-backend/resource"
	"orion-auth-backend/session"
	"orion-auth-backend/user"
)

// @title           Orion Auth Backend API
// @version         1.0
// @description     OAuth2/OIDC authentication server with user management, RBAC, MFA, and federation support.
// @host            auth.nhsoul.fr
// @BasePath        /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	switch cfg.Server.Mode {
	case "release":
		slog.Info("starting in RELEASE mode (Validate() invariants enforced)")
	case "debug":
		slog.Warn("starting in DEBUG mode — DO NOT use this configuration in production",
			"swagger_exposed", true, "validate_warnings_only", true)
	case "test":
		slog.Info("starting in TEST mode")
	default:
		slog.Warn("unknown server.mode; treating as debug", "mode", cfg.Server.Mode)
	}

	// Database
	db, err := database.Connect(&cfg.Database)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}

	if err := database.Migrate(db); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	database.StartCleanupJob(db, 1*time.Hour)

	// Dependencies
	hasher := crypto.NewArgon2Hasher(cfg.Argon2)
	emailSender := email.NewSMTPSender(cfg.SMTP, cfg.Issuer)

	// Rate limiter: 20 burst, 5 req/s sustained for auth endpoints
	authRateLimiter := middleware.NewRateLimiter(20, 5)

	// Repositories
	userRepo := user.NewRepository(db)
	sessionRepo := session.NewRepository(db)
	clientRepo := client.NewRepository(db)
	oauthRepo := oauth.NewRepository(db)
	mfaRepo := mfa.NewRepository(db)
	rbacRepo := rbac.NewRepository(db)
	fedRepo := federation.NewRepository(db)
	reauthRepo := reauth.NewRepository(db)
	passkeyRepo := passkey.NewRepository(db)
	regFormRepo := regform.NewRepository(db)

	// Services
	userService := user.NewService(userRepo, hasher, cfg.Auth)
	userService.SetEmailSender(emailSender)
	sessionService := session.NewService(sessionRepo, cfg.Auth)
	hmacEncKey := loadHMACEncryptionKey(cfg.Auth.HMACSecretEncryptionKey)
	actionTokenKey := loadActionTokenSigningKey(cfg.Auth.ActionTokenSigningKey)
	userService.SetActionTokenSigningKey(actionTokenKey)
	clientService := client.NewService(clientRepo, hasher, hmacEncKey)
	oauthService := oauth.NewService(oauthRepo, userService, sessionService, hasher, cfg.Auth)
	oidcService := oidc.NewService(db, userService, cfg.Issuer, cfg.PairwiseSalt)
	mfaService := mfa.NewService(mfaRepo, hasher)
	rbacService := rbac.NewService(rbacRepo)
	auditService := audit.NewService(db)
	fedService := federation.NewService(fedRepo, cfg.Issuer, hmacEncKey)
	fedService.SetStateRepository(federation.NewStateRepository(db))
	fedService.SetAuthUIBaseURL(cfg.AuthUI.BaseURL)
	fedService.SetAllowedReturnToOrigins(cfg.CORS.AllowedOrigins)
	fedService.SetOAuthResumer(newFederationOAuthAdapter(oauthService))
	invRepo := invitation.NewRepository(db)
	invService := invitation.NewService(invRepo, userService, rbacService, emailSender, cfg.Issuer)
	invService.SetAllowedOrigins(cfg.CORS.AllowedOrigins)
	invService.SetSessionTTLDefaults(cfg.Auth.SessionTTL, cfg.Auth.SessionExtendedTTL)
	sessionService.SetTTLResolver(invService)
	userService.SetEmailVerificationGate(invService)
	fedService.SetProvisioningDependencies(userService, invService, invService)
	regFormService := regform.NewService(regFormRepo)
	userService.SetRegFormProvider(regFormService)

	// Password policy (admin-configurable). Reads/writes the
	// settings.password_policy row; reuses the invitation repository
	// which already owns the settings table helpers.
	passwordService := password.NewService(invRepo)
	userService.SetPasswordValidator(password.NewValidator(passwordService))

	// WebAuthn / Passkeys
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.WebAuthn.RPDisplayName,
		RPID:          cfg.WebAuthn.RPID,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
	})
	if err != nil {
		slog.Error("failed to initialize webauthn", "error", err)
		os.Exit(1)
	}
	passkeyService := passkey.NewService(passkeyRepo, userService, wa, cfg.Account.PasskeyChallengeTTL)

	// Reauth (step-up)
	reauthService := reauth.NewService(reauthRepo, userService, cfg.Account.ReauthTokenTTL)
	reauthService.SetMFAValidator(mfaService)
	reauthService.SetPasskeyValidator(passkeyService)

	// Account self-service (email change, password change, deletion)
	accountService := account.NewService(
		userService,
		sessionService,
		emailSender,
		cfg.Account.EmailChangeTokenTTL,
		cfg.Account.DeletionGracePeriod,
	)

	// Policy engine
	policyRepo := policy.NewRepository(db)
	policyEngine := policy.NewEngine()
	policyService := policy.NewService(policyRepo, policyEngine)
	policyService.SetAuditService(auditService)
	if err := policyService.LoadAll(); err != nil {
		slog.Error("failed to load policies", "error", err)
		os.Exit(1)
	}

	// API Resources
	resourceRepo := resource.NewRepository(db)
	resourceService := resource.NewService(resourceRepo)

	// Seed defaults on first launch
	seedDefaults(db, userService, rbacService, cfg.Issuer)

	// Wire the default 'user' role for self-registration AFTER seeding so the
	// admin user (created via seedAdminUser) doesn't pick up the user role on top
	// of the admin role. New registrations get the user role automatically.
	userService.SetDefaultRole(uuid.MustParse(defaultUserRoleID), rbacService)

	// Initialize signing keys
	if err := oidcService.EnsureSigningKey(); err != nil {
		slog.Error("failed to initialize signing key", "error", err)
		os.Exit(1)
	}

	// Connect cross-service dependencies
	oauthService.SetIDTokenGenerator(oidc.NewIDTokenAdapter(oidcService))
	oauthService.SetAccessTokenJWTSigner(oidc.NewAccessTokenJWTSignerAdapter(oidcService))
	oauthService.SetMFAValidator(mfaService)
	oauthService.SetPolicyEvaluator(policy.NewOAuthAdapter(policyService))
	oauthService.SetRoleProvider(newRoleProviderAdapter(rbacService))
	oauthService.SetResourceValidator(resourceService)
	oauthService.SetIssuer(cfg.Issuer)
	oidcService.SetRBACService(rbacService)
	oidcService.SetSessionRevoker(sessionService)
	oidcService.SetClientFinder(clientRepo)
	oauthService.SetIDTokenValidator(oidcService)

	// Handlers
	userHandler := user.NewHandler(userService)
	userHandler.SetRegistrationChecker(invService)
	userHandler.SetAuthUIBaseURL(cfg.AuthUI.BaseURL)
	userHandler.SetOAuthBootstrapper(oauthService)
	sessionHandler := session.NewHandler(sessionService)
	clientHandler := client.NewHandler(clientService)
	oauthHandler := oauth.NewHandler(oauthService)
	oidcHandler := oidc.NewHandler(oidcService)
	mfaHandler := mfa.NewHandler(mfaService, userService)
	rbacHandler := rbac.NewHandler(rbacService)
	auditHandler := audit.NewHandler(auditService)
	fedHandler := federation.NewHandler(fedService)
	invHandler := invitation.NewHandler(invService)
	regFormHandler := regform.NewHandler(regFormService)
	passwordHandler := password.NewHandler(passwordService)
	policyHandler := policy.NewHandler(policyService)
	resourceHandler := resource.NewHandler(resourceService)
	reauthHandler := reauth.NewHandler(reauthService)
	passkeyHandler := passkey.NewHandler(passkeyService)
	accountHandler := account.NewHandler(accountService)
	accountHandler.SetReauthService(reauthService)

	// M2M: programmatic user-admin API consumed by services authenticated in
	// client_credentials with audience urn:orion:m2m.
	m2mUserService := m2m.NewUserService(
		userService,
		rbacService,
		sessionService,
		mfaService,
		passkeyService,
		fedService,
	)
	m2mUserService.SetProtectedRoles(cfg.Auth.M2MProtectedRoleIDs)
	m2mHandler := m2m.NewHandler(m2mUserService)

	// Policy gate for account_action policies (deny-on-self-service rules).
	accountPolicyGate := account.NewPolicyGate(
		userService,
		newRoleProviderAdapter(rbacService),
		mfaService,
		passkeyService,
		newAccountPolicyEvaluatorAdapter(policyService),
	)

	// Connect audit logging to handlers
	userHandler.SetAuditService(auditService)
	clientHandler.SetAuditService(auditService)
	oauthHandler.SetAuditService(auditService)
	mfaHandler.SetAuditService(auditService)
	sessionHandler.SetAuditService(auditService)
	rbacHandler.SetAuditService(auditService)
	fedHandler.SetAuditService(auditService)
	invHandler.SetAuditService(auditService)
	regFormHandler.SetAuditService(auditService)
	passwordHandler.SetAuditService(auditService)
	invHandler.SetFederationLister(&federationListerAdapter{fedService: fedService})
	policyHandler.SetAuditService(auditService)
	resourceHandler.SetAuditService(auditService)
	reauthHandler.SetAuditService(auditService)
	passkeyHandler.SetAuditService(auditService)
	accountHandler.SetAuditService(auditService)
	m2mHandler.SetAuditService(auditService)

	// Dynamic Client Registration handler
	dcrHandler := client.NewDCRHandler(clientService)
	dcrHandler.SetInitialAccessToken(cfg.Auth.DCRInitialAccessToken)
	if cfg.Auth.DCRInitialAccessToken == "" {
		slog.Warn("DCR /register is open (no initial_access_token configured); set ORION_AUTH_DCR_INITIAL_ACCESS_TOKEN in production")
	}

	// Router
	router := setupRouter(setupRouterArgs{
		cfg:               cfg,
		db:                db,
		hasher:            hasher,
		authRL:            authRateLimiter,
		rbacService:       rbacService,
		policyService:     policyService,
		reauthService:     reauthService,
		accountGate:       accountPolicyGate,
		userHandler:       userHandler,
		sessionHandler:    sessionHandler,
		clientHandler:     clientHandler,
		oauthHandler:      oauthHandler,
		oidcHandler:       oidcHandler,
		mfaHandler:        mfaHandler,
		rbacHandler:       rbacHandler,
		auditHandler:      auditHandler,
		fedHandler:        fedHandler,
		invHandler:        invHandler,
		regFormHandler:    regFormHandler,
		passwordHandler:   passwordHandler,
		policyHandler:     policyHandler,
		resourceHandler:   resourceHandler,
		reauthHandler:     reauthHandler,
		passkeyHandler:    passkeyHandler,
		accountHandler:    accountHandler,
		m2mHandler:        m2mHandler,
		dcrHandler:        dcrHandler,
		hmacEncKey:        hmacEncKey,
	})

	// Server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		slog.Info("orion-auth-backend listening", "addr", addr, "issuer", cfg.Issuer)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped")
}

type setupRouterArgs struct {
	cfg             *config.Config
	db              *gorm.DB
	hasher          *crypto.Argon2Hasher
	authRL          *middleware.RateLimiter
	rbacService     *rbac.Service
	policyService   *policy.Service
	reauthService   *reauth.Service
	accountGate     *account.PolicyGate
	userHandler     *user.Handler
	sessionHandler  *session.Handler
	clientHandler   *client.Handler
	oauthHandler    *oauth.Handler
	oidcHandler     *oidc.Handler
	mfaHandler      *mfa.Handler
	rbacHandler     *rbac.Handler
	auditHandler    *audit.Handler
	fedHandler      *federation.Handler
	invHandler      *invitation.Handler
	regFormHandler  *regform.Handler
	passwordHandler *password.Handler
	policyHandler   *policy.Handler
	resourceHandler *resource.Handler
	reauthHandler   *reauth.Handler
	passkeyHandler  *passkey.Handler
	accountHandler  *account.Handler
	m2mHandler      *m2m.Handler
	dcrHandler      *client.DCRHandler
	hmacEncKey      []byte
}

func setupRouter(a setupRouterArgs) *gin.Engine {
	cfg := a.cfg
	db := a.db
	hasher := a.hasher
	authRL := a.authRL
	rbacService := a.rbacService
	policyService := a.policyService

	gin.SetMode(cfg.Server.Mode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestID())
	router.Use(middleware.CORS(cfg.CORS))

	// Swagger UI: dev-only. Mounted ONLY when mode == "debug". Any other
	// value (release, test, an unknown override) leaves the route absent,
	// so /swagger/* returns 404 in production. Vuln 11.
	if cfg.Server.Mode == "debug" {
		slog.Info("mounting Swagger UI at /swagger/* (debug mode)")
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// Root endpoint
	router.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Health endpoints
	router.GET("/health", healthCheck)
	router.GET("/ready", readinessCheck(db))

	// Email assets (logos used by transactional emails)
	router.GET("/email-assets/:name", emailAssetHandler)

	// OAuth2 endpoints (root level, rate limited)
	oauthRL := middleware.NewRateLimiter(10, 3)
	jwksCache := middleware.NewJWKSCache()
	clientAuthMiddleware := middleware.ClientAuth(db, hasher, cfg.Issuer+"/token", jwksCache, a.hmacEncKey, newPolicyDeciderAdapter(policyService))
	a.oauthHandler.SetJWKSCache(jwksCache)
	a.oauthHandler.RegisterRoutes(router, clientAuthMiddleware, oauthRL.Middleware(), cfg.Issuer)

	// Dynamic Client Registration (RFC 7591)
	router.POST("/register", oauthRL.Middleware(), a.dcrHandler.Register)
	router.GET("/register/:client_id", a.dcrHandler.ReadRegistration)
	router.PUT("/register/:client_id", a.dcrHandler.UpdateRegistration)
	router.DELETE("/register/:client_id", a.dcrHandler.DeleteRegistration)

	// OIDC endpoints (root level)
	bearerAuthMiddleware := middleware.BearerAuth(db)
	a.oidcHandler.RegisterRoutes(router, bearerAuthMiddleware, oauthRL.Middleware())

	// Account permission gates (RBAC permissions seeded by migration 028).
	readProfilePerm := rbac.RequirePermission(rbacService, "account:read_profile")
	updateProfilePerm := rbac.RequirePermission(rbacService, "account:update_profile")
	changeEmailPerm := rbac.RequirePermission(rbacService, "account:change_email")
	changePasswordPerm := rbac.RequirePermission(rbacService, "account:change_password")
	manageSessionsPerm := rbac.RequirePermission(rbacService, "account:manage_sessions")
	manageMFAPerm := rbac.RequirePermission(rbacService, "account:manage_mfa")
	managePasskeysPerm := rbac.RequirePermission(rbacService, "account:manage_passkeys")
	manageLinkedAccountsPerm := rbac.RequirePermission(rbacService, "account:manage_linked_accounts")
	deleteAccountPerm := rbac.RequirePermission(rbacService, "account:delete_account")
	requireReauth := middleware.RequireReauth(a.reauthService)

	// account_action policy gates per action — chain after the permission gate.
	policyGateUpdateProfile := a.accountGate.Middleware("update_profile")
	policyGateChangeEmail := a.accountGate.Middleware("change_email")
	policyGateChangePassword := a.accountGate.Middleware("change_password")
	policyGateManageMFA := a.accountGate.Middleware("manage_mfa")
	policyGateManagePasskeys := a.accountGate.Middleware("manage_passkeys")
	policyGateManageLinkedAccounts := a.accountGate.Middleware("manage_linked_accounts")
	policyGateDeleteAccount := a.accountGate.Middleware("delete_account")

	// Public API routes (rate limited)
	public := router.Group("/api/v1")
	public.Use(authRL.Middleware())
	a.userHandler.RegisterRoutes(public, nil, nil, nil)
	a.invHandler.RegisterPublicRoutes(public)
	a.fedHandler.RegisterPublicRoutes(public)
	a.regFormHandler.RegisterPublicRoutes(public)
	a.passwordHandler.RegisterPublicRoutes(public)
	// Token-based account flows (no bearer): email-change confirm + deletion cancel.
	a.accountHandler.RegisterRoutes(public, nil, nil, nil, nil, nil)
	// Public passkey login (usernameless): begin + finish only.
	a.passkeyHandler.RegisterRoutes(public, nil, nil, nil, nil)

	// Authenticated API routes
	authenticated := router.Group("/api/v1")
	authenticated.Use(bearerAuthMiddleware)
	a.userHandler.RegisterRoutes(nil, authenticated, readProfilePerm, chainMW(updateProfilePerm, policyGateUpdateProfile))
	a.sessionHandler.RegisterRoutes(authenticated, readProfilePerm, manageSessionsPerm)
	a.mfaHandler.RegisterRoutes(authenticated, chainMW(manageMFAPerm, policyGateManageMFA), requireReauth)
	a.fedHandler.RegisterAuthenticatedRoutes(authenticated, readProfilePerm, chainMW(manageLinkedAccountsPerm, policyGateManageLinkedAccounts), requireReauth)
	a.reauthHandler.RegisterRoutes(authenticated)
	a.passkeyHandler.RegisterRoutes(nil, authenticated, readProfilePerm, chainMW(managePasskeysPerm, policyGateManagePasskeys), requireReauth)
	a.accountHandler.RegisterRoutes(
		nil,
		authenticated,
		chainMW(changePasswordPerm, policyGateChangePassword),
		chainMW(changeEmailPerm, policyGateChangeEmail),
		chainMW(deleteAccountPerm, policyGateDeleteAccount),
		requireReauth,
	)

	// M2M API routes — services authenticated in client_credentials with
	// audience urn:orion:m2m. Each sub-group carries its own scope gate.
	const m2mAudience = "urn:orion:m2m"
	m2mBase := router.Group("/api/v1/m2m")
	m2mRead := m2mBase.Group("")
	m2mRead.Use(middleware.RequireClientScope(db, "m2m:users:read", m2mAudience))
	m2mWrite := m2mBase.Group("")
	m2mWrite.Use(middleware.RequireClientScope(db, "m2m:users:write", m2mAudience))
	m2mDelete := m2mBase.Group("")
	m2mDelete.Use(middleware.RequireClientScope(db, "m2m:users:delete", m2mAudience))
	m2mManageAuth := m2mBase.Group("")
	m2mManageAuth.Use(middleware.RequireClientScope(db, "m2m:users:manage_auth", m2mAudience))
	m2mManageRoles := m2mBase.Group("")
	m2mManageRoles.Use(middleware.RequireClientScope(db, "m2m:users:manage_roles", m2mAudience))
	a.m2mHandler.RegisterRoutes(m2mRead, m2mWrite, m2mDelete, m2mManageAuth, m2mManageRoles)

	// Admin API routes (authenticated + RBAC)
	adminBase := router.Group("/api/v1/admin")
	adminBase.Use(bearerAuthMiddleware)

	// User management (requires users:read or users:write)
	userAdmin := adminBase.Group("")
	userAdmin.Use(rbac.RequireAnyPermission(rbacService, "users:read", "users:write"))
	a.userHandler.RegisterAdminRoutes(userAdmin)
	a.invHandler.RegisterAdminRoutes(userAdmin)
	a.regFormHandler.RegisterAdminRoutes(userAdmin)
	a.passwordHandler.RegisterAdminRoutes(userAdmin)

	// Client management (requires clients:read or clients:write)
	clientAdmin := adminBase.Group("")
	clientAdmin.Use(rbac.RequireAnyPermission(rbacService, "clients:read", "clients:write"))
	a.clientHandler.RegisterRoutes(clientAdmin)

	// RBAC management (requires roles:read or roles:write)
	rbacAdmin := adminBase.Group("")
	rbacAdmin.Use(rbac.RequireAnyPermission(rbacService, "roles:read", "roles:write"))
	a.rbacHandler.RegisterRoutes(rbacAdmin)

	// Key management (requires keys:read or keys:write)
	keyAdmin := adminBase.Group("")
	keyAdmin.Use(rbac.RequireAnyPermission(rbacService, "keys:read", "keys:write"))
	a.oidcHandler.RegisterAdminRoutes(keyAdmin)

	// Federation management (requires federation:read or federation:write)
	fedAdmin := adminBase.Group("")
	fedAdmin.Use(rbac.RequireAnyPermission(rbacService, "federation:read", "federation:write"))
	a.fedHandler.RegisterAdminRoutes(fedAdmin)

	// Policy management (requires policies:read or policies:write)
	policyAdmin := adminBase.Group("")
	policyAdmin.Use(rbac.RequireAnyPermission(rbacService, "policies:read", "policies:write"))
	a.policyHandler.RegisterRoutes(policyAdmin)

	// Resource management (requires resources:read or resources:write)
	resourceAdmin := adminBase.Group("")
	resourceAdmin.Use(rbac.RequireAnyPermission(rbacService, "resources:read", "resources:write"))
	a.resourceHandler.RegisterRoutes(resourceAdmin)

	// Audit logs (requires audit:read)
	auditAdmin := adminBase.Group("")
	auditAdmin.Use(rbac.RequirePermission(rbacService, "audit:read"))
	a.auditHandler.RegisterRoutes(auditAdmin)

	return router
}

// chainMW returns a single gin.HandlerFunc that runs the supplied middlewares
// in order, stopping at the first one that aborts. Lets callers attach a
// permission gate + a policy gate as one slot in RegisterRoutes signatures.
func chainMW(mws ...gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, mw := range mws {
			if c.IsAborted() {
				return
			}
			mw(c)
		}
	}
}

// federationOAuthAdapter bridges federation.OAuthResumer onto the real
// oauth.Service. Lives in main so the two packages stay decoupled at
// compile time.
type federationOAuthAdapter struct{ inner *oauth.Service }

func newFederationOAuthAdapter(s *oauth.Service) *federationOAuthAdapter {
	return &federationOAuthAdapter{inner: s}
}

func (a *federationOAuthAdapter) ResumeAuthorizeAfterExternalLogin(requestID, userID uuid.UUID, providerName, ip, ua string) (*federation.OAuthLoginStatus, error) {
	resp, err := a.inner.ResumeAuthorizeAfterExternalLogin(requestID, userID, providerName, ip, ua)
	if err != nil {
		return nil, err
	}
	return &federation.OAuthLoginStatus{
		RequestID:       resp.RequestID,
		Authenticated:   resp.Authenticated,
		RequiresConsent: resp.RequiresConsent,
		RequiresMFA:     resp.RequiresMFA,
		Scopes:          resp.Scopes,
	}, nil
}

func (a *federationOAuthAdapter) CompleteAuthorizeFirstParty(requestID uuid.UUID, ip, ua string) (*federation.OAuthCompletion, error) {
	resp, err := a.inner.CompleteAuthorizeFirstParty(requestID, ip, ua)
	if err != nil {
		return nil, err
	}
	url, err := oauth.BuildAuthorizeRedirectURL(resp)
	if err != nil {
		return nil, err
	}
	return &federation.OAuthCompletion{RedirectURL: url}, nil
}

// loadHMACEncryptionKey decodes the base64 AES-256 key used to seal
// per-client HMAC secrets (client_secret_jwt). Returns nil and logs a warning
// when the key is unset or invalid, in which case the server still boots but
// client_secret_jwt assertions are rejected at runtime.
func loadHMACEncryptionKey(encoded string) []byte {
	if encoded == "" {
		slog.Warn("auth.hmac_secret_encryption_key is not set; client_secret_jwt support is disabled")
		return nil
	}
	key, err := crypto.DecodeHMACEncryptionKey(encoded)
	if err != nil {
		slog.Error("invalid auth.hmac_secret_encryption_key; client_secret_jwt support is disabled", "error", err)
		return nil
	}
	return key
}

// loadActionTokenSigningKey decodes the base64 HMAC key used to sign
// out-of-band action tokens (verify-email links). In dev when the operator
// did not set one, a random ephemeral key is generated for this process —
// good enough to test the flow but every restart invalidates outstanding
// links. Release mode requires a configured key (enforced in config.Validate).
func loadActionTokenSigningKey(encoded string) []byte {
	if encoded == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			slog.Error("failed to generate ephemeral action token key", "error", err)
			return nil
		}
		return key
	}
	key, err := crypto.DecodeHMACEncryptionKey(encoded)
	if err != nil {
		slog.Error("invalid auth.action_token_signing_key; verify-email links will fail", "error", err)
		return nil
	}
	return key
}

const (
	adminRoleID       = "00000000-0000-0000-0000-000000000001"
	adminClientID     = "00000000-0000-0000-0000-000000000002"
	defaultUserRoleID = "00000000-0000-0000-0000-000000000004"
)

func seedDefaults(db *gorm.DB, userService *user.Service, rbacService *rbac.Service, issuer string) {
	seedAdminUser(db, userService, rbacService)
	seedAdminClient(db, issuer)
}

func seedAdminUser(db *gorm.DB, userService *user.Service, rbacService *rbac.Service) {
	var count int64
	if err := db.Model(&model.User{}).Count(&count).Error; err != nil {
		slog.Error("failed to check existing users", "error", err)
		return
	}
	if count > 0 {
		return
	}

	password := os.Getenv("ORION_ADMIN_PASSWORD")
	passwordFromEnv := password != ""

	if !passwordFromEnv {
		generated, err := crypto.GenerateRandomString(16)
		if err != nil {
			slog.Error("failed to generate admin password", "error", err)
			return
		}
		password = generated
	}

	adminEmail := "admin@orionauth.local"
	adminName := "Admin"
	admin, err := userService.Register(user.RegisterInput{
		Email:       adminEmail,
		Password:    password,
		DisplayName: &adminName,
	})
	if err != nil {
		slog.Error("failed to create admin user", "error", err)
		return
	}

	roleID, _ := uuid.Parse(adminRoleID)
	if err := rbacService.AssignRole(admin.ID, roleID); err != nil {
		slog.Error("failed to assign admin role", "error", err)
		return
	}

	// Operator-supplied password: never echo it, the operator already knows it.
	if passwordFromEnv {
		slog.Warn("========================================")
		slog.Warn("DEFAULT ADMIN USER CREATED")
		slog.Warn("Email:    " + adminEmail)
		slog.Warn("Password: <provided via ORION_ADMIN_PASSWORD>")
		slog.Warn("========================================")
		return
	}

	// Randomly generated: surface it somewhere or it's lost forever. Try the
	// file first, fall back to console — never silently swallow it.
	credFile := "admin-credentials.txt"
	content := fmt.Sprintf("Email:    %s\nPassword: %s\n", adminEmail, password)
	fileErr := os.WriteFile(credFile, []byte(content), 0600)

	slog.Warn("========================================")
	slog.Warn("DEFAULT ADMIN USER CREATED")
	slog.Warn("Email:    " + adminEmail)
	if fileErr != nil {
		slog.Error("failed to write admin credentials file, printing to console as fallback", "error", fileErr)
		slog.Warn("Password: " + password)
		slog.Warn("COPY THIS PASSWORD NOW — IT WILL NOT BE PRINTED AGAIN")
	} else {
		slog.Warn("Credentials written to " + credFile)
	}
	slog.Warn("CHANGE THIS PASSWORD IMMEDIATELY")
	slog.Warn("Tip: set ORION_ADMIN_PASSWORD to provision a deterministic admin password.")
	slog.Warn("========================================")
}

func seedAdminClient(db *gorm.DB, issuer string) {
	clientID := uuid.MustParse(adminClientID)
	postLogoutURI := issuer + "/admin/"

	var existing model.OAuthClient
	err := db.Where("id = ?", clientID).First(&existing).Error
	if err == nil {
		// Self-heal: ensure post_logout_redirect_uris contains the AdminUI
		// origin so end_session can validate it. The seed predated the
		// post-logout flow; older databases have an empty whitelist.
		if !existing.HasPostLogoutRedirectURI(postLogoutURI) {
			existing.PostLogoutRedirectURIs = append(existing.PostLogoutRedirectURIs, postLogoutURI)
			if err := db.Model(&existing).Update("post_logout_redirect_uris", existing.PostLogoutRedirectURIs).Error; err != nil {
				slog.Error("failed to backfill admin client post_logout_redirect_uris", "error", err)
			} else {
				slog.Info("admin client post_logout_redirect_uris backfilled", "uri", postLogoutURI)
			}
		}
		return
	}
	if err != gorm.ErrRecordNotFound {
		slog.Error("failed to check admin client", "error", err)
		return
	}

	adminClient := &model.OAuthClient{
		Name:                   "Admin UI",
		RedirectURIs:           pq.StringArray{issuer + "/admin/callback"},
		PostLogoutRedirectURIs: pq.StringArray{postLogoutURI},
		GrantTypes:             pq.StringArray{"authorization_code", "refresh_token"},
		ResponseTypes:          pq.StringArray{"code"},
		Scopes:                 pq.StringArray{"openid", "profile", "email"},
		TokenAuthMethod:        "none",
		IsPublic:               true,
		IsFirstParty:           true,
		AccessTokenTTL:         3600,
		RefreshTokenTTL:        86400,
		IDTokenTTL:             3600,
		Active:                 true,
	}
	adminClient.ID = clientID

	if err := db.Create(adminClient).Error; err != nil {
		slog.Error("failed to create admin OAuth client", "error", err)
		return
	}

	slog.Warn("========================================")
	slog.Warn("DEFAULT ADMIN UI CLIENT CREATED")
	slog.Warn("Client ID: " + adminClientID)
	slog.Warn("Public client (no secret, PKCE required)")
	slog.Warn("========================================")
}

// policyDeciderAdapter adapts policy.Service to the middleware.PolicyEvaluator
// interface (returns deny + reason rather than the full policy.EvalResult). It
// keeps the middleware package free of any direct dependency on policy.
type policyDeciderAdapter struct {
	svc *policy.Service
}

func newPolicyDeciderAdapter(svc *policy.Service) *policyDeciderAdapter {
	return &policyDeciderAdapter{svc: svc}
}

func (a *policyDeciderAdapter) Evaluate(ctx context.Context, policyType string, input map[string]any) (bool, string, error) {
	r, err := a.svc.Evaluate(ctx, policyType, input)
	if err != nil || r == nil {
		return false, "", err
	}
	return r.Deny, r.DenyReason, nil
}

// roleProviderAdapter adapts rbac.Service to oauth.RoleProvider, exposing
// just role names (not full Role objects) so the policy input stays string-flat.
type roleProviderAdapter struct {
	svc *rbac.Service
}

func newRoleProviderAdapter(svc *rbac.Service) *roleProviderAdapter {
	return &roleProviderAdapter{svc: svc}
}

func (a *roleProviderAdapter) GetUserRoleNames(userID uuid.UUID) ([]string, error) {
	roles, err := a.svc.GetUserRoles(userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return names, nil
}

func (a *roleProviderAdapter) GetUserPermissions(userID uuid.UUID) ([]string, error) {
	return a.svc.GetUserPermissions(userID)
}

// accountPolicyEvaluatorAdapter adapts policy.Service to account.PolicyEvaluator.
type accountPolicyEvaluatorAdapter struct {
	svc *policy.Service
}

func newAccountPolicyEvaluatorAdapter(svc *policy.Service) *accountPolicyEvaluatorAdapter {
	return &accountPolicyEvaluatorAdapter{svc: svc}
}

func (a *accountPolicyEvaluatorAdapter) Evaluate(ctx context.Context, policyType string, input map[string]any) (*account.PolicyResult, error) {
	r, err := a.svc.Evaluate(ctx, policyType, input)
	if err != nil || r == nil {
		return nil, err
	}
	return &account.PolicyResult{Deny: r.Deny, DenyReason: r.DenyReason}, nil
}

// federationListerAdapter adapts federation.Service to invitation.FederationLister.
type federationListerAdapter struct {
	fedService *federation.Service
}

func (a *federationListerAdapter) ListActiveProviders() ([]invitation.FederationProviderInfo, error) {
	providers, err := a.fedService.ListActiveProviders()
	if err != nil {
		return nil, err
	}
	result := make([]invitation.FederationProviderInfo, len(providers))
	for i, p := range providers {
		result[i] = invitation.FederationProviderInfo{
			Name:        p.Name,
			DisplayName: p.DisplayName,
			Type:        p.Type,
		}
	}
	return result, nil
}

// healthCheck godoc
// @Summary      Health check
// @Tags         Health
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /health [get]
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "orion-auth-backend",
	})
}

func emailAssetHandler(c *gin.Context) {
	name := c.Param("name")
	data, err := emailtemplates.Assets.ReadFile("assets/" + name)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Content-Type", "image/svg+xml")
	c.Header("Cache-Control", "public, max-age=86400, immutable")
	c.Data(http.StatusOK, "image/svg+xml", data)
}

func readinessCheck(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		sqlDB, err := db.DB()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "message": "database unavailable"})
			return
		}
		if err := sqlDB.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "message": "database unreachable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}
