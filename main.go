package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"orion-auth-backend/audit"
	"orion-auth-backend/model"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"orion-auth-backend/client"
	"orion-auth-backend/config"
	"orion-auth-backend/crypto"
	"orion-auth-backend/database"
	_ "orion-auth-backend/docs"
	"orion-auth-backend/email"
	"orion-auth-backend/federation"
	"orion-auth-backend/invitation"
	"orion-auth-backend/mfa"
	"orion-auth-backend/middleware"
	"orion-auth-backend/oauth"
	"orion-auth-backend/oidc"
	"orion-auth-backend/policy"
	"orion-auth-backend/rbac"
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

	// Services
	userService := user.NewService(userRepo, hasher, cfg.Auth)
	userService.SetEmailSender(emailSender)
	sessionService := session.NewService(sessionRepo, cfg.Auth)
	clientService := client.NewService(clientRepo, hasher)
	oauthService := oauth.NewService(oauthRepo, userService, sessionService, hasher, cfg.Auth)
	oidcService := oidc.NewService(db, userService, cfg.Issuer)
	mfaService := mfa.NewService(mfaRepo, hasher)
	rbacService := rbac.NewService(rbacRepo)
	auditService := audit.NewService(db)
	fedService := federation.NewService(fedRepo, cfg.Issuer)
	invRepo := invitation.NewRepository(db)
	invService := invitation.NewService(invRepo, userService, rbacService, emailSender, cfg.Issuer)

	// Policy engine
	policyRepo := policy.NewRepository(db)
	policyEngine := policy.NewEngine()
	policyService := policy.NewService(policyRepo, policyEngine)
	if err := policyService.LoadAll(); err != nil {
		slog.Error("failed to load policies", "error", err)
		os.Exit(1)
	}

	// Seed defaults on first launch
	seedDefaults(db, userService, rbacService, cfg.Issuer)

	// Initialize signing keys
	if err := oidcService.EnsureSigningKey(); err != nil {
		slog.Error("failed to initialize signing key", "error", err)
		os.Exit(1)
	}

	// Connect cross-service dependencies
	oauthService.SetIDTokenGenerator(oidc.NewIDTokenAdapter(oidcService))
	oauthService.SetMFAValidator(mfaService)
	oidcService.SetRBACService(rbacService)

	// Handlers
	userHandler := user.NewHandler(userService)
	userHandler.SetRegistrationChecker(invService)
	sessionHandler := session.NewHandler(sessionService)
	clientHandler := client.NewHandler(clientService)
	oauthHandler := oauth.NewHandler(oauthService)
	oidcHandler := oidc.NewHandler(oidcService)
	mfaHandler := mfa.NewHandler(mfaService, userService)
	rbacHandler := rbac.NewHandler(rbacService)
	auditHandler := audit.NewHandler(auditService)
	fedHandler := federation.NewHandler(fedService)
	invHandler := invitation.NewHandler(invService)
	policyHandler := policy.NewHandler(policyService)

	// Connect audit logging to handlers
	userHandler.SetAuditService(auditService)
	clientHandler.SetAuditService(auditService)
	oauthHandler.SetAuditService(auditService)
	mfaHandler.SetAuditService(auditService)
	sessionHandler.SetAuditService(auditService)
	rbacHandler.SetAuditService(auditService)
	fedHandler.SetAuditService(auditService)
	invHandler.SetAuditService(auditService)
	policyHandler.SetAuditService(auditService)

	// Router
	router := setupRouter(cfg, db, hasher, authRateLimiter, rbacService, userHandler, sessionHandler, clientHandler, oauthHandler, oidcHandler, mfaHandler, rbacHandler, auditHandler, fedHandler, invHandler, policyHandler)

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

func setupRouter(
	cfg *config.Config,
	db *gorm.DB,
	hasher *crypto.Argon2Hasher,
	authRL *middleware.RateLimiter,
	rbacService *rbac.Service,
	userHandler *user.Handler,
	sessionHandler *session.Handler,
	clientHandler *client.Handler,
	oauthHandler *oauth.Handler,
	oidcHandler *oidc.Handler,
	mfaHandler *mfa.Handler,
	rbacHandler *rbac.Handler,
	auditHandler *audit.Handler,
	fedHandler *federation.Handler,
	invHandler *invitation.Handler,
	policyHandler *policy.Handler,
) *gin.Engine {
	gin.SetMode(cfg.Server.Mode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestID())
	router.Use(middleware.CORS(cfg.CORS))

	// Swagger UI (dev only)
	if cfg.Server.Mode == "debug" {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// Root endpoint
	router.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Health endpoints
	router.GET("/health", healthCheck)
	router.GET("/ready", readinessCheck(db))

	// OAuth2 endpoints (root level, rate limited)
	oauthRL := middleware.NewRateLimiter(10, 3)
	clientAuthMiddleware := middleware.ClientAuth(db, hasher)
	oauthHandler.RegisterRoutes(router, clientAuthMiddleware, oauthRL.Middleware(), cfg.Issuer)

	// OIDC endpoints (root level)
	bearerAuthMiddleware := middleware.BearerAuth(db)
	oidcHandler.RegisterRoutes(router, bearerAuthMiddleware, oauthRL.Middleware())

	// Public API routes (rate limited)
	public := router.Group("/api/v1")
	public.Use(authRL.Middleware())
	userHandler.RegisterRoutes(public, nil)
	invHandler.RegisterPublicRoutes(public)
	fedHandler.RegisterPublicRoutes(public)

	// Authenticated API routes
	authenticated := router.Group("/api/v1")
	authenticated.Use(bearerAuthMiddleware)
	userHandler.RegisterRoutes(nil, authenticated)
	sessionHandler.RegisterRoutes(authenticated)
	mfaHandler.RegisterRoutes(authenticated)
	fedHandler.RegisterAuthenticatedRoutes(authenticated)

	// Admin API routes (authenticated + RBAC)
	adminBase := router.Group("/api/v1/admin")
	adminBase.Use(bearerAuthMiddleware)

	// User management (requires users:read or users:write)
	userAdmin := adminBase.Group("")
	userAdmin.Use(rbac.RequireAnyPermission(rbacService, "users:read", "users:write"))
	userHandler.RegisterAdminRoutes(userAdmin)
	invHandler.RegisterAdminRoutes(userAdmin)

	// Client management (requires clients:read or clients:write)
	clientAdmin := adminBase.Group("")
	clientAdmin.Use(rbac.RequireAnyPermission(rbacService, "clients:read", "clients:write"))
	clientHandler.RegisterRoutes(clientAdmin)

	// RBAC management (requires roles:read or roles:write)
	rbacAdmin := adminBase.Group("")
	rbacAdmin.Use(rbac.RequireAnyPermission(rbacService, "roles:read", "roles:write"))
	rbacHandler.RegisterRoutes(rbacAdmin)

	// Key management (requires keys:read or keys:write)
	keyAdmin := adminBase.Group("")
	keyAdmin.Use(rbac.RequireAnyPermission(rbacService, "keys:read", "keys:write"))
	oidcHandler.RegisterAdminRoutes(keyAdmin)

	// Federation management (requires federation:read or federation:write)
	fedAdmin := adminBase.Group("")
	fedAdmin.Use(rbac.RequireAnyPermission(rbacService, "federation:read", "federation:write"))
	fedHandler.RegisterAdminRoutes(fedAdmin)

	// Policy management (requires policies:read or policies:write)
	policyAdmin := adminBase.Group("")
	policyAdmin.Use(rbac.RequireAnyPermission(rbacService, "policies:read", "policies:write"))
	policyHandler.RegisterRoutes(policyAdmin)

	// Audit logs (requires audit:read)
	auditAdmin := adminBase.Group("")
	auditAdmin.Use(rbac.RequirePermission(rbacService, "audit:read"))
	auditHandler.RegisterRoutes(auditAdmin)

	return router
}

const (
	adminRoleID   = "00000000-0000-0000-0000-000000000001"
	adminClientID = "00000000-0000-0000-0000-000000000002"
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

	password, err := crypto.GenerateRandomString(16)
	if err != nil {
		slog.Error("failed to generate admin password", "error", err)
		return
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

	credFile := "admin-credentials.txt"
	content := fmt.Sprintf("Email:    %s\nPassword: %s\n", adminEmail, password)
	if err := os.WriteFile(credFile, []byte(content), 0600); err != nil {
		slog.Error("failed to write admin credentials file", "error", err)
		return
	}

	slog.Warn("========================================")
	slog.Warn("DEFAULT ADMIN USER CREATED")
	slog.Warn("Credentials written to " + credFile)
	slog.Warn("CHANGE THIS PASSWORD IMMEDIATELY")
	slog.Warn("========================================")
}

func seedAdminClient(db *gorm.DB, issuer string) {
	clientID := uuid.MustParse(adminClientID)

	var count int64
	if err := db.Model(&model.OAuthClient{}).Where("id = ?", clientID).Count(&count).Error; err != nil {
		slog.Error("failed to check admin client", "error", err)
		return
	}
	if count > 0 {
		return
	}

	adminClient := &model.OAuthClient{
		Name:            "Admin UI",
		RedirectURIs:    pq.StringArray{issuer + "/admin/callback"},
		GrantTypes:      pq.StringArray{"authorization_code", "refresh_token"},
		ResponseTypes:   pq.StringArray{"code"},
		Scopes:          pq.StringArray{"openid", "profile", "email"},
		TokenAuthMethod: "none",
		IsPublic:        true,
		IsFirstParty:    true,
		AccessTokenTTL:  3600,
		RefreshTokenTTL: 86400,
		IDTokenTTL:      3600,
		Active:          true,
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
