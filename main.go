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
	"gorm.io/gorm"

	"OrionAuth/audit"
	"OrionAuth/client"
	"OrionAuth/config"
	"OrionAuth/crypto"
	"OrionAuth/database"
	"OrionAuth/email"
	"OrionAuth/mfa"
	"OrionAuth/middleware"
	"OrionAuth/oauth"
	"OrionAuth/oidc"
	"OrionAuth/rbac"
	"OrionAuth/session"
	"OrionAuth/user"
)

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

	// Initialize signing keys
	if err := oidcService.EnsureSigningKey(); err != nil {
		slog.Error("failed to initialize signing key", "error", err)
		os.Exit(1)
	}

	// Connect cross-service dependencies
	oauthService.SetIDTokenGenerator(oidc.NewIDTokenAdapter(oidcService))
	oauthService.SetMFAValidator(mfaService)

	// Handlers
	userHandler := user.NewHandler(userService)
	sessionHandler := session.NewHandler(sessionService)
	clientHandler := client.NewHandler(clientService)
	oauthHandler := oauth.NewHandler(oauthService)
	oidcHandler := oidc.NewHandler(oidcService)
	mfaHandler := mfa.NewHandler(mfaService, userService)
	rbacHandler := rbac.NewHandler(rbacService)
	auditHandler := audit.NewHandler(auditService)

	// Router
	router := setupRouter(cfg, db, hasher, authRateLimiter, rbacService, userHandler, sessionHandler, clientHandler, oauthHandler, oidcHandler, mfaHandler, rbacHandler, auditHandler)

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
		slog.Info("OrionAuth listening", "addr", addr, "issuer", cfg.Issuer)
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
) *gin.Engine {
	gin.SetMode(cfg.Server.Mode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.RequestID())
	router.Use(middleware.CORS(cfg.CORS))

	// Health endpoints
	router.GET("/health", healthCheck)
	router.GET("/ready", readinessCheck(db))

	// OAuth2 endpoints (root level, rate limited)
	clientAuthMiddleware := middleware.ClientAuth(db, hasher)
	oauthHandler.RegisterRoutes(router, clientAuthMiddleware, cfg.Issuer)

	// OIDC endpoints (root level)
	bearerAuthMiddleware := middleware.BearerAuth(db)
	oidcHandler.RegisterRoutes(router, bearerAuthMiddleware)

	// Public API routes (rate limited)
	public := router.Group("/api/v1")
	public.Use(authRL.Middleware())
	userHandler.RegisterRoutes(public, nil)

	// Authenticated API routes
	authenticated := router.Group("/api/v1")
	authenticated.Use(bearerAuthMiddleware)
	userHandler.RegisterRoutes(nil, authenticated)
	sessionHandler.RegisterRoutes(authenticated)
	mfaHandler.RegisterRoutes(authenticated)

	// Admin API routes (authenticated + RBAC)
	adminBase := router.Group("/api/v1/admin")
	adminBase.Use(bearerAuthMiddleware)

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

	// Audit logs (requires audit:read)
	auditAdmin := adminBase.Group("")
	auditAdmin.Use(rbac.RequirePermission(rbacService, "audit:read"))
	auditHandler.RegisterRoutes(auditAdmin)

	return router
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "OrionAuth",
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
