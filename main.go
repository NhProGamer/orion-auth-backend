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

	"OrionAuth/config"
	"OrionAuth/crypto"
	"OrionAuth/database"
	"OrionAuth/middleware"
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

	// Repositories
	userRepo := user.NewRepository(db)
	sessionRepo := session.NewRepository(db)

	// Services
	userService := user.NewService(userRepo, hasher, cfg.Auth)
	sessionService := session.NewService(sessionRepo, cfg.Auth)

	// Handlers
	userHandler := user.NewHandler(userService)
	sessionHandler := session.NewHandler(sessionService)

	// Router
	router := setupRouter(cfg, db, userHandler, sessionHandler)

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

func setupRouter(cfg *config.Config, db *gorm.DB, userHandler *user.Handler, sessionHandler *session.Handler) *gin.Engine {
	gin.SetMode(cfg.Server.Mode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.RequestID())
	router.Use(middleware.CORS(cfg.CORS))

	// Health endpoints
	router.GET("/health", healthCheck)
	router.GET("/ready", readinessCheck(db))

	// Public API routes (no auth required)
	public := router.Group("/api/v1")
	userHandler.RegisterRoutes(public, nil) // register + login only

	// Authenticated API routes
	authenticated := router.Group("/api/v1")
	authenticated.Use(middleware.BearerAuth(db))
	userHandler.RegisterRoutes(nil, authenticated) // profile routes
	sessionHandler.RegisterRoutes(authenticated)

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
