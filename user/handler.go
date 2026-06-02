package user

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

type RegistrationChecker interface {
	IsRegistrationEnabled() bool
}

// OAuthBootstrapper resumes an in-flight AuthorizationRequest after the user
// finishes an out-of-band action (currently: email verification). Returns
// the absolute URL the user must be 302'd to, with the OAuth code already
// embedded — the SPA then hits its callback as if the user had just logged
// in. Injected to avoid a user→oauth import cycle.
type OAuthBootstrapper interface {
	CompleteAfterEmailVerification(requestID, userID uuid.UUID, ip, ua string) (string, error)
}

type Handler struct {
	service       *Service
	regChecker    RegistrationChecker
	auditService  *audit.Service
	authUIBaseURL string
	bootstrapper  OAuthBootstrapper
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) SetRegistrationChecker(checker RegistrationChecker) {
	h.regChecker = checker
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
}

func (h *Handler) SetAuthUIBaseURL(url string) {
	h.authUIBaseURL = url
}

func (h *Handler) SetOAuthBootstrapper(b OAuthBootstrapper) {
	h.bootstrapper = b
}

// RegisterRoutes wires the user-facing routes.
//
//	readProfilePerm    — account:read_profile gate (GET /me)
//	updateProfilePerm  — account:update_profile gate (PATCH /me)
//
// Password change has moved to the account package (account.Handler) so it
// can centralise step-up + session revocation + notification email.
func (h *Handler) RegisterRoutes(
	public, authenticated *gin.RouterGroup,
	readProfilePerm, updateProfilePerm gin.HandlerFunc,
) {
	if public != nil {
		public.POST("/auth/register", h.Register)
		public.POST("/auth/login", h.Login)
		public.POST("/auth/forgot-password", h.ForgotPassword)
		public.POST("/auth/reset-password", h.ResetPassword)
		public.POST("/auth/verify-email", h.VerifyEmail)
		public.GET("/auth/verify-email", h.VerifyEmailLink)
	}

	if authenticated != nil {
		read := authenticated.Group("")
		if readProfilePerm != nil {
			read.Use(readProfilePerm)
		}
		read.GET("/me", h.GetProfile)

		write := authenticated.Group("")
		if updateProfilePerm != nil {
			write.Use(updateProfilePerm)
		}
		write.PATCH("/me", h.UpdateProfile)
	}
}

func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.GET("/users", h.AdminListUsers)
	admin.GET("/users/:id", h.AdminGetUser)
	admin.PATCH("/users/:id", h.AdminUpdateUser)
	admin.DELETE("/users/:id", h.AdminDeleteUser)
	admin.POST("/users/:id/reset-password", h.AdminResetPassword)
}

// AdminListUsers godoc
// @Summary      List all users
// @Tags         Admin - Users
// @Accept       json
// @Produce      json
// @Param        page     query    int  false  "Page number"
// @Param        per_page query    int  false  "Items per page"
// @Success      200  {object}  pkg.PaginatedResponse
// @Failure      401  {object}  pkg.AppError
// @Failure      500  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/admin/users [get]
func (h *Handler) AdminListUsers(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)
	q := c.Query("q")

	users, total, err := h.service.Search(q, page, perPage)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list users"))
		return
	}

	profiles := make([]map[string]any, len(users))
	for i := range users {
		profiles[i] = users[i].PublicProfile()
	}

	pkg.Paginated(c, profiles, total, page, perPage)
}

// AdminGetUser godoc
// @Summary      Get a user by ID
// @Tags         Admin - Users
// @Accept       json
// @Produce      json
// @Param        id   path     string  true  "User ID (UUID)"
// @Success      200  {object}  map[string]any
// @Failure      400  {object}  pkg.AppError
// @Failure      401  {object}  pkg.AppError
// @Failure      404  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/admin/users/{id} [get]
func (h *Handler) AdminGetUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}

	user, err := h.service.GetByID(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"user": user.AdminView()})
}

// AdminUpdateUser godoc
// @Summary      Update a user by ID
// @Tags         Admin - Users
// @Accept       json
// @Produce      json
// @Param        id    path     string              true  "User ID (UUID)"
// @Param        body  body     user.AdminUpdateInput  true  "Fields to update"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Failure      401   {object}  pkg.AppError
// @Failure      404   {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/admin/users/{id} [patch]
func (h *Handler) AdminUpdateUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}

	var input AdminUpdateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.AdminUpdate(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserUpdated, map[string]any{
			"target_user_id": id,
		})
	}

	pkg.OK(c, gin.H{"user": user.AdminView()})
}

// AdminDeleteUser godoc
// @Summary      Delete a user by ID
// @Tags         Admin - Users
// @Accept       json
// @Produce      json
// @Param        id   path     string  true  "User ID (UUID)"
// @Success      200  {object}  map[string]any
// @Failure      400  {object}  pkg.AppError
// @Failure      401  {object}  pkg.AppError
// @Failure      404  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/admin/users/{id} [delete]
func (h *Handler) AdminDeleteUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}

	if err := h.service.Delete(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserDeleted, map[string]any{
			"target_user_id": id,
		})
	}

	pkg.OK(c, gin.H{"message": "user deleted"})
}

// AdminResetPassword godoc
// @Summary      Send a password reset email to the target user
// @Tags         Admin - Users
// @Accept       json
// @Produce      json
// @Param        id   path     string  true  "User ID (UUID)"
// @Success      200  {object}  map[string]any
// @Failure      400  {object}  pkg.AppError
// @Failure      401  {object}  pkg.AppError
// @Failure      404  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/admin/users/{id}/reset-password [post]
func (h *Handler) AdminResetPassword(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}

	if err := h.service.AdminTriggerPasswordReset(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAdminPasswordResetInitiated, map[string]any{
			"target_user_id": id,
		})
	}

	pkg.OK(c, gin.H{"message": "password reset email sent"})
}

// Register godoc
// @Summary      Register a new user
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body     user.RegisterInput  true  "Registration payload"
// @Success      201   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Failure      403   {object}  pkg.AppError
// @Failure      409   {object}  pkg.AppError
// @Router       /api/v1/auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	if h.regChecker != nil && !h.regChecker.IsRegistrationEnabled() {
		pkg.HandleError(c, pkg.ErrForbidden("public registration is disabled"))
		return
	}

	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.Register(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserRegistered, map[string]any{
			"user_id": user.ID,
			"email":   user.Email,
		})
	}

	// Best-effort: kick off the verify-email flow without OAuth context.
	// Failures are logged but do not block the response — the user can
	// hit /auth/resend-verification later if SMTP is briefly down.
	if err := h.service.SendVerificationEmail(user.ID, nil); err != nil {
		slog.Warn("failed to send verification email after register",
			"user_id", user.ID, "error", err)
	}

	c.JSON(http.StatusCreated, gin.H{
		"user": user.PublicProfile(),
	})
}

// Login godoc
// @Summary      Authenticate a user
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body     user.LoginInput  true  "Login credentials"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Failure      401   {object}  pkg.AppError
// @Router       /api/v1/auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.Authenticate(input)
	if err != nil {
		if h.auditService != nil {
			h.auditService.LogFromContext(c, audit.ActionUserLoginFailed, map[string]any{
				"email": input.Email,
			})
		}
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserLogin, map[string]any{
			"user_id": user.ID,
			"email":   user.Email,
		})
	}

	// Session creation is handled by the session package.
	// The handler returns the user; the caller (main router) can wrap this
	// with session creation logic.
	c.JSON(http.StatusOK, gin.H{
		"user": user.PublicProfile(),
	})
}

// GetProfile godoc
// @Summary      Get the current user's profile
// @Tags         Profile
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]any
// @Failure      401  {object}  pkg.AppError
// @Failure      404  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me [get]
func (h *Handler) GetProfile(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	user, err := h.service.GetByID(userID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"user": user.PublicProfile()})
}

// UpdateProfile godoc
// @Summary      Update the current user's profile
// @Tags         Profile
// @Accept       json
// @Produce      json
// @Param        body  body     user.UpdateProfileInput  true  "Profile fields to update"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Failure      401   {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me [patch]
func (h *Handler) UpdateProfile(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	var input UpdateProfileInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.UpdateProfile(userID, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"user": user.PublicProfile()})
}

// ForgotPassword godoc
// @Summary      Request a password reset email
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body     user.ForgotPasswordInput  true  "Email address"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Router       /api/v1/auth/forgot-password [post]
func (h *Handler) ForgotPassword(c *gin.Context) {
	var input ForgotPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	// Always return success to not leak email existence
	_ = h.service.ForgotPassword(input)
	pkg.OK(c, gin.H{"message": "if the email exists, a reset link has been sent"})
}

// ResetPassword godoc
// @Summary      Reset password using a token
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body     user.ResetPasswordInput  true  "Reset token and new password"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Router       /api/v1/auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	var input ResetPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.ResetPassword(input); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionPasswordReset, nil)
	}

	pkg.OK(c, gin.H{"message": "password reset successfully"})
}

// VerifyEmail godoc
// @Summary      Verify email address using a token
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        body  body     user.VerifyEmailInput  true  "Verification token"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Router       /api/v1/auth/verify-email [post]
func (h *Handler) VerifyEmail(c *gin.Context) {
	var input VerifyEmailInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.VerifyEmail(input); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionEmailVerified, nil)
	}

	pkg.OK(c, gin.H{"message": "email verified successfully"})
}

// VerifyEmailLink godoc
// @Summary      Consume a verification action token (one-click)
// @Tags         Auth
// @Produce      html
// @Param        token query string true "Action token (JWT)"
// @Success      302 {string} string "Redirect to client redirect_uri or AuthUI success page"
// @Failure      302 {string} string "Redirect to AuthUI error page"
// @Router       /api/v1/auth/verify-email [get]
//
// Single-click entrypoint targeted by the verification email link. Always
// responds with a 302 — never a JSON body — so the browser flows
// transparently into the destination:
//   - Token carried an OAuth request_id + bootstrapper wired → auto-login
//     and 302 to the original client's redirect_uri with a fresh code.
//   - Otherwise → 302 to {authUI}/verify-email/success.
//   - Token invalid/expired → 302 to {authUI}/verify-email?error=<code>.
func (h *Handler) VerifyEmailLink(c *gin.Context) {
	raw := c.Query("token")
	if raw == "" {
		h.redirectVerifyError(c, "missing_token")
		return
	}

	u, requestID, err := h.service.ConsumeVerificationToken(raw)
	if err != nil {
		h.redirectVerifyError(c, "invalid_token")
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionEmailVerified, map[string]any{
			"user_id": u.ID,
		})
	}

	if requestID != nil && h.bootstrapper != nil {
		target, err := h.bootstrapper.CompleteAfterEmailVerification(
			*requestID, u.ID, c.ClientIP(), c.Request.UserAgent(),
		)
		if err != nil {
			slog.Warn("oauth bootstrap after verify failed; falling back to success page",
				"user_id", u.ID, "request_id", requestID, "error", err)
		} else {
			c.Redirect(http.StatusFound, target)
			return
		}
	}

	c.Redirect(http.StatusFound, h.verifySuccessURL())
}

func (h *Handler) verifySuccessURL() string {
	base := h.authUIBaseURL
	if base == "" {
		base = "/ui"
	}
	return base + "/verify-email/success"
}

func (h *Handler) redirectVerifyError(c *gin.Context, code string) {
	base := h.authUIBaseURL
	if base == "" {
		base = "/ui"
	}
	c.Redirect(http.StatusFound, base+"/verify-email?error="+url.QueryEscape(code))
}
