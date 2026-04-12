package pkg

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// JSON sends a JSON response with the given status code.
func JSON(c *gin.Context, status int, data any) {
	c.JSON(status, data)
}

// OK sends a 200 response with data.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, data)
}

// Created sends a 201 response with data.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, data)
}

// NoContent sends a 204 response.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// HandleError writes the appropriate error response based on error type.
func HandleError(c *gin.Context, err error) {
	switch e := err.(type) {
	case *OAuthError:
		c.JSON(e.StatusCode, e)
	case *AppError:
		c.JSON(e.StatusCode, gin.H{"error": gin.H{"code": e.Code, "message": e.Message}})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{"code": "internal_error", "message": "an unexpected error occurred"},
		})
	}
}

// PaginatedResponse wraps paginated data.
type PaginatedResponse struct {
	Data       any   `json:"data"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	TotalPages int   `json:"total_pages"`
}

// Paginated sends a paginated response.
func Paginated(c *gin.Context, data any, total int64, page, perPage int) {
	totalPages := int(total) / perPage
	if int(total)%perPage > 0 {
		totalPages++
	}
	c.JSON(http.StatusOK, PaginatedResponse{
		Data:       data,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	})
}

// ParsePagination extracts page and per_page from query params with defaults.
func ParsePagination(c *gin.Context) (page int, perPage int) {
	page = 1
	perPage = 20

	if p := c.Query("page"); p != "" {
		if val := atoi(p); val > 0 {
			page = val
		}
	}
	if pp := c.Query("per_page"); pp != "" {
		if val := atoi(pp); val > 0 && val <= 100 {
			perPage = val
		}
	}
	return
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
