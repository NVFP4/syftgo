package middlewares

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Middleware to verify JwtAuth token
func JwtAuth(jwtSecret string) gin.HandlerFunc {
	authEnabled := jwtSecret != ""

	if !authEnabled {
		slog.Info("Auth is DISABLED. No JWT secret provided.")
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		bearerToken, err := extractTokenFromHeader(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		claims, err := validateJwtToken(bearerToken, jwtSecret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// Add email to gin context for use in protected routes
		c.Set("email", claims.Subject)

		// continue processing the request
		c.Next()
	}
}

func validateJwtToken(tokenString, jwtSecret string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func extractTokenFromHeader(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header required")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid token format")
	}

	// Remove 'Bearer ' prefix
	return strings.TrimPrefix(authHeader, "Bearer "), nil
}
