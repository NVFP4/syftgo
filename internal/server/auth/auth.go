package auth

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/mail"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	jwtIssuer = "syftbox"
	table     = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ" // base34 table
)

type AuthConfig struct {
	JwtSecret      string
	JwtExpiry      time.Duration
	EmailOTPLength int
	EmailOTPExpiry time.Duration
}

type AuthHandler struct {
	config *AuthConfig
	codes  *expirable.LRU[string, string]
}

func New(config AuthConfig) *AuthHandler {
	return &AuthHandler{
		config: &config,
		codes:  expirable.NewLRU[string, string](0, nil, config.EmailOTPExpiry), // 0 = LRU off
	}
}

func (h *AuthHandler) Login(ctx *gin.Context) {
	var req EmailRequest
	if err := ctx.ShouldBindQuery(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if !validEmail(req.Email) {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email address",
		})
		return
	}

	emailOTP, err := generateEmailOTP(h.config.EmailOTPLength)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate verification code",
		})
		return
	}

	// prevent replay attacks of the same code
	h.codes.Add(req.Email, emailOTP)

	// TODO - send a mail!
	ctx.String(http.StatusOK, emailOTP)
}

func (h *AuthHandler) Verify(ctx *gin.Context) {
	var req VerifyRequest
	if err := ctx.ShouldBindQuery(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if !validEmail(req.Email) || len(req.Code) != h.config.EmailOTPLength {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email address or code",
		})
		return
	}

	// get code from ttl cache
	code, ok := h.codes.Get(req.Email)

	if !ok || code != req.Code {
		// don't remove code from cache yet
		// slow emails can cause this & would want to preserve the last valid code
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid verification code",
		})
		return
	}

	// remove code from cache
	h.codes.Remove(req.Email)
	token, err := generateJwtToken(req.Email, h.config.JwtSecret, h.config.EmailOTPExpiry)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"token": token,
	})
}

func generateJwtToken(email, jwtSecret string, expiry time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   email,
		Issuer:    jwtIssuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func generateEmailOTP(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be greater than 0")
	}

	result := make([]byte, length)
	if _, err := rand.Read(result); err != nil {
		return "", err
	}

	for i := range result {
		result[i] = table[result[i]%byte(len(table))]
	}

	return string(result), nil
}

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
