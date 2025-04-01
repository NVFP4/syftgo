package auth

type EmailRequest struct {
	Email string `json:"email" form:"email" binding:"required"`
}

type VerifyRequest struct {
	Email string `json:"email" form:"email" binding:"required"`
	Code  string `json:"code" form:"code" binding:"required"`
}
