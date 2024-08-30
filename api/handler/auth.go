package handler

import (
	"auth/api/helper"
	"auth/api/token"
	pb "auth/genproto/auth"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/spf13/cast"
	"google.golang.org/protobuf/proto"
)

// @Summary Enter user email for verification
// @Description Allows users to enter their email address for actions such as account recovery or verification. A verification code will be sent to the provided email.
// @Security BearerAuth
// @Tags Authentication
// @Accept json
// @Produce json
// @Param email path string true "User Email"
// @Success 200 {object} pb.LogInAdminRequest
// @Failure 400 {string} string "Invalid input data"
// @Failure 500 {string} string "Internal server error"
// @Router /auth/enterAccount/{email} [post]  // Include {email} in the route
func (h *Handler) EnterAccount(ctx *gin.Context) {
	email := ctx.Param("email")
	if email == "" {
		ctx.JSON(http.StatusBadRequest, pb.InfoResponse{
			Success: false,
			Message: "Email parameter is required",
		})
		return
	}

	req := pb.EmailRequest{
		AdminId: uuid.NewString(),
		Email:   email,
		Role:    "user",
	}

	code, err := h.SendEmail(&req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to send email: " + err.Error(),
		})
		return
	}

	response, err := h.StoreVerificationCodeToRedis(ctx, req.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to store verification code: " + err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// @Summary Verify user email
// @Description Verifies a user's email address using a verification code. If successful, returns an authentication token.
// @Security BearerAuth
// @Tags Authentication
// @Accept json
// @Produce json
// @Param email query string true "User email address"
// @Param verification_code query string true "Verification code sent to the user's email"
// @Success 200 {object} pb.TokenResponse "Token generated upon successful verification"
// @Failure 400 {object} pb.InfoResponse "Invalid input or verification code"
// @Failure 500 {object} pb.InfoResponse "Internal server error"
// @Router /auth/verifyEmail [post]
func (h *Handler) VerifyEmail(ctx *gin.Context) {
	email := ctx.Query("email")
	code := ctx.Query("verification_code")

	user := &pb.VerifyEmailRequest{
		UserId:           uuid.NewString(),
		Email:            email,
		VerificationCode: code,
		Role:             "user",
	}

	checkResponse, err := h.CheckTheVerificationCode(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Internal server error: " + err.Error(),
		})
		return
	}

	if !checkResponse.Success {
		ctx.JSON(http.StatusBadRequest, checkResponse)
		return
	}

	response, err := h.Auth.VerifyEmail(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to verify email: " + err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// RefreshToken godoc
// @Summary Refresh an access token
// @Description Refresh a user's access token using the refresh token
// @Security BearerAuth
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200 {object} pb.TokenResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "Internal Server Error"
// @Router /auth/refreshToken [post]
func (h *Handler) RefreshToken(ctx *gin.Context) {
	var tokenReq pb.ById

	id, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to get user ID from token: " + err.Error()})
		return
	}
	tokenReq.UserId = id

	res, err := h.Auth.RefreshToken(context.Background(), &tokenReq)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token: " + err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// ChangeEmail godoc
// @Summary Change user email
// @Description Change the email address of a user
// @Security BearerAuth
// @Tags Auth
// @Accept json
// @Produce json
// @Param new_email query string true "New Email"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /auth/changeEmail [put]
func (h *Handler) ChangeEmail(ctx *gin.Context) {
	newEmail := ctx.Query("new_email")

	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	claims, err := token.ExtractClaim(authHeader)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	currentEmail := cast.ToString(claims["email"])
	if currentEmail == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Current email not found in token"})
		return
	}

	changeEmailReq := pb.ChangeEmailRequest{
		CurrentEmail: currentEmail,
		NewEmail:     newEmail,
	}

	emailReq := pb.EmailRequest{
		Email: newEmail,
	}

	_, err = h.SendEmail(&emailReq)
	if err != nil {
		panic(err)
	}

	response, err := h.Auth.ChangeEmail(ctx, &changeEmailReq)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// @Summary Verify user email
// @Description Verifies a user's email address using a verification code. If successful, returns an authentication token.
// @Security BearerAuth
// @Tags Authentication
// @Accept json
// @Produce json
// @Param email query string true "User email address"
// @Param verification_code query string true "Verification code sent to the user's email"
// @Success 200 {object} pb.TokenResponse "Token generated upon successful verification"
// @Failure 400 {object} pb.InfoResponse "Invalid input or verification code"
// @Failure 500 {object} pb.InfoResponse "Internal server error"
// @Router /auth/completeChangeEmail [post]
func (h *Handler) CompleteChangeEmail(ctx *gin.Context) {
	email := ctx.Query("email")
	code := ctx.Query("verification_code")

	id, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to get user ID from token: " + err.Error()})
		return
	}

	user := pb.VerifyEmailRequest{
		UserId:           id,
		Email:            email,
		VerificationCode: code,
	}

	_, err = h.CheckTheVerificationCode(ctx, &user)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, pb.InfoResponse{
			Success: false,
			Message: "Invalid verification code: " + err.Error(),
		})
		return
	}

	response, err := h.Auth.CompleteChangeEmail(ctx, &user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to verify email: " + err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// UpdateUser godoc
// @Summary Update the user
// @Description Updates the user's data
// @Security BearerAuth
// @Tags Users
// @Accept json
// @Produce json
// @Param body body helper.SwaggerReq true "User update data"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {object} map[string]string "Bad Request"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /auth/updateUser [put]
func (h *Handler) UpdateUser(ctx *gin.Context) {
	var getFromSwagger helper.SwaggerReq

	id, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get id from the token"})
		return
	}

	if err := ctx.ShouldBindJSON(&getFromSwagger); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req := pb.UpdateUserRequest{
		UserId:      id,
		FirstName:   getFromSwagger.FirstName,
		LastName:    getFromSwagger.LastName,
		DateOfBirth: getFromSwagger.DateOfBirth,
		Email:       getFromSwagger.Email,
		PhoneNumber: getFromSwagger.PhoneNumber,
	}

	res, err := h.Auth.UpdateUser(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// GetProfile godoc
// @Summary Get the profile informations
// @Description Gets the all information about the user
// @Security BearerAuth
// @Tags Users
// @Accept json
// @Produce json
// @Success 200 {object} pb.Users
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /auth/getProfile [get]
func (h *Handler) GetProfile(ctx *gin.Context) {
	var req pb.ById

	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	claims, err := token.ExtractClaim(authHeader)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	userId := cast.ToString(claims["id"])
	if userId == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}

	req.UserId = userId

	res, err := h.Auth.GetProfile(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// GetAllUsers godoc
// @Summary Get all users
// @Description Gets all users
// @Security BearerAuth
// @Tags Users
// @Accept json
// @Produce json
// @Success 200 {object} pb.GetAllUsersResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /auth/getAllUsers [get]
func (h *Handler) GetAllUsers(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	claims, err := token.ExtractClaim(authHeader)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	userId := cast.ToString(claims["id"])
	if userId == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}

	req := pb.ById{UserId: userId}

	res, err := h.Auth.GetAllUsers(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// DeleteUser godoc
// @Summary Deletes the user
// @Description Deletes the user data
// @Security BearerAuth
// @Tags Users
// @Accept json
// @Produce json
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /auth/deleteUser [delete]
func (h *Handler) DeleteUser(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	userId, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	req := pb.ById{UserId: userId}

	res, err := h.Auth.DeleteUser(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// DeleteUser godoc
// @Summary Deletes the user by entered id
// @Description Deletes the user data
// @Security BearerAuth
// @Tags Users
// @Accept json
// @Produce json
// @Param userID query string true "User ID"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /auth/deleteUserByAdmin [delete]
func (h *Handler) DeleteUserByAdmin(ctx *gin.Context) {
	userID := ctx.Query("userID")

	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	adminID, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	req := pb.ByAdmin{UserId: userID, AdminId: adminID}

	res, err := h.Auth.DeleteUserByAdmin(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// @Summary Enter admin email for verification
// @Description Allows admins to enter their email address for actions such as account recovery or verification. A verification code will be sent to the provided email.
// @Security BearerAuth
// @Tags Admin
// @Accept json
// @Produce json
// @Param email path string true "Admin Email"
// @Success 200 {object} pb.LogInAdminRequest
// @Failure 400 {string} string "Invalid input data"
// @Failure 500 {string} string "Internal server error"
// @Router /admin/createAdmin/{email} [post]  // Include {email} in the route
func (h *Handler) CreateAdmin(ctx *gin.Context) {
	email := ctx.Param("email")
	if email == "" {
		ctx.JSON(http.StatusBadRequest, pb.InfoResponse{
			Success: false,
			Message: "Email parameter is required",
		})
		return
	}

	id, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	req := pb.EmailRequest{
		AdminId:      uuid.NewString(),
		Email:        email,
		Role:         "admin",
		SuperAdminId: id,
	}

	response, err := h.Auth.CreateAdmin(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// LoginAdmin handles the admin login request
// @Summary Admin Login
// @Description Login as an admin user with email and password
// @Tags Admin
// @Accept  json
// @Produce  json
// @Param   body  body  auth.LogInAdminRequest  true  "Admin Login Credentials"
// @Success 200 {object} auth.TokenResponse "Successful login"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Unauthorized"
// @Router /admin/loginAdmin [post]
func (h *Handler) LoginAdmin(ctx *gin.Context) {
	var req pb.LogInAdminRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request", "success": false})
		return
	}

	res, err := h.Auth.LogInAdmin(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized", "success": false})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// UpdateUser godoc
// @Summary Update the admin
// @Description Updates the admin's data
// @Security BearerAuth
// @Tags Admin
// @Accept json
// @Produce json
// @Param body body helper.SwaggerReq true "Admin update data"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {object} map[string]string "Bad Request"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /admin/updateAdmin [put]
func (h *Handler) UpdateAdmin(ctx *gin.Context) {
	var getFromSwagger helper.SwaggerReq

	if err := ctx.ShouldBindJSON(&getFromSwagger); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request", "success": false})
		return
	}

	id, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized", "success": false})
		return
	}

	req := pb.UpdateUserRequest{
		UserId:      id,
		FirstName:   getFromSwagger.FirstName,
		LastName:    getFromSwagger.LastName,
		DateOfBirth: getFromSwagger.DateOfBirth,
		PhoneNumber: getFromSwagger.PhoneNumber,
	}

	res, err := h.Auth.UpdateAdminRequest(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update admin", "success": false})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// GetProfile godoc
// @Summary Get the profile informations
// @Description Gets the all information about the user
// @Security BearerAuth
// @Tags Admin
// @Accept json
// @Produce json
// @Success 200 {object} pb.Users
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /admin/getProfile [get]
func (h *Handler) GetAdminProfile(ctx *gin.Context) {
	var req pb.ById

	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	claims, err := token.ExtractClaim(authHeader)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	userId := cast.ToString(claims["id"])
	if userId == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}

	req.UserId = userId

	res, err := h.Auth.GetAdmin(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// GetAllUsers godoc
// @Summary Get all admins
// @Description Gets all admins
// @Security BearerAuth
// @Tags Admin
// @Accept json
// @Produce json
// @Success 200 {object} pb.GetAllUsersResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /admin/getAllAdmins [get]
func (h *Handler) GetAllAdmins(ctx *gin.Context) {
	var req pb.ById

	if err := ctx.ShouldBindQuery(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request", "success": false})
		return
	}

	id, err := token.GetIdFromToken(ctx)
	if err != nil {
		return
	}

	req.UserId = id

	res, err := h.Auth.GetAllAdmins(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve admins", "success": false})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// DeleteUser godoc
// @Summary Deletes the admin by entered id
// @Description Deletes the user data
// @Security BearerAuth
// @Tags Admin
// @Accept json
// @Produce json
// @Param adminID query string true "Admin ID"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /admin/deleteAdmin [delete]
func (h *Handler) DeleteAdmin(ctx *gin.Context) {
	adminID := ctx.Query("adminID")

	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	super_admin_ID, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	req := pb.BySuperAdmin{AdminId: adminID, SuperAdminId: super_admin_ID}

	res, err := h.Auth.DeleteAdmin(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// ChangePassword godoc
// @Summary Change admin's password
// @Description Change password for a user
// @Security BearerAuth
// @Tags Admin
// @Accept json
// @Produce json
// @Param current_password query string true "Current Password"
// @Param new_password query string true "New Password"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /admin/changePassword [put]
func (h *Handler) ChangePassword(ctx *gin.Context) {
	current_password := ctx.Query("current_password")
	new_password := ctx.Query("new_password")
	admin_id, err := token.GetIdFromToken(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	req := pb.ChangePasswordRequest{
		OldPassword: current_password,
		NewPassword: new_password,
		UserId:      admin_id,
	}

	response, err := h.Auth.ChangePassword(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// ForgetPassword godoc
// @Summary Initiate password reset
// @Description Request a password reset email
// @Security BearerAuth
// @Tags Admin
// @Accept json
// @Produce json
// @Param email path string true "Admin Email"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /admin/forgetPassword/{email} [post]
func (h *Handler) ForgetPassword(ctx *gin.Context) {
	email := ctx.Param("email")
	if email == "" {
		ctx.JSON(http.StatusBadRequest, pb.InfoResponse{
			Success: false,
			Message: "Email parameter is required",
		})
		return
	}

	req := pb.EmailRequest{
		Email: email,
	}

	code, err := h.SendEmail((*pb.EmailRequest)(&req))
	if err != nil {
		panic(err)
	}

	response, err := h.StoreVerificationCodeToRedis(ctx, req.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to store verification code: " + err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// ResetPassword godoc
// @Summary Reset admin password
// @Description Reset a admin's password using a temporary password
// @Security BearerAuth
// @Tags Admin
// @Accept json
// @Produce json
// @Param body body pb.ResetPasswordRequest true "Reset password details"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /admin/resetPassword [post]
func (h *Handler) ResetPassword(ctx *gin.Context) {
	var req pb.ResetPasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	request := pb.VerifyEmailRequest{
		Email:            req.Email,
		VerificationCode: req.VerificationCode,
	}

	_, err := h.CheckTheVerificationCode(ctx, &request)
	if err != nil {
		panic(err)
	}

	response, err := h.Auth.ResetPassword(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// @Summary Enter user phone for verification
// @Description Allows users to enter their phone address for actions such as account recovery or verification. A verification code will be sent to the provided phone.
// @Security BearerAuth
// @Tags Authentication
// @Accept json
// @Produce json
// @Param phone path string true "User Phone"
// @Success 200 {object} pb.LogInAdminRequest
// @Failure 400 {string} string "Invalid input data"
// @Failure 500 {string} string "Internal server error"
// @Router /auth/enterAccountByPhone/{phone} [post]
func (h *Handler) EnterAccountByPhone(ctx *gin.Context) {
	phone := ctx.Param("phone")
	if phone == "" {
		ctx.JSON(http.StatusBadRequest, pb.InfoResponse{
			Success: false,
			Message: "Email parameter is required",
		})
		return
	}

	req := pb.PhoneRequest{
		Phone: phone,
	}

	code, err := helper.SendSms(phone)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to send phone: " + err.Error(),
		})
		return
	}

	response, err := h.StoreVerificationCodeToRedisForPhone(ctx, req.Phone, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to store verification code: " + err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// @Summary Verify user phone
// @Description Verifies a user's phone address using a verification code. If successful, returns an authentication token.
// @Security BearerAuth
// @Tags Authentication
// @Accept json
// @Produce json
// @Param phone query string true "User phone address"
// @Param verification_code query string true "Verification code sent to the user's phone"
// @Success 200 {object} pb.TokenResponse "Token generated upon successful verification"
// @Failure 400 {object} pb.InfoResponse "Invalid input or verification code"
// @Failure 500 {object} pb.InfoResponse "Internal server error"
// @Router /auth/verifyPhone [post]
func (h *Handler) VerifyPhone(ctx *gin.Context) {
	phone := ctx.Query("phone")
	code := ctx.Query("verification_code")

	user := &pb.VerifyPhoneRequest{
		UserId:           uuid.NewString(),
		Phone:            phone,
		VerificationCode: code,
		Role:             "user",
	}

	checkResponse, err := h.CheckTheVerificationCodeForPhone(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Internal server error: " + err.Error(),
		})
		return
	}

	if !checkResponse.Success {
		ctx.JSON(http.StatusBadRequest, checkResponse)
		return
	}

	response, err := h.Auth.VerifyPhone(ctx, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to verify phone: " + err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// ResetPassword godoc
// @Summary SignUp Publisher
// @Description Sign Up Publisher
// @Security BearerAuth
// @Tags Publisher
// @Accept json
// @Produce json
// @Param body body helper.SignUpPublisher true "Sign Up details"
// @Success 200 {object} pb.InfoResponse
// @Failure 400 {string} string "Bad Request"
// @Failure 500 {string} string "Internal Server Error"
// @Router /publisher/SignUpPublisher [post]
func (h *Handler) SignUpPublisher(ctx *gin.Context) {
	var request helper.SignUpPublisher
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req := pb.SignUpPublisherRequest{
		Name:        request.Name,
		Email:       request.Email,
		Password:    request.Password,
		PhoneNumber: request.Phone_number,
		Username:    request.Username,
		ImgUrl:      "",
		Role:        "publisher",
	}

	emailReq := pb.EmailRequest{
		Email: req.Email,
	}

	code, err := h.SendEmail(&emailReq)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
		return
	}

	reqData, err := proto.Marshal(&req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to serialize request data"})
		return
	}

	err = h.Rdb.Set(ctx, code, reqData, time.Minute*3).Err()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store verification code"})
		return
	}

	ctx.JSON(http.StatusOK, pb.InfoResponse{Success: true, Message: "The verification code has bee sended to your email. Please verify it!"})
}

// @Summary Verify publisher email
// @Description Verifies a publisher's email address using a verification code. If successful, returns an authentication token.
// @Security BearerAuth
// @Tags Publisher
// @Accept json
// @Produce json
// @Param email query string true "Publisher email address"
// @Param verification_code query string true "Verification code sent to the publisher's email"
// @Success 200 {object} pb.TokenResponse "Token generated upon successful verification"
// @Failure 400 {object} pb.InfoResponse "Invalid input or verification code"
// @Failure 500 {object} pb.InfoResponse "Internal server error"
// @Router /publisher/VerifyPublisherEmail [post]
func (h *Handler) VerifyPublisherEmail(ctx *gin.Context) {
	email := ctx.Query("email")
	code := ctx.Query("verification_code")

	storedData, err := h.Rdb.Get(ctx, code).Bytes()
	if err == redis.Nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verification code"})
		return
	} else if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve data"})
		return
	}

	var storedReq pb.SignUpPublisherRequest
	if err := proto.Unmarshal(storedData, &storedReq); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse stored data"})
		return
	}
	hashed, err := helper.HashPassword(storedReq.Password)
	if err != nil {
		panic(err)
	}

	if storedReq.Email != email {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email"})
		return
	}

	req := pb.VerifyPublisherEmailRequest{
		PublisherId: uuid.NewString(),
		Name:        storedReq.Name,
		Email:       email,
		Password:    hashed,
		PhoneNumber: storedReq.PhoneNumber,
		Username:    storedReq.Username,
		ImgUrl:      "",
		Role:        "publisher",
	}

	if err := h.Rdb.Del(ctx, code).Err(); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete verification code"})
		return
	}
	res, err := h.Auth.VerifyPublisherEmail(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, pb.InfoResponse{
			Success: false,
			Message: "Failed to verify email: " + err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, res)
}

// LoginPublisher handles the publisher login request
// @Summary Publisher Login
// @Description Login as an publisher user with email and password
// @Security BearerAuth
// @Tags Publisher
// @Accept  json
// @Produce  json
// @Param email query string true "Publisher email address or username"
// @Param password query string true "The password to log in"
// @Success 200 {object} pb.LoginPublisherRequest "Successful login"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Unauthorized"
// @Router /publisher/LogInPublisher [post]
func (h *Handler) LogInPublisher(ctx *gin.Context) {
	email := ctx.Query("email")
	password := ctx.Query("password")

	req := pb.LoginPublisherRequest{
		Username: email,
		Password: password,
	}

	res, err := h.Auth.LogInPublisher(ctx, &req)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized", "success": false})
		return
	}

	ctx.JSON(http.StatusOK, res)
}
