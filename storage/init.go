package storage

import (
	"auth/genproto/auth"
)

type InitRoot interface {
	Auth() AuthService
}

type AuthService interface {
	EnterAccount(req *auth.EmailRequest) (*auth.InfoResponse, error)
	VerifyEmail(req *auth.VerifyEmailRequest) (*auth.TokenResponse, error)
	VerifyPhone(req *auth.VerifyPhoneRequest) (*auth.TokenResponse, error)
	RefreshToken(req *auth.ById) (*auth.TokenResponse, error)
	ChangeEmail(req *auth.ChangeEmailRequest) (*auth.InfoResponse, error)
	CompleteChangeEmail(req *auth.VerifyEmailRequest) (*auth.TokenResponse, error)
	// --------------------------------------------------------------------
	UpdateUser(req *auth.UpdateUserRequest) (*auth.InfoResponse, error)
	GetProfile(req *auth.ById) (*auth.Users, error)
	GetAllUsers(req *auth.ById) (*auth.GetAllUsersResponse, error)
	DeleteUser(req *auth.ById) (*auth.InfoResponse, error)
	DeleteUserByAdmin(req *auth.ByAdmin) (*auth.InfoResponse, error)
	// --------------------------------------------------------------------
	CreateAdmin(req *auth.EmailRequest) (*auth.LogInAdminRequest, error)
	LogInAdmin(req *auth.LogInAdminRequest) (*auth.TokenResponse, error)
	UpdateAdmin(req *auth.UpdateUserRequest) (*auth.InfoResponse, error)
	ChangePassword(req *auth.ChangePasswordRequest) (*auth.InfoResponse, error)
	ResetPassword(req *auth.ResetPasswordRequest) (*auth.InfoResponse, error)
	GetAdmin(req *auth.ById) (*auth.Users, error)
	GetAllAdmins(req *auth.ById) (*auth.GetAllUsersResponse, error)
	DeleteAdmin(req *auth.BySuperAdmin) (*auth.InfoResponse, error)
	//--------------------------------------------------------------------
	VerifyPublisherEmail(req *auth.VerifyPublisherEmailRequest) (*auth.TokenResponse, error)
	LogInPublisher(req *auth.LoginPublisherRequest) (*auth.TokenResponse, error)
}
