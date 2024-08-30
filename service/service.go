package service

import (
	"context"
	"log"

	pb "auth/genproto/auth"
	stg "auth/storage"
)

type AuthService struct {
	stg stg.InitRoot
	pb.UnimplementedAuthServiceServer
}

func NewAuthService(stg stg.InitRoot) *AuthService {
	return &AuthService{
		stg: stg,
	}
}

func (s *AuthService) EnterAccount(ctx context.Context, req *pb.EmailRequest) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().EnterAccount(req)
	if err != nil {
		log.Println("Error changing email: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.TokenResponse, error) {
	resp, err := s.stg.Auth().VerifyEmail(req)
	if err != nil {
		log.Println("Error verifying email: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) VerifyPhone(ctx context.Context, req *pb.VerifyPhoneRequest) (*pb.TokenResponse, error) {
	resp, err := s.stg.Auth().VerifyPhone(req)
	if err != nil {
		log.Println("Error verifying email: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, req *pb.ById) (*pb.TokenResponse, error) {
	resp, err := s.stg.Auth().RefreshToken(req)
	if err != nil {
		log.Println("Error refreshing token: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) ChangeEmail(ctx context.Context, req *pb.ChangeEmailRequest) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().ChangeEmail(req)
	if err != nil {
		log.Println("Error changing email: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) CompleteChangeEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.TokenResponse, error) {
	resp, err := s.stg.Auth().CompleteChangeEmail(req)
	if err != nil {
		log.Println("Error changing email: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().UpdateUser(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) GetProfile(ctx context.Context, req *pb.ById) (*pb.Users, error) {
	resp, err := s.stg.Auth().GetProfile(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) GetAllUsers(ctx context.Context, req *pb.ById) (*pb.GetAllUsersResponse, error) {
	resp, err := s.stg.Auth().GetAllUsers(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) DeleteUser(ctx context.Context, req *pb.ById) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().DeleteUser(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) DeleteUserByAdmin(ctx context.Context, req *pb.ByAdmin) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().DeleteUserByAdmin(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) CreateAdmin(ctx context.Context, req *pb.EmailRequest) (*pb.LogInAdminRequest, error) {
	resp, err := s.stg.Auth().CreateAdmin(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) LogInAdmin(ctx context.Context, req *pb.LogInAdminRequest) (*pb.TokenResponse, error) {
	resp, err := s.stg.Auth().LogInAdmin(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) UpdateAdminRequest(ctx context.Context, req *pb.UpdateUserRequest) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().UpdateAdmin(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().ChangePassword(req)
	if err != nil {
		log.Println("Error changing password: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().ResetPassword(req)
	if err != nil {
		log.Println("Error resetting password: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) GetAdmin(ctx context.Context, req *pb.ById) (*pb.Users, error) {
	resp, err := s.stg.Auth().GetAdmin(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) GetAllAdmins(ctx context.Context, req *pb.ById) (*pb.GetAllUsersResponse, error) {
	resp, err := s.stg.Auth().GetAllAdmins(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) DeleteAdmin(ctx context.Context, req *pb.BySuperAdmin) (*pb.InfoResponse, error) {
	resp, err := s.stg.Auth().DeleteAdmin(req)
	if err != nil {
		log.Println("Error while getting the profile: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) VerifyPublisherEmail(ctx context.Context, req *pb.VerifyPublisherEmailRequest) (*pb.TokenResponse, error) {
	resp, err := s.stg.Auth().VerifyPublisherEmail(req)
	if err != nil {
		log.Println("Error verifying email: ", err)
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) LogInPublisher(ctx context.Context, req *pb.LoginPublisherRequest) (*pb.TokenResponse, error) {
	resp, err := s.stg.Auth().LogInPublisher(req)
	if err != nil {
		log.Println("Error verifying email: ", err)
		return nil, err
	}
	return resp, nil
}
