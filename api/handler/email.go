package handler

import (
	"context"
	"fmt"
	"time"

	"auth/config"
	pb "auth/genproto/auth"

	"auth/api/helper"

	"math/rand"

	"github.com/go-redis/redis/v8"
)

func (h *Handler) SendEmail(req *pb.EmailRequest) (string, error) {
	cfg := config.Load()

	rand.Seed(time.Now().UnixNano())

	code := rand.Intn(899999) + 100000

	from := "muhammadjonxudaynazarov226@gmail.com"
	password := cfg.EMAIL_PASSWORD
	err := helper.SendVerificationCode(helper.Params{
		From:     from,
		Password: password,
		To:       req.Email,
		Message:  fmt.Sprintf("Hi, here is your verification code: %d", code),
		Code:     fmt.Sprint(code),
	})
	if err != nil {
		return "", fmt.Errorf("failed to send verification email: %v", err)
	}

	return fmt.Sprint(code), nil
}

func (h *Handler) StoreVerificationCodeToRedis(ctx context.Context, email string, code string) (*pb.InfoResponse, error) {
	err := h.Rdb.Set(ctx, code, email, time.Minute*3).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store verification code in Redis: %v", err)
	}

	return &pb.InfoResponse{
		Success: true,
		Message: "The verification code has been sent to your email. Please verify it.",
	}, nil
}

func (h *Handler) StoreVerificationCodeToRedisForPhone(ctx context.Context, email string, code string) (*pb.InfoResponse, error) {
	err := h.Rdb.Set(ctx, code, email, time.Minute*3).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to store verification code in Redis: %v", err)
	}

	return &pb.InfoResponse{
		Success: true,
		Message: "The verification code has been sent to your phone. Please verify it.",
	}, nil
}

func (h *Handler) CheckTheVerificationCode(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.InfoResponse, error) {
	storedEmail, err := h.Rdb.Get(ctx, req.VerificationCode).Result()
	if err == redis.Nil {
		return &pb.InfoResponse{
			Message: "Verification code is invalid or expired",
			Success: false,
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to retrieve verification code from Redis: %v", err)
	}

	if storedEmail != req.Email {
		return &pb.InfoResponse{
			Message: "Email does not match the verification code",
			Success: false,
		}, nil
	}

	err = h.Rdb.Del(ctx, req.VerificationCode).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to delete verification code from Redis: %v", err)
	}

	return &pb.InfoResponse{
		Message: "Verification code is valid",
		Success: true,
	}, nil
}

func (h *Handler) CheckTheVerificationCodeForPhone(ctx context.Context, req *pb.VerifyPhoneRequest) (*pb.InfoResponse, error) {
	storedEmail, err := h.Rdb.Get(ctx, req.VerificationCode).Result()
	if err == redis.Nil {
		return &pb.InfoResponse{
			Message: "Verification code is invalid or expired",
			Success: false,
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to retrieve verification code from Redis: %v", err)
	}

	if storedEmail != req.Phone {
		return &pb.InfoResponse{
			Message: "Phone does not match the verification code",
			Success: false,
		}, nil
	}

	err = h.Rdb.Del(ctx, req.VerificationCode).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to delete verification code from Redis: %v", err)
	}

	return &pb.InfoResponse{
		Message: "Verification code is valid",
		Success: true,
	}, nil
}
