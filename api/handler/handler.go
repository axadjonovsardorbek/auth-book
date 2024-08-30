package handler

import (
	"auth/service"

	"github.com/go-redis/redis/v8"
)

type Handler struct {
	Auth *service.AuthService
	Rdb  *redis.Client
}

func NewHandler(auth *service.AuthService, rdb redis.Client) *Handler {
	return &Handler{
		Auth: auth,
		Rdb:  &rdb,
	}
}
