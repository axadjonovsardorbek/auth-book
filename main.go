package main

import (
	"auth/api"
	"auth/api/handler"
	"auth/config"
	"auth/service"
	"auth/storage/postgres"
	"fmt"
	"log"

	_ "auth/docs"

	"github.com/go-redis/redis/v8"
)

func main() {
	cfg := config.Load()

	stg, err := postgres.NewPostgresStorage(cfg)
	if err != nil {
		log.Fatalln("Error while connecting to database", err)
	}
	log.Println("Database connected successfully! ")

	as := service.NewAuthService(stg)
	rdb := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.REDIS_HOST, cfg.REDIS_PORT),
	})

	h := handler.NewHandler(as, *rdb)
	r := api.NewGin(h)

	err = r.Run(cfg.HTTP_PORT)
	if err != nil {
		log.Fatalln("Error while running server: ", err.Error())
	}

}
