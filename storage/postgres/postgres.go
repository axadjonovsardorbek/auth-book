package postgres

import (
	"auth/config"
	stg "auth/storage"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Storage struct {
	Db   *sql.DB
	auth stg.AuthService
}

func NewPostgresStorage(cfg config.Config) (stg.InitRoot, error) {
	con := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.PostgresUser, cfg.PostgresPassword,
		cfg.PostgresHost, cfg.PostgresPort,
		cfg.PostgresDatabase)
	db, err := sql.Open("postgres", con)
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return &Storage{Db: db}, nil
}

func (s *Storage) Auth() stg.AuthService {
	if s.auth == nil {
		s.auth = &AuthStorage{db: s.Db}
	}
	return s.auth
}
