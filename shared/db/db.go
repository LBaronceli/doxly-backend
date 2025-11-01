package db

import (
	"context"
	"os"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func MustOpen(ctx context.Context, envKey string) *sqlx.DB {
	dsn := os.Getenv(envKey)
	if dsn == "" {
		panic("missing " + envKey)
	}
	db := sqlx.MustOpen("pgx", dsn)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		panic(err)
	}
	return db
}
