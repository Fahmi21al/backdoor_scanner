package database

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

func Connect(connString string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	DB = pool
	log.Println("Successfully connected to the database.")
	
	// Ensure schema sfs exists
	_, err = pool.Exec(context.Background(), "CREATE SCHEMA IF NOT EXISTS sfs;")
	if err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}
	
	return pool, nil
}
