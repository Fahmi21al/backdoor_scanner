package project

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Project struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	TargetType   string    `json:"targetType"`
	TargetPath   string    `json:"targetPath"`
	BaselinePath string    `json:"baselinePath"`
	DbDumpPath   string    `json:"dbDumpPath"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) InitSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS sfs.projects (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name VARCHAR(255),
		target_type VARCHAR(100),
		target_path TEXT,
		baseline_path TEXT,
		db_dump_path TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := r.db.Exec(context.Background(), query)
	return err
}

func (r *Repository) Create(p *Project) error {
	query := `
		INSERT INTO sfs.projects (name, target_type, target_path, baseline_path, db_dump_path)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at
	`
	return r.db.QueryRow(context.Background(), query, p.Name, p.TargetType, p.TargetPath, p.BaselinePath, p.DbDumpPath).
		Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
}

func (r *Repository) GetAll() ([]Project, error) {
	query := `SELECT id, name, target_type, target_path, COALESCE(baseline_path, ''), COALESCE(db_dump_path, ''), created_at, updated_at FROM sfs.projects`
	rows, err := r.db.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.TargetType, &p.TargetPath, &p.BaselinePath, &p.DbDumpPath, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return projects, nil
}

func (r *Repository) GetByID(id string) (*Project, error) {
	query := `SELECT id, name, target_type, target_path, COALESCE(baseline_path, ''), COALESCE(db_dump_path, ''), created_at, updated_at FROM sfs.projects WHERE id = $1`
	var p Project
	err := r.db.QueryRow(context.Background(), query, id).
		Scan(&p.ID, &p.Name, &p.TargetType, &p.TargetPath, &p.BaselinePath, &p.DbDumpPath, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *Repository) Delete(id string) error {
	query := `DELETE FROM sfs.projects WHERE id = $1`
	res, err := r.db.Exec(context.Background(), query, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("project not found")
	}
	return nil
}
