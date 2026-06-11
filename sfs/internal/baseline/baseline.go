package baseline

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Baseline struct {
	ID         string    `json:"id"`
	ProjectID  string    `json:"projectId"`
	Name       string    `json:"name"`
	SourcePath string    `json:"sourcePath"`
	Version    string    `json:"version"`
	CreatedAt  time.Time `json:"createdAt"`
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) InitSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS sfs.baselines (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		project_id UUID NOT NULL,
		name VARCHAR(255),
		source_path TEXT,
		version VARCHAR(100),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (project_id) REFERENCES sfs.projects(id) ON DELETE CASCADE
	);
	`
	_, err := r.db.Exec(context.Background(), query)
	return err
}

func (r *Repository) Create(b *Baseline) error {
	query := `
		INSERT INTO sfs.baselines (project_id, name, source_path, version)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`
	return r.db.QueryRow(context.Background(), query, b.ProjectID, b.Name, b.SourcePath, b.Version).
		Scan(&b.ID, &b.CreatedAt)
}

func (r *Repository) GetAll() ([]Baseline, error) {
	query := `SELECT id, project_id, name, source_path, version, created_at FROM sfs.baselines`
	rows, err := r.db.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var baselines []Baseline
	for rows.Next() {
		var b Baseline
		if err := rows.Scan(&b.ID, &b.ProjectID, &b.Name, &b.SourcePath, &b.Version, &b.CreatedAt); err != nil {
			return nil, err
		}
		baselines = append(baselines, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return baselines, nil
}
