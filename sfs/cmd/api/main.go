package main

import (
	"context"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"

	"sfs/internal/baseline"
	"sfs/internal/database"
	"sfs/internal/project"
	"sfs/internal/scan"
	"sfs/internal/attacksurface"
	"sfs/internal/vulnerability"
)

func createDBIfNotExists() {
	connStr := "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		log.Fatalf("Unable to connect to default database: %v", err)
	}
	defer conn.Close(context.Background())

	var exists bool
	err = conn.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'sfs')").Scan(&exists)
	if err != nil {
		log.Fatalf("Failed to check if database exists: %v", err)
	}

	if !exists {
		_, err = conn.Exec(context.Background(), "CREATE DATABASE sfs")
		if err != nil {
			log.Fatalf("Failed to create database: %v", err)
		}
		log.Println("Database 'sfs' created successfully.")
	}
}

func main() {
	// Auto create database
	createDBIfNotExists()

	// Initialize database connection
	connString := "postgres://postgres:postgres@localhost:5432/sfs?sslmode=disable"
	dbPool, err := database.Connect(connString)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer dbPool.Close()

	// Initialize Repositories and schemas
	projectRepo := project.NewRepository(dbPool)
	if err := projectRepo.InitSchema(); err != nil {
		log.Fatalf("Failed to init project schema: %v", err)
	}

	baselineRepo := baseline.NewRepository(dbPool)
	if err := baselineRepo.InitSchema(); err != nil {
		log.Fatalf("Failed to init baseline schema: %v", err)
	}

	// Seeder
	projects, err := projectRepo.GetAll()
	if err == nil && len(projects) == 0 {
		log.Println("Seeding default project and baseline...")
		p := &project.Project{
			Name:         "OJS Production",
			TargetType:   "ojs",
			TargetPath:   "C:\\Users\\Puskom\\Downloads\\project fahmi\\Forensics scanner system\\sfs\\dummy_target",
			BaselinePath: "C:\\Users\\Puskom\\Downloads\\project fahmi\\Forensics scanner system\\sfs\\dummy_baseline",
		}
		if err := projectRepo.Create(p); err == nil {
			b := &baseline.Baseline{
				ProjectID:  p.ID,
				Name:       "OJS 3.3.0 Clean",
				SourcePath: "C:\\Users\\Puskom\\Downloads\\project fahmi\\Forensics scanner system\\sfs\\dummy_baseline",
				Version:    "3.3.0",
			}
			baselineRepo.Create(b)
		}
	}

	// Initialize Handlers
	projectHandler := project.NewHandler(projectRepo)
	baselineHandler := baseline.NewHandler(baselineRepo)
	scanHandler := scan.NewHandler(projectRepo)

	// Setup Gin router
	r := gin.Default()

	// Serve static files for frontend dashboard and reports
	r.Static("/web", "./web")
	r.Static("/reports", "./reports")
	r.GET("/", func(c *gin.Context) {
		c.Redirect(302, "/web/index.html")
	})

	// API Routes (v1)
	api := r.Group("/api/v1")
	{
		// Projects
		api.GET("/projects", projectHandler.GetProjects)
		api.GET("/projects/:id", projectHandler.GetProject)
		api.POST("/projects", projectHandler.CreateProject)
		api.DELETE("/projects/:id", projectHandler.DeleteProject)

		// System Helpers
		api.GET("/system/pick-path", projectHandler.PickPath)

		// Baselines
		api.GET("/baselines", baselineHandler.GetBaselines)
		api.POST("/baselines", baselineHandler.CreateBaseline)

		// Scans
		api.GET("/scans/stream", scanHandler.StreamScan)

		// Attack Surface Discovery
		api.POST("/attack-surface/discover", attacksurface.DiscoverHandler)

		// Vulnerability Assessment
		api.POST("/vulnerability/scan", vulnerability.ScanHandler)
	}

	// Start server
	log.Println("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
