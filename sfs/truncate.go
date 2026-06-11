package main
import (
	"context"
	"log"
	"github.com/jackc/pgx/v5"
)
func main() {
	conn, _ := pgx.Connect(context.Background(), "postgres://postgres:postgres@localhost:5432/sfs?sslmode=disable")
	conn.Exec(context.Background(), "TRUNCATE TABLE sfs.projects CASCADE;")
	log.Println("Done")
}
