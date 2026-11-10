package handler

import "github.com/jackc/pgx/v5/pgxpool"

var dbpool *pgxpool.Pool

func SetDBPool(p *pgxpool.Pool) {
	dbpool = p
}
