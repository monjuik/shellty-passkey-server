package assets

import "embed"

//go:embed migrations/*.sql
var Migrations embed.FS

//go:embed templates/*.html static/*
var Admin embed.FS
