package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/monjuik/shellty-passkey-server/passkeys"
)

const databaseTimeout = 3 * time.Second

func Run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("passkey-server", flag.ContinueOnError)
	flags.SetOutput(output)
	listen := flags.String("listen", ":8443", "HTTPS listen address or port")
	configFile := flags.String("config", "", "product JSON configuration")
	dsn := flags.String("database-dsn", "", "PostgreSQL connection string")
	cert := flags.String("tls-cert", "", "TLS certificate file")
	key := flags.String("tls-key", "", "TLS key file")
	ca := flags.String("client-ca", "", "trusted client CA PEM file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *configFile == "" || *dsn == "" {
		return fmt.Errorf("config and database-dsn are required; positional arguments are not supported")
	}
	if _, err := net.LookupPort("tcp", *listen); err == nil {
		*listen = ":" + *listen
	}
	if _, _, err := net.SplitHostPort(*listen); err != nil {
		return fmt.Errorf("invalid listen address")
	}
	file, err := os.Open(*configFile)
	if err != nil {
		return fmt.Errorf("open product configuration: %w", err)
	}
	config, err := LoadConfig(file)
	_ = file.Close()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(output, nil))
	tlsConfig, err := TLSConfig(*cert, *key, *ca)
	if err != nil {
		return err
	}
	poolConfig, err := pgxpool.ParseConfig(*dsn)
	if err != nil {
		return fmt.Errorf("invalid database DSN")
	}
	poolConfig.ConnConfig.ConnectTimeout = databaseTimeout
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return fmt.Errorf("initialize database pool")
	}
	defer pool.Close()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = Migrate(startup, pool)
	cancel()
	if err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}
	webauthn, err := passkeys.NewWebAuthn(config.Applications)
	if err != nil {
		return err
	}
	service := passkeys.NewService(config.Applications, passkeys.NewPostgres(pool), webauthn)
	ready := func(ctx context.Context) error { return CheckSchema(ctx, pool) }
	admin, err := newAdmin(config, &adminPostgres{pool}, logger)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           Handler(service, ready, logger, admin),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	logger.Info("server ready", "listen", listener.Addr().String())
	select {
	case err = <-done:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err = server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}
