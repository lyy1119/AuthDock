// Command AuthDock is a small SSO pedestal: one SQLite database, one users
// table and an admin-only login for the management area.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lyy1119/AuthDock/internal/httpapi"
	"github.com/lyy1119/AuthDock/internal/passwd"
	"github.com/lyy1119/AuthDock/internal/store"
)

const bannerRule = "──────────────────────────────────────────────────────────────────────"

// Build metadata. Release builds inject real values through
// -ldflags "-X main.version=... -X main.commit=... -X main.buildDate=...";
// the defaults describe a plain `go build`.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := run(); err != nil {
		slog.Error("AuthDock stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", envOr("AUTH_DOCK_ADDR", "127.0.0.1:8080"), "HTTP listen address")
	dbPath := flag.String("db", envOr("AUTH_DOCK_DB", "data/authdock.db"), "path to the SQLite database file")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("AuthDock %s (commit %s, built %s)\n", version, commit, buildDate)
		return nil
	}

	setSecureUmask()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	hasher, err := passwd.NewHasher(passwd.DefaultParams())
	if err != nil {
		return fmt.Errorf("configure password hasher: %w", err)
	}

	db, err := store.Open(*dbPath, hasher)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, cancelSeed := context.WithTimeout(context.Background(), 30*time.Second)
	password, created, err := db.SeedBootstrapAdmin(ctx)
	cancelSeed()
	if err != nil {
		return fmt.Errorf("seed bootstrap administrator: %w", err)
	}
	if created {
		printBootstrapCredentials(*dbPath, store.BootstrapAdminUsername, password)
		// Drop the reference as soon as the banner is written; the plaintext is
		// not needed again and is never logged through slog.
		password = ""
	}

	handler := httpapi.New(httpapi.Options{
		Store:    db,
		Sessions: httpapi.NewSessionStore(httpapi.DefaultSessionTTL),
		Limiter:  httpapi.NewAttemptLimiter(5, time.Minute, 15*time.Minute),
		Logger:   logger,
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("AuthDock listening", "version", version, "addr", *addr, "db", *dbPath, "login_page", "http://"+*addr+"/login")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("serve http: %w", err)
	case <-shutdownCtx.Done():
	}

	logger.Info("shutting down")
	stopCtx, cancelStop := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStop()
	if err := srv.Shutdown(stopCtx); err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}
	return nil
}

// printBootstrapCredentials writes the one-time administrator password to
// stdout. The plaintext only ever exists here: the database stores an Argon2id
// hash, so the password cannot be recovered later.
func printBootstrapCredentials(dbPath, username, password string) {
	fmt.Fprintf(os.Stdout, `
%s
  AuthDock 已初始化默认管理员账号（users 表原本为空）

    username : %s
    password : %s

  Only show once —— 该密码只显示这一次，请立即保存到安全的地方。
  数据库中只保存 Argon2id 哈希，关闭本提示后无法再取回该密码。
  （如需重置，请在数据库中删除该行后重启，程序会重新生成。）
  database : %s
%s

`, bannerRule, username, password, dbPath, bannerRule)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
