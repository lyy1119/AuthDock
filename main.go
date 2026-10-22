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
	"path/filepath"
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
	portalAddr := flag.String("portal-addr", envOr("AUTH_DOCK_PORTAL_ADDR", "127.0.0.1:8081"),
		"listen address of the user login portal")
	noDNCheck := flag.Bool("no-dn-check", false,
		"skip the gateway domain check on the user portal (debug only)")
	showVersion := flag.Bool("version", false, "print version information and exit")
	resetAdminPassword := flag.Bool("reset-admin-password", false,
		"give the admin account a new random password (creating the account if needed), print it once and exit")
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

	// Report and banner the absolute path: a relative path makes it far too easy
	// to end up with two databases (one per working directory) and two different
	// bootstrap passwords.
	dbFile := *dbPath
	if abs, err := filepath.Abs(*dbPath); err == nil {
		dbFile = abs
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if *resetAdminPassword {
		password, created, err := db.ResetAdminPassword(ctx)
		if err != nil {
			return fmt.Errorf("reset admin password: %w", err)
		}
		printResetBanner(dbFile, store.BootstrapAdminUsername, created, password)
		return nil
	}

	password, created, err := db.SeedBootstrapAdmin(ctx)
	if err != nil {
		return fmt.Errorf("seed bootstrap administrator: %w", err)
	}
	if created {
		printBootstrapCredentials(dbFile, store.BootstrapAdminUsername, password)
		// Drop the reference as soon as the banner is written; the plaintext is
		// not needed again and is never logged through slog.
		password = ""
	} else {
		users, err := db.CountUsers(ctx)
		if err != nil {
			return fmt.Errorf("count users: %w", err)
		}
		logger.Info("users table already initialized; the bootstrap password is not printed again",
			"users", users, "db", dbFile,
			"hint", "run `authdock -reset-admin-password` if that password was lost or never saved")
	}

	// The management UI and the user portal share one session store, so signing
	// in at the portal also satisfies the admin API for an admin account.
	options := httpapi.Options{
		Store:     db,
		Sessions:  httpapi.NewSessionStore(httpapi.DefaultSessionTTL),
		Limiter:   httpapi.NewAttemptLimiter(5, time.Minute, 15*time.Minute),
		Logger:    logger,
		NoDNCheck: *noDNCheck,
	}

	adminSrv := &http.Server{
		Addr:              *addr,
		Handler:           httpapi.New(options),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	portalSrv := &http.Server{
		Addr:              *portalAddr,
		Handler:           httpapi.NewPortal(options),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 2)
	go func() {
		logger.Info("AuthDock listening", "version", version, "addr", *addr, "db", dbFile,
			"login_page", "http://"+*addr+"/login")
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("admin listener: %w", err)
		}
	}()
	go func() {
		domainCheck := "on"
		if *noDNCheck {
			domainCheck = "off (-no-dn-check)"
		}
		logger.Info("AuthDock portal listening", "addr", *portalAddr, "domain_check", domainCheck)
		if err := portalSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("portal listener: %w", err)
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
	for _, srv := range []*http.Server{adminSrv, portalSrv} {
		if err := srv.Shutdown(stopCtx); err != nil {
			return fmt.Errorf("shutdown %s: %w", srv.Addr, err)
		}
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
  登录时只填冒号右边这 8 个字符，不要带空格或 "password :" 前缀。
  忘记密码可随时执行：authdock -reset-admin-password
  database : %s
%s

`, bannerRule, username, password, dbPath, bannerRule)
}

// printResetBanner writes the one-time replacement password for the admin
// account after -reset-admin-password.
func printResetBanner(dbFile, username string, created bool, password string) {
	headline := "已重置管理员密码（Only show once）"
	if created {
		headline = "users 表中没有 admin 账号，已创建并生成密码（Only show once）"
	}
	fmt.Fprintf(os.Stdout, `
%s
  %s

    username : %s
    password : %s

  该密码只显示这一次，请立即保存；数据库中只保存 Argon2id 哈希。
  登录时只填冒号右边这 8 个字符，不要带空格或 "password :" 前缀。
  database : %s
%s

`, bannerRule, headline, username, password, dbFile, bannerRule)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
