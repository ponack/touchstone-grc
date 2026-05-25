package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Env       string
	BaseURL   string
	SecretKey string

	Postgres PostgresConfig
	MinIO    MinIOConfig
	OIDC     OIDCConfig
	Local    LocalAuthConfig

	ScannerAPIURL string
}

type PostgresConfig struct {
	Host     string
	Port     string
	DB       string
	User     string
	Password string
}

type MinIOConfig struct {
	Endpoint         string
	AccessKey        string
	SecretKey        string
	BucketEvidence   string
	BucketArtifacts  string
	UseSSL           bool
}

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type LocalAuthConfig struct {
	Enabled  bool
	Email    string
	Password string
}

// Load reads configuration from env vars (TOUCHSTONE_* / POSTGRES_* / MINIO_* /
// OIDC_* / LOCAL_AUTH_* / SCANNER_*). Every field needs a SetDefault for
// AutomaticEnv to bind it — same gotcha as Crucible.
func Load() (*Config, error) {
	v := viper.New()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("touchstone_env", "production")
	v.SetDefault("touchstone_base_url", "")
	v.SetDefault("touchstone_secret_key", "")

	v.SetDefault("postgres_host", "postgres")
	v.SetDefault("postgres_port", "5432")
	v.SetDefault("postgres_db", "touchstone")
	v.SetDefault("postgres_user", "touchstone")
	v.SetDefault("postgres_password", "")

	v.SetDefault("minio_endpoint", "minio:9000")
	v.SetDefault("minio_access_key", "minioadmin")
	v.SetDefault("minio_secret_key", "")
	v.SetDefault("minio_bucket_evidence", "touchstone-evidence")
	v.SetDefault("minio_bucket_artifacts", "touchstone-artifacts")
	v.SetDefault("minio_use_ssl", false)

	v.SetDefault("oidc_issuer_url", "")
	v.SetDefault("oidc_client_id", "")
	v.SetDefault("oidc_client_secret", "")
	v.SetDefault("oidc_redirect_url", "")

	v.SetDefault("local_auth_enabled", false)
	v.SetDefault("local_auth_email", "")
	v.SetDefault("local_auth_password", "")

	v.SetDefault("scanner_api_url", "http://touchstone-api:8080")

	cfg := &Config{
		Env:       v.GetString("touchstone_env"),
		BaseURL:   v.GetString("touchstone_base_url"),
		SecretKey: v.GetString("touchstone_secret_key"),
		Postgres: PostgresConfig{
			Host:     v.GetString("postgres_host"),
			Port:     v.GetString("postgres_port"),
			DB:       v.GetString("postgres_db"),
			User:     v.GetString("postgres_user"),
			Password: v.GetString("postgres_password"),
		},
		MinIO: MinIOConfig{
			Endpoint:        v.GetString("minio_endpoint"),
			AccessKey:       v.GetString("minio_access_key"),
			SecretKey:       v.GetString("minio_secret_key"),
			BucketEvidence:  v.GetString("minio_bucket_evidence"),
			BucketArtifacts: v.GetString("minio_bucket_artifacts"),
			UseSSL:          v.GetBool("minio_use_ssl"),
		},
		OIDC: OIDCConfig{
			IssuerURL:    v.GetString("oidc_issuer_url"),
			ClientID:     v.GetString("oidc_client_id"),
			ClientSecret: v.GetString("oidc_client_secret"),
			RedirectURL:  v.GetString("oidc_redirect_url"),
		},
		Local: LocalAuthConfig{
			Enabled:  v.GetBool("local_auth_enabled"),
			Email:    v.GetString("local_auth_email"),
			Password: v.GetString("local_auth_password"),
		},
		ScannerAPIURL: v.GetString("scanner_api_url"),
	}

	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("TOUCHSTONE_SECRET_KEY is required")
	}
	if cfg.Postgres.Password == "" {
		return nil, fmt.Errorf("POSTGRES_PASSWORD is required")
	}
	return cfg, nil
}

func (p PostgresConfig) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		p.User, p.Password, p.Host, p.Port, p.DB)
}
