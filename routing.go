package caddy_dynamic_routing

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("routing", parseCaddyfile)
}

type Middleware struct {
	Prefix   string `json:"prefix,omitempty"`
	TokenKey string `json:"tokenKey,omitempty"`
	Domain   string `json:"domain"`

	ctx          context.Context
	redisClient  *redis.Client
	redisOptions redis.Options
	logger       *zap.SugaredLogger
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.routing",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.ctx = ctx
	m.logger = ctx.Logger().Sugar()
	m.redisClient = redis.NewClient(&m.redisOptions)

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// get token from redis
	token, err := m.redisClient.HGet(m.ctx, fmt.Sprintf("%s:%s", m.Prefix, r.Host), m.TokenKey).Result()
	if err != nil {
		return err
	}

	if token != "" {
		newHost := strings.Replace(m.Domain, "{{token}}", token, 1)
		m.logger.Debugf("Replacing %s to %s", r.Host, newHost)
		r.Host = newHost
	}

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// default config
	host := "127.0.0.1"
	port := "6379"
	db := 0
	prefix := "s"
	tokenKey := "token"

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "host":
				if d.NextArg() {
					host = d.Val()
				}
			case "port":
				if d.NextArg() {
					port = d.Val()
				}
			case "db":
				if d.NextArg() {
					parsedDb, err := strconv.Atoi(d.Val())
					if err != nil {
						return d.ArgErr()
					}
					db = parsedDb
				}
			case "prefix":
				if d.NextArg() {
					prefix = d.Val()
				}
				m.Prefix = prefix
			case "domain":
				if !d.NextArg() {
					return d.Err("expect domain value")
				}
				m.Domain = d.Val()
			case "tokenKey":
				if d.NextArg() {
					tokenKey = d.Val()
				}
				m.TokenKey = tokenKey
			default:
				return d.Errf("Unknown field: %s", d.Val())
			}
		}
	}

	// prepare options for new redis
	m.redisOptions = redis.Options{
		Addr: strings.Join([]string{host, port}, ":"),
		DB:   db,
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Cleanup frees up resources allocated during Provision.
func (m *Middleware) Cleanup() error {
	m.logger.Debug("Cleaning up routing redis")
	err := m.redisClient.Close()
	if err != nil {
		return err
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
