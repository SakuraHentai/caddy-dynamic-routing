package caddy_dynamic_routing

// inspired by caddyserver/caddy/modules/caddytls/certmanagers.go
import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"encoding/pem"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type RedisCertGetter struct {
	Prefix  string `json:"prefix,omitempty"`
	CertKey string `json:"certKey,omitempty"`

	redisClient  *redis.Client
	redisOptions redis.Options
	logger       *zap.SugaredLogger
}

func init() {
	caddy.RegisterModule(RedisCertGetter{})
}

// CaddyModule returns the Caddy module information.
func (rcg RedisCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.redis",
		New: func() caddy.Module { return new(RedisCertGetter) },
	}
}

// Provision implements caddy.Provisioner.
func (rcg *RedisCertGetter) Provision(ctx caddy.Context) error {
	rcg.logger = ctx.Logger().Sugar()
	rcg.redisClient = redis.NewClient(&rcg.redisOptions)

	return nil
}

func (rcg RedisCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	rcg.logger.Debugf("SNI: %s", hello.ServerName)

	// get cert from redis
	pem, err := rcg.redisClient.HGet(ctx, fmt.Sprintf("%s:%s", rcg.Prefix, hello.ServerName), rcg.CertKey).Result()
	if err != nil {
		return nil, err
	}

	// convert to X509
	cert, err := tlsCertFromCertAndKeyPEMBundle([]byte(pem))
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//		... redis {
//
//	  }
func (rcg *RedisCertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// default config
	host := "127.0.0.1"
	port := "6379"
	db := 0
	prefix := "s"
	certKey := "cert"

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
				rcg.Prefix = prefix

			case "certKey":
				if d.NextArg() {
					certKey = d.Val()
				}
				rcg.CertKey = certKey
			default:
				return d.Errf("Unknown field: %s", d.Val())
			}
		}
	}

	// prepare options for new redis
	rcg.redisOptions = redis.Options{
		Addr: strings.Join([]string{host, port}, ":"),
		DB:   db,
	}

	return nil

}

// Cleanup frees up resources allocated during Provision.
func (rcg *RedisCertGetter) Cleanup() error {
	rcg.logger.Debug("Cleaning up tls redis")
	err := rcg.redisClient.Close()
	if err != nil {
		return err
	}

	return nil
}

// Ref caddyserver/caddy/modules/caddytls/folderloader.go:84
// This func not exported by caddy
func tlsCertFromCertAndKeyPEMBundle(bundle []byte) (tls.Certificate, error) {
	certBuilder, keyBuilder := new(bytes.Buffer), new(bytes.Buffer)
	var foundKey bool // use only the first key in the file

	for {
		// Decode next block so we can see what type it is
		var derBlock *pem.Block
		derBlock, bundle = pem.Decode(bundle)
		if derBlock == nil {
			break
		}

		if derBlock.Type == "CERTIFICATE" {
			// Re-encode certificate as PEM, appending to certificate chain
			if err := pem.Encode(certBuilder, derBlock); err != nil {
				return tls.Certificate{}, err
			}
		} else if derBlock.Type == "EC PARAMETERS" {
			// EC keys generated from openssl can be composed of two blocks:
			// parameters and key (parameter block should come first)
			if !foundKey {
				// Encode parameters
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}

				// Key must immediately follow
				derBlock, bundle = pem.Decode(bundle)
				if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
					return tls.Certificate{}, fmt.Errorf("expected elliptic private key to immediately follow EC parameters")
				}
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
			// RSA key
			if !foundKey {
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else {
			return tls.Certificate{}, fmt.Errorf("unrecognized PEM block type: %s", derBlock.Type)
		}
	}

	certPEMBytes, keyPEMBytes := certBuilder.Bytes(), keyBuilder.Bytes()
	if len(certPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("failed to parse PEM data")
	}
	if len(keyPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("no private key block found")
	}

	cert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("making X509 key pair: %v", err)
	}

	return cert, nil
}

// Interface guards
var (
	_ certmagic.Manager     = (*RedisCertGetter)(nil)
	_ caddy.Provisioner     = (*RedisCertGetter)(nil)
	_ caddyfile.Unmarshaler = (*RedisCertGetter)(nil)
)
