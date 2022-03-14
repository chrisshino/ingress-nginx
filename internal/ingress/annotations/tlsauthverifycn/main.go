package tlsauthverifycn

import (
	"fmt"
	"regexp"

	networking "k8s.io/api/networking/v1"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	ing_errors "k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

const (
	defaultAuthTLSDepth     = 1
	defaultAuthVerifyClient = "on"
)

var (
	authVerifyClientRegex = regexp.MustCompile(`on|off|optional|optional_no_ca`)
)

type Config struct {
	CACert resolver.AuthSSLCert
}

type tlsAuthVerifyCN struct {
	r resolver.Resolver
}

// NewParser creates a new tls auth verify common name parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return tlsAuthVerifyCN{r}
}

func (t tlsAuthVerifyCN) Parse(ing *networking.Ingress) (interface{}, error) {
	var err error
	config := &Config{}

	tlsauthsecret, err := parser.GetStringAnnotation("auth-tls-secret", ing)
	if err != nil {
		return &Config{}, err
	}

	authCert, err := t.r.GetAuthCertificate(tlsauthsecret)
	if err != nil {
		e := fmt.Errorf("error obtaining certificate: %w", err)
		return &Config{}, ing_errors.LocationDenied{Reason: e}
	}

	fmt.Println(authCert)
	config.CACert = *authCert

	return config, nil
}
