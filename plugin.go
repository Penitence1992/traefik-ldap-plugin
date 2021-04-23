package auth

import (
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net/http"
	"net/url"
)

const (
	defaultRealm        = "traefik"
	authorizationHeader = "Authorization"
	LdapUsernameKey     = "uid"
	contentType         = "Content-Type"
	testInfo		    = "abc"
)

// Config the plugin configuration.
type Config struct {
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	BaseDN      string `json:"baseDn"`
	UsernameKey string `json:"usernameKey"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type LdapAuth struct {
	next   http.Handler
	name   string
	config *Config

	// ...
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// ...
	return &LdapAuth{
		name:   name,
		next:   next,
		config: config,
	}, nil
}

func (b *LdapAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	user, password, ok := req.BasicAuth()
	if user == testInfo && password == testInfo {
		rw.WriteHeader(204)
		return
	}
	if ok {
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", b.config.Host, b.config.Port))
		if err != nil {
			ok = false
		} else {
			defer conn.Close()
			filter := fmt.Sprintf("((%s=%s))", b.config.UsernameKey, user)
			attributes := []string{b.config.UsernameKey}
			search := ldap.NewSearchRequest(b.config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, attributes, nil)
			cur, err := conn.Search(search)
			if err != nil || len(cur.Entries) != 1 {
				ok = false
			} else {
				ok = conn.Bind(cur.Entries[0].DN, password) == nil
			}
		}
	}

	if !ok {
		RequireAuth(rw, req)
		return
	}

	req.URL.User = url.User(user)

	req.Header["user"] = []string{user}
	req.Header.Del(authorizationHeader)

	b.next.ServeHTTP(rw, req)
}

func RequireAuth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set(contentType, "text/plan")
	w.Header().Set("WWW-Authenticate", `Basic realm="`+defaultRealm+`"`)
	w.WriteHeader(401)
	w.Write([]byte(fmt.Sprintf("%d %s\n", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))))
}
