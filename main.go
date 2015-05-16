// GoIndieAuth project main.go
package goindieauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type IndieAuth struct {
	tokens          map[string]*Token
	tokenSync       sync.Mutex
	accessTokens    map[string]*AccessToken
	accessTokenSync sync.Mutex
	LoginPage       func(rw http.ResponseWriter, req *http.Request, user, token, client_id string)
	InfoPage        func(rw http.ResponseWriter, req *http.Request)
	CheckLogin      func(rw http.ResponseWriter, req *http.Request, user, password string) bool
}

var AuthorizationRegex = regexp.MustCompile("Bearer (\\S+)")

type ResponseType int

const (
	ResponseID ResponseType = iota
	ResponseCode
)

type Token struct {
	ID           string
	me           string
	client_id    string
	redirect_uri string
	Response     ResponseType
	Scope        string
	state        string
	Authed       bool
	Expires      time.Time
}

type AccessToken struct {
	ID        string
	Me        string
	Client_id string
	Scope     []string
	Issued    time.Time
	Authed    bool
}

func New() *IndieAuth {
	ia := &IndieAuth{
		tokens:       make(map[string]*Token),
		accessTokens: make(map[string]*AccessToken),
	}
	return ia
}

func (ia *IndieAuth) AuthEndpoint(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("IndieAuth", "authorization_endpoint")
	if me := req.FormValue("me"); me != "" {
		pass := req.FormValue("password")
		id := req.FormValue("token")
		client_id := req.FormValue("client_id")
		redirect_uri := req.FormValue("redirect_uri")
		scope := req.FormValue("scope")
		state := req.FormValue("state")
		if id == "" {
			buf := make([]byte, 32)
			_, err := rand.Read(buf)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				rw.Write([]byte("Error generating Token"))
				return
			}
			id = hex.EncodeToString(buf)
		}
		token := ia.GetToken(id)
		token.me = me
		if client_id != "" {
			token.client_id = client_id
		}
		if redirect_uri != "" {
			token.redirect_uri = redirect_uri
		}
		if state != "" {
			token.state = state
		}
		if scope != "" {
			token.Scope = scope
		}
		responseType := req.FormValue("response_type")
		if responseType == "code" {
			token.Response = ResponseCode
		}
		meparsed, _ := url.Parse(me)
		if loggedin := ia.CheckLogin(rw, req, meparsed.Host, pass); loggedin {
			redirect, _ := url.Parse(token.redirect_uri)
			query := redirect.Query()
			query.Set("code", token.ID)
			query.Set("state", token.state)
			query.Set("me", me)
			redirect.RawQuery = query.Encode()
			token.Authed = true
			token.Expires = time.Now().Add(10 * time.Minute)
			ia.SaveToken(token.ID, token)
			http.Redirect(rw, req, redirect.String(), http.StatusSeeOther)
			return
		}
		ia.SaveToken(token.ID, token)
		ia.LoginPage(rw, req, me, token.ID, client_id)
	} else if code := req.FormValue("code"); code != "" {
		client_id := req.FormValue("client_id")
		redirect_uri := req.FormValue("redirect_uri")
		state := req.FormValue("state")
		token := ia.GetToken(code)
		if token.client_id == client_id && token.redirect_uri == redirect_uri && token.state == state && token.Authed && token.Expires.After(time.Now()) {
			values := &url.Values{}
			values.Set("me", token.me)
			if token.Response == ResponseCode {
				values.Set("scope", token.Scope)
			}
			rw.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			rw.WriteHeader(http.StatusOK)
			rw.Write([]byte(values.Encode()))
			return
		}
		rw.WriteHeader(http.StatusBadRequest)
	} else {
		ia.InfoPage(rw, req)
	}
}

func (ia *IndieAuth) TokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	if token := ia.GetReqAccessToken(req); token != nil {
		values := &url.Values{}
		values.Set("me", token.Me)
		values.Set("client_id", token.Client_id)
		values.Set("scope", strings.Join(token.Scope, " "))
		values.Set("issued_at", fmt.Sprintf("%d", token.Issued.Unix()))
		values.Set("nonce", "nonce")
		rw.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(values.Encode()))
		return
	}
	code := req.FormValue("code")
	client_id := req.FormValue("client_id")
	redirect_uri := req.FormValue("redirect_uri")
	state := req.FormValue("state")
	token := ia.GetToken(code)
	if token.client_id == client_id && token.redirect_uri == redirect_uri && token.state == state && token.Authed && token.Expires.After(time.Now()) {
		values := &url.Values{}
		at := ia.GetAccessToken(token.ID)
		at.Client_id = token.client_id
		at.Issued = time.Now()
		at.Me = token.me
		at.Scope = strings.Split(token.Scope, " ")
		at.Authed = true
		ia.SaveAccessToken(token.ID, at)
		values.Set("me", token.me)
		values.Set("access_token", token.ID)
		values.Set("scope", token.Scope)
		rw.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(values.Encode()))
		return
	}
	rw.WriteHeader(http.StatusBadRequest)
}

func (ia *IndieAuth) GetToken(id string) *Token {
	ia.tokenSync.Lock()
	defer ia.tokenSync.Unlock()
	token, ok := ia.tokens[id]
	if !ok {
		token = &Token{
			ID: id,
		}
	}
	return token
}

func (ia *IndieAuth) SaveToken(id string, token *Token) {
	ia.tokenSync.Lock()
	defer ia.tokenSync.Unlock()
	ia.tokens[id] = token
}

func (ia *IndieAuth) DeleteToken(id string) {
	ia.tokenSync.Lock()
	defer ia.tokenSync.Unlock()
	delete(ia.tokens, id)
}

func (ia *IndieAuth) GetAccessToken(id string) *AccessToken {
	ia.accessTokenSync.Lock()
	defer ia.accessTokenSync.Unlock()
	token, ok := ia.accessTokens[id]
	if !ok {
		token = &AccessToken{
			ID: id,
		}
	}
	return token
}

func (ia *IndieAuth) SaveAccessToken(id string, token *AccessToken) {
	ia.accessTokenSync.Lock()
	defer ia.accessTokenSync.Unlock()
	ia.accessTokens[id] = token
}

func (ia *IndieAuth) DeleteAccessToken(id string) {
	ia.tokenSync.Lock()
	defer ia.tokenSync.Unlock()
	delete(ia.tokens, id)
}

func (ia *IndieAuth) GetReqAccessToken(req *http.Request) *AccessToken {
	for _, header := range req.Header["Authorization"] {
		matches := AuthorizationRegex.FindStringSubmatch(header)
		if matches != nil {
			token := ia.GetAccessToken(matches[1])
			if !token.Authed {
				return nil
			}
			return token
		}
	}
	token := ia.GetAccessToken(req.FormValue("access_token"))
	if !token.Authed {
		return nil
	}
	return token
}
