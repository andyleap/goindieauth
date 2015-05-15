// GoIndieAuth project main.go
package goindieauth

import (
	"crypto/rand"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type IndieAuth struct {
	tokens     map[string]*Token
	tokenSync  sync.Mutex
	LoginPage  func(rw http.ResponseWriter, user, token, client_id string)
	InfoPage   func(rw http.ResponseWriter)
	CheckLogin func(user, password string) bool
}

type ResponseType int

const (
	ResponseID ResponseType = iota
	ResponseCode
)

type Token struct {
	ID           string
	me           string
	client_id    string
	redirect_url string
	Response     ResponseType
	Scope        string
	state        string
	Authed       bool
	Expires      time.Time
}

func New() *IndieAuth {
	ia := &IndieAuth{
		tokens:    make(map[string]*Token),
		tokenSync: *new(sync.Mutex),
	}
	return ia
}

func (ia *IndieAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if me := req.FormValue("me"); me != "" {
		pass := req.FormValue("password")
		id := req.FormValue("code")
		client_id := req.FormValue("client_id")
		redirect_url := req.FormValue("redirect_url")
		scope := req.FormValue("scope")
		if id == "" {
			buf := make([]byte, 32)
			_, err := rand.Read(buf)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				rw.Write([]byte("Error generating Token"))
				return
			}
			id = string(buf)
		}
		token := ia.GetToken(id)
		token.me = me
		if client_id != "" {
			token.client_id = client_id
		}
		if redirect_url != "" {
			token.redirect_url = redirect_url
		}
		if scope != "" {
			token.Scope = scope
		}
		responseType := req.FormValue("response_type")
		if responseType == "code" {
			token.Response = ResponseCode
		}
		if loggedin := ia.CheckLogin(me, pass); loggedin {
			redirect, _ := url.Parse(token.redirect_url)
			redirect.Query().Set("code", token.ID)
			redirect.Query().Set("state", token.state)
			redirect.Query().Set("me", me)
			token.Authed = true
			token.Expires = time.Now().Add(10 * time.Minute)
			ia.SaveToken(token.ID, token)
			http.Redirect(rw, req, redirect.String(), http.StatusSeeOther)
			return
		}
		ia.SaveToken(token.ID, token)
		ia.LoginPage(rw, me, token.ID, client_id)
	} else if code := req.FormValue("code"); code != "" {
		id := req.FormValue("token")
		client_id := req.FormValue("client_id")
		redirect_url := req.FormValue("redirect_url")
		state := req.FormValue("state")
		token := ia.GetToken(id)
		if token.client_id == client_id && token.redirect_url == redirect_url && token.state == state {
			values := &url.Values{}
			values.Set("me", token.me)
			if token.Response == ResponseCode {
				values.Set("scope", token.Scope)
			}
			rw.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			rw.Write([]byte(values.Encode()))
		}
		rw.WriteHeader(http.StatusBadRequest)
	} else {
		ia.InfoPage(rw)
	}
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
