package oidc

import (
	"net/http"

	"github.com/gorilla/sessions"
)

func newSessionStore(options *SessionOptions) (*SessionStore, error) {
	store := sessions.NewCookieStore([]byte(options.SecretSigningKey), []byte(options.SecretEncryptionKey))
	store.Options = &sessions.Options{
		Domain:   options.Domain,
		MaxAge:   options.MaxAge,
		Secure:   options.Secure,
		HttpOnly: true,
	}

	sessionStore := &SessionStore{
		Options: options,
		Store:   store,
	}

	return sessionStore, nil
}

func (s *SessionStore) GetStringValue(r *http.Request, key string) (string, error) {
	session, err := s.Store.Get(r, s.Options.Name)
	if err != nil {
		return "", err
	}
	value, ok := session.Values[key].(string)
	if !ok {
		return "", nil
	}
	return value, nil
}

func (s *SessionStore) NewSession(r *http.Request, w http.ResponseWriter) (*sessions.Session, error) {
	session, err := s.Store.New(r, s.Options.Name)
	if err != nil {
		return nil, err
	}
	err = session.Save(r, w)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (s *SessionStore) SetStringValue(r *http.Request, w http.ResponseWriter, key string, value string) error {
	session, err := s.Store.Get(r, s.Options.Name)
	if err != nil {
		return err
	}
	session.Values[key] = value
	return session.Save(r, w)
}

func (s *SessionStore) SetSessionData(r *http.Request, w http.ResponseWriter, data *SessionData) error {
	session, err := s.Store.Get(r, s.Options.Name)
	if err != nil {
		return err
	}
	session.Values["data"] = data
	return session.Save(r, w)
}

func (s *SessionStore) GetSessionData(r *http.Request) (*SessionData, error) {
	session, err := s.Store.Get(r, s.Options.Name)
	if err != nil {
		return nil, err
	}
	data, ok := session.Values["data"].(SessionData)
	if !ok {
		return nil, nil
	}
	return &data, nil
}

func (s *SessionStore) SetStringFlash(r *http.Request, w http.ResponseWriter, value string) error {
	session, err := s.Store.Get(r, s.Options.Name)
	if err != nil {
		return err
	}
	session.AddFlash(value)
	return session.Save(r, w)
}

func (s *SessionStore) GetStringFlash(r *http.Request, w http.ResponseWriter) (*string, error) {
	session, err := s.Store.Get(r, s.Options.Name)
	if err != nil {
		return nil, err
	}
	flashes := session.Flashes()
	if len(flashes) == 0 {
		return nil, nil
	}
	strFlash, ok := flashes[0].(string)
	if !ok {
		return nil, nil
	}
	err = session.Save(r, w)
	if err != nil {
		return nil, err
	}
	return &strFlash, nil
}

func (s *SessionStore) Get(r *http.Request) (*sessions.Session, error) {
	return s.Store.Get(r, s.Options.Name)
}

func (s *SessionStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	return session.Save(r, w)
}

func (s *SessionStore) Delete(r *http.Request, w http.ResponseWriter) error {
	session, err := s.Store.Get(r, s.Options.Name)
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1
	return session.Save(r, w)
}
