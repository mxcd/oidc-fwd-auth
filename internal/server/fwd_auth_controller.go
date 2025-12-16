package server

import "fmt"

func (s *Server) registerFwdAuthRoutes() error {
	s.Engine.GET(fmt.Sprintf("%s/", s.Options.ApiBaseUrl), s.getHealthHandler())
	return nil
}
