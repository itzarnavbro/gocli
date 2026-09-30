package cli

import (
	"context"
	"sort"
	"strings"
)

type AuthReq int

const (
	Any AuthReq = iota
	Anonymous
	LoggedIn
)

type Command struct {
	Name string
	Help string
	Auth AuthReq
	Run  func(ctx context.Context, s *Shell, args []string) error
}

func (c Command) availableTo(loggedIn bool) bool {
	switch c.Auth {
	case Anonymous:
		return !loggedIn
	case LoggedIn:
		return loggedIn
	}
	return true
}

func (s *Shell) find(name string) (Command, bool) {
	for _, c := range s.cmds {
		if c.Name == name {
			return c, true
		}
	}
	return Command{}, false
}

func (s *Shell) Available() []Command {
	var out []Command
	for _, c := range s.cmds {
		if c.availableTo(s.loggedIn()) {
			out = append(out, c)
		}
	}
	return out
}

func (s *Shell) complete(prefix string) []string {
	var out []string
	for _, c := range s.Available() {
		if strings.HasPrefix(c.Name, prefix) {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}
