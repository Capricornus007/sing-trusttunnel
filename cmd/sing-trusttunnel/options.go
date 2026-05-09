package main

import (
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
)

type ClientOptions struct {
	Server        string
	ServerPort    uint16
	Username      string
	Password      string
	ServerName    string
	AllowInsecure bool
	HealthCheck   bool
	QUIC          bool

	Listen     string
	ListenPort uint16
	Auth       badoption.Listable[auth.User]
}

type ServerOptions struct {
	Listen     string
	ListenPort uint16
	Cert       string
	Key        string
	ServerName string
	Users      badoption.Listable[auth.User]
	ListenQUIC bool
}
