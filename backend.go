package iam

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	return Backend().Setup(conf)
}

func Backend() *backend {
	var b backend

	b.Backend = &framework.Backend{
		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},

		Paths: append([]*framework.Path{pathLogin(&b)}),

		AuthRenew: b.pathLoginRenew,
	}

	return &b
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The IAM credential provider allows authentication via AWS IAM.

Users provide a AWS access id, secret key and optionally a session token.  
`
