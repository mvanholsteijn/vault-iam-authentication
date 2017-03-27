package iam

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/vault/api"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (string, error) {
	mount, ok := m["mount"]
	if !ok {
		mount = "iam"
	}

	var sess *session.Session

	profile, ok := m["profile"]
	if !ok {
		sess = session.Must(session.NewSessionWithOptions(session.Options{}))
	} else {
		sess = session.Must(session.NewSessionWithOptions(session.Options{Profile: profile}))
	}

	cred, err := sess.Config.Credentials.Get()
	if err != nil {
		return "", fmt.Errorf("Failed to get credentials from session, %s", err)
	}

	path := fmt.Sprintf("auth/%s/login", mount)
	secret, err := c.Logical().Write(path, map[string]interface{}{
		"aws_access_key_id":     cred.AccessKeyID,
		"aws_secret_access_key": cred.SecretAccessKey,
		"aws_session_token":     cred.SessionToken,
	})
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("empty response from credential provider")
	}

	return secret.Auth.ClientToken, nil
}

func (h *CLIHandler) Help() string {
	help := `
The IAM credential provider allows you to authenticate using your AWS IAM credentials.

It will use your default profile credentials, unless you specify the "profile" parameter.

    Example: vault auth -method=iam [profile=dev-account]

Key/Value Pairs:

    mount=github      The mountpoint for the IAM credential provider.
                      Defaults to "iam"

    profile=<name>    The AWS profile to use the credentials from. Overrides
		      the profile set with AWS_PROFILE and AWS_DEFAULT_PROFILE.
`

	return strings.TrimSpace(help)
}
