package iam

import (
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
)

func TestBackend_Config(t *testing.T) {
	defaultLeaseTTLVal := time.Hour * 24
	maxLeaseTTLVal := time.Hour * 24 * 2
	b, err := Factory(&logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
	})
	if err != nil {
		t.Fatalf("Unable to create backend: %s", err)
	}

	login_data := map[string]interface{}{
		"aws_access_id":     os.Getenv("AWS_ACCESS_KEY_ID"),
		"aws_secret_key":    os.Getenv("AWS_SECRET_KEY"),
		"aws_session_token": os.Getenv("AWS_SESSION_TOKEN"),
	}

	logicaltest.Test(t, logicaltest.TestCase{
		AcceptanceTest: true,
		PreCheck:       func() { testAccPreCheck(t) },
		Backend:        b,
		Steps: []logicaltest.TestStep{
			testLoginWrite(t, login_data, false),
		},
	})
}

func testLoginWrite(t *testing.T, d map[string]interface{}, expectFail bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "login",
		ErrorOk:   true,
		Data:      d,
		Check: func(resp *logical.Response) error {
			if resp.IsError() && !expectFail {
				t.Fatal(resp)
			}
			return nil
		},
	}
}

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("_AWS_ACCESS_KEY_ID"); v == "" {
		t.Fatal("_AWS_ACCESS_KEY_ID must be set for acceptance tests")
	}

	if v := os.Getenv("_AWS_SECRET_KEY"); v == "" {
		t.Fatal("_AWS_SECRET_KEY must be set for acceptance tests")
	}
}
