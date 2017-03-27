package iam

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"aws_access_key_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "AWS access key id",
			},
			"aws_secret_access_key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "AWS access secret key",
			},
			"aws_session_token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "AWS session token",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLogin,
		},
	}
}

func authenticate(awsAccessID, awsSecretAccessKey, awsSessionToken string) (*sts.GetCallerIdentityOutput, error) {
	creds := credentials.NewStaticCredentials(awsAccessID, awsSecretAccessKey, awsSessionToken)
	sess := session.Must(session.NewSession(&aws.Config{Credentials: creds}))
	svc := sts.New(sess)

	var params *sts.GetCallerIdentityInput
	return svc.GetCallerIdentity(params)
}

func (b *backend) pathLogin(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	awsAccessID := data.Get("aws_access_id").(string)
	awsSecretAccessKey := data.Get("aws_secret_access_key").(string)
	awsSessionToken := data.Get("aws_session_token").(string)

	resp, err := authenticate(awsAccessID, awsSecretAccessKey, awsSessionToken)

	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"aws_secret_id":         awsAccessID,
				"aws_secret_access_key": awsSecretAccessKey,
				"aws_session_token":     awsSessionToken,
			},
			Metadata: map[string]string{
				"account": *resp.Account,
				"arn":     *resp.Arn,
				"userid":  *resp.UserId,
			},
			DisplayName: *resp.Arn,
			LeaseOptions: logical.LeaseOptions{
				TTL:       5 * time.Minute,
				Renewable: true,
			},
		},
	}, nil
}

func (b *backend) pathLoginRenew(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	if req.Auth == nil {
		return nil, fmt.Errorf("request auth was nil")
	}

	awsAccessID, _ := req.Auth.InternalData["aws_access_id"].(string)
	awsSecretAccessKey, _ := req.Auth.InternalData["aws_secret_access_key"].(string)
	awsSessionToken, _ := req.Auth.InternalData["aws_session_token"].(string)

	if _, err := authenticate(awsAccessID, awsSecretAccessKey, awsSessionToken); err != nil {
		return nil, err
	}

	return framework.LeaseExtend(5*time.Minute, 5*time.Minute, b.System())(req, d)
}
