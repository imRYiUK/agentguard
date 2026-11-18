module github.com/imRYiUK/agentguard/cli

go 1.27

require (
	github.com/imRYiUK/agentguard/collector v0.0.0
	github.com/imRYiUK/agentguard/core v0.0.0
	github.com/imRYiUK/agentguard/proto v0.0.0
	google.golang.org/protobuf v1.36.10
)

require (
	github.com/aws/aws-sdk-go-v2 v1.48.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.33.19 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.21.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/iam v1.66.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.52.0 // indirect
	github.com/aws/smithy-go v1.28.9 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
)

replace (
	github.com/imRYiUK/agentguard/collector => ../collector
	github.com/imRYiUK/agentguard/core => ../core
	github.com/imRYiUK/agentguard/proto => ../proto
)
