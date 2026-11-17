module github.com/imRYiUK/agentguard/cli

go 1.27

require (
	github.com/imRYiUK/agentguard/collector v0.0.0
	github.com/imRYiUK/agentguard/core v0.0.0
)

require (
	github.com/imRYiUK/agentguard/proto v0.0.0 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace (
	github.com/imRYiUK/agentguard/collector => ../collector
	github.com/imRYiUK/agentguard/core => ../core
	github.com/imRYiUK/agentguard/proto => ../proto
)
