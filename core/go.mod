module github.com/imRYiUK/agentguard/core

go 1.27

require (
	github.com/imRYiUK/agentguard/proto v0.0.0
	go.yaml.in/yaml/v3 v3.0.6
	google.golang.org/protobuf v1.36.10
)

replace github.com/imRYiUK/agentguard/proto => ../proto
