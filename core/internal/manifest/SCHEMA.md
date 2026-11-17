# Agent Manifest schema, version 1

An Agent Manifest declares one Agent Deployment. It is a YAML file named
`agentguard.yaml` at the root of the folder passed to `agentguard analyze`.
Every path in it is relative to that folder, uses `/`, and must stay inside
it (no leading `/`, no `..`).

Analysis reads only the files the manifest names. A Snapshot file the
manifest does not name is ignored.

```yaml
version: 1                      # required; the only supported value is 1
agent:
  name: deploy-agent            # required; the Agent Deployment's name
  configs:                      # optional
    claudeCodeSettings:         # Claude Code settings files
      - .claude/settings.json
    mcp:                        # MCP configuration files
      - .mcp.json
environments:                   # required; at least one
  - name: build-host            # required; unique in the manifest
    type: linux                 # required; linux or aws
    identity:                   # required; the expected provider-native identity
      machineId: e8c913f01b6f9ef3d7f19c3cef1cc390
      sshHostKeyFingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
    snapshot: snapshots/linux.json   # required; this Environment's Snapshot
  - name: prod-aws
    type: aws
    identity:
      accountId: "123456789012"
    snapshot: snapshots/aws.json
declaredBindings:               # optional
  - environment: build-host     # the name of an Environment above
    identity: deploy            # a Linux user name, or an ARN for an aws Environment
resourceSensitivity:            # optional
  - resource: "arn:aws:s3:::prod-*"   # a resource name or pattern
    sensitivity: critical             # low, medium, high, or critical
```

## Fields

| Field | Rules |
|---|---|
| `version` | Integer, required. A manifest with another version is rejected. |
| `agent.name` | 1-128 characters: letters, digits, `.`, `_`, `-`, starting with a letter or digit. |
| `agent.configs.claudeCodeSettings`, `agent.configs.mcp` | Lists of file paths. A listed file that does not exist is an error. |
| `environments[].name` | Same rules as `agent.name`; unique. |
| `environments[].type` | `linux` or `aws`. |
| `environments[].identity` (linux) | `machineId`: the 32 lowercase hex characters of `/etc/machine-id`. `sshHostKeyFingerprint`: `SHA256:` plus 43 base64 characters. At least one is required; every one given must match the Snapshot. |
| `environments[].identity` (aws) | `accountId`: 12 digits. Required. |
| `environments[].snapshot` | Path of the Snapshot file for this Environment. |
| `declaredBindings[]` | `environment` must name an Environment in the manifest; `identity` is not empty. |
| `resourceSensitivity[]` | `resource` is not empty; `sensitivity` is one of `low`, `medium`, `high`, `critical`. A resource with no label has unknown sensitivity. |

Unknown fields are errors, so a misspelled field is never silently ignored.
YAML aliases are not supported.

## Errors

A malformed manifest is rejected before any analysis, with a message that
names the file, the line, and the exact field:

```
agentguard: agentguard.yaml:19: environments[1].identity.accountId: must be a 12-digit AWS account ID, got "12345"
```

## Environment identity check

A Snapshot is rejected when its recorded Environment identity differs from
the one the manifest expects for its Environment, or when it is not a
Snapshot of that Environment's type:

```
agentguard: snapshots/aws.json: Environment identity mismatch: Environment "prod-aws" (environments[1]) expects accountId "999999999999", but the Snapshot records accountId "123456789012"
```

## Changing the schema

A change that old manifests cannot satisfy raises `version`. The core
library reads only the version it was built for.
