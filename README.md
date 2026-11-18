# AgentGuard

**What can this AI agent reach, through which tools and credentials, wherever it runs?**

AgentGuard answers that question with static analysis over collected evidence. It
reads an agent's configuration, takes read-only Snapshots of the host and cloud
account the agent runs in, and reports every chain from the agent to a dangerous
permission as a **Reach Path**, with the evidence and confidence for each link.

It never runs the agent, never executes its tools, and never enforces anything at
runtime.

> **Status: early.** The CLI, the Linux and AWS Collectors, and the analysis core
> are built and tested. The distributed platform (Drift, triage, a web UI) is
> design only. [What is built, and what is not](#status) is listed below, and
> nothing in this README describes the unbuilt parts as working.

## The problem

An agent's reach comes from a combination of layers that different people own:

- the agent's **tools** (an MCP config, Claude Code settings),
- the **Linux user** it runs as,
- the **credentials** that user can read,
- the **cloud permissions** those credentials carry.

Each layer looks fine on its own. The MCP config is "a shell tool". The IAM role is
"ops". Together:

```
Claude Code agent
  └─ MCP "shell" tool                      (agent config)
      └─ runs as Linux user `deploy`        (host)
          └─ can read ~/.aws/credentials    (host)
              └─ AWS role `ops`             (cloud)
                  └─ Allow s3:* on *        (IAM policy)
                      └─ Destroy Data
```

Nobody wrote "let the agent delete production data". It emerged from four reasonable
decisions. MCP scanners see the tool and IAM analyzers see the role; AgentGuard
looks at the chain, which is where the risk is. This is OWASP's
[Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) made
concrete.

## Try it in two minutes

The `demo/` folder holds one Agent Deployment in two variants. They run from fixed
Snapshots, so you need no AWS account. You need Go (the version in
[`go.work`](./go.work)).

```sh
git clone https://github.com/imRYiUK/agentguard.git && cd agentguard
go build -o bin/ ./cli/cmd/agentguard

bin/agentguard analyze --now 2026-11-17T12:00:00Z demo/vulnerable
bin/agentguard analyze --now 2026-11-17T12:00:00Z demo/secure
```

(`--now` pins the clock. The demo Snapshots are fixed files; without it they would
turn into Stale Snapshots after 7 days and the report would say so.)

| Variant | What differs | Result |
|---|---|---|
| [`demo/vulnerable`](./demo/vulnerable) | The role `ops` has `Allow s3:* on *`. | Four Reach Paths. Destroy Data and Exfiltrate are critical. |
| [`demo/secure`](./demo/secure) | `ops` can only list one bucket and `s3:GetObject` its objects. | No Destroy Data path. |

The agent, its shell tool, and its access to the credentials are identical in both.
Only the permissions behind them changed, and the analysis shows exactly that.

### What a Reach Path looks like

This is the Destroy Data path from the vulnerable demo, as printed:

```
2. critical  deploy-agent (confidence: reduced)
   fingerprint rpf1:f2b3b33c58c83259f16dbc43c6642666070252f2dbc07e455ea20530b8f90bce, resource sensitivity critical
      Tool: shell Tool (MCP server shell)
        evidence: .mcp.json $.mcpServers.shell
   -> Identity: Linux user deploy (uid 1001) [discovered]
        evidence: snapshots/linux.json $.linux.agentUser
   -> Identity Hop: can read AWS credential file /home/deploy/.aws/credentials (profile ops)
        evidence: snapshots/linux.json $.linux.credentialFiles[0].awsProfiles[0]
   -> Identity: AWS role arn:aws:iam::123456789012:role/ops [discovered]
        evidence: snapshots/aws.json $.aws.identities[0]
   -> Native Permission: Allow s3:* on *
        evidence: snapshots/aws.json $.aws.identities[0].policies[0].document.Statement[0]
   -> Impact: Destroy Data
        evidence: agentguard:impact-mappings/v2 $.mappings[3]
   confidence reduced: Blind Spot in Environment build-host: the Collector could not complete "read /etc/sudoers" (permission denied)
   confidence reduced: Blind Spot in Environment prod-aws: the Collector could not complete "organizations:ListPolicies (SCPs)" (not collected)
```

Every link names the file and JSONPath it came from, so a reviewer can check the claim
instead of trusting it. The confidence is *reduced* because the Snapshots recorded
things the Collector could not see (here, SCPs and `/etc/sudoers`), and AgentGuard
treats what it could not see as unknown, never as absent.

Besides Reach Paths, the report lists **Secondary Findings** (an unrestricted shell
tool, a wildcard policy) and every Blind Spot. `--format json` prints the whole result
for a program, and identical inputs give byte-identical output.

## Use it as a Deployment Gate

`--fail-on` turns the command into a gate for CI:

```sh
bin/agentguard analyze --fail-on high ./agent-deployment
```

| Exit status | Meaning |
|---|---|
| 0 | Success. No Reach Path met `--fail-on`. |
| 1 | The analysis failed. |
| 2 | Usage error. |
| 3 | **Deployment Gate failed:** a Reach Path has the given severity or above. |

A blocked deploy is therefore told apart from a broken run. Reach Paths of unknown
severity never meet the threshold.

## How it works

```
 User's side (trusted by the user)            AgentGuard
 ─────────────────────────────────            ──────────────────────────────
 Agent configs  ─┐
 Agent Manifest ─┼─► Collector ─► Snapshots ─►  Parse and validate
 Live Environment┘   (read-only,  (protojson,     │
                      your creds)  secret-free)   ▼
                                                Model: Tools, Identities, Bindings,
                                                Identity Hops, Native Permissions → Impact
                                                  │
                                                  ▼
                                                Reach Path search (depth-limited)
                                                  │
                                                  ▼
                                                Reach Paths, Secondary Findings, Blind Spots
```

1. **Collect.** The **Collector** runs on your side, with your credentials, and writes a
   **Snapshot** of a Linux host or an AWS account. A Snapshot is plain JSON you can read
   and diff before using it.
2. **Declare.** An **Agent Manifest** (`agentguard.yaml`) names the agent's config files and,
   for each Environment, the identity you expect and the Snapshot file. A Snapshot whose
   identity differs from the manifest is rejected, so you cannot analyze the wrong account
   by mistake.
3. **Analyze.** The core library links the evidence into Reach Paths. Each permission is kept
   exactly as the Environment expresses it (a **Native Permission**) and gets an
   explainable **Impact** label from a versioned mapping table. Each path carries a
   **Confidence** (its weakest link) and a **Severity** (Impact × the Resource Sensitivity
   *you* labelled).

### Guarantees

- **Evidence before conclusions.** Every link points to the evidence and rule that produced it.
- **Deterministic.** No LLM takes part in detection or path-finding.
- **Honest uncertainty.** Blind Spots, Conditional Grants (IAM conditions are not evaluated),
  Inferred Bindings, and Stale Snapshots lower confidence and are always shown.
- **Never guesses what matters.** Resource names, required permissions, and Resource
  Sensitivity come from you. Unknown stays unknown.
- **Over-reports rather than under-reports.** An IAM Deny removes an Allow only when it
  provably covers all of it.
- **No secrets leave the host.** The Collector records that a credential exists, where it
  is, its file permissions, a fingerprint, and the Identity it resolves to, never its
  value. It refuses to write a Snapshot that would contain a secret it read, and analysis
  rejects Snapshots that look like they hold one.
- **Read-only.** The AWS Collector reaches AWS through an interface with no method that
  writes, and a test enforces it. The platform design never holds your cloud roles or SSH
  keys: Collectors run on your side, with your credentials.
- **The analyzer is a target too.** Every input is untrusted; parsers have resource limits
  and are fuzzed.

## Analyze your own deployment

> The Collector and the manifest format are built, and
> [`demo/smoke-test.md`](./demo/smoke-test.md) is the manual check against a real host and
> AWS account. **That smoke test has not been run yet**, so treat collection against real
> environments as unproven until it has.

```sh
go build -o bin/ ./cli/cmd/agentguard ./collector/cmd/agentguard-collector

# As the Linux user the agent runs as (no root needed):
bin/agentguard-collector linux --out my-deployment/snapshots/linux.json

# With the AWS credentials found on that host (read-only calls):
bin/agentguard-collector aws --profile ops --out my-deployment/snapshots/aws.json
```

Then write `my-deployment/agentguard.yaml` next to your `.mcp.json` and Claude Code
settings (start from [`demo/vulnerable/agentguard.yaml`](./demo/vulnerable/agentguard.yaml);
the format is in [`SCHEMA.md`](./core/internal/manifest/SCHEMA.md)) and run
`bin/agentguard analyze my-deployment`.

## Status

| Area | State |
|---|---|
| Agent config parsing: MCP configs, Claude Code settings | Built |
| Agent Manifest, with Environment identity checks | Built |
| Linux Collector (user, groups, credential files, Docker socket, host identity) | Built |
| AWS Collector (caller identity, managed, inline and group policies) | Built |
| AWS identity-policy semantics: `Allow`/`Deny`, wildcards, `NotAction`, `NotResource`, groups | Built |
| Identity Bindings and Identity Hops (depth limit 3) | Built |
| Impact mapping table (10 S3 and 18 IAM actions, in [`core/internal/impact/mappings.json`](./core/internal/impact/mappings.json)) | Built, small |
| Confidence, Severity, Reach Path Fingerprints | Built |
| Secondary Findings (unrestricted shell Tool, broad filesystem MCP server, wildcard Allow) | Built |
| CLI text and JSON output, Deployment Gate | Built |
| Smoke test against a real host and AWS account | Written, **not yet run** |
| Triage carry-over, Widened Paths, Resolved by Drift | Design |
| Shadow Agent discovery | Design |
| Platform: Ingestion, Inventory, Analysis, Findings, API and UI (Kafka, Postgres) | Design |
| GCP, Azure, containers; remediation proposals | Design |

### Known limitations

These are stated plainly because a security tool that hides them is worse than one that
has them.

- **Narrow coverage.** The Environments are Linux hosts and AWS accounts only. The agent
  side is MCP configs and Claude Code settings; tools defined only in source code are out
  of scope.
- **Identity policies only.** SCPs, RCPs, permission boundaries, session policies, and
  resource-based policies are not read. Every AWS Snapshot records a Blind Spot for each,
  and the paths that depend on it say so. An SCP could be blocking something AgentGuard
  reports.
- **IAM conditions are not evaluated.** A conditioned grant is reported as a Conditional
  Grant with reduced confidence.
- **A small Impact table.** An action the table does not name gets the Impact "unknown" and
  is still reported, but the table covers few actions so far.
- **One Identity per AWS Snapshot.** The Collector records the Identity behind the
  credentials it finds, not every role the agent could assume.
- **Reach Paths are candidates, not proof of exploitability.** They show a chain the
  evidence supports; they do not show an attack worked.

## Repository layout

A Go workspace of four modules. They share nothing except the generated contract types
and the core library.

| Path | Contents |
|---|---|
| [`core/`](./core) | The analysis library: parsing, AWS policy evaluation, Impact mapping, Identity Hop search, scoring. Used by the CLI, and by the platform's Analysis workers once they exist. |
| [`cli/`](./cli) | `agentguard analyze`: a thin shell over `core`, with text output and the Deployment Gate. |
| [`collector/`](./collector) | `agentguard-collector linux` and `agentguard-collector aws`. |
| [`proto/`](./proto) | Protobuf schemas for Snapshots and analysis results, the single schema source. Checked with `buf`. |
| [`demo/`](./demo) | The vulnerable and secure demo deployments, and the real-environment smoke test. |

## Development

```sh
for m in proto collector core cli; do (cd $m && go test ./...); done
```

CI runs on every pull request: `buf` lint, format, breaking-change check and a
generated-code freshness check for the contracts, then `gofmt`, `go vet`, and
`go test` for each of the four modules.

Testing is built around evidence rather than line coverage:

- 48 CLI golden fixtures (`cli/testdata/fixtures`): each is a small Agent Deployment with
  its expected report in text and JSON. They cover wildcards against scoped permissions,
  explicit Deny, `NotAction`, `NotResource`, group policies, Conditional Grants, binding
  mismatches, and Blind Spots.
- Fuzz tests for the parsers that take untrusted input.
- Property tests that the Collectors never emit a planted secret.
- A regression test for every false positive or negative found.

Every change reaches `main` through a reviewed pull request linked to an issue.

## More detail

| Document | What it covers |
|---|---|
| [`demo/README.md`](./demo/README.md) | The demos, and an example CI gate |
| [`demo/smoke-test.md`](./demo/smoke-test.md) | The manual check against a real host and AWS account |
| [`core/internal/manifest/SCHEMA.md`](./core/internal/manifest/SCHEMA.md) | The Agent Manifest format |

## Related work

AgentGuard builds on an ecosystem it does not claim to replace:
[Snyk Agent Scan](https://github.com/snyk/agent-scan),
[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner),
[Trail of Bits MCP Context Protector](https://github.com/trailofbits/mcp-context-protector),
and [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html).
Those tools look at one layer. AgentGuard's contribution is the chain across layers, with
evidence for each link.

## License

AgentGuard is licensed under the [Apache License, Version 2.0](./LICENSE).
