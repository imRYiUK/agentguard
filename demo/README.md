# Demo Agent Deployments

One Agent Deployment, `deploy-agent`, in two variants. You can run both
without an AWS account: the Snapshots are fixed files, so only the analysis
runs. To see AgentGuard work against a real host and AWS account, follow
[`smoke-test.md`](./smoke-test.md) instead.

| Folder | What differs | Result |
|---|---|---|
| [`vulnerable/`](./vulnerable) | The AWS role `ops` has `Allow s3:* on *`. | Destroy Data Reach Path, severity critical. |
| [`secure/`](./secure) | `ops` can only list the `prod-reports` bucket and `s3:GetObject` its objects. | No Destroy Data Reach Path. |

Everything else is identical, and a test checks that it stays so: the Agent
Manifest, the MCP configuration (a `shell` server), the Claude Code settings
(which allow it), and the Linux Snapshot (the agent runs as `deploy`, who can
read `~/.aws/credentials` for the profile `ops`). Only `snapshots/aws.json`
differs. The point of the comparison is that the agent, its Tool, and its
access to the credentials did not change; the permissions behind them did.

## Run it

From the repository root, build the CLI once. (`go run` would also work for
the reports, but it reports every non-zero exit status of the program as 1,
which hides the Deployment Gate's status 3 below.)

```sh
go build -o bin/ ./cli/cmd/agentguard
```

The Snapshots were collected on 2026-11-17 and are fixed files, so pass
`--now` to keep them from becoming Stale Snapshots as the calendar moves on.
Without it, a Snapshot older than 7 days lowers every link taken from it, and
the report says so.

```sh
bin/agentguard analyze --now 2026-11-17T12:00:00Z demo/vulnerable
bin/agentguard analyze --now 2026-11-17T12:00:00Z demo/secure
```

The vulnerable run prints four Reach Paths, one for each Impact of
`s3:*`: Exfiltrate and Destroy Data are critical, Modify Data is high, and
Read Data is medium. Read the Destroy Data one: the shell Tool, the Linux user
`deploy`, the readable `~/.aws/credentials`, the role `ops`, `Allow s3:* on *`,
then the Impact, each link with the file and JSONPath it came from.

The secure run still prints two Reach Paths, because the shell Tool and the
readable credential file are still there. One is medium severity and ends in
Read Data on the objects of `prod-reports`, the most the scoped policy
grants. The other is unknown: `s3:ListBucket` has no Impact in the mapping
table, and AgentGuard reports it as "unknown" rather than dropping it.
Nothing reaches Destroy Data. A scoped policy lowers what the agent can do;
it does not remove the shell Tool, which is still reported as an unrestricted
command execution Secondary Finding.

Both reports also list the Blind Spots the Snapshots recorded, and every path
says in `confidence reduced:` which of them it depends on. That is expected:
the demo Snapshots record that SCPs were not collected, and AgentGuard never
treats what it could not see as absent.

## Use it as a Deployment Gate

`--fail-on high` makes the command exit with status 3 when a Reach Path has
severity high or above, so a CI job can stop the deploy:

```sh
bin/agentguard analyze --now 2026-11-17T12:00:00Z --fail-on high demo/vulnerable >/dev/null; echo $?   # 3
bin/agentguard analyze --now 2026-11-17T12:00:00Z --fail-on high demo/secure >/dev/null; echo $?       # 0
```

Status 1 means the analysis itself failed and 2 means a usage error, so a
blocked deploy is told apart from a broken run. A CI job that has the
Snapshots next to the configs only needs the same command; this is an example
and is not run by this repository's own CI:

```yaml
- name: Deployment Gate
  run: agentguard analyze --fail-on high ./agent-deployment
```

## Make your own variant

Copy a folder, change `snapshots/aws.json`, and run it again. The Environment
identity check compares each Snapshot with the account ID and machine ID the
Agent Manifest expects, so a Snapshot of the wrong account is refused rather
than analyzed. The manifest format is in
[`core/internal/manifest/SCHEMA.md`](../core/internal/manifest/SCHEMA.md).
