# Smoke test against a real host and AWS account

The [demo folders](./README.md) run over fixed Snapshots. This is the manual
check that the same result comes out of a real Linux host and a real AWS
account, through both Collectors, the Agent Manifest, and the analysis. It is
**not run in CI**: it needs an AWS account and a host, and it creates and
deletes IAM resources.

Run it before a release, and after a change to a Collector or to the Snapshot
schema.

**Last run:** not yet run. Fill in the table at the end when you do.

## Use a sandbox

- Use an AWS account that holds nothing you care about. The steps create a
  role with `s3:*` on `*` on purpose, and the agent being modelled can use it.
  AgentGuard itself never calls S3; the permission is only evidence.
- Use a throwaway Linux user and host (a VM or container is fine). The
  Collector reads that user's home directory and the host's identity files.
- Delete everything in the cleanup step when you are done.

## What you need

- A Linux host and a user on it, `agent` below, standing for the user the AI
  agent runs as. The Collector must run as that user: it takes the user it
  runs as to be the agent's user.
- An AWS account you own, with the AWS CLI configured for an administrator
  profile `admin` (used only to set up and clean up).
- Go (the version in `go.work`) to build the two binaries.
- Agent configuration files to review: a `.mcp.json` with a `shell` server and
  a `.claude/settings.json` that allows it. The ones in
  [`vulnerable/`](./vulnerable) work.

## 1. Build

From the repository root:

```sh
go build -o bin/ ./cli/cmd/agentguard ./collector/cmd/agentguard-collector
```

## 2. Create the vulnerable IAM user

The Collector uses the credentials it finds on the host, the way the AWS CLI
does, and reads the IAM policies of the Identity they resolve to. So the
agent's Identity, here an IAM user, needs to be allowed to read its own
policies, or those calls become Blind Spots. (Giving the agent's own Identity
IAM read access is a choice for this test; the demo folders model the same
thing with a role, `ops`, because the Collector handles both. In real use,
accept the Blind Spots, or collect with credentials that can read the policies
of the Identity the agent uses.)

```sh
aws --profile admin iam create-user --user-name agentguard-smoke
aws --profile admin iam put-user-policy --user-name agentguard-smoke \
  --policy-name smoke --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
      {"Effect": "Allow", "Action": [
        "iam:ListAttachedUserPolicies", "iam:ListUserPolicies",
        "iam:GetUserPolicy", "iam:ListGroupsForUser", "iam:GetPolicy",
        "iam:GetPolicyVersion"], "Resource": "*"}
    ]}'
aws --profile admin iam create-access-key --user-name agentguard-smoke
```

The last command prints an access key. Put it on the host, as the user
`agent`, in `~/.aws/credentials`:

```ini
[smoke]
aws_access_key_id = <the access key ID>
aws_secret_access_key = <the secret access key>
```

and `chmod 600 ~/.aws/credentials`. Check `aws --profile smoke sts
get-caller-identity` works.

## 3. Collect both Snapshots

On the host, as `agent`:

```sh
mkdir -p ~/smoke/snapshots
bin/agentguard-collector linux --out ~/smoke/snapshots/linux.json
bin/agentguard-collector aws --profile smoke --out ~/smoke/snapshots/aws.json
```

Both must exit 0 and print nothing secret. Without `--out`, a Snapshot goes
to standard output.

## 4. Read the Snapshots before trusting them

- `snapshots/linux.json` has `environment.linux.machineId`,
  `linux.agentUser.name` equal to `agent`, and under `linux.credentialFiles` an
  entry for `~/.aws/credentials` with an `awsProfiles` entry named `smoke`.
- `snapshots/aws.json` has your account ID, an identity for the user
  `agentguard-smoke` with the inline policy `smoke`, and the same
  `accessKeyIdFingerprints` value as the `smoke` profile's
  `accessKeyIdFingerprint` in the Linux Snapshot. That match is what links
  the two layers.
- `blindSpots` in both lists what could not be read, such as
  `/etc/sudoers` on the host when you are not root.
- **No secret values.** The secret access key must not appear in either file:

  ```sh
  ! grep -F "$(aws configure get aws_secret_access_key --profile smoke)" ~/smoke/snapshots/*.json && echo "no secret"
  ```

  and nor must the access key ID itself (only its `sha256:` fingerprint):

  ```sh
  ! grep -F "$(aws configure get aws_access_key_id --profile smoke)" ~/smoke/snapshots/*.json && echo "no key ID"
  ```

## 5. Write the Agent Manifest and analyze

Put the agent's config files next to the manifest, in `~/smoke`:

```sh
cp <the .mcp.json> ~/smoke/.mcp.json
mkdir -p ~/smoke/.claude && cp <the settings.json> ~/smoke/.claude/settings.json
cat /etc/machine-id
aws --profile smoke sts get-caller-identity --query Account --output text
```

Write `~/smoke/agentguard.yaml`, using those two values (the format is in
[`SCHEMA.md`](../core/internal/manifest/SCHEMA.md)):

```yaml
version: 1
agent:
  name: smoke-agent
  configs:
    claudeCodeSettings: [.claude/settings.json]
    mcp: [.mcp.json]
environments:
  - name: smoke-host
    type: linux
    identity:
      machineId: <contents of /etc/machine-id>
    snapshot: snapshots/linux.json
  - name: smoke-aws
    type: aws
    identity:
      accountId: "<the account ID>"
    snapshot: snapshots/aws.json
resourceSensitivity:
  - resource: "arn:aws:s3:::*"
    sensitivity: critical
```

Then:

```sh
bin/agentguard analyze ~/smoke
bin/agentguard analyze --fail-on high ~/smoke > /dev/null; echo $?
```

**Expect:**

- [ ] A Destroy Data Reach Path of severity critical: the `shell` Tool, the
      Linux user `agent`, the readable `~/.aws/credentials` (profile
      `smoke`), the AWS user `agentguard-smoke`, `Allow s3:* on *`.
- [ ] Every link names a file and location under `snapshots/` or the config
      files.
- [ ] The Identity link to the AWS user is `[discovered]`.
- [ ] Reach Paths have `confidence: reduced`, with the reason: the Blind Spots
      of both Snapshots (at least the policy types the AWS Collector does not
      collect: SCPs, permission boundaries, session policies, and resource
      policies).
- [ ] Secondary Findings: an unrestricted command execution Tool and a
      wildcard policy.
- [ ] `--fail-on high` exits with status 3.

## 6. Check it refuses the wrong account

Change one digit of `accountId` in the manifest and run `analyze` again. It
must fail with status 1 and say `Environment identity mismatch`, naming both
account IDs, and print no Reach Path. Restore the digit.

## 7. Fix it, collect again, run again

Scope the policy to what the agent needs, then collect the AWS Snapshot again
(the Linux one has not changed):

```sh
aws --profile admin iam put-user-policy --user-name agentguard-smoke \
  --policy-name smoke --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::smoke-reports"},
      {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::smoke-reports/*"},
      {"Effect": "Allow", "Action": [
        "iam:ListAttachedUserPolicies", "iam:ListUserPolicies",
        "iam:GetUserPolicy", "iam:ListGroupsForUser", "iam:GetPolicy",
        "iam:GetPolicyVersion"], "Resource": "*"}
    ]}'
bin/agentguard-collector aws --profile smoke --out ~/smoke/snapshots/aws.json
bin/agentguard analyze --fail-on high ~/smoke; echo $?
```

**Expect:**

- [ ] No Destroy Data Reach Path, and exit status 0.
- [ ] A Read Data Reach Path on `arn:aws:s3:::smoke-reports/*`.
- [ ] The `iam:*` read grants show up as Reach Paths of unknown Impact. That
      is the cost of letting the agent's own role read its policies, and
      it is why you keep that grant out of an Identity you review for real.

## 8. Check what a denied call looks like

Remove `iam:GetUserPolicy` from the policy, collect the AWS Snapshot again,
and run `analyze`. The Collector must still exit 0, and the Snapshot must
list a Blind Spot naming `iam:GetUserPolicy` and the AWS error code
(`AccessDenied`). The analysis must report that Blind Spot and must not
invent a permission it could not read.

## Clean up

```sh
aws --profile admin iam delete-user-policy --user-name agentguard-smoke --policy-name smoke
aws --profile admin iam delete-access-key --user-name agentguard-smoke --access-key-id <the access key ID>
aws --profile admin iam delete-user --user-name agentguard-smoke
shred -u ~/.aws/credentials   # on the throwaway host only
rm -r ~/smoke
```

## Record the run

| Date | Commit | Host | Result | Problems found |
|---|---|---|---|---|
| not yet run | | | | |
