package main_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the real Collector binary on the machine they run on.

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "agentguard-collector-test")
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	binary = filepath.Join(dir, "agentguard-collector")
	build := exec.Command("go", "build", "-ldflags", "-X main.version=9.9.9-test", "-o", binary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.Stderr.WriteString("building the Collector: " + err.Error() + "\n")
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// hostIsIdentifiable reports whether this machine has a machine ID or an SSH
// host key, without which the Collector rightly refuses to run.
func hostIsIdentifiable() bool {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/ssh/ssh_host_ed25519_key.pub", "/etc/ssh/ssh_host_ecdsa_key.pub", "/etc/ssh/ssh_host_rsa_key.pub"} {
		if _, err := os.ReadFile(p); err == nil {
			return true
		}
	}
	return false
}

func TestLinuxWritesASnapshotToStdout(t *testing.T) {
	if !hostIsIdentifiable() {
		t.Skip("this machine has no machine ID or readable SSH host key")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("cannot look up the current user")
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binary, "linux")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agentguard-collector linux: %v\nstderr:\n%s", err, stderr.String())
	}
	var snap struct {
		SchemaVersion    string `json:"schemaVersion"`
		SnapshotID       string `json:"snapshotId"`
		CollectorVersion string `json:"collectorVersion"`
		CollectedAt      string `json:"collectedAt"`
		CollectedBy      string `json:"collectedBy"`
		Linux            struct {
			AgentUser struct {
				UID json.Number `json:"uid"`
			} `json:"agentUser"`
		} `json:"linux"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &snap); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if snap.SchemaVersion != "1" || !strings.HasPrefix(snap.SnapshotID, "snap-linux-") || snap.CollectorVersion != "9.9.9-test" ||
		snap.CollectedAt == "" {
		t.Errorf("unexpected provenance: %+v", snap)
	}
	if snap.CollectedBy != me.Username && snap.CollectedBy != "uid-"+me.Uid {
		t.Errorf("collectedBy = %q, want %q", snap.CollectedBy, me.Username)
	}
}

func TestLinuxOutWritesAFileAndPrintsNothing(t *testing.T) {
	if !hostIsIdentifiable() {
		t.Skip("this machine has no machine ID or readable SSH host key")
	}
	out := filepath.Join(t.TempDir(), "linux.json")
	var stdout bytes.Buffer
	cmd := exec.Command(binary, "linux", "--out", out)
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(out)
	if err != nil || !json.Valid(content) {
		t.Fatalf("the --out file is missing or not JSON: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("with --out, stdout must be empty, got %q", stdout.String())
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the --out file must be readable by its owner only, got %v (%v)", info.Mode().Perm(), err)
	}
}

func TestUsageErrorsExitWithStatus2(t *testing.T) {
	for _, args := range [][]string{{}, {"windows"}, {"linux", "extra"}, {"linux", "--nope"}, {"aws", "extra"}, {"aws", "--nope"}, {"aws", "--profile"}} {
		var stderr bytes.Buffer
		cmd := exec.Command(binary, args...)
		cmd.Stderr = &stderr
		var exit *exec.ExitError
		if err := cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 2 {
			t.Errorf("%v: want exit status 2, got %v", args, err)
		}
		if !strings.Contains(stderr.String(), "usage: agentguard-collector linux [--out FILE]") ||
			!strings.Contains(stderr.String(), "agentguard-collector aws [--profile NAME] [--out FILE]") {
			t.Errorf("%v: stderr = %q", args, stderr.String())
		}
	}
}

// fakeAWS answers the two calls the test needs, and denies every other one,
// like an account whose credentials may only say who they are.
func fakeAWS(t *testing.T, actions *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.PostForm.Get("Action")
		*actions = append(*actions, action)
		w.Header().Set("Content-Type", "text/xml")
		if action == "GetCallerIdentity" {
			fmt.Fprint(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>`+
				`<Arn>arn:aws:iam::123456789012:user/deploy</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>`+
				`</GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>AccessDenied</Code>`+
			`<Message>not authorized</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// awsEnv is an environment with only the given AWS settings, so a test never
// picks up the credentials of the machine it runs on.
func awsEnv(t *testing.T, extra ...string) []string {
	home := t.TempDir()
	return append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "AWS_EC2_METADATA_DISABLED=true", "AWS_REGION=us-east-1"}, extra...)
}

func TestAWSWritesASnapshotOfTheIdentityBehindTheCredentials(t *testing.T) {
	const (
		accessKeyID = "AKIAIOSFODNN7EXAMPLE"
		secretKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		sessionTok  = "IQoJb3JpZ2luX2VjEXAMPLESESSIONTOKEN0123456789"
	)
	var actions []string
	srv := fakeAWS(t, &actions)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binary, "aws")
	cmd.Env = awsEnv(t, "AWS_ENDPOINT_URL="+srv.URL, "AWS_ACCESS_KEY_ID="+accessKeyID, "AWS_SECRET_ACCESS_KEY="+secretKey, "AWS_SESSION_TOKEN="+sessionTok)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agentguard-collector aws: %v\nstderr:\n%s", err, stderr.String())
	}
	for _, secret := range []string{accessKeyID, secretKey, sessionTok} {
		if strings.Contains(stdout.String()+stderr.String(), secret) {
			t.Fatalf("a secret value reached the output:\n%s", stdout.String())
		}
	}
	var snap struct {
		SnapshotID  string `json:"snapshotId"`
		CollectedBy string `json:"collectedBy"`
		Environment struct {
			AWS struct {
				AccountID string `json:"accountId"`
			} `json:"aws"`
		} `json:"environment"`
		BlindSpots []struct {
			Attempted string `json:"attempted"`
			Reason    string `json:"reason"`
		} `json:"blindSpots"`
		AWS struct {
			Identities []struct {
				ARN          string   `json:"arn"`
				Fingerprints []string `json:"accessKeyIdFingerprints"`
			} `json:"identities"`
		} `json:"aws"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &snap); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if !strings.HasPrefix(snap.SnapshotID, "snap-aws-") || snap.Environment.AWS.AccountID != "123456789012" ||
		snap.CollectedBy != "arn:aws:iam::123456789012:user/deploy" {
		t.Errorf("unexpected provenance: %+v", snap)
	}
	if len(snap.AWS.Identities) != 1 || snap.AWS.Identities[0].ARN != "arn:aws:iam::123456789012:user/deploy" ||
		len(snap.AWS.Identities[0].Fingerprints) != 1 {
		t.Errorf("unexpected Identity: %+v", snap.AWS.Identities)
	}
	denied := false
	for _, b := range snap.BlindSpots {
		denied = denied || strings.Contains(b.Attempted, "iam:ListAttachedUserPolicies") && b.Reason == "AccessDenied"
	}
	if !denied {
		t.Errorf("the denied calls are not Blind Spots: %+v", snap.BlindSpots)
	}
	for _, a := range actions {
		if a != "GetCallerIdentity" && !strings.HasPrefix(a, "Get") && !strings.HasPrefix(a, "List") {
			t.Errorf("the Collector sent %s, which is not a read", a)
		}
	}
}

func TestAWSWithoutCredentialsFailsWithoutASnapshot(t *testing.T) {
	var actions []string
	srv := fakeAWS(t, &actions)
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binary, "aws")
	cmd.Env = awsEnv(t, "AWS_ENDPOINT_URL="+srv.URL)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	var exit *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("want exit status 1, got %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "credentials") {
		t.Errorf("stderr does not say the credentials are the problem: %q", stderr.String())
	}
}

func TestAWSOutWritesAFileReadableByItsOwnerOnly(t *testing.T) {
	var actions []string
	srv := fakeAWS(t, &actions)
	out := filepath.Join(t.TempDir(), "aws.json")
	cmd := exec.Command(binary, "aws", "--out", out)
	cmd.Env = awsEnv(t, "AWS_ENDPOINT_URL="+srv.URL, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 || stdout.Len() != 0 {
		t.Errorf("--out: %v %v, stdout %q", info, err, stdout.String())
	}
}

func TestAWSProfileSelectsTheCredentialsOfThatProfile(t *testing.T) {
	var actions []string
	srv := fakeAWS(t, &actions)
	env := awsEnv(t, "AWS_ENDPOINT_URL="+srv.URL)
	home := ""
	for _, e := range env {
		if strings.HasPrefix(e, "HOME=") {
			home = strings.TrimPrefix(e, "HOME=")
		}
	}
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	creds := "[ops]\naws_access_key_id = AKIAOPSOPSOPSOPSOPSO\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if err := os.WriteFile(filepath.Join(home, ".aws", "credentials"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	cmd := exec.Command(binary, "aws", "--profile", "ops")
	cmd.Env = env
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	// The fingerprint of the profile's access key ID: its SHA-256 in hex.
	sum := sha256.Sum256([]byte("AKIAOPSOPSOPSOPSOPSO"))
	if want := "sha256:" + hex.EncodeToString(sum[:]); !strings.Contains(stdout.String(), want) {
		t.Errorf("the Snapshot does not hold the fingerprint of the profile's key %s:\n%s", want, stdout.String())
	}
}
