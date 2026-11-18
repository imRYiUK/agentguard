package aws_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/imRYiUK/agentguard/collector/aws"
)

// fakeAWS is a local HTTP server that answers IAM and STS query requests, and
// records the Action of each. It lets the real SDK adapter run end to end
// with no network and no account.
type fakeAWS struct {
	mu      sync.Mutex
	actions []string
	server  *httptest.Server
}

func newFakeAWS(t *testing.T) *fakeAWS {
	t.Helper()
	f := &fakeAWS{}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAWS) Actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.actions...)
}

func xmlResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func (f *fakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action := r.PostForm.Get("Action")
	f.mu.Lock()
	f.actions = append(f.actions, action)
	f.mu.Unlock()

	const ns = `xmlns="https://iam.amazonaws.com/doc/2010-05-08/"`
	meta := `<ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>`
	result := func(name, inner string) string {
		return fmt.Sprintf(`<%sResponse %s><%sResult>%s</%sResult>%s</%sResponse>`, name, ns, name, inner, name, meta, name)
	}
	switch action {
	case "GetCallerIdentity":
		xmlResponse(w, 200, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>`+
			`<Arn>arn:aws:iam::123456789012:user/deploy</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>`+
			`</GetCallerIdentityResult>`+meta+`</GetCallerIdentityResponse>`)
	case "GetRole":
		xmlResponse(w, 200, result("GetRole", `<Role><Path>/platform/</Path><RoleName>ops</RoleName><RoleId>AROAEXAMPLE</RoleId>`+
			`<Arn>arn:aws:iam::123456789012:role/platform/ops</Arn><CreateDate>2026-01-01T00:00:00Z</CreateDate></Role>`))
	case "ListGroupsForUser":
		xmlResponse(w, 200, result("ListGroupsForUser", `<IsTruncated>false</IsTruncated><Groups><member><Path>/</Path><GroupName>admins</GroupName>`+
			`<GroupId>AGPAEXAMPLE</GroupId><Arn>arn:aws:iam::123456789012:group/admins</Arn><CreateDate>2026-01-01T00:00:00Z</CreateDate></member></Groups>`))
	case "ListAttachedUserPolicies":
		// Two pages, to exercise paging.
		if r.PostForm.Get("Marker") == "" {
			xmlResponse(w, 200, result("ListAttachedUserPolicies", `<IsTruncated>true</IsTruncated><Marker>page2</Marker><AttachedPolicies>`+
				`<member><PolicyName>First</PolicyName><PolicyArn>arn:aws:iam::123456789012:policy/First</PolicyArn></member></AttachedPolicies>`))
			return
		}
		xmlResponse(w, 200, result("ListAttachedUserPolicies", `<IsTruncated>false</IsTruncated><AttachedPolicies>`+
			`<member><PolicyName>Second</PolicyName><PolicyArn>arn:aws:iam::123456789012:policy/Second</PolicyArn></member></AttachedPolicies>`))
	case "ListUserPolicies":
		xmlResponse(w, 200, result("ListUserPolicies", `<IsTruncated>false</IsTruncated><PolicyNames><member>scratch</member></PolicyNames>`))
	case "GetUserPolicy":
		// The document is URL-encoded, as AWS returns it.
		doc := url.PathEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Put*","Resource":"arn:aws:s3:::a b+c/*"}]}`)
		xmlResponse(w, 200, result("GetUserPolicy", `<UserName>deploy</UserName><PolicyName>scratch</PolicyName><PolicyDocument>`+doc+`</PolicyDocument>`))
	case "ListAttachedGroupPolicies":
		xmlResponse(w, 403, `<ErrorResponse `+ns+`><Error><Type>Sender</Type><Code>AccessDenied</Code>`+
			`<Message>User is not authorized to perform iam:ListAttachedGroupPolicies</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
	case "ListGroupPolicies":
		xmlResponse(w, 200, result("ListGroupPolicies", `<IsTruncated>false</IsTruncated><PolicyNames/>`))
	case "GetPolicy":
		arn := r.PostForm.Get("PolicyArn")
		xmlResponse(w, 200, result("GetPolicy", `<Policy><PolicyName>p</PolicyName><Arn>`+arn+`</Arn><DefaultVersionId>v3</DefaultVersionId></Policy>`))
	case "GetPolicyVersion":
		if r.PostForm.Get("VersionId") != "v3" {
			xmlResponse(w, 404, `<ErrorResponse `+ns+`><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>no</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
			return
		}
		doc := url.PathEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`)
		xmlResponse(w, 200, result("GetPolicyVersion", `<PolicyVersion><Document>`+doc+`</Document><VersionId>v3</VersionId><IsDefaultVersion>true</IsDefaultVersion></PolicyVersion>`))
	default:
		xmlResponse(w, 400, `<ErrorResponse `+ns+`><Error><Type>Sender</Type><Code>InvalidAction</Code><Message>unknown</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
	}
}

func (f *fakeAWS) api(t *testing.T, keyID string) aws.API {
	t.Helper()
	return aws.NewSDK(awssdk.Config{
		Region:           "us-east-1",
		BaseEndpoint:     &f.server.URL,
		Credentials:      credentials.NewStaticCredentialsProvider(keyID, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""),
		HTTPClient:       f.server.Client(),
		RetryMaxAttempts: 1,
	})
}

// The real adapter, run against a local server that speaks IAM and STS,
// collects a user with a group, pages through lists, decodes documents, turns
// a denied call into a Blind Spot, and sends nothing but Get and List
// requests.
func TestSDKAdapterCollectsOverHTTPAndOnlyReads(t *testing.T) {
	fake := newFakeAWS(t)
	snap, err := aws.Collect(context.Background(), fake.api(t, "AKIAIOSFODNN7EXAMPLE"), testOptions)
	if err != nil {
		t.Fatal(err)
	}

	id := snap.GetAws().GetIdentities()[0]
	if id.GetArn() != "arn:aws:iam::123456789012:user/deploy" {
		t.Errorf("Identity = %q", id.GetArn())
	}
	if len(id.GetAccessKeyIdFingerprints()) != 1 || !strings.HasPrefix(id.GetAccessKeyIdFingerprints()[0], "sha256:") {
		t.Errorf("fingerprints = %v", id.GetAccessKeyIdFingerprints())
	}
	var names []string
	for _, p := range id.GetPolicies() {
		names = append(names, p.GetName())
	}
	if got := strings.Join(names, ","); got != "First,Second,scratch" {
		t.Errorf("policies = %s, want First,Second,scratch (both pages, then inline)", got)
	}
	last := id.GetPolicies()[2].GetDocument().AsMap()
	statement := last["Statement"].([]any)[0].(map[string]any)
	if statement["Resource"] != "arn:aws:s3:::a b+c/*" {
		t.Errorf("the document was not URL-decoded: %v", statement["Resource"])
	}
	if got := id.GetPolicies()[0].GetDocument().AsMap()["Statement"].([]any)[0].(map[string]any)["Action"]; got != "s3:Get*" {
		t.Errorf("managed policy document = %v", got)
	}

	var denied bool
	for _, b := range snap.GetBlindSpots() {
		if strings.Contains(b.GetAttempted(), "iam:ListAttachedGroupPolicies") && b.GetReason() == "AccessDenied" {
			denied = true
		}
		if strings.Contains(b.GetReason(), "not authorized") {
			t.Errorf("a Blind Spot repeats AWS's message: %v", b)
		}
	}
	if !denied {
		t.Errorf("the denied call is not a Blind Spot: %v", snap.GetBlindSpots())
	}

	actions := fake.Actions()
	if len(actions) == 0 {
		t.Fatal("the adapter sent no requests")
	}
	for _, a := range actions {
		if a != "GetCallerIdentity" && !strings.HasPrefix(a, "Get") && !strings.HasPrefix(a, "List") {
			t.Errorf("the adapter sent %s, which is not a read", a)
		}
	}
}

func TestSDKAdapterResolvesAnAssumedRolesPath(t *testing.T) {
	fake := newFakeAWS(t)
	got, err := fake.api(t, "ASIAIOSFODNN7EXAMPLE").GetRole(context.Background(), "ops")
	if err != nil {
		t.Fatal(err)
	}
	if got != "arn:aws:iam::123456789012:role/platform/ops" {
		t.Errorf("role ARN = %q", got)
	}
}

func TestSDKAdapterReportsAWSErrorsWithTheirCode(t *testing.T) {
	fake := newFakeAWS(t)
	_, err := fake.api(t, "AKIAIOSFODNN7EXAMPLE").GetPolicyVersion(context.Background(), "arn:aws:iam::123456789012:policy/p", "v9")
	var ae *aws.Error
	if !errors.As(err, &ae) || ae.Code != "NoSuchEntity" {
		t.Errorf("err = %v, want an *aws.Error with code NoSuchEntity", err)
	}
}

func TestSDKAdapterReadsTheAccessKeyIDWithoutAnyRequest(t *testing.T) {
	fake := newFakeAWS(t)
	got, err := fake.api(t, "AKIAIOSFODNN7EXAMPLE").AccessKeyID(context.Background())
	if err != nil || got != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AccessKeyID = %q, %v", got, err)
	}
	if n := len(fake.Actions()); n != 0 {
		t.Errorf("reading the access key ID sent %d requests", n)
	}
}
