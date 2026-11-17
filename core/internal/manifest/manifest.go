// Package manifest reads and validates the Agent Manifest, the user-authored
// declaration of an Agent Deployment. The schema is documented in
// SCHEMA.md.
package manifest

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/imRYiUK/agentguard/core/internal/limits"
)

// SchemaVersion is the Agent Manifest schema version this package reads.
const SchemaVersion = 1

// Environment types.
const (
	TypeLinux = "linux"
	TypeAWS   = "aws"
)

// Resource Sensitivity levels, lowest first.
const (
	SensitivityLow      = "low"
	SensitivityMedium   = "medium"
	SensitivityHigh     = "high"
	SensitivityCritical = "critical"
)

var (
	types         = []string{TypeLinux, TypeAWS}
	sensitivities = []string{SensitivityLow, SensitivityMedium, SensitivityHigh, SensitivityCritical}
)

// Manifest is a parsed, validated Agent Manifest.
type Manifest struct {
	// Version is the schema version the manifest declares.
	Version int
	Agent   Agent
	// Environments are the Environments the agent runs in, in manifest order.
	Environments []Environment
	// DeclaredBindings are the Identity Bindings the user states.
	DeclaredBindings []DeclaredBinding
	// ResourceSensitivities are the user's Resource Sensitivity labels.
	ResourceSensitivities []ResourceSensitivity
}

// Agent names the agent and the configuration files that declare its Tools.
type Agent struct {
	Name string
	// ClaudeCodeSettings and MCP list the agent's configuration files as
	// slash-separated paths relative to the manifest's folder.
	ClaudeCodeSettings []string
	MCP                []string
}

// Environment is an Environment the agent runs in.
type Environment struct {
	Name string
	// Type is TypeLinux or TypeAWS.
	Type string
	// Index is the Environment's position in the manifest's environments
	// list, used to point at it in messages.
	Index int
	// Expected provider-native identity. Only the fields of Type are set. For
	// a Linux Environment at least one of MachineID and SSHHostKeyFingerprint
	// is set, and each one that is set must match the Snapshot.
	MachineID             string
	SSHHostKeyFingerprint string
	AccountID             string
	// Snapshot is the path of the Environment's Snapshot file, relative to
	// the manifest's folder.
	Snapshot string
}

// DeclaredBinding is an Identity Binding stated by the user: the agent can act
// as Identity in the named Environment.
type DeclaredBinding struct {
	// Environment is the name of an Environment in the manifest.
	Environment string
	// Identity is a Linux user name for a Linux Environment, or an ARN for an
	// AWS Environment.
	Identity string
}

// ResourceSensitivity is a Resource Sensitivity label on a resource pattern.
type ResourceSensitivity struct {
	// Resource is a resource name or pattern, for example an ARN with
	// wildcards.
	Resource string
	// Sensitivity is one of the Sensitivity constants.
	Sensitivity string
}

// Error is a malformed-manifest error. It names the manifest field and the
// line it is on.
type Error struct {
	Source  string
	Line    int
	Field   string
	Message string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Source)
	if e.Line > 0 {
		fmt.Fprintf(&b, ":%d", e.Line)
	}
	b.WriteString(": ")
	if e.Field != "" {
		b.WriteString(e.Field + ": ")
	}
	b.WriteString(e.Message)
	return b.String()
}

// Parse reads and validates an Agent Manifest. source is the name used in
// error messages.
func Parse(source string, content []byte) (*Manifest, error) {
	if err := limits.CheckSize(len(content), limits.MaxConfigBytes); err != nil {
		return nil, &Error{Source: source, Message: err.Error()}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, &Error{Source: source, Message: "invalid YAML: " + strings.TrimPrefix(err.Error(), "yaml: ")}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, &Error{Source: source, Message: "the manifest is empty"}
	}
	if deeper(&doc, 0) {
		return nil, &Error{Source: source, Message: limits.ErrTooDeep.Error()}
	}
	d := &decoder{source: source}
	m, err := d.manifest(doc.Content[0])
	if err != nil {
		return nil, err
	}
	return m, nil
}

// deeper reports whether n nests more than limits.MaxDepth levels of mappings
// and lists. It does not follow aliases.
func deeper(n *yaml.Node, depth int) bool {
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		depth++
		if depth > limits.MaxDepth {
			return true
		}
	}
	for _, c := range n.Content {
		if deeper(c, depth) {
			return true
		}
	}
	return false
}

type decoder struct {
	source string
}

func (d *decoder) errorf(n *yaml.Node, field, format string, args ...any) error {
	return &Error{Source: d.source, Line: n.Line, Field: field, Message: fmt.Sprintf(format, args...)}
}

// fields checks that n is a mapping with only the allowed keys, once each,
// and returns its values by key.
func (d *decoder) fields(n *yaml.Node, path string, allowed ...string) (map[string]*yaml.Node, error) {
	if n.Kind == yaml.AliasNode {
		return nil, d.errorf(n, path, "YAML aliases are not supported")
	}
	if n.Kind != yaml.MappingNode {
		return nil, d.errorf(n, path, "must be a mapping")
	}
	out := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		name := key.Value
		if key.Kind != yaml.ScalarNode {
			return nil, d.errorf(key, path, "keys must be strings")
		}
		if !slices.Contains(allowed, name) {
			return nil, d.errorf(key, join(path, name), "unknown field (allowed: %s)", strings.Join(allowed, ", "))
		}
		if _, dup := out[name]; dup {
			return nil, d.errorf(key, join(path, name), "duplicate field")
		}
		out[name] = value
	}
	return out, nil
}

func (d *decoder) required(fields map[string]*yaml.Node, parent *yaml.Node, path, name string) (*yaml.Node, error) {
	n, ok := fields[name]
	if !ok {
		return nil, d.errorf(parent, join(path, name), "required field is missing")
	}
	return n, nil
}

func (d *decoder) str(n *yaml.Node, path string) (string, error) {
	if n.Kind == yaml.AliasNode {
		return "", d.errorf(n, path, "YAML aliases are not supported")
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", d.errorf(n, path, "must be a string (quote it if it looks like a number)")
	}
	return n.Value, nil
}

func (d *decoder) nonEmptyStr(n *yaml.Node, path string) (string, error) {
	s, err := d.str(n, path)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(s) == "" {
		return "", d.errorf(n, path, "must not be empty")
	}
	return s, nil
}

func (d *decoder) sequence(n *yaml.Node, path string) ([]*yaml.Node, error) {
	if n.Kind == yaml.AliasNode {
		return nil, d.errorf(n, path, "YAML aliases are not supported")
	}
	if n.Kind != yaml.SequenceNode {
		return nil, d.errorf(n, path, "must be a list")
	}
	if len(n.Content) > limits.MaxListLength {
		return nil, d.errorf(n, path, "too many entries (%d; the limit is %d)", len(n.Content), limits.MaxListLength)
	}
	return n.Content, nil
}

func (d *decoder) enum(n *yaml.Node, path string, allowed []string) (string, error) {
	s, err := d.str(n, path)
	if err != nil {
		return "", err
	}
	if !slices.Contains(allowed, s) {
		return "", d.errorf(n, path, "must be one of %s, got %q", strings.Join(allowed, ", "), s)
	}
	return s, nil
}

var agentName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (d *decoder) manifest(root *yaml.Node) (*Manifest, error) {
	f, err := d.fields(root, "", "version", "agent", "environments", "declaredBindings", "resourceSensitivity")
	if err != nil {
		return nil, err
	}
	m := &Manifest{}

	versionNode, err := d.required(f, root, "", "version")
	if err != nil {
		return nil, err
	}
	if versionNode.Kind != yaml.ScalarNode || versionNode.Tag != "!!int" {
		return nil, d.errorf(versionNode, "version", "must be the integer %d", SchemaVersion)
	}
	v, convErr := strconv.Atoi(versionNode.Value)
	if convErr != nil || v != SchemaVersion {
		return nil, d.errorf(versionNode, "version", "unsupported version %s (this AgentGuard reads version %d)", versionNode.Value, SchemaVersion)
	}
	m.Version = v

	agentNode, err := d.required(f, root, "", "agent")
	if err != nil {
		return nil, err
	}
	if m.Agent, err = d.agent(agentNode); err != nil {
		return nil, err
	}

	envsNode, err := d.required(f, root, "", "environments")
	if err != nil {
		return nil, err
	}
	if m.Environments, err = d.environments(envsNode); err != nil {
		return nil, err
	}

	if n, ok := f["declaredBindings"]; ok {
		if m.DeclaredBindings, err = d.declaredBindings(n, m.Environments); err != nil {
			return nil, err
		}
	}
	if n, ok := f["resourceSensitivity"]; ok {
		if m.ResourceSensitivities, err = d.resourceSensitivities(n); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (d *decoder) agent(n *yaml.Node) (Agent, error) {
	var a Agent
	f, err := d.fields(n, "agent", "name", "configs")
	if err != nil {
		return a, err
	}
	nameNode, err := d.required(f, n, "agent", "name")
	if err != nil {
		return a, err
	}
	if a.Name, err = d.nonEmptyStr(nameNode, "agent.name"); err != nil {
		return a, err
	}
	if !agentName.MatchString(a.Name) {
		return a, d.errorf(nameNode, "agent.name", "must be 1-128 letters, digits, '.', '_' or '-', starting with a letter or digit, got %q", a.Name)
	}
	if cn, ok := f["configs"]; ok {
		cf, err := d.fields(cn, "agent.configs", "claudeCodeSettings", "mcp")
		if err != nil {
			return a, err
		}
		if a.ClaudeCodeSettings, err = d.paths(cf["claudeCodeSettings"], "agent.configs.claudeCodeSettings"); err != nil {
			return a, err
		}
		if a.MCP, err = d.paths(cf["mcp"], "agent.configs.mcp"); err != nil {
			return a, err
		}
	}
	return a, nil
}

// paths reads an optional list of file paths.
func (d *decoder) paths(n *yaml.Node, path string) ([]string, error) {
	if n == nil {
		return nil, nil
	}
	items, err := d.sequence(n, path)
	if err != nil {
		return nil, err
	}
	var out []string
	for i, item := range items {
		p, err := d.filePath(item, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// filePath reads a path that must stay inside the manifest's folder.
func (d *decoder) filePath(n *yaml.Node, path string) (string, error) {
	p, err := d.nonEmptyStr(n, path)
	if err != nil {
		return "", err
	}
	if !fs.ValidPath(p) || p == "." {
		return "", d.errorf(n, path, "must be a slash-separated path inside the manifest's folder (no leading '/', '..', or empty segments), got %q", p)
	}
	return p, nil
}

var (
	machineID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hostKeyFP   = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	awsAccount  = regexp.MustCompile(`^[0-9]{12}$`)
	environName = agentName
)

func (d *decoder) environments(n *yaml.Node) ([]Environment, error) {
	items, err := d.sequence(n, "environments")
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, d.errorf(n, "environments", "must list at least one Environment")
	}
	var envs []Environment
	for i, item := range items {
		env, err := d.environment(item, i)
		if err != nil {
			return nil, err
		}
		if j := slices.IndexFunc(envs, func(e Environment) bool { return e.Name == env.Name }); j >= 0 {
			return nil, d.errorf(item, fmt.Sprintf("environments[%d].name", i), "duplicate Environment name %q (also environments[%d])", env.Name, j)
		}
		envs = append(envs, env)
	}
	return envs, nil
}

func (d *decoder) environment(n *yaml.Node, index int) (Environment, error) {
	env := Environment{Index: index}
	path := fmt.Sprintf("environments[%d]", index)
	f, err := d.fields(n, path, "name", "type", "identity", "snapshot")
	if err != nil {
		return env, err
	}

	nameNode, err := d.required(f, n, path, "name")
	if err != nil {
		return env, err
	}
	if env.Name, err = d.nonEmptyStr(nameNode, path+".name"); err != nil {
		return env, err
	}
	if !environName.MatchString(env.Name) {
		return env, d.errorf(nameNode, path+".name", "must be 1-128 letters, digits, '.', '_' or '-', starting with a letter or digit, got %q", env.Name)
	}

	typeNode, err := d.required(f, n, path, "type")
	if err != nil {
		return env, err
	}
	if env.Type, err = d.enum(typeNode, path+".type", types); err != nil {
		return env, err
	}

	snapNode, err := d.required(f, n, path, "snapshot")
	if err != nil {
		return env, err
	}
	if env.Snapshot, err = d.filePath(snapNode, path+".snapshot"); err != nil {
		return env, err
	}

	idNode, err := d.required(f, n, path, "identity")
	if err != nil {
		return env, err
	}
	idPath := path + ".identity"
	switch env.Type {
	case TypeLinux:
		idf, err := d.fields(idNode, idPath, "machineId", "sshHostKeyFingerprint")
		if err != nil {
			return env, err
		}
		if len(idf) == 0 {
			return env, d.errorf(idNode, idPath, "a linux Environment needs machineId or sshHostKeyFingerprint")
		}
		if v, ok := idf["machineId"]; ok {
			if env.MachineID, err = d.matching(v, idPath+".machineId", machineID, "the 32 lowercase hex characters of /etc/machine-id"); err != nil {
				return env, err
			}
		}
		if v, ok := idf["sshHostKeyFingerprint"]; ok {
			if env.SSHHostKeyFingerprint, err = d.matching(v, idPath+".sshHostKeyFingerprint", hostKeyFP, `an SSH host key fingerprint such as "SHA256:..."`); err != nil {
				return env, err
			}
		}
	case TypeAWS:
		idf, err := d.fields(idNode, idPath, "accountId")
		if err != nil {
			return env, err
		}
		v, err := d.required(idf, idNode, idPath, "accountId")
		if err != nil {
			return env, err
		}
		if env.AccountID, err = d.matching(v, idPath+".accountId", awsAccount, "a 12-digit AWS account ID"); err != nil {
			return env, err
		}
	}
	return env, nil
}

// matching reads an identity value. A machine ID or account ID made only of
// digits is a valid YAML number, so a number is accepted and read as the text
// the user wrote.
func (d *decoder) matching(n *yaml.Node, path string, re *regexp.Regexp, want string) (string, error) {
	if n.Kind != yaml.ScalarNode || (n.Tag != "!!str" && n.Tag != "!!int" && n.Tag != "!!float") {
		return "", d.errorf(n, path, "must be %s", want)
	}
	s := n.Value
	if !re.MatchString(s) {
		return "", d.errorf(n, path, "must be %s, got %q", want, s)
	}
	return s, nil
}

func (d *decoder) declaredBindings(n *yaml.Node, envs []Environment) ([]DeclaredBinding, error) {
	items, err := d.sequence(n, "declaredBindings")
	if err != nil {
		return nil, err
	}
	var out []DeclaredBinding
	for i, item := range items {
		path := fmt.Sprintf("declaredBindings[%d]", i)
		f, err := d.fields(item, path, "environment", "identity")
		if err != nil {
			return nil, err
		}
		var b DeclaredBinding
		envNode, err := d.required(f, item, path, "environment")
		if err != nil {
			return nil, err
		}
		if b.Environment, err = d.nonEmptyStr(envNode, path+".environment"); err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(envs, func(e Environment) bool { return e.Name == b.Environment }) {
			return nil, d.errorf(envNode, path+".environment", "no Environment named %q in environments", b.Environment)
		}
		idNode, err := d.required(f, item, path, "identity")
		if err != nil {
			return nil, err
		}
		if b.Identity, err = d.nonEmptyStr(idNode, path+".identity"); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func (d *decoder) resourceSensitivities(n *yaml.Node) ([]ResourceSensitivity, error) {
	items, err := d.sequence(n, "resourceSensitivity")
	if err != nil {
		return nil, err
	}
	var out []ResourceSensitivity
	for i, item := range items {
		path := fmt.Sprintf("resourceSensitivity[%d]", i)
		f, err := d.fields(item, path, "resource", "sensitivity")
		if err != nil {
			return nil, err
		}
		var r ResourceSensitivity
		resNode, err := d.required(f, item, path, "resource")
		if err != nil {
			return nil, err
		}
		if r.Resource, err = d.nonEmptyStr(resNode, path+".resource"); err != nil {
			return nil, err
		}
		sensNode, err := d.required(f, item, path, "sensitivity")
		if err != nil {
			return nil, err
		}
		if r.Sensitivity, err = d.enum(sensNode, path+".sensitivity", sensitivities); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
