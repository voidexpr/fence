package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fencesandbox/fence/internal/config"
)

// carveOutCase describes a set of deny and allow entries and the answer
// expected for each path. The entries are used as denyRead/allowRead or as
// denyWrite/allowWrite. Paths are relative to a temp root, except "**/"
// globs, which are kept as written. The same cases drive the path predicates, the
// macOS profile and the Linux mount plan.
type carveOutCase struct {
	name    string
	allow   []string
	deny    []string
	open    []string
	blocked []string
}

var carveOutCases = []carveOutCase{
	{
		name:    "plain deny",
		deny:    []string{"d"},
		open:    []string{"other/x"},
		blocked: []string{"d", "d/f", "d/sub/x"},
	},
	{
		name:    "carve-out file",
		allow:   []string{"d/f"},
		deny:    []string{"d"},
		open:    []string{"d/f"},
		blocked: []string{"d", "d/g", "d/sub/x"},
	},
	{
		name:    "carve-out directory",
		allow:   []string{"d/sub"},
		deny:    []string{"d"},
		open:    []string{"d/sub", "d/sub/x", "d/sub/deep/y"},
		blocked: []string{"d", "d/f"},
	},
	{
		name:    "three-level nesting",
		allow:   []string{"d/sub", "d/sub/deep/y"},
		deny:    []string{"d", "d/sub/deep"},
		open:    []string{"d/sub/x", "d/sub/deep/y"},
		blocked: []string{"d/f", "d/sub/deep", "d/sub/deep/z"},
	},
	{
		name:    "tie goes to deny",
		allow:   []string{"d"},
		deny:    []string{"d"},
		blocked: []string{"d", "d/f"},
	},
	{
		name:    "deeper deny beats allow",
		allow:   []string{"d"},
		deny:    []string{"d/sub"},
		open:    []string{"d/f"},
		blocked: []string{"d/sub/x"},
	},
	{
		name:    "glob allow inside deny does not reopen",
		allow:   []string{"d/*"},
		deny:    []string{"d"},
		blocked: []string{"d/f", "d/g"},
	},
	{
		name:    "glob deny reopened by literal allow",
		allow:   []string{"d/f"},
		deny:    []string{"d/**"},
		open:    []string{"d/f"},
		blocked: []string{"d/g", "d/sub/x"},
	},
	{
		name:    "glob deny stays inside an unrelated carve-out",
		allow:   []string{"d/sub"},
		deny:    []string{"d", "**/*.pem"},
		open:    []string{"d/sub/x"},
		blocked: []string{"d/sub/key.pem", "other/key.pem"},
	},
}

// newCarveOutTree creates the files the cases refer to and returns the
// symlink-resolved root. It also moves into the root, because Linux expands
// "**/" globs from the working directory.
func newCarveOutTree(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to resolve temp dir: %v", err)
	}
	for _, name := range []string{
		"other/x", "other/key.pem",
		"d/f", "d/g", "d/sub/x", "d/sub/key.pem", "d/sub/deep/y", "d/sub/deep/z",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}
	t.Chdir(root)
	return root
}

func joinAll(root string, names []string) []string {
	paths := make([]string, 0, len(names))
	for _, name := range names {
		if strings.HasPrefix(name, "**/") {
			paths = append(paths, name)
			continue
		}
		paths = append(paths, filepath.Join(root, name))
	}
	return paths
}

// filesystemConfig builds the config for a case. In defaultDenyRead mode the
// root is granted, so only denyRead decides the outcome.
func (c carveOutCase) filesystemConfig(root string, defaultDenyRead bool) config.FilesystemConfig {
	fs := config.FilesystemConfig{
		DefaultDenyRead: defaultDenyRead,
		AllowRead:       joinAll(root, c.allow),
		DenyRead:        joinAll(root, c.deny),
	}
	if defaultDenyRead {
		fs.AllowRead = append(fs.AllowRead, root)
	}
	return fs
}

// writeConfig builds the config that uses a case as write rules. The root is
// writable, so only denyWrite decides the outcome.
func (c carveOutCase) writeConfig(root string) config.FilesystemConfig {
	return config.FilesystemConfig{
		AllowWrite: append(joinAll(root, c.allow), root),
		DenyWrite:  joinAll(root, c.deny),
	}
}

func TestCheckWritePath_CarveOuts(t *testing.T) {
	root := newCarveOutTree(t)

	for _, tc := range carveOutCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Filesystem: tc.writeConfig(root)}
			for _, path := range joinAll(root, tc.open) {
				if err := CheckWritePath(path, "", cfg); err != nil {
					t.Errorf("expected %s to be writable, got %v", path, err)
				}
			}
			for _, path := range joinAll(root, tc.blocked) {
				if err := CheckWritePath(path, "", cfg); err == nil {
					t.Errorf("expected %s to be blocked", path)
				}
			}
		})
	}
}

// A dangerous path stays blocked inside a write carve-out.
func TestCheckWritePath_CarveOutDoesNotReopenDangerousPath(t *testing.T) {
	root := newCarveOutTree(t)
	in := func(name string) string { return filepath.Join(root, name) }

	cfg := &config.Config{Filesystem: config.FilesystemConfig{
		AllowWrite: []string{in("d/sub")},
		DenyWrite:  []string{in("d")},
	}}
	if err := CheckWritePath(in("d/sub/x"), "", cfg); err != nil {
		t.Errorf("expected the carve-out to be writable, got %v", err)
	}
	for _, path := range []string{in("d/sub/.bashrc"), in("d/sub/.git/hooks/pre-commit")} {
		if err := CheckWritePath(path, "", cfg); err == nil {
			t.Errorf("expected dangerous path %s to stay blocked", path)
		}
	}
}

func TestPathPolicy_DenyGivenByLinkRecordsTheLink(t *testing.T) {
	root := newCarveOutTree(t)
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "d"), link); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	policy := newPathPolicy([]string{filepath.Join(link, "f")}, []string{link})
	if got := policy.literalDenies[0].linkPath; got != link {
		t.Fatalf("linkPath = %q, want %q", got, link)
	}
	// The carve-out is reached through the link, so the link must be
	// stat-able.
	carveOuts := policy.carveOuts()
	if len(carveOuts) != 1 || !slices.Contains(carveOuts[0].closedAncestors, link) {
		t.Fatalf("expected the link among the closed ancestors, got %#v", carveOuts)
	}

	// A plain directory has no link path.
	if got := newPathPolicy(nil, []string{filepath.Join(root, "d")}).literalDenies[0].linkPath; got != "" {
		t.Fatalf("linkPath = %q, want empty", got)
	}
}

func TestCheckReadPath_CarveOuts(t *testing.T) {
	root := newCarveOutTree(t)

	for _, tc := range carveOutCases {
		for _, defaultDenyRead := range []bool{false, true} {
			name := tc.name + "/read-mostly"
			if defaultDenyRead {
				name = tc.name + "/defaultDenyRead"
			}
			t.Run(name, func(t *testing.T) {
				cfg := &config.Config{Filesystem: tc.filesystemConfig(root, defaultDenyRead)}
				for _, path := range joinAll(root, tc.open) {
					if err := CheckReadPath(path, "", cfg); err != nil {
						t.Errorf("expected %s to be readable, got %v", path, err)
					}
				}
				for _, path := range joinAll(root, tc.blocked) {
					if err := CheckReadPath(path, "", cfg); err == nil {
						t.Errorf("expected %s to be blocked", path)
					}
				}
			})
		}
	}
}

func TestReadPolicy_CarveOutList(t *testing.T) {
	root := newCarveOutTree(t)
	in := func(name string) string { return filepath.Join(root, name) }

	policy := newPathPolicy(
		[]string{in("d/sub/deep/y"), in("d/sub"), in("other"), in("d/*")},
		[]string{in("d"), in("d/sub/deep"), "**/*.pem"},
	)

	carveOuts := policy.carveOuts()
	if len(carveOuts) != 2 {
		t.Fatalf("expected two carve-outs, got %#v", carveOuts)
	}
	if carveOuts[0].path != in("d/sub") || carveOuts[1].path != in("d/sub/deep/y") {
		t.Fatalf("expected carve-outs ordered by depth, got %#v", carveOuts)
	}
	if !slices.Equal(carveOuts[0].closedAncestors, []string{in("d")}) {
		t.Errorf("unexpected closed ancestors for d/sub: %v", carveOuts[0].closedAncestors)
	}
	if !slices.Equal(carveOuts[1].closedAncestors, []string{in("d/sub/deep"), in("d")}) {
		t.Errorf("unexpected closed ancestors for d/sub/deep/y: %v", carveOuts[1].closedAncestors)
	}
	if !slices.Equal(carveOuts[0].residualGlobs, []string{"**/*.pem"}) {
		t.Errorf("expected the unrelated glob to stay in force, got %v", carveOuts[0].residualGlobs)
	}
}

// The denied folder is often a link into another folder. The carve-out must
// work whichever name each entry uses.
func TestCheckReadPath_CarveOutThroughSymlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to resolve temp dir: %v", err)
	}
	target := filepath.Join(root, "Sync", "ssh")
	link := filepath.Join(root, "ssh")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatalf("failed to create target: %v", err)
	}
	for _, name := range []string{"config", "id_ed25519"} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(name), 0o600); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	for _, deny := range []string{link, target} {
		for _, allowDir := range []string{link, target} {
			cfg := &config.Config{Filesystem: config.FilesystemConfig{
				DenyRead: []string{deny},
				// "later" does not exist: only its ancestors can be resolved.
				AllowRead: []string{filepath.Join(allowDir, "config"), filepath.Join(allowDir, "later")},
			}}
			for _, dir := range []string{link, target} {
				for _, name := range []string{"config", "later"} {
					if err := CheckReadPath(filepath.Join(dir, name), "", cfg); err != nil {
						t.Errorf("deny=%s allow=%s: expected %s/%s readable, got %v", deny, allowDir, dir, name, err)
					}
				}
				if err := CheckReadPath(filepath.Join(dir, "id_ed25519"), "", cfg); err == nil {
					t.Errorf("deny=%s allow=%s: expected %s/id_ed25519 blocked", deny, allowDir, dir)
				}
			}
		}
	}
}
