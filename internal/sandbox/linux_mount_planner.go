//go:build linux

package sandbox

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fencesandbox/fence/internal/config"
	"github.com/fencesandbox/fence/internal/fencelog"
)

type linuxLateMountKind int

const (
	linuxLateMountReadOnly linuxLateMountKind = iota
	linuxLateMountMaskFile
	linuxLateMountMaskDir
	// linuxLateMountReveal binds the real path read-only onto itself inside a
	// masked directory (an allowRead carve-out).
	linuxLateMountReveal
	// linuxLateMountWritable binds the real path read-write onto itself
	// inside a read-only directory (an allowWrite carve-out).
	linuxLateMountWritable
)

type linuxLateMount struct {
	Path string
	Kind linuxLateMountKind
}

type linuxLateMountPlanner struct {
	mounts []linuxLateMount
}

func newLinuxLateMountPlanner() *linuxLateMountPlanner {
	return &linuxLateMountPlanner{}
}

func (p *linuxLateMountPlanner) Add(path string, kind linuxLateMountKind) {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return
	}

	for i, existing := range p.mounts {
		if existing.Path != path {
			continue
		}
		if linuxLateMountPriority(kind) > linuxLateMountPriority(existing.Kind) {
			p.mounts[i].Kind = kind
		}
		return
	}

	p.mounts = append(p.mounts, linuxLateMount{Path: path, Kind: kind})
}

func (p *linuxLateMountPlanner) hasStrictAncestor(path string, kind linuxLateMountKind) bool {
	for _, mount := range p.mounts {
		if mount.Kind != kind || mount.Path == path {
			continue
		}
		if pathContains(mount.Path, path) {
			return true
		}
	}
	return false
}

// closestAncestorKind returns the kind of the closest strict ancestor of path
// that has one of kinds.
func (p *linuxLateMountPlanner) closestAncestorKind(path string, kinds ...linuxLateMountKind) (linuxLateMountKind, bool) {
	closest := -1
	for i, mount := range p.mounts {
		if !slices.Contains(kinds, mount.Kind) {
			continue
		}
		if mount.Path == path || !pathContains(mount.Path, path) {
			continue
		}
		if closest < 0 || len(mount.Path) > len(p.mounts[closest].Path) {
			closest = i
		}
	}
	if closest < 0 {
		return 0, false
	}
	return p.mounts[closest].Kind, true
}

// Mounts returns the planned mounts in emission order. Shallower paths come
// first, so a carve-out is emitted after the mount it punctures and a deny
// nested in a carve-out after that carve-out. A mount is dropped when a
// shallower one already decides its fate:
//   - anything but a reveal inside a masked directory with no reveal in between
//   - a read-only bind inside a read-only bind with no writable bind in between
func (p *linuxLateMountPlanner) Mounts() []linuxLateMount {
	var mounts []linuxLateMount
	for _, mount := range p.mounts {
		if mount.Kind != linuxLateMountReveal {
			if kind, ok := p.closestAncestorKind(mount.Path, linuxLateMountMaskDir, linuxLateMountReveal); ok && kind == linuxLateMountMaskDir {
				continue
			}
		}
		if mount.Kind == linuxLateMountReadOnly {
			if kind, ok := p.closestAncestorKind(mount.Path, linuxLateMountReadOnly, linuxLateMountWritable); ok && kind == linuxLateMountReadOnly {
				continue
			}
		}
		mounts = append(mounts, mount)
	}
	slices.SortFunc(mounts, func(a, b linuxLateMount) int {
		depthA := pathDepth(a.Path)
		depthB := pathDepth(b.Path)
		if depthA != depthB {
			return depthA - depthB
		}
		return strings.Compare(a.Path, b.Path)
	})
	return mounts
}

func appendLinuxLateMounts(args []string, mounts []linuxLateMount) []string {
	for _, mount := range mounts {
		switch mount.Kind {
		case linuxLateMountMaskDir:
			args = append(args, "--tmpfs", mount.Path)
		case linuxLateMountMaskFile:
			args = append(args, "--ro-bind", "/dev/null", mount.Path)
		case linuxLateMountReadOnly, linuxLateMountReveal:
			args = append(args, "--ro-bind", mount.Path, mount.Path)
		case linuxLateMountWritable:
			args = append(args, "--bind", mount.Path, mount.Path)
		}
	}
	return args
}

func linuxLateMountPriority(kind linuxLateMountKind) int {
	switch kind {
	case linuxLateMountMaskDir:
		return 5
	case linuxLateMountMaskFile:
		return 4
	case linuxLateMountReveal:
		return 3
	case linuxLateMountReadOnly:
		return 2
	case linuxLateMountWritable:
		return 1
	default:
		return 0
	}
}

func collectResolvedLinuxLateMountPaths(patterns []string) []string {
	if len(patterns) == 0 {
		return nil
	}

	var paths []string
	seen := make(map[string]bool)
	for _, path := range ExpandGlobPatterns(patterns) {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			continue
		}
		mountPath = filepath.Clean(mountPath)
		if seen[mountPath] {
			continue
		}
		seen[mountPath] = true
		paths = append(paths, mountPath)
	}
	return paths
}

// hasExplicitLinuxReadGrant reports whether the config explicitly makes either
// spelling of a path readable. Dangerous-path protection is write-only, but in
// defaultDenyRead mode a read-only bind must not expose a path that the read
// policy never granted. Default system-readable paths are intentionally absent:
// some (notably /tmp) are replaced inside the sandbox rather than exposing the
// corresponding host path.
func hasExplicitLinuxReadGrant(cfg *config.Config, paths ...string) bool {
	if cfg == nil {
		return false
	}

	policy := newPathPolicy(cfg.Filesystem.AllowRead, cfg.Filesystem.DenyRead)
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, denied := policy.deniedBy(path); denied {
			return false
		}
	}

	grants := [][]string{
		cfg.Filesystem.AllowRead,
		cfg.Filesystem.AllowExecute,
		cfg.Filesystem.AllowWrite,
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		for _, rules := range grants {
			if _, allowed := matchPathRule(path, rules); allowed {
				return true
			}
		}
	}
	return false
}

func isLinuxSpecialReadSource(path string) bool {
	return pathContains("/dev", path) || pathContains("/proc", path)
}

func isLinuxRuntimeDeniedSource(path string, deniedExecPaths []string) bool {
	path = filepath.Clean(path)
	for _, deniedPath := range deniedExecPaths {
		resolved, ok := resolvePathForMount(deniedPath)
		if ok && filepath.Clean(resolved) == path {
			return true
		}
		if filepath.Clean(deniedPath) == path {
			return true
		}
	}
	return false
}

// appendLinuxLatePolicyMounts plans the final policy overlays with subtree-aware
// precedence so masked directories cannot be punctured by later self-binds.
// The exceptions are carve-outs: an allowRead path is revealed inside the mask
// that covers it, and an allowWrite path is bound read-write inside a
// denyWrite directory. A missing read carve-out is an error: starting without
// it would silently drop a path the config promises. A missing write carve-out
// only warns, like other missing write paths, and stays read-only.
func appendLinuxLatePolicyMounts(
	bwrapArgs []string,
	cfg *config.Config,
	cwd string,
	defaultDenyRead bool,
	deniedExecPaths []string,
	debug bool,
) ([]string, error) {
	planner := newLinuxLateMountPlanner()

	if cfg != nil {
		policy := newPathPolicy(cfg.Filesystem.AllowRead, cfg.Filesystem.DenyRead)
		for _, pattern := range cfg.Filesystem.DenyRead {
			rule, glob, ok := newPathRule(pattern)
			for _, mountPath := range collectResolvedLinuxLateMountPaths([]string{pattern}) {
				if ok && glob && policy.globReopenedAt(rule, mountPath) {
					continue
				}
				if isDirectory(mountPath) {
					planner.Add(mountPath, linuxLateMountMaskDir)
				} else {
					planner.Add(mountPath, linuxLateMountMaskFile)
				}
			}
		}

		for _, carve := range policy.carveOuts() {
			if !planner.hasStrictAncestor(carve.path, linuxLateMountMaskDir) {
				continue
			}
			mountPath, ok := resolvePathForMount(carve.path)
			if !ok {
				return nil, fmt.Errorf("allowRead %q is inside a denyRead directory but does not exist; Linux cannot re-expose a missing path", carve.raw)
			}
			planner.Add(mountPath, linuxLateMountReveal)
		}
	}

	allowGitConfig := cfg != nil && cfg.Filesystem.AllowGitConfig
	for _, path := range getMandatoryDenyPaths(cwd, allowGitConfig) {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			continue
		}
		// Device and proc exposure is controlled by their dedicated mounts.
		// Do not let a dangerous symlink create a second path to those sources
		// or plan a redundant self-bind against the synthetic mount.
		if isLinuxSpecialReadSource(mountPath) {
			continue
		}
		readable := hasExplicitLinuxReadGrant(cfg, path, mountPath)
		if defaultDenyRead && !readable {
			if isDirectory(mountPath) {
				planner.Add(mountPath, linuxLateMountMaskDir)
			} else {
				planner.Add(mountPath, linuxLateMountMaskFile)
			}
			continue
		}

		// NormalizePath resolves symlinks in any path component, so the earlier
		// allowRead bind exposes only the canonical target. Under
		// defaultDenyRead the lexical name is otherwise absent because its
		// containing directory is not mounted. Restore mandatory dangerous file
		// aliases read-only without bypassing a runtime exec deny. Directories
		// are excluded because canonical descendant masks would not automatically
		// carry over to a second bind-mounted view of the subtree.
		if defaultDenyRead && readable &&
			!isDirectory(mountPath) &&
			filepath.Clean(path) != filepath.Clean(mountPath) &&
			!isLinuxRuntimeDeniedSource(mountPath, deniedExecPaths) {
			bwrapArgs = append(bwrapArgs, "--ro-bind", mountPath, filepath.Clean(path))
		}
		planner.Add(mountPath, linuxLateMountReadOnly)
	}

	if cfg != nil {
		policy := newPathPolicy(cfg.Filesystem.AllowWrite, cfg.Filesystem.DenyWrite)
		var readOnly []string
		for _, pattern := range cfg.Filesystem.DenyWrite {
			rule, glob, ok := newPathRule(pattern)
			for _, mountPath := range collectResolvedLinuxLateMountPaths([]string{pattern}) {
				if ok && glob && policy.globReopenedAt(rule, mountPath) {
					continue
				}
				planner.Add(mountPath, linuxLateMountReadOnly)
				readOnly = append(readOnly, mountPath)
			}
		}

		for _, carve := range policy.carveOuts() {
			inDenyWrite := slices.ContainsFunc(readOnly, func(dir string) bool {
				return dir != carve.path && pathContains(dir, carve.path)
			})
			if !inDenyWrite || linuxDedicatedWritableMount(carve.path) {
				continue
			}
			// Mandatory dangerous-path protection is never reopened.
			if _, dangerous := matchesDangerousPath(carve.path); dangerous {
				continue
			}
			mountPath, ok := resolvePathForMount(carve.path)
			if !ok {
				// Fails safe: the path stays read-only. Warn regardless of
				// debug, like a missing ExposeHostPath, because the caller
				// expects to write there.
				fencelog.Printf("[fence:linux] allowWrite %q is inside a denyWrite directory but does not exist; it will not be writable\n", carve.raw)
				continue
			}
			planner.Add(mountPath, linuxLateMountWritable)
		}
	}

	for _, path := range deniedExecPaths {
		mountPath, ok := resolvePathForMount(path)
		if !ok {
			if debug {
				fencelog.Printf("[fence:linux] Skipping runtime exec deny mount for %s (unmountable)\n", path)
			}
			continue
		}
		planner.Add(mountPath, linuxLateMountMaskFile)
	}

	return appendLinuxLateMounts(bwrapArgs, planner.Mounts()), nil
}
