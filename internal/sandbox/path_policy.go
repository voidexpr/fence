package sandbox

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// pathRule is one allow or deny entry. For a literal entry, resolved has
// symlinks resolved through the deepest existing ancestor, so a rule on a path
// that does not exist yet still lands in the directory its parent links to.
// For a glob entry, lexical and resolved are both the expanded pattern.
type pathRule struct {
	raw      string
	lexical  string
	resolved string
	// linkPath is set when the last component of a literal entry is a
	// symlink: the path of the link itself, as the kernel names it.
	linkPath string
}

// pathPolicy is the single source of precedence between a deny list and its
// allow list: denyRead against allowRead, or denyWrite against allowWrite.
// The macOS profile generator, the Linux mount planner and the CheckReadPath
// / CheckWritePath predicates all consult it, so they cannot disagree.
//
// Precedence:
//   - Among literal entries containing a path, the deepest one wins. On a tie
//     deny wins. So a literal allow strictly inside a deny entry reopens its
//     subtree (a carve-out), and a deeper deny closes part of it again.
//   - A glob deny entry is reopened only by a literal allow that the glob
//     itself matches, for that entry's subtree.
//   - Glob allow entries never reopen anything.
type pathPolicy struct {
	literalAllows []pathRule
	literalDenies []pathRule
	globDenies    []pathRule
}

func newPathPolicy(allow, deny []string) *pathPolicy {
	p := &pathPolicy{}
	for _, raw := range allow {
		if rule, glob, ok := newPathRule(raw); ok && !glob {
			p.literalAllows = append(p.literalAllows, rule)
		}
	}
	for _, raw := range deny {
		rule, glob, ok := newPathRule(raw)
		switch {
		case !ok:
		case glob:
			p.globDenies = append(p.globDenies, rule)
		default:
			p.literalDenies = append(p.literalDenies, rule)
		}
	}
	return p
}

func newPathRule(raw string) (rule pathRule, glob bool, ok bool) {
	if raw == "" {
		return pathRule{}, false, false
	}
	lexical := expandPathPattern(raw)
	if hasGlobMeta(lexical) || ContainsGlobChars(lexical) {
		return pathRule{raw: raw, lexical: lexical, resolved: lexical}, true, true
	}
	lexical = filepath.Clean(lexical)
	if !filepath.IsAbs(lexical) {
		return pathRule{}, false, false
	}
	rule = pathRule{raw: raw, lexical: lexical, resolved: resolveExistingPrefix(lexical)}
	link := filepath.Join(resolveExistingPrefix(filepath.Dir(lexical)), filepath.Base(lexical))
	if link != rule.resolved && isSymlink(link) {
		rule.linkPath = link
	}
	return rule, false, true
}

// resolveExistingPrefix resolves symlinks in path. When path does not exist,
// the deepest existing ancestor is resolved and the remainder is appended.
func resolveExistingPrefix(path string) string {
	path = filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path
	}
	return filepath.Join(resolveExistingPrefix(parent), filepath.Base(path))
}

// pathContains reports whether path is ancestor or lies below it.
func pathContains(ancestor, path string) bool {
	ancestor = filepath.Clean(ancestor)
	path = filepath.Clean(path)

	if ancestor == path {
		return true
	}
	if ancestor == string(filepath.Separator) {
		return strings.HasPrefix(path, string(filepath.Separator))
	}
	return strings.HasPrefix(path, ancestor+string(filepath.Separator))
}

func pathDepth(path string) int {
	trimmed := strings.Trim(filepath.Clean(path), string(filepath.Separator))
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, string(filepath.Separator)) + 1
}

func (r pathRule) contains(path string) bool {
	return pathContains(r.resolved, path) || pathContains(r.lexical, path)
}

func globMatches(glob pathRule, path string) bool {
	matched, err := doublestar.Match(glob.lexical, path)
	return err == nil && matched
}

func globMatchesRule(glob, rule pathRule) bool {
	return globMatches(glob, rule.resolved) || globMatches(glob, rule.lexical)
}

// deepestPathRule returns the deepest rule whose resolved path contains path.
func deepestPathRule(rules []pathRule, path string) (pathRule, bool) {
	var best pathRule
	found := false
	for _, rule := range rules {
		if !pathContains(rule.resolved, path) {
			continue
		}
		if !found || len(rule.resolved) > len(best.resolved) {
			best, found = rule, true
		}
	}
	return best, found
}

// globReopenedAt reports whether a literal allow reopens glob for path:
// the glob matches the allow entry and the entry contains path.
func (p *pathPolicy) globReopenedAt(glob pathRule, path string) bool {
	for _, allow := range p.literalAllows {
		if allow.contains(path) && globMatchesRule(glob, allow) {
			return true
		}
	}
	return false
}

// deniedBy returns the deny entry (as written) that blocks path, if any.
// path must be absolute and clean; callers that hold a symlinked spelling
// should also ask about the resolved one.
func (p *pathPolicy) deniedBy(path string) (string, bool) {
	if deny, ok := deepestPathRule(p.literalDenies, path); ok {
		allow, reopened := deepestPathRule(p.literalAllows, path)
		if !reopened || len(allow.resolved) <= len(deny.resolved) {
			return deny.raw, true
		}
	}
	for _, glob := range p.globDenies {
		if globMatches(glob, path) && !p.globReopenedAt(glob, path) {
			return glob.raw, true
		}
	}
	return "", false
}

// pathCarveOut is a literal allow entry that reopens part of a denied area.
type pathCarveOut struct {
	raw  string
	path string
	// closedAncestors are the ancestors of path that stay denied, plus the
	// symlink a covering deny entry was given by. They must be stat-able to
	// reach path, and they stay unlistable. For the symlink this has a cost:
	// on macOS following a link and readlink need the same permission, so a
	// carve-out below a denied link makes the link's target visible again.
	closedAncestors []string
	// residualGlobs are the deny globs that still apply inside path.
	residualGlobs []string
}

// carveOuts returns the carve-outs ordered by depth, shallowest first.
func (p *pathPolicy) carveOuts() []pathCarveOut {
	var out []pathCarveOut
	seen := make(map[string]bool)
	for _, allow := range p.literalAllows {
		if seen[allow.resolved] || !p.coveredByDeny(allow) {
			continue
		}
		if _, denied := p.deniedBy(allow.resolved); denied {
			continue
		}
		seen[allow.resolved] = true

		carve := pathCarveOut{raw: allow.raw, path: allow.resolved}
		for dir := filepath.Dir(allow.resolved); ; dir = filepath.Dir(dir) {
			if _, denied := p.deniedBy(dir); denied {
				carve.closedAncestors = append(carve.closedAncestors, dir)
			}
			if dir == filepath.Dir(dir) {
				break
			}
		}
		for _, deny := range p.literalDenies {
			if deny.linkPath != "" && pathContains(deny.resolved, allow.resolved) {
				carve.closedAncestors = append(carve.closedAncestors, deny.linkPath)
			}
		}
		for _, glob := range p.globDenies {
			if !p.globReopenedAt(glob, allow.resolved) {
				carve.residualGlobs = append(carve.residualGlobs, glob.lexical)
			}
		}
		out = append(out, carve)
	}
	slices.SortStableFunc(out, func(a, b pathCarveOut) int {
		return pathDepth(a.path) - pathDepth(b.path)
	})
	return out
}

// coveredByDeny reports whether some deny entry would block allow if the
// allow entry were absent.
func (p *pathPolicy) coveredByDeny(allow pathRule) bool {
	for _, deny := range p.literalDenies {
		if deny.resolved != allow.resolved && pathContains(deny.resolved, allow.resolved) {
			return true
		}
	}
	for _, glob := range p.globDenies {
		if globMatchesRule(glob, allow) {
			return true
		}
	}
	return false
}
