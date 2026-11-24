package sandbox

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// readRule is one allowRead or denyRead entry. For a literal entry, resolved
// has symlinks resolved through the deepest existing ancestor, so a rule on a
// path that does not exist yet still lands in the directory its parent links
// to. For a glob entry, lexical and resolved are both the expanded pattern.
type readRule struct {
	raw      string
	lexical  string
	resolved string
}

// readPolicy is the single source of read precedence between denyRead and
// allowRead. The macOS profile generator, the Linux mount planner and
// CheckReadPath all consult it, so they cannot disagree.
//
// Precedence:
//   - Among literal entries containing a path, the deepest one wins. On a tie
//     denyRead wins. So a literal allowRead strictly inside a denyRead entry
//     reopens its subtree (a carve-out), and a deeper denyRead closes part of
//     it again.
//   - A glob denyRead entry is reopened only by a literal allowRead that the
//     glob itself matches, for that entry's subtree.
//   - Glob allowRead entries never reopen anything.
type readPolicy struct {
	literalAllows []readRule
	literalDenies []readRule
	globDenies    []readRule
}

func newReadPolicy(allowRead, denyRead []string) *readPolicy {
	p := &readPolicy{}
	for _, raw := range allowRead {
		if rule, glob, ok := newReadRule(raw); ok && !glob {
			p.literalAllows = append(p.literalAllows, rule)
		}
	}
	for _, raw := range denyRead {
		rule, glob, ok := newReadRule(raw)
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

func newReadRule(raw string) (rule readRule, glob bool, ok bool) {
	if raw == "" {
		return readRule{}, false, false
	}
	lexical := expandPathPattern(raw)
	if hasGlobMeta(lexical) || ContainsGlobChars(lexical) {
		return readRule{raw: raw, lexical: lexical, resolved: lexical}, true, true
	}
	lexical = filepath.Clean(lexical)
	if !filepath.IsAbs(lexical) {
		return readRule{}, false, false
	}
	return readRule{raw: raw, lexical: lexical, resolved: resolveExistingPrefix(lexical)}, false, true
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

func (r readRule) contains(path string) bool {
	return pathContains(r.resolved, path) || pathContains(r.lexical, path)
}

func globMatches(glob readRule, path string) bool {
	matched, err := doublestar.Match(glob.lexical, path)
	return err == nil && matched
}

func globMatchesRule(glob, rule readRule) bool {
	return globMatches(glob, rule.resolved) || globMatches(glob, rule.lexical)
}

// deepestReadRule returns the deepest rule whose resolved path contains path.
func deepestReadRule(rules []readRule, path string) (readRule, bool) {
	var best readRule
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

// globReopenedAt reports whether a literal allowRead reopens glob for path:
// the glob matches the allow entry and the entry contains path.
func (p *readPolicy) globReopenedAt(glob readRule, path string) bool {
	for _, allow := range p.literalAllows {
		if allow.contains(path) && globMatchesRule(glob, allow) {
			return true
		}
	}
	return false
}

// deniedBy returns the denyRead entry (as written) that blocks path, if any.
// path must be absolute and clean; callers that hold a symlinked spelling
// should also ask about the resolved one.
func (p *readPolicy) deniedBy(path string) (string, bool) {
	if deny, ok := deepestReadRule(p.literalDenies, path); ok {
		allow, reopened := deepestReadRule(p.literalAllows, path)
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

// readCarveOut is a literal allowRead entry that reopens part of a denied
// area.
type readCarveOut struct {
	raw  string
	path string
	// closedAncestors are the ancestors of path that stay denied. Tools need
	// to stat them to reach path; they stay unlistable.
	closedAncestors []string
	// residualGlobs are the denyRead globs that still apply inside path.
	residualGlobs []string
}

// carveOuts returns the carve-outs ordered by depth, shallowest first.
func (p *readPolicy) carveOuts() []readCarveOut {
	var out []readCarveOut
	seen := make(map[string]bool)
	for _, allow := range p.literalAllows {
		if seen[allow.resolved] || !p.coveredByDeny(allow) {
			continue
		}
		if _, denied := p.deniedBy(allow.resolved); denied {
			continue
		}
		seen[allow.resolved] = true

		carve := readCarveOut{raw: allow.raw, path: allow.resolved}
		for dir := filepath.Dir(allow.resolved); ; dir = filepath.Dir(dir) {
			if _, denied := p.deniedBy(dir); denied {
				carve.closedAncestors = append(carve.closedAncestors, dir)
			}
			if dir == filepath.Dir(dir) {
				break
			}
		}
		for _, glob := range p.globDenies {
			if !p.globReopenedAt(glob, allow.resolved) {
				carve.residualGlobs = append(carve.residualGlobs, glob.lexical)
			}
		}
		out = append(out, carve)
	}
	slices.SortStableFunc(out, func(a, b readCarveOut) int {
		return pathDepth(a.path) - pathDepth(b.path)
	})
	return out
}

// coveredByDeny reports whether some denyRead entry would block allow if the
// allow entry were absent.
func (p *readPolicy) coveredByDeny(allow readRule) bool {
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
