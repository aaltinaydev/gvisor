// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vfs

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// rulesetWith returns a ruleset handling handled, with each entry of rules
// added as a path rule.
func rulesetWith(handled uint64, rules map[string]uint64) *LandlockRuleset {
	rs := NewLandlockRuleset(handled)
	for p, access := range rules {
		rs.AddPathRule(p, access)
	}
	return rs
}

// domainWith returns a domain formed by merging rulesets in order.
func domainWith(t *testing.T, rulesets ...*LandlockRuleset) *LandlockDomain {
	t.Helper()
	var d *LandlockDomain
	for i, rs := range rulesets {
		next, err := d.Merge(rs)
		if err != nil {
			t.Fatalf("Merge(layer %d) failed: %v", i, err)
		}
		d = next
	}
	return d
}

func TestLandlockCheckAccessPath(t *testing.T) {
	const (
		read  = linux.LANDLOCK_ACCESS_FS_READ_FILE
		write = linux.LANDLOCK_ACCESS_FS_WRITE_FILE
		rdDir = linux.LANDLOCK_ACCESS_FS_READ_DIR
	)

	for _, test := range []struct {
		name    string
		layers  []*LandlockRuleset
		path    string
		rights  uint64
		allowed bool
	}{
		{
			name:    "rule on the path itself grants access",
			layers:  []*LandlockRuleset{rulesetWith(read, map[string]uint64{"/a/b": read})},
			path:    "/a/b",
			rights:  read,
			allowed: true,
		},
		{
			name:    "rule on an ancestor grants access beneath it",
			layers:  []*LandlockRuleset{rulesetWith(read, map[string]uint64{"/a": read})},
			path:    "/a/b/c",
			rights:  read,
			allowed: true,
		},
		{
			name:    "no covering rule denies access",
			layers:  []*LandlockRuleset{rulesetWith(read, map[string]uint64{"/a": read})},
			path:    "/other/file",
			rights:  read,
			allowed: false,
		},
		{
			name:    "a sibling prefix is not an ancestor",
			layers:  []*LandlockRuleset{rulesetWith(read, map[string]uint64{"/allowed": read})},
			path:    "/allowedother",
			rights:  read,
			allowed: false,
		},
		{
			name:    "unhandled rights are unconstrained",
			layers:  []*LandlockRuleset{rulesetWith(read, map[string]uint64{"/a": read})},
			path:    "/other/file",
			rights:  write,
			allowed: true,
		},
		{
			name:    "a right the rule omits is denied",
			layers:  []*LandlockRuleset{rulesetWith(read|write, map[string]uint64{"/a": read})},
			path:    "/a/b",
			rights:  write,
			allowed: false,
		},
		{
			// O_RDWR requires both rights; granting only one is not enough.
			name:    "all requested rights must be granted",
			layers:  []*LandlockRuleset{rulesetWith(read|write, map[string]uint64{"/a": read})},
			path:    "/a/b",
			rights:  read | write,
			allowed: false,
		},
		{
			name:    "both requested rights granted by one rule",
			layers:  []*LandlockRuleset{rulesetWith(read|write, map[string]uint64{"/a": read | write})},
			path:    "/a/b",
			rights:  read | write,
			allowed: true,
		},
		{
			// Linux's unmask_layers() clears rights as it walks up, so rights
			// granted by different ancestors combine.
			name: "rights accumulate across ancestors",
			layers: []*LandlockRuleset{rulesetWith(read|write, map[string]uint64{
				"/a":   read,
				"/a/b": write,
			})},
			path:    "/a/b/c",
			rights:  read | write,
			allowed: true,
		},
		{
			name: "layers intersect: denied by the second layer",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[string]uint64{"/a": read}),
				rulesetWith(read, map[string]uint64{"/b": read}),
			},
			path:    "/a/file",
			rights:  read,
			allowed: false,
		},
		{
			name: "layers intersect: allowed by both layers",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[string]uint64{"/a": read}),
				rulesetWith(read, map[string]uint64{"/a/b": read}),
			},
			path:    "/a/b/file",
			rights:  read,
			allowed: true,
		},
		{
			name: "a later layer only handling other rights does not deny",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[string]uint64{"/a": read}),
				rulesetWith(rdDir, map[string]uint64{"/b": rdDir}),
			},
			path:    "/a/file",
			rights:  read,
			allowed: true,
		},
		{
			name:    "a rule on the root covers everything",
			layers:  []*LandlockRuleset{rulesetWith(read, map[string]uint64{"/": read})},
			path:    "/any/deep/path",
			rights:  read,
			allowed: true,
		},
		{
			name:    "unclean paths are normalized",
			layers:  []*LandlockRuleset{rulesetWith(read, map[string]uint64{"/a//b/": read})},
			path:    "/a/b/../b/c",
			rights:  read,
			allowed: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := domainWith(t, test.layers...)
			err := d.CheckAccessPath(test.path, test.rights)
			if got := err == nil; got != test.allowed {
				t.Errorf("CheckAccessPath(%q, %#x) = %v, want allowed=%v", test.path, test.rights, err, test.allowed)
			}
			if err != nil && !linuxerr.Equals(linuxerr.EACCES, err) {
				t.Errorf("CheckAccessPath(%q, %#x) = %v, want EACCES", test.path, test.rights, err)
			}
		})
	}
}

func TestLandlockCheckAccessPathNilDomain(t *testing.T) {
	var d *LandlockDomain
	if err := d.CheckAccessPath("/anything", linux.LANDLOCK_ACCESS_FS_READ_FILE); err != nil {
		t.Errorf("CheckAccessPath on nil domain = %v, want nil", err)
	}
	if got := d.NumLayers(); got != 0 {
		t.Errorf("NumLayers on nil domain = %d, want 0", got)
	}
}

// TestLandlockMergeSnapshotsRules verifies that rules added to a ruleset after
// it has been merged into a domain do not affect that domain, matching Linux's
// landlock_merge_ruleset().
func TestLandlockMergeSnapshotsRules(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	rs := rulesetWith(read, map[string]uint64{"/a": read})
	d := domainWith(t, rs)

	rs.AddPathRule("/b", read)

	if err := d.CheckAccessPath("/b/file", read); err == nil {
		t.Error("CheckAccessPath(/b/file) = nil, want EACCES: rule added after merge must not apply")
	}
}

func TestLandlockMergeLayerLimit(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	var d *LandlockDomain
	for i := 0; i < linux.LANDLOCK_MAX_NUM_LAYERS; i++ {
		next, err := d.Merge(rulesetWith(read, map[string]uint64{"/": read}))
		if err != nil {
			t.Fatalf("Merge(layer %d) = %v, want nil", i, err)
		}
		d = next
	}
	if got := d.NumLayers(); got != linux.LANDLOCK_MAX_NUM_LAYERS {
		t.Errorf("NumLayers = %d, want %d", got, linux.LANDLOCK_MAX_NUM_LAYERS)
	}

	if _, err := d.Merge(rulesetWith(read, map[string]uint64{"/": read})); !linuxerr.Equals(linuxerr.E2BIG, err) {
		t.Errorf("Merge beyond LANDLOCK_MAX_NUM_LAYERS = %v, want E2BIG", err)
	}
	// The over-limit merge must leave the original domain untouched.
	if got := d.NumLayers(); got != linux.LANDLOCK_MAX_NUM_LAYERS {
		t.Errorf("NumLayers after failed merge = %d, want %d", got, linux.LANDLOCK_MAX_NUM_LAYERS)
	}
}

func TestLandlockOpenAccessRights(t *testing.T) {
	for _, test := range []struct {
		name  string
		opts  OpenOptions
		isDir bool
		want  uint64
	}{
		{
			name: "O_RDONLY requires read",
			opts: OpenOptions{Flags: linux.O_RDONLY},
			want: linux.LANDLOCK_ACCESS_FS_READ_FILE,
		},
		{
			name: "O_WRONLY requires write",
			opts: OpenOptions{Flags: linux.O_WRONLY},
			want: linux.LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{
			// Linux derives the rights from f_mode, which has both bits set.
			name: "O_RDWR requires read and write",
			opts: OpenOptions{Flags: linux.O_RDWR},
			want: linux.LANDLOCK_ACCESS_FS_READ_FILE | linux.LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{
			name: "exec requires execute",
			opts: OpenOptions{Flags: linux.O_RDONLY, FileExec: true},
			want: linux.LANDLOCK_ACCESS_FS_EXECUTE,
		},
		{
			name:  "a directory requires read_dir",
			opts:  OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY},
			isDir: true,
			want:  linux.LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{
			// Landlock keys on the file type, not on O_DIRECTORY.
			name:  "a directory opened without O_DIRECTORY still requires read_dir",
			opts:  OpenOptions{Flags: linux.O_RDONLY},
			isDir: true,
			want:  linux.LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{
			name: "unrelated flags do not change the rights",
			opts: OpenOptions{Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC | linux.O_APPEND},
			want: linux.LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := test.opts
			if got := landlockOpenAccessRights(&opts, test.isDir); got != test.want {
				t.Errorf("landlockOpenAccessRights() = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestCleanPathString(t *testing.T) {
	for _, test := range []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"/a/b", "/a/b"},
		{"/a//b/", "/a/b"},
		{"/a/./b", "/a/b"},
		{"/a/b/../c", "/a/c"},
		{"/..", "/"},
	} {
		if got := cleanPathString(test.in); got != test.want {
			t.Errorf("cleanPathString(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}
