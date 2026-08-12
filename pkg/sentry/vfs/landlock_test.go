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
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

const (
	inoRoot = iota + 1
	inoA
	inoB
	inoC
	inoOther
)

var testFS = &Filesystem{id: 1}

func id(ino uint64) InodeIdentity {
	return MakeInodeIdentity(testFS, 0, 1, ino)
}

func ids(inos ...uint64) []InodeIdentity {
	out := make([]InodeIdentity, 0, len(inos))
	for _, ino := range inos {
		out = append(out, id(ino))
	}
	return out
}

func rulesetWith(handled uint64, rules map[uint64]uint64) *LandlockRuleset {
	rs := NewLandlockRuleset(handled)
	for ino, access := range rules {
		rs.InsertRule(id(ino), access)
	}
	return rs
}

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

func checkAncestry(d *LandlockDomain, ancestry []InodeIdentity, accessRights uint64) error {
	if d.NumLayers() == 0 {
		return nil
	}
	masks := d.newLayerMasks(accessRights)
	for _, ancestor := range ancestry {
		if masks.allowed() {
			break
		}
		masks.unmask(ancestor)
	}
	if !masks.allowed() {
		return linuxerr.EACCES
	}
	return nil
}

func TestLandlockCheckAccess(t *testing.T) {
	const (
		read  = linux.LANDLOCK_ACCESS_FS_READ_FILE
		write = linux.LANDLOCK_ACCESS_FS_WRITE_FILE
		rdDir = linux.LANDLOCK_ACCESS_FS_READ_DIR
	)

	for _, test := range []struct {
		name     string
		layers   []*LandlockRuleset
		ancestry []InodeIdentity
		rights   uint64
		allowed  bool
	}{
		{
			name:     "rule on the file itself grants access",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoB: read})},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name:     "rule on an ancestor grants access beneath it",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name:     "no covering rule denies access",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoOther, inoRoot),
			rights:   read,
			allowed:  false,
		},
		{
			name:     "a sibling is not an ancestor",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoB, inoRoot),
			rights:   read,
			allowed:  false,
		},
		{
			name:     "unhandled rights are unconstrained",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoOther, inoRoot),
			rights:   write,
			allowed:  true,
		},
		{
			name:     "a right the rule omits is denied",
			layers:   []*LandlockRuleset{rulesetWith(read|write, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   write,
			allowed:  false,
		},
		{
			name:     "all requested rights must be granted",
			layers:   []*LandlockRuleset{rulesetWith(read|write, map[uint64]uint64{inoA: read})},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read | write,
			allowed:  false,
		},
		{
			name:     "both requested rights granted by one rule",
			layers:   []*LandlockRuleset{rulesetWith(read|write, map[uint64]uint64{inoA: read | write})},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read | write,
			allowed:  true,
		},
		{
			name: "rights accumulate across ancestors",
			layers: []*LandlockRuleset{rulesetWith(read|write, map[uint64]uint64{
				inoA: read,
				inoB: write,
			})},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read | write,
			allowed:  true,
		},
		{
			name: "layers intersect: denied by the second layer",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[uint64]uint64{inoA: read}),
				rulesetWith(read, map[uint64]uint64{inoB: read}),
			},
			ancestry: ids(inoC, inoA, inoRoot),
			rights:   read,
			allowed:  false,
		},
		{
			name: "layers intersect: allowed by both layers",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[uint64]uint64{inoA: read}),
				rulesetWith(read, map[uint64]uint64{inoB: read}),
			},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name: "same inode in two layers: rights intersect, not union",
			layers: []*LandlockRuleset{
				rulesetWith(read|write, map[uint64]uint64{inoA: read}),
				rulesetWith(read|write, map[uint64]uint64{inoA: write}),
			},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read | write,
			allowed:  false,
		},
		{
			name: "same inode in two layers: both grant the right",
			layers: []*LandlockRuleset{
				rulesetWith(read|write, map[uint64]uint64{inoA: read}),
				rulesetWith(read|write, map[uint64]uint64{inoA: read}),
			},
			ancestry: ids(inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name: "a second grant to a satisfied layer is harmless",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[uint64]uint64{inoB: read, inoA: read}),
				rulesetWith(read, map[uint64]uint64{inoA: read}),
			},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name: "a later layer only handling other rights does not deny",
			layers: []*LandlockRuleset{
				rulesetWith(read, map[uint64]uint64{inoA: read}),
				rulesetWith(rdDir, map[uint64]uint64{inoB: rdDir}),
			},
			ancestry: ids(inoC, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name:     "a rule on the root covers everything",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoRoot: read})},
			ancestry: ids(inoC, inoB, inoA, inoRoot),
			rights:   read,
			allowed:  true,
		},
		{
			name:     "an ancestor with no identity is skipped",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: []InodeIdentity{id(inoB), {}, id(inoA), id(inoRoot)},
			rights:   read,
			allowed:  true,
		},
		{
			name:     "a file with no identity and no covering rule is denied",
			layers:   []*LandlockRuleset{rulesetWith(read, map[uint64]uint64{inoA: read})},
			ancestry: []InodeIdentity{{}},
			rights:   read,
			allowed:  false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := domainWith(t, test.layers...)
			err := checkAncestry(d, test.ancestry, test.rights)
			if got := err == nil; got != test.allowed {
				t.Errorf("checkAncestry(%v, %#x) = %v, want allowed=%v", test.ancestry, test.rights, err, test.allowed)
			}
			if err != nil && !linuxerr.Equals(linuxerr.EACCES, err) {
				t.Errorf("checkAncestry(%v, %#x) = %v, want EACCES", test.ancestry, test.rights, err)
			}
		})
	}
}

func TestLandlockCheckAccessNilDomain(t *testing.T) {
	var d *LandlockDomain
	if err := checkAncestry(d, ids(inoA), linux.LANDLOCK_ACCESS_FS_READ_FILE); err != nil {
		t.Errorf("checkAncestry on nil domain = %v, want nil", err)
	}
	if got := d.NumLayers(); got != 0 {
		t.Errorf("NumLayers on nil domain = %d, want 0", got)
	}
}

func TestLandlockRuleUnionsRights(t *testing.T) {
	const (
		read  = linux.LANDLOCK_ACCESS_FS_READ_FILE
		write = linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	)

	rs := NewLandlockRuleset(read | write)
	rs.InsertRule(id(inoA), read)
	rs.InsertRule(id(inoA), write)
	d := domainWith(t, rs)

	if err := checkAncestry(d, ids(inoB, inoA), read|write); err != nil {
		t.Errorf("checkAncestry = %v, want nil: rights from both rules must apply", err)
	}
}

func TestLandlockRuleFollowsTheFile(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	d := domainWith(t, rulesetWith(read, map[uint64]uint64{inoA: read}))

	if err := checkAncestry(d, ids(inoA, inoC, inoRoot), read); err != nil {
		t.Errorf("checkAncestry via a second name = %v, want nil", err)
	}
	if err := checkAncestry(d, ids(inoA), read); err != nil {
		t.Errorf("checkAncestry with no shared ancestor = %v, want nil", err)
	}
}

func TestLandlockMergeSnapshotsRules(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	rs := rulesetWith(read, map[uint64]uint64{inoA: read})
	d := domainWith(t, rs)

	rs.InsertRule(id(inoB), read)

	if err := checkAncestry(d, ids(inoC, inoB), read); err == nil {
		t.Error("checkAncestry = nil, want EACCES: rule added after merge must not apply")
	}
}

func TestLandlockMergeLayerLimit(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	var d *LandlockDomain
	for i := 0; i < linux.LANDLOCK_MAX_NUM_LAYERS; i++ {
		next, err := d.Merge(rulesetWith(read, map[uint64]uint64{inoRoot: read}))
		if err != nil {
			t.Fatalf("Merge(layer %d) = %v, want nil", i, err)
		}
		d = next
	}
	if got := d.NumLayers(); got != linux.LANDLOCK_MAX_NUM_LAYERS {
		t.Errorf("NumLayers = %d, want %d", got, linux.LANDLOCK_MAX_NUM_LAYERS)
	}

	if _, err := d.Merge(rulesetWith(read, map[uint64]uint64{inoRoot: read})); !linuxerr.Equals(linuxerr.E2BIG, err) {
		t.Errorf("Merge beyond LANDLOCK_MAX_NUM_LAYERS = %v, want E2BIG", err)
	}
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
			name: "O_RDWR requires read and write",
			opts: OpenOptions{Flags: linux.O_RDWR},
			want: linux.LANDLOCK_ACCESS_FS_READ_FILE | linux.LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		{
			name: "exec requires execute and read",
			opts: OpenOptions{Flags: linux.O_RDONLY, FileExec: true},
			want: linux.LANDLOCK_ACCESS_FS_READ_FILE | linux.LANDLOCK_ACCESS_FS_EXECUTE,
		},
		{
			name:  "a directory requires read_dir",
			opts:  OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY},
			isDir: true,
			want:  linux.LANDLOCK_ACCESS_FS_READ_DIR,
		},
		{
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
		{
			name: "the fourth access mode requires nothing",
			opts: OpenOptions{Flags: linux.O_ACCMODE},
			want: 0,
		},
		{
			name:  "the fourth access mode on a directory requires nothing",
			opts:  OpenOptions{Flags: linux.O_ACCMODE},
			isDir: true,
			want:  0,
		},
		{
			name: "the fourth access mode with exec requires execute",
			opts: OpenOptions{Flags: linux.O_ACCMODE, FileExec: true},
			want: linux.LANDLOCK_ACCESS_FS_EXECUTE,
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

func TestCheckLandlockMount(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	var none *LandlockDomain
	if err := CheckLandlockMount(none); err != nil {
		t.Errorf("CheckLandlockMount(nil) = %v, want nil", err)
	}

	d := domainWith(t, rulesetWith(read, map[uint64]uint64{inoRoot: read}))
	if err := CheckLandlockMount(d); !linuxerr.Equals(linuxerr.EPERM, err) {
		t.Errorf("CheckLandlockMount(domain) = %v, want EPERM", err)
	}
}

func TestLandlockScopeLE(t *testing.T) {
	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE

	d1 := domainWith(t, rulesetWith(read, map[uint64]uint64{inoA: read}))
	d2, err := d1.Merge(rulesetWith(read, map[uint64]uint64{inoB: read}))
	if err != nil {
		t.Fatalf("Merge = %v, want nil", err)
	}
	other := domainWith(t, rulesetWith(read, map[uint64]uint64{inoA: read}))

	var none *LandlockDomain
	for _, test := range []struct {
		name           string
		tracer, tracee *LandlockDomain
		want           bool
	}{
		{"unsandboxed tracer, unsandboxed tracee", none, none, true},
		{"unsandboxed tracer, sandboxed tracee", none, d1, true},
		{"sandboxed tracer, unsandboxed tracee", d1, none, false},
		{"same domain", d1, d1, true},
		{"ancestor tracing descendant", d1, d2, true},
		{"descendant tracing ancestor", d2, d1, false},
		{"unrelated domains", d1, other, false},
		{"unrelated domains, reversed", other, d1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.tracer.ScopeLE(test.tracee); got != test.want {
				t.Errorf("ScopeLE = %v, want %v", got, test.want)
			}
			var tracer, tracee auth.LandlockDomain
			if test.tracer != nil {
				tracer = test.tracer
			}
			if test.tracee != nil {
				tracee = test.tracee
			}
			if got := auth.LandlockCanPtrace(tracer, tracee); got != test.want {
				t.Errorf("auth.LandlockCanPtrace = %v, want %v", got, test.want)
			}
		})
	}
}

func TestInodeIdentityIsScopedToFilesystem(t *testing.T) {
	const devMajor, devMinor, ino = 0, 7, 42
	destroyed := &Filesystem{id: 1}
	recycled := &Filesystem{id: 2}

	first := MakeInodeIdentity(destroyed, devMajor, devMinor, ino)
	second := MakeInodeIdentity(recycled, devMajor, devMinor, ino)
	if first == second {
		t.Errorf("identities on distinct filesystems compare equal: %+v", first)
	}

	const read = linux.LANDLOCK_ACCESS_FS_READ_FILE
	rs := NewLandlockRuleset(read)
	rs.InsertRule(first, read)
	d := domainWith(t, rs)

	masks := d.newLayerMasks(read)
	masks.unmask(second)
	if masks.allowed() {
		t.Error("a rule from a destroyed filesystem granted access to a file on the filesystem that reused its device number")
	}

	masks = d.newLayerMasks(read)
	masks.unmask(first)
	if !masks.allowed() {
		t.Error("rule did not match the file it names")
	}
}
