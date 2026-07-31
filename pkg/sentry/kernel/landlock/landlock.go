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

// Package landlock implements Landlock LSM ruleset and domain enforcement.
package landlock

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Ruleset represents a Landlock ruleset being built before restriction.
// Matches Linux [security/landlock/ruleset.h]:struct landlock_ruleset
//
// +stateify savable
type Ruleset struct {
	mu sync.Mutex `state:"nosave"`

	// HandledAccessFS stores the set of handled filesystem accesses.
	HandledAccessFS uint64

	// Rules maps a target dentry pointer to allowed access mask.
	Rules map[*vfs.Dentry]uint64

	// NumLayers is 1 for unmerged rulesets being built.
	NumLayers int
}

// NewRuleset creates a new Landlock ruleset handling handledAccessFS.
// Matches Linux [security/landlock/ruleset.c]:landlock_create_ruleset()
func NewRuleset(handledAccessFS uint64) *Ruleset {
	return &Ruleset{
		HandledAccessFS: handledAccessFS,
		Rules:           make(map[*vfs.Dentry]uint64),
		NumLayers:       1,
	}
}

// AddPathBeneathRule adds a path beneath rule to r.
// Matches Linux [security/landlock/fs.c]:landlock_append_fs_rule()
func (r *Ruleset) AddPathBeneathRule(d *vfs.Dentry, allowedAccess uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Invert allowed access to match Linux ruleset representation:
	// a rule stores allowed access for the dentry.
	if existing, ok := r.Rules[d]; ok {
		r.Rules[d] = existing | allowedAccess
	} else {
		r.Rules[d] = allowedAccess
	}
}

// RulesetFD represents an anonymous file description wrapping a Landlock Ruleset.
// Matches Linux [security/landlock/syscalls.c]:ruleset_fops
//
// +stateify savable
type RulesetFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	Ruleset *Ruleset
}

var _ vfs.FileDescriptionImpl = (*RulesetFD)(nil)

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *RulesetFD) Release(ctx context.Context) {}

// Read implements vfs.FileDescriptionImpl.Read.
// Matches Linux [security/landlock/syscalls.c]:fop_dummy_read()
func (fd *RulesetFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.EINVAL
}

// Write implements vfs.FileDescriptionImpl.Write.
// Matches Linux [security/landlock/syscalls.c]:fop_dummy_write()
func (fd *RulesetFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EINVAL
}

// NewRulesetFD creates a new anon FileDescription for ruleset.
// Matches Linux [security/landlock/syscalls.c]:anon_inode_getfd("[landlock-ruleset]")
func NewRulesetFD(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, ruleset *Ruleset) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(ctx)

	rfd := &RulesetFD{Ruleset: ruleset}
	fd := &vfs.FileDescription{}
	if err := fd.Init(rfd, linux.O_RDWR, creds, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return fd, nil
}

// LandlockDomain represents an immutable stacked Landlock domain attached to process credentials.
// Matches Linux [security/landlock/domain.h]:struct landlock_ruleset (when merged as domain)
//
// +stateify savable
type LandlockDomain struct {
	Layers []*Ruleset
}

// Merge merges a ruleset into the domain stack.
// Matches Linux [security/landlock/ruleset.c]:landlock_merge_ruleset()
func (d *LandlockDomain) Merge(ruleset *Ruleset) (*LandlockDomain, error) {
	currentLayers := 0
	if d != nil {
		currentLayers = len(d.Layers)
	}

	// Maximum domain layer depth check.
	// Matches Linux [security/landlock/ruleset.c]:landlock_merge_ruleset()
	if currentLayers >= linux.LANDLOCK_MAX_NUM_LAYERS {
		return nil, linuxerr.E2BIG
	}

	newLayers := make([]*Ruleset, 0, currentLayers+1)
	if d != nil {
		newLayers = append(newLayers, d.Layers...)
	}
	newLayers = append(newLayers, ruleset)

	return &LandlockDomain{Layers: newLayers}, nil
}

// CanAccessPath checks whether requested accessMask is granted on vd across all domain layers.
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CanAccessPath(vfsObj *vfs.VirtualFilesystem, vd vfs.VirtualDentry, accessMask uint64) bool {
	if d == nil || len(d.Layers) == 0 {
		return true
	}

	if !vd.Ok() {
		return true
	}

	for _, layer := range d.Layers {
		handled := layer.HandledAccessFS
		reqHandled := accessMask & handled
		if reqHandled == 0 {
			// Negative invariance: layer does not restrict this access.
			// Matches Linux [security/landlock/ruleset.c]:landlock_init_layer_masks()
			continue
		}

		allowed := false
		var accumulatedAccess uint64
		currVD := vd
		var refVD vfs.VirtualDentry

		for currVD.Ok() {
			dentry := currVD.Dentry()
			if dentry != nil {
				layer.mu.Lock()
				layerAccess, ok := layer.Rules[dentry]
				layer.mu.Unlock()

				if ok {
					// Union of access rights granted by rules along path walk.
					// Matches Linux [security/landlock/ruleset.c]:landlock_unmask_layers()
					accumulatedAccess |= layerAccess
					if (accumulatedAccess & reqHandled) == reqHandled {
						allowed = true
						break
					}
				}

				// Parent walk within filesystem dentry tree
				// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
				parentD := dentry.Parent()
				if parentD != nil {
					currVD = vfs.MakeVirtualDentry(currVD.Mount(), parentD)
					continue
				}
			}

			// If dentry has no parent in filesystem, cross mount point
			// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed() (jump_up / follow_up)
			// Surgical Change Rationale: Landlock path traversal requires crossing mount points
			// when reaching a mount root. vfsObj.GetMountpointAt() acquires a reference on the
			// returned VirtualDentry, which must be tracked in refVD and released via DecRef(nil)
			// when crossing to a subsequent mount or exiting the traversal loop to prevent reference leaks.
			if currVD.Mount() != nil {
				nextVD := vfsObj.GetMountpointAt(currVD.Mount())
				if nextVD.Ok() && nextVD != currVD {
					if refVD.Ok() {
						refVD.DecRef(nil)
					}
					refVD = nextVD
					currVD = nextVD
					continue
				}
			}
			break
		}

		if refVD.Ok() {
			refVD.DecRef(nil)
			refVD = vfs.VirtualDentry{}
		}

		if !allowed {
			return false
		}
	}

	return true
}
