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

// Package vfs implements a virtual filesystem layer.
package vfs

import (
	"path"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// LandlockDomainFromContext returns the Landlock domain associated with ctx, or nil.
func LandlockDomainFromContext(ctx context.Context) *LandlockDomain {
	if v := ctx.Value(CtxLandlockDomain); v != nil {
		return v.(*LandlockDomain)
	}
	return nil
}

// LandlockRuleset represents a mutable set of Landlock rules tied to a handled access mask.
// Matches Linux [security/landlock/ruleset.h]:struct landlock_ruleset
type LandlockRuleset struct {
	mu              sync.Mutex
	handledAccessFS uint64
	rules           map[string]uint64
}

// NewLandlockRuleset creates a new Landlock ruleset with handledAccessFS.
// Matches Linux [security/landlock/ruleset.c]:landlock_create_ruleset()
func NewLandlockRuleset(handledAccessFS uint64) *LandlockRuleset {
	return &LandlockRuleset{
		handledAccessFS: handledAccessFS,
		rules:           make(map[string]uint64),
	}
}

// HandledAccessFS returns the handled filesystem access mask.
func (r *LandlockRuleset) HandledAccessFS() uint64 {
	return r.handledAccessFS
}

// AddPathRule adds or updates a path rule in the ruleset.
// Matches Linux [security/landlock/ruleset.c]:landlock_insert_rule()
func (r *LandlockRuleset) AddPathRule(path string, allowedAccess uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cleanPath := cleanPathString(path)
	r.rules[cleanPath] |= allowedAccess
}

// LandlockRulesetFileDescription implements vfs.FileDescriptionImpl for anonymous Landlock ruleset file descriptors.
// Matches Linux [security/landlock/syscalls.c]:ruleset_fops
type LandlockRulesetFileDescription struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	NoLockFD

	ruleset *LandlockRuleset
}

var _ FileDescriptionImpl = (*LandlockRulesetFileDescription)(nil)

// NewLandlockRulesetFD creates a new anonymous file description wrapping ruleset.
// Matches Linux [security/landlock/syscalls.c]:sys_landlock_create_ruleset()
func NewLandlockRulesetFD(ctx context.Context, vfsObj *VirtualFilesystem, ruleset *LandlockRuleset) (*FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(ctx)

	rfd := &LandlockRulesetFileDescription{
		ruleset: ruleset,
	}
	if err := rfd.vfsfd.Init(rfd, linux.O_RDWR, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
		DenySpliceIn:      true,
	}); err != nil {
		return nil, err
	}
	return &rfd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
// Matches gVisor [pkg/sentry/vfs/file_description.go]:[FileDescriptionImpl.Release]()
func (rfd *LandlockRulesetFileDescription) Release(ctx context.Context) {
}

// LandlockRulesetFromFD returns the underlying LandlockRuleset from a file description.
// Matches Linux [security/landlock/syscalls.c]:get_ruleset_from_fd()
func LandlockRulesetFromFD(file *FileDescription, requiredMode uint32) (*LandlockRuleset, error) {
	rfd, ok := file.Impl().(*LandlockRulesetFileDescription)
	if !ok {
		return nil, linuxerr.EBADFD
	}
	status := file.StatusFlags()
	if requiredMode == linux.O_WRONLY && (status&linux.O_ACCMODE) == linux.O_RDONLY {
		return nil, linuxerr.EPERM
	}
	if requiredMode == linux.O_RDONLY && (status&linux.O_ACCMODE) == linux.O_WRONLY {
		return nil, linuxerr.EPERM
	}
	return rfd.ruleset, nil
}

// LandlockDomainLayer represents a snapshot of a ruleset's rules at enforcement time.
// Matches Linux [security/landlock/ruleset.h]:struct landlock_layer
type LandlockDomainLayer struct {
	handledAccessFS uint64
	rules           map[string]uint64
}

// LandlockDomain represents an immutable stacked hierarchy of Landlock domain layers.
// Matches Linux [security/landlock/ruleset.h]:struct landlock_ruleset (used as a domain)
type LandlockDomain struct {
	layers []LandlockDomainLayer
}

// NumLayers returns the number of domain layers currently stacked.
func (d *LandlockDomain) NumLayers() int {
	if d == nil {
		return 0
	}
	return len(d.layers)
}

// Merge merges a ruleset into a new stacked LandlockDomain layer.
// Matches Linux [security/landlock/ruleset.c]:landlock_merge_ruleset()
func (d *LandlockDomain) Merge(ruleset *LandlockRuleset) (*LandlockDomain, error) {
	currentLayers := 0
	if d != nil {
		currentLayers = len(d.layers)
	}
	if currentLayers >= linux.LANDLOCK_MAX_NUM_LAYERS {
		return nil, linuxerr.E2BIG
	}

	ruleset.mu.Lock()
	snapshotRules := make(map[string]uint64, len(ruleset.rules))
	for k, v := range ruleset.rules {
		snapshotRules[k] = v
	}
	newLayer := LandlockDomainLayer{
		handledAccessFS: ruleset.handledAccessFS,
		rules:           snapshotRules,
	}
	ruleset.mu.Unlock()

	newLayers := make([]LandlockDomainLayer, currentLayers+1)
	if currentLayers > 0 {
		copy(newLayers, d.layers)
	}
	newLayers[currentLayers] = newLayer

	return &LandlockDomain{layers: newLayers}, nil
}

// CheckAccess evaluates if accessRight on vd is allowed by all domain layers.
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CheckAccess(ctx context.Context, vfsObj *VirtualFilesystem, vd VirtualDentry, accessRight uint64) error {
	if d == nil || len(d.layers) == 0 {
		return nil
	}
	if !vd.Ok() {
		return nil
	}

	vfsroot := VirtualDentry{}
	targetPath, err := vfsObj.PathnameWithDeleted(ctx, vfsroot, vd)
	if err != nil {
		return nil
	}
	targetPath = cleanPathString(targetPath)

	for _, layer := range d.layers {
		if layer.handledAccessFS&accessRight == 0 {
			continue
		}

		allowedInLayer := false
		curr := targetPath
		for {
			if allowed, ok := layer.rules[curr]; ok {
				if allowed&accessRight == accessRight {
					allowedInLayer = true
					break
				}
			}
			if curr == "/" || curr == "." || curr == "" {
				break
			}
			parent := path.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}

		if !allowedInLayer {
			return linuxerr.EACCES
		}
	}

	return nil
}

// CheckAccessPath evaluates accessRight on a clean path string against all domain layers.
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CheckAccessPath(targetPath string, accessRight uint64) error {
	if d == nil || len(d.layers) == 0 {
		return nil
	}
	cleanTarget := cleanPathString(targetPath)

	for _, layer := range d.layers {
		if layer.handledAccessFS&accessRight == 0 {
			continue
		}

		allowedInLayer := false
		curr := cleanTarget
		for {
			if allowed, ok := layer.rules[curr]; ok {
				if allowed&accessRight == accessRight {
					allowedInLayer = true
					break
				}
			}
			if curr == "/" || curr == "." || curr == "" {
				break
			}
			parent := path.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}

		if !allowedInLayer {
			return linuxerr.EACCES
		}
	}

	return nil
}

func cleanPathString(p string) string {
	cp := path.Clean(p)
	if cp == "" {
		return "/"
	}
	return cp
}
