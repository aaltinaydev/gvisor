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

package unique_name_landlock

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Ruleset represents a Landlock ruleset.
// It implements vfs.FileDescriptionImpl.
type Ruleset struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	mu sync.Mutex
	// handledAccessFS is the set of access rights that this ruleset restricts.
	handledAccessFS uint64
	// rules maps virtual dentries to their allowed access mask.
	// We store vfs.VirtualDentry and must hold references to it.
	rules map[vfs.VirtualDentry]uint64
}

// NewRuleset creates a new Ruleset FD.
func NewRuleset(ctx context.Context, vfsObj *vfs.VirtualFilesystem, handledAccessFS uint64) (*vfs.FileDescription, error) {
	r := &Ruleset{
		handledAccessFS: handledAccessFS,
		rules:           make(map[vfs.VirtualDentry]uint64),
	}

	vd := vfsObj.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(ctx)

	err := r.vfsfd.Init(r, linux.O_RDWR, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	})
	if err != nil {
		return nil, err
	}

	return &r.vfsfd, nil
}

// AddRule adds a path beneath rule to the ruleset.
func (r *Ruleset) AddRule(ctx context.Context, vd vfs.VirtualDentry, allowedAccess uint64) error {
	// Validate allowedAccess is subset of handledAccessFS.
	if (allowedAccess & r.handledAccessFS) != allowedAccess {
		return linuxerr.EINVAL
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if oldAccess, ok := r.rules[vd]; ok {
		r.rules[vd] = oldAccess | allowedAccess
	} else {
		vd.IncRef()
		r.rules[vd] = allowedAccess
	}
	return nil
}

// HandledAccessFS returns the handled FS access mask.
func (r *Ruleset) HandledAccessFS() uint64 {
	return r.handledAccessFS
}

// Rules returns a copy of the rules map.
// The caller must not modify the map. The dentries in the map do not have
// their refcounts incremented, so this should only be used while holding
// ruleset references or when copying to a Domain.
func (r *Ruleset) Rules() map[vfs.VirtualDentry]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := make(map[vfs.VirtualDentry]uint64, len(r.rules))
	for k, v := range r.rules {
		m[k] = v
	}
	return m
}

// Release implements vfs.FileDescriptionImpl.Release.
func (r *Ruleset) Release(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for vd := range r.rules {
		vd.DecRef(ctx)
	}
	r.rules = nil
}
