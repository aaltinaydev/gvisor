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

package landlock

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Ruleset represents a Landlock ruleset under construction or frozen.
//
// Matches Linux security/landlock/ruleset.h:struct landlock_ruleset.
type Ruleset struct {
	refCount atomicbitops.Int64

	// mu protects the fields below.
	mu sync.Mutex

	// handledAccessFS is the set of filesystem access rights handled by this ruleset.
	handledAccessFS uint64

	// rules maps a Dentry to its allowed access mask in this ruleset.
	// Since rules are added by path, we hold a reference to each dentry in the map.
	rules map[*vfs.Dentry]uint64
}

// NewRuleset creates a new Ruleset.
func NewRuleset(handledAccessFS uint64) *Ruleset {
	r := &Ruleset{
		handledAccessFS: handledAccessFS,
		rules:           make(map[*vfs.Dentry]uint64),
	}
	r.refCount.Store(1)
	refs.Register(r)
	return r
}

// RefType implements refs.CheckedObject.RefType.
func (r *Ruleset) RefType() string {
	return "landlock.Ruleset"
}

// LeakMessage implements refs.CheckedObject.LeakMessage.
func (r *Ruleset) LeakMessage() string {
	return fmt.Sprintf("[landlock.Ruleset %p] reference count of %d instead of 0", r, r.refCount.Load())
}

// LogRefs implements refs.CheckedObject.LogRefs.
func (r *Ruleset) LogRefs() bool {
	return false
}

// IncRef increments the reference count.
func (r *Ruleset) IncRef() {
	v := r.refCount.Add(1)
	if v <= 1 {
		panic(fmt.Sprintf("Incrementing non-positive count %p on %s", r, r.RefType()))
	}
}

// DecRef decrements the reference count and frees the ruleset if it reaches 0.
//
// Matches Linux security/landlock/ruleset.c:landlock_put_ruleset()
func (r *Ruleset) DecRef(ctx context.Context) {
	v := r.refCount.Add(-1)
	switch {
	case v < 0:
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %s", r, r.RefType()))
	case v == 0:
		refs.Unregister(r)
		// No lock needed as v == 0 guarantees exclusive access.
		// This also avoids lock inversion with fs.ancestryMu/renameMu.
		for d := range r.rules {
			d.DecRef(ctx)
		}
		r.rules = nil
	}
}

// AddRule adds a path beneath rule to the ruleset.
func (r *Ruleset) AddRule(d *vfs.Dentry, allowedAccess uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// allowedAccess must be a subset of handledAccessFS.
	if (allowedAccess | r.handledAccessFS) != r.handledAccessFS {
		return linuxerr.EINVAL
	}

	if oldAccess, ok := r.rules[d]; ok {
		r.rules[d] = oldAccess | allowedAccess
	} else {
		d.IncRef()
		r.rules[d] = allowedAccess
	}
	return nil
}

// HandledAccessFS returns the handled filesystem access rights of this ruleset.
func (r *Ruleset) HandledAccessFS() uint64 {
	// handledAccessFS is read-only after creation, no lock needed.
	return r.handledAccessFS
}

// Freeze returns a new, read-only copy of the Ruleset for use in a Domain.
// It increments references of all dentries in the copied rules map.
func (r *Ruleset) Freeze() *Ruleset {
	r.mu.Lock()
	defer r.mu.Unlock()

	frozen := &Ruleset{
		handledAccessFS: r.handledAccessFS,
		rules:           make(map[*vfs.Dentry]uint64),
	}
	frozen.refCount.Store(1)
	refs.Register(frozen)
	for d, access := range r.rules {
		d.IncRef()
		frozen.rules[d] = access
	}
	return frozen
}

// RulesetFileDescription implements vfs.FileDescriptionImpl for the anonymous
// file descriptor representing a Landlock ruleset.
type RulesetFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	ruleset *Ruleset
}

// NewRulesetFD creates a new anonymous file descriptor representing a Ruleset.
func NewRulesetFD(vfsObj *vfs.VirtualFilesystem, r *Ruleset) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(context.Background())

	fd := &RulesetFileDescription{
		ruleset: r,
	}
	if err := fd.vfsfd.Init(fd, linux.O_RDWR, auth.CredentialsFromContext(context.Background()), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		DenyPRead:         true,
		DenyPWrite:        true,
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *RulesetFileDescription) Release(ctx context.Context) {
	fd.ruleset.DecRef(ctx)
}

// GetRulesetFromFD extracts the Ruleset from a file description.
func GetRulesetFromFD(fd *vfs.FileDescription) (*Ruleset, error) {
	impl, ok := fd.Impl().(*RulesetFileDescription)
	if !ok {
		return nil, linuxerr.EBADFD
	}
	return impl.ruleset, nil
}

// Domain represents an immutable stacked ruleset hierarchy.
//
// Matches Linux security/landlock/ruleset.h:struct landlock_ruleset (used as a domain).
type Domain struct {
	refCount atomicbitops.Int64
	layers   []*Ruleset
}

// NewDomain creates a new Domain from a slice of frozen rulesets.
func NewDomain(layers []*Ruleset) *Domain {
	d := &Domain{
		layers: layers,
	}
	d.refCount.Store(1)
	refs.Register(d)
	return d
}

// RefType implements refs.CheckedObject.RefType.
func (d *Domain) RefType() string {
	return "landlock.Domain"
}

// LeakMessage implements refs.CheckedObject.LeakMessage.
func (d *Domain) LeakMessage() string {
	return fmt.Sprintf("[landlock.Domain %p] reference count of %d instead of 0", d, d.refCount.Load())
}

// LogRefs implements refs.CheckedObject.LogRefs.
func (d *Domain) LogRefs() bool {
	return false
}

// IncRef increments the reference count.
func (d *Domain) IncRef() {
	v := d.refCount.Add(1)
	if v <= 1 {
		panic(fmt.Sprintf("Incrementing non-positive count %p on %s", d, d.RefType()))
	}
}

// Clone implements auth.SecurityObject.Clone.
func (d *Domain) Clone() auth.SecurityObject {
	d.IncRef()
	return d
}

// DecRef decrements the reference count and frees the domain if it reaches 0.
func (d *Domain) DecRef(ctx context.Context) {
	v := d.refCount.Add(-1)
	switch {
	case v < 0:
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %s", d, d.RefType()))
	case v == 0:
		refs.Unregister(d)
		for _, layer := range d.layers {
			layer.DecRef(ctx)
		}
	}
}

// Merge creates a new Domain that is the combination of the current domain and the new ruleset.
//
// Matches Linux security/landlock/ruleset.c:landlock_merge_ruleset()
//
// Note: Unlike Linux which merges the rule trees of the parent domain and the new ruleset
// into a single tree (via inherit_ruleset and merge_ruleset), gVisor's Domain stacks
// the Ruleset pointers as layers and performs sequential checks during path traversal.
func (d *Domain) Merge(r *Ruleset) *Domain {
	newLayers := make([]*Ruleset, len(d.layers)+1)
	for i, layer := range d.layers {
		layer.IncRef()
		newLayers[i] = layer
	}
	newLayers[len(d.layers)] = r
	return NewDomain(newLayers)
}

// NumLayers implements vfs.LandlockDomain.NumLayers.
func (d *Domain) NumLayers() int {
	return len(d.layers)
}

// HandledAccessFS implements vfs.LandlockDomain.HandledAccessFS.
func (d *Domain) HandledAccessFS(layer int) uint64 {
	return d.layers[layer].HandledAccessFS()
}

// GetRule implements vfs.LandlockDomain.GetRule.
func (d *Domain) GetRule(layer int, de *vfs.Dentry) (uint64, bool) {
	r := d.layers[layer]
	// Frozen rulesets in a Domain are read-only, no lock needed.
	// This also avoids lock inversion with fs.ancestryMu/renameMu.
	access, ok := r.rules[de]
	return access, ok
}
