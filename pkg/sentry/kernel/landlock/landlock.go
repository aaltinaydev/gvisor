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
	"runtime"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// NumFSAccesses is the number of filesystem access rights supported by Landlock.
const NumFSAccesses = 16

// Ruleset is a set of Landlock rules being built.
// It is referred to by a file descriptor.
type Ruleset struct {
	// HandledAccessFS is the mask of FS accesses handled by this ruleset.
	HandledAccessFS uint64

	mu    sync.Mutex
	rules map[*vfs.Dentry]uint64 // maps pinned dentry to allowed access mask
}

// NewRuleset creates a new Ruleset.
func NewRuleset(handledAccessFS uint64) *Ruleset {
	r := &Ruleset{
		HandledAccessFS: handledAccessFS,
		rules:           make(map[*vfs.Dentry]uint64),
	}
	runtime.SetFinalizer(r, finalizeRuleset)
	return r
}

func finalizeRuleset(r *Ruleset) {
	r.Destroy()
}

// AddRule adds a path beneath rule to the ruleset.
// It takes ownership of a reference on dentry (it will IncRef it and DecRef when ruleset is destroyed).
func (r *Ruleset) AddRule(dentry *vfs.Dentry, allowedAccess uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Pin the dentry.
	dentry.IncRef()

	// If there is already a rule for this dentry, we extend it (OR).
	if existing, ok := r.rules[dentry]; ok {
		r.rules[dentry] = existing | allowedAccess
	} else {
		r.rules[dentry] = allowedAccess
	}
	return nil
}

func (r *Ruleset) Destroy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx := context.Background()
	for dentry := range r.rules {
		dentry.DecRef(ctx)
	}
	r.rules = nil
}

// LayerAccess specifies the allowed access mask for a specific layer.
type LayerAccess struct {
	Level  int    // 1-based level
	Access uint64 // Allowed access mask
}

// Rule specifies the access rights for a dentry across different layers.
type Rule struct {
	Layers []LayerAccess
}

// Domain represents a Landlock domain (stacked rulesets).
// It implements auth.LandlockDomain.
type Domain struct {
	// refs is the reference count.
	refs atomicbitops.Int64

	// HandledAccessFS is the handled FS access mask for each layer.
	// Level is `index + 1`.
	HandledAccessFS []uint64

	// Rules maps pinned dentries to their layer access masks.
	// The slice length corresponds to the level of the rule.
	// Rules[dentry][layerIndex] is the allowed access mask for that layer.
	Rules map[*vfs.Dentry][]uint64
}

// Clone implements auth.LandlockDomain.Clone.
func (d *Domain) Clone() auth.LandlockDomain {
	if d != nil {
		d.IncRef()
	}
	return d
}

// IncRef increments the reference count of the domain.
func (d *Domain) IncRef() {
	d.refs.Add(1)
}

// DecRef implements auth.LandlockDomain.DecRef.
func (d *Domain) DecRef(ctx context.Context) {
	if d == nil {
		return
	}
	if d.refs.Add(-1) == 0 {
		for dentry := range d.Rules {
			dentry.DecRef(ctx)
		}
	}
}

// Merge merges a Ruleset into the Domain, returning a new Domain.
// It does not modify d.
// Matches Linux security/landlock/ruleset.c:landlock_merge_ruleset()
func (d *Domain) Merge(r *Ruleset) *Domain {
	var numParentLayers int
	if d != nil {
		numParentLayers = len(d.HandledAccessFS)
	}
	newD := &Domain{
		HandledAccessFS: make([]uint64, numParentLayers+1),
		Rules:           make(map[*vfs.Dentry][]uint64),
	}
	newD.refs.Store(1)

	// Copy parent layers.
	if d != nil {
		copy(newD.HandledAccessFS, d.HandledAccessFS)
	}
	// Add the new layer.
	newD.HandledAccessFS[len(newD.HandledAccessFS)-1] = r.HandledAccessFS

	// Copy parent rules.
	if d != nil {
		for dentry, parentRule := range d.Rules {
			// IncRef for the new domain.
			dentry.IncRef()
			// Copy the slice.
			newRule := make([]uint64, len(newD.HandledAccessFS))
			copy(newRule, parentRule)
			newD.Rules[dentry] = newRule
		}
	}

	// Merge the new ruleset.
	newLayerIndex := len(newD.HandledAccessFS) - 1
	r.mu.Lock()
	for dentry, allowedAccess := range r.rules {
		if existingRule, ok := newD.Rules[dentry]; ok {
			// Rule already exists (was inherited from parent).
			// We update the new layer's allowed access.
			existingRule[newLayerIndex] = allowedAccess
		} else {
			// New rule.
			dentry.IncRef()
			newRule := make([]uint64, len(newD.HandledAccessFS))
			newRule[newLayerIndex] = allowedAccess
			newD.Rules[dentry] = newRule
		}
	}
	r.mu.Unlock()

	return newD
}

// CheckAccess checks if the domain allows the requested access to the given VirtualDentry.
// It returns true if allowed, false if denied.
// Matches Linux security/landlock/fs.c:is_access_to_paths_allowed
func (d *Domain) CheckAccess(ctx context.Context, vfsObj any, vd any, accessRequest uint64) bool {
	if d == nil {
		return true
	}
	vfsObjConcrete, ok := vfsObj.(*vfs.VirtualFilesystem)
	if !ok {
		return false
	}
	vdConcrete, ok := vd.(vfs.VirtualDentry)
	if !ok {
		return false
	}

	if accessRequest == 0 {
		return true
	}

	// Initialize layer masks.
	// layerMasks[accessBit] is a bitmask of layers that handle this access.
	// Bit L (0-based) is set if layer L handles accessBit.
	layerMasks := make([]uint16, NumFSAccesses)
	var handledAccesses uint64

	numLayers := len(d.HandledAccessFS)
	for l := 0; l < numLayers; l++ {
		handled := d.HandledAccessFS[l]
		for b := 0; b < NumFSAccesses; b++ {
			accessBit := uint64(1 << b)
			if (accessRequest & accessBit) != 0 {
				if (handled & accessBit) != 0 {
					layerMasks[b] |= 1 << l
					handledAccesses |= accessBit
				}
			}
		}
	}
	// LANDLOCK_ACCESS_FS_REFER (bit 13) is denied by default in ABI v1.
	// We treat it as handled by all layers.
	// Matches Linux security/landlock/fs.c:current_check_refer_path()
	// where REFER is checked and required for cross-directory actions.
	const referBit = 13
	const referAccess = uint64(linux.LANDLOCK_ACCESS_FS_REFER)
	if (accessRequest & referAccess) != 0 {
		layerMasks[referBit] = uint16((uint32(1) << numLayers) - 1)
		handledAccesses |= referAccess
	}

	// If none of the active layers handle any of the requested accesses, it is allowed.
	if handledAccesses == 0 {
		return true
	}

	// Helper to check if all handled accesses have been allowed (masks are 0).
	isAllowed := func() bool {
		for b := 0; b < NumFSAccesses; b++ {
			if (accessRequest & (1 << b)) != 0 {
				if layerMasks[b] != 0 {
					return false
				}
			}
		}
		return true
	}

	if isAllowed() {
		return true
	}

	// Walk up the path.
	err := vfsObjConcrete.WalkUp(ctx, vdConcrete, func(currVD vfs.VirtualDentry) (bool, error) {
		// Check if we have a rule for this dentry.
		if rule, ok := d.Rules[currVD.Dentry()]; ok {
			// Apply the rule.
			// rule is a slice of allowed access masks for each layer.
			for l := 0; l < len(rule); l++ {
				allowed := rule[l]
				layerBit := uint16(1 << l)
				for b := 0; b < NumFSAccesses; b++ {
					accessBit := uint64(1 << b)
					if (accessRequest & accessBit) != 0 {
						if (allowed & accessBit) != 0 {
							// Clear the bit for this layer.
							layerMasks[b] &= ^layerBit
						}
					}
				}
			}
			if isAllowed() {
				return false, nil // Stop walk, allowed.
			}
		}
		return true, nil // Continue walk.
	})

	if err != nil {
		// If WalkUp returned an error (e.g. ELOOP), we deny access.
		return false
	}

	return isAllowed()
}
