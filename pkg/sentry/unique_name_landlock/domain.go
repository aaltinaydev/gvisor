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
	"runtime"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Domain represents a Landlock domain (stacked rulesets).
type Domain struct {
	// layers is the stack of layers.
	// Index 0 is the oldest (top-most) layer.
	// Index len-1 is the newest (bottom-most) layer.
	layers []layer
}

type layer struct {
	handledAccessFS uint64
	// rules maps virtual dentries to their allowed access mask.
	rules map[vfs.VirtualDentry]uint64
}

// NewDomain creates a new Domain and sets a finalizer to clean up references.
func NewDomain(layers []layer) *Domain {
	d := &Domain{layers: layers}
	runtime.SetFinalizer(d, (*Domain).finalize)
	return d
}

func (d *Domain) finalize() {
	ctx := context.Background()
	for _, l := range d.layers {
		for vd := range l.rules {
			vd.DecRef(ctx)
		}
	}
}

// Merge merges a ruleset into the domain, returning a new domain.
func Merge(parent *Domain, child *Ruleset) (*Domain, error) {
	numLayers := 0
	if parent != nil {
		numLayers = len(parent.layers)
	}
	if numLayers >= 16 {
		return nil, linuxerr.E2BIG
	}

	newLayers := make([]layer, 0, numLayers+1)
	if parent != nil {
		for _, l := range parent.layers {
			newRules := make(map[vfs.VirtualDentry]uint64, len(l.rules))
			for vd, access := range l.rules {
				vd.IncRef()
				newRules[vd] = access
			}
			newLayers = append(newLayers, layer{
				handledAccessFS: l.handledAccessFS,
				rules:           newRules,
			})
		}
	}

	childRules := child.Rules()
	for vd := range childRules {
		vd.IncRef()
	}

	newLayers = append(newLayers, layer{
		handledAccessFS: child.HandledAccessFS(),
		rules:           childRules,
	})

	return NewDomain(newLayers), nil
}

// CheckAccess checks if the operation is allowed for the given path.
// vd is the target of the operation.
// accessMask is the requested access.
func (d *Domain) CheckAccess(ctx context.Context, vfsObj *vfs.VirtualFilesystem, vd vfs.VirtualDentry, accessMask uint64) error {
	if accessMask == 0 {
		return nil
	}

	// Initialize remaining restrictions per layer.
	restrictions := make([]uint64, len(d.layers))
	hasRestrictions := false
	for i, l := range d.layers {
		restrictions[i] = accessMask & l.handledAccessFS
		if restrictions[i] != 0 {
			hasRestrictions = true
		}
	}

	if !hasRestrictions {
		return nil
	}

	// For each layer, check if the restrictions are allowed by any rule.
	for i, l := range d.layers {
		if restrictions[i] == 0 {
			continue
		}
		for ruleVD, allowed := range l.rules {
			beneath, err := vfsObj.IsBeneath(ctx, vd, ruleVD)
			if err != nil {
				return err
			}
			if beneath {
				restrictions[i] &= ^allowed
			}
			if restrictions[i] == 0 {
				break
			}
		}
		if restrictions[i] != 0 {
			return linuxerr.EACCES
		}
	}

	return nil
}
