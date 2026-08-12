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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/refs"
)

// +stateify savable
type InodeIdentity struct {
	ok       bool
	fsID     uint64
	devMajor uint32
	devMinor uint32
	ino      uint64
}

func MakeInodeIdentity(fs *Filesystem, devMajor, devMinor uint32, ino uint64) InodeIdentity {
	return InodeIdentity{
		ok:       true,
		fsID:     fs.id,
		devMajor: devMajor,
		devMinor: devMinor,
		ino:      ino,
	}
}

func (id InodeIdentity) Ok() bool {
	return id.ok
}

func (d *Dentry) InodeIdentity() InodeIdentity {
	return d.impl.InodeIdentity()
}

type inodeIdentityPinner interface {
	PinInodeIdentity()
}

func (d *Dentry) PinInodeIdentity() {
	if pinner, ok := d.impl.(inodeIdentityPinner); ok {
		pinner.PinInodeIdentity()
	}
}

func (vfs *VirtualFilesystem) WalkAncestors(ctx context.Context, vd VirtualDentry, toDecRef *[]refs.RefCounter, fn func(d *Dentry) bool) {
	crossed := false
	for {
		stopped := false
		first := true
		var last *Dentry
		vd.mount.fs.impl.WalkAncestors(ctx, vd, func(d *Dentry) bool {
			last = d
			if first {
				first = false
				if crossed {
					return true
				}
			}
			if fn(d) {
				return true
			}
			stopped = true
			return false
		})
		if stopped {
			return
		}
		if root := vd.mount.root; root != nil && last != root {
			if !fn(root) {
				return
			}
		}

		nextVD := vfs.getMountpointAt(ctx, vd.mount, VirtualDentry{}, toDecRef)
		if !nextVD.Ok() {
			return
		}
		*toDecRef = append(*toDecRef, nextVD.dentry, nextVD.mount)
		vd = nextVD
		crossed = true
	}
}
