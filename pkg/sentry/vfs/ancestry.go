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

// WalkAncestors calls fn on vd's Dentry and then on each of its ancestors, from
// vd upward toward the root of vd's mount namespace, crossing mount boundaries
// as it goes. The walk stops when fn returns false, or when it reaches a mount
// that has no mount point to continue from — the root of the mount namespace,
// or a mount that was never connected to one.
//
// Dentries covered by a mount are skipped, since no path names them; the mount
// root that covers them is visited in their place. This mirrors the way Linux's
// follow_up() moves past a mount point without examining it.
//
// A Dentry that has been moved out of the subtree its mount exposes no longer
// has that mount's root among its ancestors. The walk from it reaches the root
// of the filesystem instead, and the mount root is visited there before the
// walk crosses to the mount point.
//
// Dentries passed to fn are not referenced and are only valid for the duration
// of the call. FilesystemImpls may hold filesystem locks across the walk, so fn
// must not reenter the filesystem.
//
// Moving above a mount point takes references on it. WalkAncestors appends them
// to *toDecRef instead of dropping them itself, because a caller holding
// filesystem locks cannot drop them safely: releasing the last reference to a
// mount point can release the filesystem it is on, which acquires that
// filesystem's own locks. The caller must drop them once it holds none.
func (vfs *VirtualFilesystem) WalkAncestors(ctx context.Context, vd VirtualDentry, toDecRef *[]refs.RefCounter, fn func(d *Dentry) bool) {
	// crossed reports whether vd is a mount point that this walk arrived at from
	// the mount covering it, in which case vd's Dentry itself is skipped.
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
		// A walk that ends at the root of the filesystem without passing
		// through the root of the mount started from a disconnected Dentry:
		// one that was moved out of the subtree the mount exposes, so that the
		// mount's root is no longer its ancestor. The mount root is visited
		// anyway, since the rights that reaching the file through this mount
		// carries are the ones the mount root's ancestry gives, and the walk
		// then continues from the mount point as usual.
		//
		// Linux does the same in [security/landlock/fs.c]:
		// is_access_to_paths_allowed(), since commit 49c9e09d9610 ("landlock:
		// Fix handling of disconnected directories"), reported by
		// LANDLOCK_CREATE_RULESET_ERRATA as erratum 3.
		if root := vd.mount.root; root != nil && last != root {
			if !fn(root) {
				return
			}
		}

		// toDecRef is passed through so that references taken on intermediate
		// mounts in a stack are not dropped here either: any of them can be
		// the last one after a racing umount.
		nextVD := vfs.getMountpointAt(ctx, vd.mount, VirtualDentry{}, toDecRef)
		if !nextVD.Ok() {
			return
		}
		*toDecRef = append(*toDecRef, nextVD.dentry, nextVD.mount)
		vd = nextVD
		crossed = true
	}
}
