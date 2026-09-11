// Copyright 2019 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
)

var fspathBuilderPool = sync.Pool{
	New: func() any {
		return &fspath.Builder{}
	},
}

func getFSPathBuilder() *fspath.Builder {
	return fspathBuilderPool.Get().(*fspath.Builder)
}

func putFSPathBuilder(b *fspath.Builder) {
	// No methods can be called on b after b.String(), so reset it to its zero
	// value (as returned by fspathBuilderPool.New) instead.
	*b = fspath.Builder{}
	fspathBuilderPool.Put(b)
}

// PathnameWithDeleted returns an absolute pathname to vd, consistent with
// Linux's d_path(). In particular, if vd.Dentry() has been disowned,
// PathnameWithDeleted appends " (deleted)" to the returned pathname.
func (vfs *VirtualFilesystem) PathnameWithDeleted(ctx context.Context, vfsroot, vd VirtualDentry) (string, error) {
	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	haveRef := false
	defer func() {
		if haveRef {
			vd.DecRef(ctx)
		}
	}()

	origD := vd.dentry
loop:
	for {
		err := vd.mount.fs.impl.PrependPath(ctx, vfsroot, vd, b)
		switch err.(type) {
		case nil:
			if vd.mount == vfsroot.mount && vd.mount.root == vfsroot.dentry {
				// genericfstree.PrependPath() will have returned
				// PrependPathAtVFSRootError in this case since it checks
				// against vfsroot before mnt.root, but other implementations
				// of FilesystemImpl.PrependPath() may return nil instead.
				break loop
			}
			nextVD := vfs.getMountpointAt(ctx, vd.mount, vfsroot, nil)
			if !nextVD.Ok() {
				break loop
			}
			if haveRef {
				vd.DecRef(ctx)
			}
			vd = nextVD
			haveRef = true
			// continue loop
		case PrependPathSyntheticError:
			// Skip prepending "/" and appending " (deleted)".
			return b.String(), nil
		case PrependPathAtVFSRootError, PrependPathAtNonMountRootError:
			break loop
		default:
			return "", err
		}
	}
	b.PrependByte('/')
	if origD.IsDead() {
		b.AppendString(" (deleted)")
	}
	return b.String(), nil
}

// PathnameReachable returns an absolute pathname to vd, consistent with
// Linux's __d_path() (as used by seq_path_root()). If vfsroot.Ok() and vd is
// not reachable from vfsroot, such that seq_path_root() would return SEQ_SKIP
// (causing the entire containing entry to be skipped), PathnameReachable
// returns ("", nil).
func (vfs *VirtualFilesystem) PathnameReachable(ctx context.Context, vfsroot, vd VirtualDentry) (string, error) {
	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	haveRef := false
	defer func() {
		if haveRef {
			vd.DecRef(ctx)
		}
	}()
loop:
	for {
		err := vd.mount.fs.impl.PrependPath(ctx, vfsroot, vd, b)
		switch err.(type) {
		case nil:
			if vd.mount == vfsroot.mount && vd.mount.root == vfsroot.dentry {
				break loop
			}
			nextVD := vfs.getMountpointAt(ctx, vd.mount, vfsroot, nil)
			if !nextVD.Ok() {
				return "", nil
			}
			if haveRef {
				vd.DecRef(ctx)
			}
			vd = nextVD
			haveRef = true
		case PrependPathAtVFSRootError:
			break loop
		case PrependPathAtNonMountRootError, PrependPathSyntheticError:
			return "", nil
		default:
			return "", err
		}
	}
	b.PrependByte('/')
	return b.String(), nil
}

// PathnameInFilesystem returns an absolute path to vd relative to vd's
// Filesystem root. It also appends //deleted to for disowned entries. It is
// equivalent to Linux's dentry_path().
func (vfs *VirtualFilesystem) PathnameInFilesystem(ctx context.Context, vd VirtualDentry) (string, error) {
	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	if vd.dentry.IsDead() {
		b.PrependString("//deleted")
	}
	if err := vd.mount.fs.impl.PrependPath(ctx, VirtualDentry{}, VirtualDentry{dentry: vd.dentry}, b); err != nil {
		// PrependPath returns an error if it encounters a filesystem root before
		// the provided vfsroot. We don't provide a vfsroot, so encountering this
		// error is expected and can be ignored.
		switch err.(type) {
		case PrependPathAtNonMountRootError:
		default:
			return "", err
		}
	}
	b.PrependByte('/')
	return b.String(), nil
}

// PathnameForGetcwd returns an absolute pathname to vd, consistent with
// Linux's sys_getcwd().
func (vfs *VirtualFilesystem) PathnameForGetcwd(ctx context.Context, vfsroot, vd VirtualDentry) (string, error) {
	if vd.dentry.IsDead() {
		return "", linuxerr.ENOENT
	}

	b := getFSPathBuilder()
	defer putFSPathBuilder(b)
	haveRef := false
	defer func() {
		if haveRef {
			vd.DecRef(ctx)
		}
	}()
	unreachable := false
loop:
	for {
		err := vd.mount.fs.impl.PrependPath(ctx, vfsroot, vd, b)
		switch err.(type) {
		case nil:
			if vd.mount == vfsroot.mount && vd.mount.root == vfsroot.dentry {
				break loop
			}
			nextVD := vfs.getMountpointAt(ctx, vd.mount, vfsroot, nil)
			if !nextVD.Ok() {
				unreachable = true
				break loop
			}
			if haveRef {
				vd.DecRef(ctx)
			}
			vd = nextVD
			haveRef = true
		case PrependPathAtVFSRootError:
			break loop
		case PrependPathAtNonMountRootError, PrependPathSyntheticError:
			unreachable = true
			break loop
		default:
			return "", err
		}
	}
	b.PrependByte('/')
	if unreachable {
		b.PrependString("(unreachable)")
	}
	return b.String(), nil
}

// As of this writing, we do not have equivalents to:
//
//	- d_absolute_path(), which returns EINVAL if (effectively) any call to
//		FilesystemImpl.PrependPath() would return PrependPathAtNonMountRootError.
//
// These should be added as necessary.

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
