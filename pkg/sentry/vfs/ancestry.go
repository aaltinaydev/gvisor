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

// InodeIdentity identifies the file underlying a Dentry, in the sense in which
// Linux's struct inode identifies a file. Two Dentries have equal identities
// exactly when they name the same file, whether they reach it as hard links to
// each other, through different mounts of the same filesystem, or through the
// same path before and after a rename.
//
// The zero value is the "no identity" value, for which Ok returns false: a
// Filesystem's ID is never zero (see VirtualFilesystem.lastFilesystemID), so
// no file has it. It is returned for Dentries whose filesystem cannot name the
// underlying file, which as of this writing means only anonymous inodes; no
// path reaches those, so they never appear in a path walk.
//
// InodeIdentity is comparable, so it can be used as a map key. Its components
// are filesystem-defined and are not necessarily the ones that stat(2) reports,
// so identities are only meaningful when compared against each other.
//
// +stateify savable
type InodeIdentity struct {
	fsID uint64
	ino  uint64

	// aux is zero for an identity a filesystem produces for its own file, and
	// the ID of the filesystem an identity was derived from for one made by
	// MakeDerivedInodeIdentity, which is how the overlay names a merged file
	// after the layer file it is built from without being confused with it.
	aux uint64
}

// MakeInodeIdentity returns the InodeIdentity of the file on fs identified by
// ino.
//
// ino need not be the inode number that stat(2) reports; it need only identify
// the file uniquely within its filesystem. It must, however, be stable across
// destruction and re-instantiation of the Dentries naming the file, since
// Dentries are cached and callers hold identities for longer than a Dentry
// necessarily lives. In particular, a pointer to a cached per-inode structure
// is not a valid ino.
//
// The identity is scoped to fs because an inode number only names a file
// within its own filesystem. Device numbers, which is how stat(2) tells
// filesystems apart, would not be a safe scope: they are recycled, since an
// anonymous block device minor is returned to the pool when its filesystem is
// destroyed, and the next filesystem to be created may be given the same one.
// An identity held from the destroyed filesystem could then come to match a
// file on the new one. fs identifies the filesystem for as long as the sentry
// runs, so identities from distinct filesystems never collide even if their
// device numbers do.
func MakeInodeIdentity(fs *Filesystem, ino uint64) InodeIdentity {
	return InodeIdentity{
		fsID: fs.id,
		ino:  ino,
	}
}

// MakeDerivedInodeIdentity returns an identity on fs for a file whose identity
// fs derives from a file on another filesystem, as the overlay derives the
// identity of a merged file from the layer file it is built from. The result
// is scoped to fs, so it never equals base, any other identity of base's
// filesystem, or an identity fs produces with MakeInodeIdentity, and two
// derivations from the same base are equal. Nothing is allocated or
// remembered: the derivation records base's filesystem in the aux field and
// keeps its inode number.
//
// For that reason it cannot be applied to a base that is itself derived
// without losing the base's own aux, and returns false for one; the caller
// must then number such files itself, as the overlay does for a layer that
// is itself an overlay. It also returns false for a base that identifies no
// file.
func MakeDerivedInodeIdentity(fs *Filesystem, base InodeIdentity) (InodeIdentity, bool) {
	if !base.Ok() || base.aux != 0 {
		return InodeIdentity{}, false
	}
	return InodeIdentity{
		fsID: fs.id,
		ino:  base.ino,
		aux:  base.fsID,
	}, true
}

// Ok returns whether id identifies a file. A Filesystem's ID is never zero, so
// a zero fsID can only be the zero InodeIdentity, which names no file.
func (id InodeIdentity) Ok() bool {
	return id.fsID != 0
}

// InodeIdentity returns the identity of the file underlying d, which may be the
// zero InodeIdentity if d's filesystem cannot name it.
func (d *Dentry) InodeIdentity() InodeIdentity {
	return d.impl.InodeIdentity()
}

// inodeIdentityPinner is an optional interface implemented by DentryImpls whose
// identities are not naturally stable for the lifetime of the filesystem.
type inodeIdentityPinner interface {
	// PinInodeIdentity asks the FilesystemImpl to keep returning the current
	// identity for the file underlying the Dentry for as long as the file
	// exists, at whatever cost that carries.
	PinInodeIdentity()
}

// PinInodeIdentity tells d's filesystem that d's identity is about to be
// remembered, so that it must keep naming the same file afterwards even if the
// filesystem's own idea of that file changes.
//
// Two filesystems need this. The gofer mints sentry inode numbers on lookup and
// forgets them when a dentry is evicted, so it pins the dentry to keep the
// number. The overlay switches, on copy-up, to a copy that lives in a different
// filesystem with an inode number of its own, which a Dentry instantiated after
// the copy-up cannot see past, so it records the correspondence and pins the
// layer dentries its identity comes from. Linux has nothing to do here because
// a Landlock rule takes a reference to the inode itself, which outlives any
// dentry naming it; gVisor has no such inode to hold, so the filesystem is told
// instead.
//
// Callers must call this before recording an identity that later checks have to
// agree with, which as of this writing means adding a Landlock rule. The caller
// must hold a reference on d.
func (d *Dentry) PinInodeIdentity() {
	if pinner, ok := d.impl.(inodeIdentityPinner); ok {
		pinner.PinInodeIdentity()
	}
}
