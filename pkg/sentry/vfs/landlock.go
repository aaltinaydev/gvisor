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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// LandlockDomain represents the interface that a Landlock domain must implement
// to allow VFS to perform Landlock path verification checks.
type LandlockDomain interface {
	// NumLayers returns the number of layers in the domain.
	NumLayers() int

	// HandledAccessFS returns the handled filesystem access rights of the given layer.
	HandledAccessFS(layer int) uint64

	// GetRule returns the allowed access mask for a dentry in the given layer,
	// and true if a rule exists.
	GetRule(layer int, d *Dentry) (uint64, bool)
}

// CheckLandlockOpen checks Landlock permissions for open operations.
// Matches Linux security/landlock/fs.c:hook_file_open()
func (vfs *VirtualFilesystem) CheckLandlockOpen(ctx context.Context, creds *auth.Credentials, vd VirtualDentry, flags uint32, fileExec bool) error {
	if !IsLandlocked(creds) {
		return nil
	}
	domain := creds.Security.(LandlockDomain)

	// Matches Linux security/landlock/fs.c:get_required_file_open_access()
	var accessRequest uint64

	isDir := false
	if flags&linux.O_DIRECTORY != 0 {
		isDir = true
	} else {
		mode, err := vfs.fileMode(ctx, creds, vd)
		if err != nil {
			return err
		}
		if mode.IsDir() {
			isDir = true
		}
	}

	accMode := flags & linux.O_ACCMODE
	hasRead := accMode == linux.O_RDONLY || accMode == linux.O_RDWR
	hasWrite := accMode == linux.O_WRONLY || accMode == linux.O_RDWR

	if hasRead {
		if isDir {
			// A directory can only be opened in read mode.
			return vfs.checkLandlockPath(ctx, domain, vd, linux.LANDLOCK_ACCESS_FS_READ_DIR)
		}
		accessRequest |= linux.LANDLOCK_ACCESS_FS_READ_FILE
	}
	if hasWrite {
		accessRequest |= linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	}
	if fileExec {
		accessRequest |= linux.LANDLOCK_ACCESS_FS_EXECUTE
	}

	return vfs.checkLandlockPath(ctx, domain, vd, accessRequest)
}

// CheckLandlockPath checks Landlock permissions for a path.
func (vfs *VirtualFilesystem) CheckLandlockPath(ctx context.Context, creds *auth.Credentials, vd VirtualDentry, accessRequest uint64) error {
	if !IsLandlocked(creds) {
		return nil
	}
	domain := creds.Security.(LandlockDomain)
	return vfs.checkLandlockPath(ctx, domain, vd, accessRequest)
}

func (vfs *VirtualFilesystem) checkLandlockPath(ctx context.Context, domain LandlockDomain, vd VirtualDentry, accessRequest uint64) error {
	if accessRequest == 0 {
		return nil
	}

	// Skip checks for mounts that are not user-visible (e.g. pipefs, sockfs).
	if vd.mount.neverConnected() {
		return nil
	}

	numLayers := domain.NumLayers()
	if numLayers == 0 {
		return nil
	}

	// Initialize layer masks.
	// layerMasks[bit] is a bitmask of layers that restrict the access right at index 'bit'.
	var layerMasks [16]uint16
	var handledAccesses uint64

	for layer := 0; layer < numLayers; layer++ {
		layerBit := uint16(1 << layer)
		handledFS := domain.HandledAccessFS(layer)

		for bit := 0; bit < 16; bit++ {
			accessBit := uint64(1 << bit)
			if (accessRequest & accessBit) != 0 {
				if (handledFS & accessBit) != 0 {
					layerMasks[bit] |= layerBit
					handledAccesses |= accessBit
				}
			}
		}
	}

	// If none of the layers handle any of the requested accesses, it's allowed.
	if handledAccesses == 0 {
		return nil
	}

	// Walk up the ancestry tree.
	curr := vd
	curr.IncRef()
	// Use a closure to defer DecRef on the *current* value of curr,
	// as curr may be reassigned when crossing mount boundaries.
	defer func() {
		curr.DecRef(ctx)
	}()

	for {
		// Check if the filesystem implements AncestorsWalker.
		walker, ok := curr.mount.fs.impl.(AncestorsWalker)
		if !ok {
			// If we can't walk ancestors, we must stop and fail.
			return linuxerr.EACCES
		}

		var walkErr error
		lastDentry := curr.dentry
		// Walk up within the current filesystem.
		// Matches Linux security/landlock/fs.c:is_access_to_paths_allowed()
		walkErr = walker.WalkAncestors(ctx, curr.dentry, func(d *Dentry) bool {
			if d != curr.dentry {
				d.IncRef()
				if lastDentry != curr.dentry {
					lastDentry.DecRef(ctx)
				}
				lastDentry = d
			}

			// For each layer, check if there is a rule for this dentry.
			for layer := 0; layer < numLayers; layer++ {
				layerBit := uint16(1 << layer)
				if allowedAccess, ok := domain.GetRule(layer, d); ok {
					// Clear the layer's bit from all access rights that are allowed by this rule.
					for bit := 0; bit < 16; bit++ {
						accessBit := uint64(1 << bit)
						if (allowedAccess & accessBit) != 0 {
							layerMasks[bit] &^= layerBit
						}
					}
				}
			}

			// Check if all layers have allowed all requested accesses.
			allAllowed := true
			for bit := 0; bit < 16; bit++ {
				accessBit := uint64(1 << bit)
				if (handledAccesses & accessBit) != 0 {
					if layerMasks[bit] != 0 {
						allAllowed = false
						break
					}
				}
			}
			if allAllowed {
				return false // stop walking
			}

			return true // continue walking up
		})

		if walkErr != nil {
			if lastDentry != curr.dentry {
				lastDentry.DecRef(ctx)
			}
			return walkErr
		}

		if lastDentry != curr.dentry {
			curr.dentry.DecRef(ctx)
			curr.dentry = lastDentry
		}

		// Check if we are done (all allowed).
		allAllowed := true
		for bit := 0; bit < 16; bit++ {
			accessBit := uint64(1 << bit)
			if (handledAccesses & accessBit) != 0 {
				if layerMasks[bit] != 0 {
					allAllowed = false
					break
				}
			}
		}
		if allAllowed {
			return nil
		}

		// If we reached the mount root, cross the mount boundary.
		// Matches Linux follow_up() behavior by walking up to the global root.
		if curr.dentry == curr.mount.Root() {
			parentVD := vfs.getMountpointAt(ctx, curr.mount, VirtualDentry{})
			if parentVD.Ok() {
				curr.DecRef(ctx)
				curr = parentVD
				// parentVD is returned with a reference taken, so we just continue.
				continue
			} else {
				// Reached the absolute root.
				return linuxerr.EACCES
			}
		}

		// If WalkAncestors finished without reaching the mount root, but we still aren't allowed:
		if curr.dentry != curr.mount.Root() {
			return linuxerr.EACCES
		}
	}
}

// fileMode returns the file mode of the file represented by vd.
func (vfs *VirtualFilesystem) fileMode(ctx context.Context, creds *auth.Credentials, vd VirtualDentry) (linux.FileMode, error) {
	statVal, err := vfs.StatAt(ctx, creds, &PathOperation{Start: vd}, &StatOptions{
		Mask: linux.STATX_TYPE,
		Sync: linux.AT_STATX_DONT_SYNC,
	})
	if err != nil {
		return 0, err
	}
	return linux.FileMode(statVal.Mode), nil
}

// getModeAccess returns the Landlock access right that corresponds to the
// file type of the given mode.
// Matches Linux security/landlock/fs.c:get_mode_access()
func getModeAccess(mode linux.FileMode) uint64 {
	switch mode.FileType() {
	case linux.S_IFLNK:
		return linux.LANDLOCK_ACCESS_FS_MAKE_SYM
	case linux.S_IFDIR:
		return linux.LANDLOCK_ACCESS_FS_MAKE_DIR
	case linux.S_IFCHR:
		return linux.LANDLOCK_ACCESS_FS_MAKE_CHAR
	case linux.S_IFBLK:
		return linux.LANDLOCK_ACCESS_FS_MAKE_BLOCK
	case linux.S_IFIFO:
		return linux.LANDLOCK_ACCESS_FS_MAKE_FIFO
	case linux.S_IFSOCK:
		return linux.LANDLOCK_ACCESS_FS_MAKE_SOCK
	case linux.S_IFREG, 0:
		return linux.LANDLOCK_ACCESS_FS_MAKE_REG
	default:
		return linux.LANDLOCK_ACCESS_FS_MAKE_REG
	}
}

// IsLandlocked returns true if the credentials represent a sandboxed task.
func IsLandlocked(creds *auth.Credentials) bool {
	if creds.Security == nil {
		return false
	}
	domain, ok := creds.Security.(LandlockDomain)
	if !ok {
		return false
	}
	return domain.NumLayers() > 0
}
