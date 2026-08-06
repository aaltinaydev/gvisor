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
	"path"

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
//
// +stateify savable
type LandlockRuleset struct {
	mu              landlockRulesetMutex `state:"nosave"`
	handledAccessFS uint64

	// rules maps a cleaned pathname to the access rights granted beneath it.
	//
	// Linux keys rules by struct inode, so a rule follows the file it was added
	// for. Keying by pathname instead means a rule is bypassed by a hard link or
	// bind mount that reaches the same file by another path, and is silently
	// dropped when a covered directory is renamed.
	rules map[string]uint64
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
//
// +stateify savable
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
//
// There is nothing to release: the ruleset holds no references and no host
// resources, and it may outlive this file description because
// landlock_restrict_self(2) keeps it alive through the domains layered on top
// of it. It is reclaimed by the garbage collector once no domain refers to it.
//
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
//
// +stateify savable
type LandlockDomainLayer struct {
	handledAccessFS uint64
	rules           map[string]uint64
}

// LandlockDomain represents an immutable stacked hierarchy of Landlock domain layers.
// Matches Linux [security/landlock/ruleset.h]:struct landlock_ruleset (used as a domain)
//
// +stateify savable
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

// CheckAccess evaluates if all of accessRights on vd are allowed by every
// domain layer.
//
// If vd's pathname cannot be determined, access is denied: an unresolvable
// path cannot be checked against the domain's rules, and Landlock must fail
// closed.
//
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CheckAccess(ctx context.Context, vfsObj *VirtualFilesystem, vd VirtualDentry, accessRights uint64) error {
	if d == nil || len(d.layers) == 0 {
		return nil
	}
	if !vd.Ok() {
		return linuxerr.EACCES
	}

	vfsroot := VirtualDentry{}
	targetPath, err := vfsObj.PathnameWithDeleted(ctx, vfsroot, vd)
	if err != nil {
		return linuxerr.EACCES
	}
	return d.CheckAccessPath(targetPath, accessRights)
}

// CheckAccessPath evaluates if all of accessRights on targetPath are allowed by
// every domain layer.
//
// A layer only constrains the rights it handles; within a layer, a right is
// granted if targetPath or any of its ancestors has a rule granting it, and
// rights accumulate across ancestors. All handled rights must be granted for
// the layer to allow the access.
//
// Matches Linux [security/landlock/fs.c]:is_access_to_paths_allowed()
func (d *LandlockDomain) CheckAccessPath(targetPath string, accessRights uint64) error {
	if d == nil || len(d.layers) == 0 {
		return nil
	}
	cleanTarget := cleanPathString(targetPath)

	for _, layer := range d.layers {
		// Rights this layer does not handle are outside its concern.
		// Matches Linux [security/landlock/fs.c]:init_layer_masks()
		remaining := layer.handledAccessFS & accessRights
		if remaining == 0 {
			continue
		}

		// Matches Linux [security/landlock/fs.c]:unmask_layers(), which walks
		// up the path clearing rights as matching rules grant them.
		curr := cleanTarget
		for {
			remaining &^= layer.rules[curr]
			if remaining == 0 {
				break
			}
			parent := path.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}

		if remaining != 0 {
			return linuxerr.EACCES
		}
	}

	return nil
}

// landlockOpenAccessRights returns the filesystem access rights that an open
// with opts of a file of the given type requires.
//
// Matches Linux [security/landlock/fs.c]:hook_file_open(), which derives the
// required rights from the resulting file's f_mode, so that O_RDWR requires
// both read and write.
func landlockOpenAccessRights(opts *OpenOptions, isDir bool) uint64 {
	if opts.FileExec {
		return linux.LANDLOCK_ACCESS_FS_EXECUTE
	}
	if isDir {
		return linux.LANDLOCK_ACCESS_FS_READ_DIR
	}
	switch opts.Flags & linux.O_ACCMODE {
	case linux.O_WRONLY:
		return linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	case linux.O_RDWR:
		return linux.LANDLOCK_ACCESS_FS_READ_FILE | linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	default:
		return linux.LANDLOCK_ACCESS_FS_READ_FILE
	}
}

// checkLandlockOpen checks domain's filesystem access rights for an open of the
// file at pop.
//
// This runs before the open so that a denied open(2) leaves no trace: Linux
// denies creation in [security/landlock/fs.c]:hook_path_mknod() before the file
// is created, and checks access rights in hook_file_open() before O_TRUNC is
// honored by handle_truncate().
func (vfs *VirtualFilesystem) checkLandlockOpen(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *OpenOptions, domain *LandlockDomain) error {
	// Resolve the target without creating it, so that access rights are
	// evaluated against the file that open(2) would act on.
	vd, err := vfs.GetDentryAt(ctx, creds, pop, &GetDentryOptions{})
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) && opts.Flags&linux.O_CREAT != 0 {
			return vfs.checkLandlockCreate(ctx, creds, pop, opts, domain)
		}
		// Fail closed: a path that cannot be resolved cannot be checked. The
		// open below would fail with this same error in any case.
		return err
	}
	defer vd.DecRef(ctx)

	if opts.Flags&(linux.O_CREAT|linux.O_EXCL) == linux.O_CREAT|linux.O_EXCL {
		// The file exists, so open(2) fails with EEXIST without touching it.
		// Returning EACCES here would mask that error.
		return nil
	}

	if opts.Flags&linux.O_TMPFILE != 0 {
		// vd is the directory that will hold the new unnamed file.
		if err := domain.CheckAccess(ctx, vfs, vd, linux.LANDLOCK_ACCESS_FS_MAKE_REG); err != nil {
			return err
		}
		return domain.CheckAccess(ctx, vfs, vd, landlockOpenAccessRights(opts, false /* isDir */))
	}

	stat, err := vfs.StatAt(ctx, creds, &PathOperation{
		Root:  vd,
		Start: vd,
	}, &StatOptions{
		Mask: linux.STATX_MODE,
	})
	if err != nil {
		// Fail closed: without the file type the required rights are unknown.
		return linuxerr.EACCES
	}
	isDir := stat.Mode&linux.S_IFMT == linux.S_IFDIR

	return domain.CheckAccess(ctx, vfs, vd, landlockOpenAccessRights(opts, isDir))
}

// checkLandlockCreate checks domain's filesystem access rights for an open(2)
// that will create a regular file at pop.
//
// Matches Linux [security/landlock/fs.c]:hook_path_mknod()
//
// TODO(b/...): If pop's final component is a dangling symlink, the file is
// created at the symlink's target, but this checks the symlink's own parent
// directory. Rules are keyed by pathname rather than by dentry, so the two
// cannot currently be reconciled; see the comment on LandlockRuleset.rules.
func (vfs *VirtualFilesystem) checkLandlockCreate(ctx context.Context, creds *auth.Credentials, pop *PathOperation, opts *OpenOptions, domain *LandlockDomain) error {
	if !pop.Path.Begin.Ok() {
		// An empty path resolves to pop.Start, which cannot have returned
		// ENOENT, so this should be unreachable. Fail closed regardless, since
		// getParentDirAndName() requires a non-empty path.
		return linuxerr.EACCES
	}
	parentVD, name, err := vfs.getParentDirAndName(ctx, creds, pop)
	if err != nil {
		return err
	}
	defer parentVD.DecRef(ctx)

	parentPath, err := vfs.PathnameWithDeleted(ctx, VirtualDentry{}, parentVD)
	if err != nil {
		return linuxerr.EACCES
	}
	if err := domain.CheckAccessPath(parentPath, linux.LANDLOCK_ACCESS_FS_MAKE_REG); err != nil {
		return err
	}
	// The new file is covered by the rules on its own path, so evaluate the
	// access mode against it as hook_file_open() would.
	return domain.CheckAccessPath(path.Join(parentPath, name), landlockOpenAccessRights(opts, false /* isDir */))
}

// landlockModeAccess returns the right required to create a file of the given
// mode in a directory.
//
// Matches Linux [security/landlock/fs.c]:get_mode_access()
func landlockModeAccess(mode uint16) uint64 {
	switch mode & linux.S_IFMT {
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
	default:
		// Linux treats a zero mode as S_IFREG.
		return linux.LANDLOCK_ACCESS_FS_MAKE_REG
	}
}

// landlockRemoveAccess returns the right required to remove a file of the given
// mode from a directory.
//
// Matches Linux [security/landlock/fs.c]:maybe_remove()
func landlockRemoveAccess(mode uint16) uint64 {
	if mode&linux.S_IFMT == linux.S_IFDIR {
		return linux.LANDLOCK_ACCESS_FS_REMOVE_DIR
	}
	return linux.LANDLOCK_ACCESS_FS_REMOVE_FILE
}

// landlockStatMode returns the mode of the file at pop and whether it exists.
// A path that does not exist is not an error.
func (vfs *VirtualFilesystem) landlockStatMode(ctx context.Context, creds *auth.Credentials, pop *PathOperation) (uint16, bool, error) {
	stat, err := vfs.StatAt(ctx, creds, pop, &StatOptions{
		Mask: linux.STATX_MODE,
	})
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return stat.Mode, true, nil
}

// checkLandlockRefer checks domain's filesystem access rights for a rename(2)
// or link(2) of the file at oldpop to newpop.
//
// removable distinguishes rename(2), which detaches the source from its
// directory, from link(2), which does not. exchange reports whether the rename
// is a RENAME_EXCHANGE, in which case the destination is also moved.
//
// Landlock ABI v1 has no LANDLOCK_ACCESS_FS_REFER right, so a sandboxed thread
// cannot move or link a file between two different directories at all: the
// operation fails with EXDEV whenever a domain is active, whatever rights that
// domain handles or grants. Only same-directory operations can be permitted,
// and those are allowed if the domain grants the rights they need there.
//
// Matches Linux [security/landlock/fs.c]:current_check_refer_path()
func (vfs *VirtualFilesystem) checkLandlockRefer(ctx context.Context, creds *auth.Credentials, oldpop, newpop *PathOperation, domain *LandlockDomain, removable, exchange bool) error {
	if !oldpop.Path.Begin.Ok() {
		// The source is named by a file descriptor alone (AT_EMPTY_PATH), so its
		// directory cannot be derived from the path. Without it the operation
		// cannot be shown to stay within one directory, so forbid it as
		// reparenting.
		return linuxerr.EXDEV
	}

	// Linux resolves both dentries before comparing their parents, so a missing
	// source is reported as ENOENT rather than EXDEV.
	srcMode, srcExists, err := vfs.landlockStatMode(ctx, creds, oldpop)
	if err != nil {
		return err
	}
	if !srcExists {
		return linuxerr.ENOENT
	}
	dstMode, dstExists, err := vfs.landlockStatMode(ctx, creds, newpop)
	if err != nil {
		return err
	}
	if exchange && !dstExists {
		return linuxerr.ENOENT
	}

	oldParentVD, _, err := vfs.getParentDirAndName(ctx, creds, oldpop)
	if err != nil {
		return err
	}
	defer oldParentVD.DecRef(ctx)
	newParentVD, _, err := vfs.getParentDirAndName(ctx, creds, newpop)
	if err != nil {
		return err
	}
	defer newParentVD.DecRef(ctx)

	if oldParentVD != newParentVD {
		// Backward compatibility: no reparenting support.
		return linuxerr.EXDEV
	}

	// Both parents are the same directory, so all rights are required there.
	accessRights := landlockModeAccess(srcMode)
	if exchange {
		accessRights |= landlockModeAccess(dstMode)
	}
	if removable {
		accessRights |= landlockRemoveAccess(srcMode)
		if dstExists {
			accessRights |= landlockRemoveAccess(dstMode)
		}
	}
	return domain.CheckAccess(ctx, vfs, oldParentVD, accessRights)
}

// checkLandlockParent checks domain's accessRights on the parent directory of
// pop, which must name a file to be created or removed.
//
// Preconditions: pop.Path.Begin.Ok().
func (vfs *VirtualFilesystem) checkLandlockParent(ctx context.Context, creds *auth.Credentials, pop *PathOperation, domain *LandlockDomain, accessRights uint64) error {
	parentVD, _, err := vfs.getParentDirAndName(ctx, creds, pop)
	if err != nil {
		// Fail closed: a parent that cannot be resolved cannot be checked. The
		// operation itself would fail with this same error in any case.
		return err
	}
	defer parentVD.DecRef(ctx)
	return domain.CheckAccess(ctx, vfs, parentVD, accessRights)
}

// cleanPathString normalizes p so that rules and lookups agree on a single
// spelling of each path. Rules are only ever keyed by absolute pathnames, so a
// degenerate path is normalized to the root rather than left as ".", which
// path.Clean returns for the empty string and which would not chain up to "/".
func cleanPathString(p string) string {
	switch cp := path.Clean(p); cp {
	case "", ".":
		return "/"
	default:
		return cp
	}
}
