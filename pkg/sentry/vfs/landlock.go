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
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

func LandlockDomainFromCredentials(creds *auth.Credentials) *LandlockDomain {
	domain, _ := creds.LandlockDomain.(*LandlockDomain)
	return domain
}

// +stateify savable
type LandlockRuleset struct {
	mu              landlockRulesetMutex `state:"nosave"`
	handledAccessFS uint64

	rules map[InodeIdentity]uint64
}

func NewLandlockRuleset(handledAccessFS uint64) *LandlockRuleset {
	return &LandlockRuleset{
		handledAccessFS: handledAccessFS,
		rules:           make(map[InodeIdentity]uint64),
	}
}

func (r *LandlockRuleset) HandledAccessFS() uint64 {
	return r.handledAccessFS
}

func (r *LandlockRuleset) InsertRule(id InodeIdentity, allowedAccess uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules[id] |= allowedAccess
}

// +stateify savable
type LandlockRulesetFileDescription struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	NoLockFD

	ruleset *LandlockRuleset
}

var _ FileDescriptionImpl = (*LandlockRulesetFileDescription)(nil)

func NewLandlockRulesetFD(ctx context.Context, vfsObj *VirtualFilesystem, ruleset *LandlockRuleset) (*FileDescription, error) {
	vfsObj.landlockInUse.Store(true)

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

func (rfd *LandlockRulesetFileDescription) Release(ctx context.Context) {
}

func (vfs *VirtualFilesystem) LandlockInUse() bool {
	return vfs.landlockInUse.Load()
}

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

// +stateify savable
type LandlockDomainLayer struct {
	handledAccessFS uint64
	rules           map[InodeIdentity]uint64
}

// +stateify savable
type LandlockDomain struct {
	layers []LandlockDomainLayer

	parent *LandlockDomain
}

var _ auth.LandlockDomain = (*LandlockDomain)(nil)

func (d *LandlockDomain) IsLandlockDomain() {}

func (d *LandlockDomain) ScopeLE(other auth.LandlockDomain) bool {
	if d == nil {
		return true
	}
	child, _ := other.(*LandlockDomain)
	if child == nil {
		return false
	}
	for walker := child; walker != nil; walker = walker.parent {
		if walker == d {
			return true
		}
	}
	return false
}

func (d *LandlockDomain) NumLayers() int {
	if d == nil {
		return 0
	}
	return len(d.layers)
}

func (d *LandlockDomain) Merge(ruleset *LandlockRuleset) (*LandlockDomain, error) {
	currentLayers := 0
	if d != nil {
		currentLayers = len(d.layers)
	}
	if currentLayers >= linux.LANDLOCK_MAX_NUM_LAYERS {
		return nil, linuxerr.E2BIG
	}

	ruleset.mu.Lock()
	snapshotRules := make(map[InodeIdentity]uint64, len(ruleset.rules))
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

	return &LandlockDomain{layers: newLayers, parent: d}, nil
}

type landlockLayerMasks struct {
	domain *LandlockDomain

	remaining []uint64

	unsatisfied int
}

func (d *LandlockDomain) newLayerMasks(accessRights uint64) landlockLayerMasks {
	m := landlockLayerMasks{
		domain:    d,
		remaining: make([]uint64, len(d.layers)),
	}
	for i, layer := range d.layers {
		m.remaining[i] = layer.handledAccessFS & accessRights
		if m.remaining[i] != 0 {
			m.unsatisfied++
		}
	}
	return m
}

func (m *landlockLayerMasks) unmask(id InodeIdentity) {
	if !id.Ok() {
		return
	}
	for i := range m.domain.layers {
		if m.remaining[i] == 0 {
			continue
		}
		m.remaining[i] &^= m.domain.layers[i].rules[id]
		if m.remaining[i] == 0 {
			m.unsatisfied--
		}
	}
}

func (m *landlockLayerMasks) allowed() bool {
	return m.unsatisfied == 0
}

func (d *LandlockDomain) CheckAccess(ctx context.Context, vfsObj *VirtualFilesystem, vd VirtualDentry, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	return d.checkAccess(ctx, vfsObj, vd, InodeIdentity{}, accessRights, toDecRef)
}

func (d *LandlockDomain) CheckAccessDetached(ctx context.Context, vfsObj *VirtualFilesystem, id InodeIdentity, vd VirtualDentry, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	return d.checkAccess(ctx, vfsObj, vd, id, accessRights, toDecRef)
}

func (d *LandlockDomain) checkAccess(ctx context.Context, vfsObj *VirtualFilesystem, vd VirtualDentry, leaf InodeIdentity, accessRights uint64, toDecRef *[]refs.RefCounter) error {
	if d == nil || len(d.layers) == 0 {
		return nil
	}
	if !vd.Ok() {
		return linuxerr.EACCES
	}
	if vd.mount.internal {
		return nil
	}

	masks := d.newLayerMasks(accessRights)
	masks.unmask(leaf)
	if masks.allowed() {
		return nil
	}

	vfsObj.WalkAncestors(ctx, vd, toDecRef, func(dentry *Dentry) bool {
		masks.unmask(dentry.InodeIdentity())
		return !masks.allowed()
	})

	if !masks.allowed() {
		return linuxerr.EACCES
	}
	return nil
}

func landlockOpenAccessRights(opts *OpenOptions, isDir bool) uint64 {
	const fmodeRead, fmodeWrite = 0x1, 0x2
	fmode := (opts.Flags + 1) & linux.O_ACCMODE

	var accessRights uint64
	if fmode&fmodeRead != 0 {
		if isDir {
			return linux.LANDLOCK_ACCESS_FS_READ_DIR
		}
		accessRights = linux.LANDLOCK_ACCESS_FS_READ_FILE
	}
	if fmode&fmodeWrite != 0 {
		accessRights |= linux.LANDLOCK_ACCESS_FS_WRITE_FILE
	}
	if opts.FileExec {
		accessRights |= linux.LANDLOCK_ACCESS_FS_EXECUTE
	}
	return accessRights
}

func LandlockOpenAccessRights(flags uint32) uint64 {
	return landlockOpenAccessRights(&OpenOptions{Flags: flags}, false)
}

func landlockModeAccess(mode linux.FileMode) uint64 {
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
		return linux.LANDLOCK_ACCESS_FS_MAKE_REG
	}
}

func landlockRemoveAccess(mode linux.FileMode) uint64 {
	if mode.FileType() == linux.S_IFDIR {
		return linux.LANDLOCK_ACCESS_FS_REMOVE_DIR
	}
	return linux.LANDLOCK_ACCESS_FS_REMOVE_FILE
}

func (rp *ResolvingPath) checkLandlockAccess(ctx context.Context, d *Dentry, accessRights uint64) error {
	domain := LandlockDomainFromCredentials(rp.creds)
	if domain.NumLayers() == 0 {
		return nil
	}
	if d == nil {
		return linuxerr.EACCES
	}
	return domain.CheckAccess(ctx, rp.vfs, VirtualDentry{mount: rp.mount, dentry: d}, accessRights, &rp.toDecRef)
}

func (rp *ResolvingPath) CheckLandlockOpen(ctx context.Context, d *Dentry, opts *OpenOptions, isDir bool) error {
	return rp.checkLandlockAccess(ctx, d, landlockOpenAccessRights(opts, isDir))
}

func (rp *ResolvingPath) CheckLandlockOpenCreate(ctx context.Context, parent *Dentry, opts *OpenOptions) error {
	accessRights := linux.LANDLOCK_ACCESS_FS_MAKE_REG | landlockOpenAccessRights(opts, false)
	return rp.checkLandlockAccess(ctx, parent, accessRights)
}

func (rp *ResolvingPath) CheckLandlockCreate(ctx context.Context, parent *Dentry, mode linux.FileMode) error {
	return rp.checkLandlockAccess(ctx, parent, landlockModeAccess(mode))
}

func (rp *ResolvingPath) CheckLandlockRemove(ctx context.Context, parent *Dentry, isDir bool) error {
	accessRights := uint64(linux.LANDLOCK_ACCESS_FS_REMOVE_FILE)
	if isDir {
		accessRights = linux.LANDLOCK_ACCESS_FS_REMOVE_DIR
	}
	return rp.checkLandlockAccess(ctx, parent, accessRights)
}

type LandlockReferOptions struct {
	OldParent *Dentry
	NewParent *Dentry

	SrcMode linux.FileMode

	DstExists bool
	DstMode   linux.FileMode

	Removable bool

	RenameFlags uint32
}

func (rp *ResolvingPath) CheckLandlockRefer(ctx context.Context, opts *LandlockReferOptions) error {
	if LandlockDomainFromCredentials(rp.creds).NumLayers() == 0 {
		return nil
	}

	var srcParentRights uint64
	if opts.RenameFlags&linux.RENAME_EXCHANGE != 0 {
		if !opts.DstExists {
			return linuxerr.ENOENT
		}
		srcParentRights = landlockModeAccess(opts.DstMode)
	}
	dstParentRights := landlockModeAccess(opts.SrcMode)
	if opts.Removable {
		srcParentRights |= landlockRemoveAccess(opts.SrcMode)
		if opts.DstExists {
			dstParentRights |= landlockRemoveAccess(opts.DstMode)
		}
	}

	if opts.OldParent == opts.NewParent {
		return rp.checkLandlockAccess(ctx, opts.NewParent, srcParentRights|dstParentRights)
	}

	if srcParentRights != 0 {
		if err := rp.checkLandlockAccess(ctx, opts.OldParent, srcParentRights); err != nil {
			return err
		}
	}
	if err := rp.checkLandlockAccess(ctx, opts.NewParent, dstParentRights); err != nil {
		return err
	}
	return linuxerr.EXDEV
}

func CheckLandlockMount(domain *LandlockDomain) error {
	if domain.NumLayers() != 0 {
		return linuxerr.EPERM
	}
	return nil
}

func (vfs *VirtualFilesystem) CheckLandlockMountAt(ctx context.Context, creds *auth.Credentials, pops ...*PathOperation) error {
	return vfs.checkLandlockMountAt(ctx, creds, false /* requireDir */, pops...)
}

// CheckLandlockMountDirAt is CheckLandlockMountAt for operations whose Linux
// counterpart resolves the paths with LOOKUP_DIRECTORY before the Landlock
// hook (pivot_root), so that ENOTDIR takes priority over EPERM.
func (vfs *VirtualFilesystem) CheckLandlockMountDirAt(ctx context.Context, creds *auth.Credentials, pops ...*PathOperation) error {
	return vfs.checkLandlockMountAt(ctx, creds, true /* requireDir */, pops...)
}

func (vfs *VirtualFilesystem) checkLandlockMountAt(ctx context.Context, creds *auth.Credentials, requireDir bool, pops ...*PathOperation) error {
	if err := CheckLandlockMount(LandlockDomainFromCredentials(creds)); err == nil {
		return nil
	}
	for _, pop := range pops {
		if requireDir {
			stat, err := vfs.StatAt(ctx, creds, pop, &StatOptions{Mask: linux.STATX_TYPE})
			if err != nil {
				return err
			}
			if stat.Mask&linux.STATX_TYPE != 0 && stat.Mode&linux.S_IFMT != linux.S_IFDIR {
				return linuxerr.ENOTDIR
			}
			continue
		}
		vd, err := vfs.GetDentryAt(ctx, creds, pop, &GetDentryOptions{})
		if err != nil {
			return err
		}
		vd.DecRef(ctx)
	}
	return linuxerr.EPERM
}
