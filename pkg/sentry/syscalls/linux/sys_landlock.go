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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/landlock"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

var sizeofLandlockRulesetAttr = (*linux.LandlockRulesetAttr)(nil).SizeBytes()

// LandlockCreateRuleset implements linux syscall landlock_create_ruleset(2).
// Matches Linux security/landlock/syscalls.c:sys_landlock_create_ruleset
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	size := args[1].SizeT()
	flags := args[2].Uint()

	if flags != 0 {
		if addr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if flags == linux.LANDLOCK_CREATE_RULESET_VERSION {
			return 1, nil, nil // We support ABI v1
		}
		return 0, nil, linuxerr.EINVAL
	}

	// In Linux Landlock ABI v1, the struct must be at least 8 bytes
	// (size of handled_access_fs), and passing a size smaller than this should
	// fail with EINVAL. This matches copy_min_struct_from_user behavior.
	if size < 8 {
		return 0, nil, linuxerr.EINVAL
	}

	if size > hostarch.PageSize {
		return 0, nil, linuxerr.E2BIG
	}

	var attr linux.LandlockRulesetAttr
	if size > 0 {
		// Matches Linux copy_struct_from_user behavior where we copy up to the
		// size of our known struct and verify that any extra bytes are zero.
		copySize := int(size)
		if copySize > sizeofLandlockRulesetAttr {
			copySize = sizeofLandlockRulesetAttr
		}
		if _, err := attr.CopyInN(t, addr, copySize); err != nil {
			return 0, nil, err
		}

		if int(size) > sizeofLandlockRulesetAttr {
			extraSize := int(size) - sizeofLandlockRulesetAttr
			buf := t.CopyScratchBuffer(extraSize)
			if _, err := t.CopyInBytes(addr+hostarch.Addr(sizeofLandlockRulesetAttr), buf[:extraSize]); err != nil {
				return 0, nil, err
			}
			for _, b := range buf[:extraSize] {
				if b != 0 {
					return 0, nil, linuxerr.E2BIG
				}
			}
		}
	}

	// We only support FS access rights in ABI v1.
	if attr.HandledAccessNet != 0 || attr.Scoped != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Only allow access rights defined in ABI v1.
	if attr.HandledAccessFS&^linux.LANDLOCK_MASK_ACCESS_FS != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Rulesets must not be initialized empty (all masks = 0).
	// Matches Linux security/landlock/ruleset.c:landlock_create_ruleset()
	if attr.HandledAccessFS == 0 {
		return 0, nil, linuxerr.ENOMSG
	}

	ruleset := landlock.NewRuleset(attr.HandledAccessFS)
	fd, err := landlock.NewRulesetFD(t.Kernel().VFS(), ruleset)
	if err != nil {
		return 0, nil, err
	}
	defer fd.DecRef(t)

	newFD, err := t.NewFDFrom(0, fd, kernel.FDFlags{
		CloseOnExec: true, // Landlock FDs are close-on-exec by default
	})
	if err != nil {
		return 0, nil, err
	}

	return uintptr(newFD), nil, nil
}

// LandlockAddRule implements linux syscall landlock_add_rule(2).
// Matches Linux security/landlock/syscalls.c:sys_landlock_add_rule
func LandlockAddRule(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	ruleType := args[1].Int()
	ruleAttrAddr := args[2].Pointer()
	flags := args[3].Uint()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	if ruleType != linux.LANDLOCK_RULE_PATH_BENEATH {
		return 0, nil, linuxerr.EINVAL
	}

	// Retrieve Ruleset from rulesetFD.
	rulesetFile := t.GetFile(rulesetFD)
	if rulesetFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer rulesetFile.DecRef(t)

	ruleset, err := landlock.GetRulesetFromFD(rulesetFile)
	if err != nil {
		return 0, nil, err
	}

	if !rulesetFile.IsWritable() {
		return 0, nil, linuxerr.EPERM
	}

	var attr linux.LandlockPathBeneathAttr
	if _, err := attr.CopyIn(t, ruleAttrAddr); err != nil {
		return 0, nil, err
	}

	// Matches Linux security/landlock/syscalls.c:add_rule_path_beneath() allowed_access check.
	// This validation must happen before resolving the parent FD.
	allowedAccess := attr.GetAllowedAccess()
	if allowedAccess == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if (allowedAccess | ruleset.HandledAccessFS()) != ruleset.HandledAccessFS() {
		return 0, nil, linuxerr.EINVAL
	}

	// Get target dentry from ParentFD.
	parentFile := t.GetFile(attr.ParentFD)
	if parentFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer parentFile.DecRef(t)

	// Matches Linux security/landlock/syscalls.c:get_path_from_fd() ruleset FD check.
	// We cannot use a Landlock ruleset FD as the parent for a rule.
	if _, err := landlock.GetRulesetFromFD(parentFile); err == nil {
		return 0, nil, linuxerr.EBADFD
	}

	parentVD := parentFile.VirtualDentry()

	// Matches Linux security/landlock/syscalls.c:get_path_from_fd() internal filesystems check.
	if parentVD.Mount().NeverConnected() {
		return 0, nil, linuxerr.EBADFD
	}

	// Add rule to ruleset.
	if err := ruleset.AddRule(parentVD.Dentry(), allowedAccess); err != nil {
		return 0, nil, err
	}

	return 0, nil, nil
}

// LandlockRestrictSelf implements linux syscall landlock_restrict_self(2).
// Matches Linux security/landlock/syscalls.c:sys_landlock_restrict_self
func LandlockRestrictSelf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rulesetFD := args[0].Int()
	flags := args[1].Uint()

	// Matches Linux security/landlock/syscalls.c:sys_landlock_restrict_self() flags check.
	if flags&^linux.LANDLOCK_MASK_RESTRICT_SELF != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Check no_new_privs or CAP_SYS_ADMIN in user namespace.
	if !t.GetNoNewPrivs() && !t.Credentials().HasCapabilityIn(linux.CAP_SYS_ADMIN, t.UserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}

	// Matches Linux security/landlock/syscalls.c:sys_landlock_restrict_self() ruleset_fd check.
	var rulesetFile *vfs.FileDescription
	if !(rulesetFD == -1 && flags == linux.LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF) {
		rulesetFile = t.GetFile(rulesetFD)
		if rulesetFile == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer rulesetFile.DecRef(t)
	}

	if rulesetFile == nil {
		// This is the special case where we only modify logging flags (which we ignore).
		// Omit creds fork as we don't implement audit logging.
		return 0, nil, nil
	}

	ruleset, err := landlock.GetRulesetFromFD(rulesetFile)
	if err != nil {
		return 0, nil, err
	}

	if !rulesetFile.IsReadable() {
		return 0, nil, linuxerr.EPERM
	}

	// 1. Validate domain stacking limit before forking.
	oldCreds := t.Credentials()
	if oldCreds.Security != nil {
		oldDomain, ok := oldCreds.Security.(*landlock.Domain)
		if !ok {
			return 0, nil, linuxerr.EPERM
		}
		// Matches Linux security/landlock/ruleset.c:landlock_merge_ruleset()
		// which returns E2BIG if parent domain layers exceed the limit.
		if oldDomain.NumLayers() >= linux.LANDLOCK_MAX_NUM_LAYERS {
			return 0, nil, linuxerr.E2BIG
		}
	}

	// 2. Freeze the ruleset only after we know validation succeeded.
	frozenRuleset := ruleset.Freeze()

	// 3. Fork credentials.
	creds := t.Credentials().Fork()

	var newDomain *landlock.Domain
	if creds.Security == nil {
		newDomain = landlock.NewDomain([]*landlock.Ruleset{frozenRuleset})
	} else {
		// Safe to cast directly as we verified the type above.
		oldDomain := creds.Security.(*landlock.Domain)
		newDomain = oldDomain.Merge(frozenRuleset)
		oldDomain.DecRef(t) // Release the reference inherited from Fork.
	}

	creds.Security = newDomain
	t.UpdateCredentials(creds)
	return 0, nil, nil
}
