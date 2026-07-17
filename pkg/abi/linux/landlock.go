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

import "structs"

// Landlock syscall flags.
const (
	LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
)

// Landlock rule types.
const (
	LANDLOCK_RULE_PATH_BENEATH = 1
)

// Landlock access rights for filesystem.
const (
	LANDLOCK_ACCESS_FS_EXECUTE     = 1 << 0
	LANDLOCK_ACCESS_FS_WRITE_FILE  = 1 << 1
	LANDLOCK_ACCESS_FS_READ_FILE   = 1 << 2
	LANDLOCK_ACCESS_FS_READ_DIR    = 1 << 3
	LANDLOCK_ACCESS_FS_REMOVE_DIR  = 1 << 4
	LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
	LANDLOCK_ACCESS_FS_MAKE_CHAR   = 1 << 6
	LANDLOCK_ACCESS_FS_MAKE_DIR    = 1 << 7
	LANDLOCK_ACCESS_FS_MAKE_REG    = 1 << 8
	LANDLOCK_ACCESS_FS_MAKE_SOCK   = 1 << 9
	LANDLOCK_ACCESS_FS_MAKE_FIFO   = 1 << 10
	LANDLOCK_ACCESS_FS_MAKE_BLOCK  = 1 << 11
	LANDLOCK_ACCESS_FS_MAKE_SYM    = 1 << 12
	LANDLOCK_ACCESS_FS_REFER       = 1 << 13
	LANDLOCK_ACCESS_FS_TRUNCATE    = 1 << 14
	LANDLOCK_ACCESS_FS_IOCTL_DEV   = 1 << 15
)

// Landlock limits.
const (
	// LANDLOCK_MAX_NUM_LAYERS is the maximum number of stacked Landlock domains.
	LANDLOCK_MAX_NUM_LAYERS = 16
)

// Landlock access masks.
const (
	// LANDLOCK_MASK_ACCESS_FS_V1 is the mask of all FS access rights supported in ABI v1.
	LANDLOCK_MASK_ACCESS_FS_V1 = 0x1fff

	// LANDLOCK_ACCESS_FS_FILE is the mask of FS access rights that can be applied to a regular file.
	LANDLOCK_ACCESS_FS_FILE = LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_TRUNCATE |
		LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// LandlockRulesetAttr identifies the scope of a new ruleset.
// It corresponds to struct landlock_ruleset_attr in Linux.
//
// Matches Linux include/uapi/linux/landlock.h:landlock_ruleset_attr
//
// +marshal
type LandlockRulesetAttr struct {
	_                structs.HostLayout
	HandledAccessFS  uint64
	HandledAccessNet uint64
	Scoped           uint64
}

// LandlockPathBeneathAttr identifies a path beneath rule.
// It corresponds to struct landlock_path_beneath_attr in Linux.
//
// Matches Linux include/uapi/linux/landlock.h:landlock_path_beneath_attr
//
// +marshal
type LandlockPathBeneathAttr struct {
	_             structs.HostLayout
	AllowedAccess [2]uint32
	ParentFD      int32
}
