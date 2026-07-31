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

// Matches Linux include/uapi/linux/landlock.h

// Flags for sys_landlock_create_ruleset.
const (
	LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
)

// Rule types for sys_landlock_add_rule.
const (
	LANDLOCK_RULE_PATH_BENEATH = 1
)

// Filesystem access rights for Landlock ABI v1.
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

	// LANDLOCK_MASK_ACCESS_FS covers all ABI v1 access rights (bits 0..12).
	LANDLOCK_MASK_ACCESS_FS = (1 << 13) - 1

	// LANDLOCK_MASK_ACCESS_FS_FILE covers access rights applicable to non-directory files.
	// Matches Linux [security/landlock/fs.c]:LANDLOCK_ACCESS_FS_INITIALLY_FILE
	LANDLOCK_MASK_ACCESS_FS_FILE = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE
)

// Limits.
const (
	LANDLOCK_MAX_NUM_LAYERS = 16
	LANDLOCK_MAX_NUM_RULES  = (1 << 16) - 1
)

// LandlockRulesetAttr identifies the scope of a new ruleset.
// Matches Linux struct landlock_ruleset_attr in include/uapi/linux/landlock.h.
//
// +marshal
// +stateify savable
type LandlockRulesetAttr struct {
	HandledAccessFS uint64
}

// LandlockPathBeneathAttr identifies a path beneath rule.
// Matches Linux struct landlock_path_beneath_attr in include/uapi/linux/landlock.h.
//
// +marshal
// +stateify savable
type LandlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
}
