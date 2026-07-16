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

// Landlock constants.
const (
	LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
)

// Rule types.
const (
	LANDLOCK_RULE_PATH_BENEATH = 1
)

// Filesystem access rights.
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
)

// LANDLOCK_MASK_ACCESS_FS is the mask of all FS access rights supported in ABI v1.
const LANDLOCK_MASK_ACCESS_FS = (1 << 13) - 1

// LandlockRulesetAttr matches struct landlock_ruleset_attr for ABI v1.
//
// +marshal
type LandlockRulesetAttr struct {
	_               structs.HostLayout
	HandledAccessFS uint64
}

// LandlockPathBeneathAttr matches struct landlock_path_beneath_attr.
// It is packed in C, so we marshal/unmarshal it manually to avoid padding.
type LandlockPathBeneathAttr struct {
	AllowedAccess uint64
	ParentFd      int32
}
