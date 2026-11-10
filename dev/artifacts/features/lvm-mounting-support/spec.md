---
slug: lvm-mounting-support
issue: https://github.com/openrelik/openrelik/issues/40
created: 2026-11-10
by: hacktobeer (Ramses de Beer)
---
# Spec: Add LVM2 mounting support

Implements idea.md (#40).

## Scope

- Detect LVM2 physical volumes on a whole disk and on partitions in `BlockDevice`,
  and mount the logical volumes with a supported filesystem.
- Activate volume groups read-only, track them, and deactivate them on cleanup so
  the underlying loop/NBD device can be detached.
- Skip logical volumes without a filesystem signature instead of failing.
- Distinguish "no filesystem on an existing device" from other `blkid` failures.
- Install the `lvm2` package in the worker images that mount disk images.
- Out of scope: reading LVM2 metadata directly (no kernel device state), encrypted
  or thin-provisioned LVM layouts, and mounting filesystems not already in
  `supported_fstypes`.

## Requirements

- R1: A whole-disk LVM2 physical volume (raw or QCOW2) is detected, its volume
  group activated, and its supported logical volumes mounted read-only.
- R2: An LVM2 physical volume on a partition is detected, its volume group
  activated, and its supported logical volumes mounted read-only.
- R3: A logical volume without a filesystem signature is skipped with a warning;
  the remaining supported logical volumes are still mounted.
- R4: `blkid` returning exit code 2 for an existing device raises
  `NoFilesystemError`, while exit code 2 for a missing device raises a plain
  `RuntimeError`.
- R5: LVM logical volumes are mounted with the same read-only options as the
  existing mount path, and the source image is not written to.
- R6: `umount()` deactivates all activated volume groups before detaching the
  block device, and a failed `setup()` unwinds any activated volume groups, block
  device, EWF mount, and Redis lock.
- R7: Worker images that mount disk images install `lvm2` so `pvs`, `lvs` and
  `vgchange` are available.
- R8: Failures from `pvs`, `lvs` and `vgchange` propagate as `RuntimeError` with
  the failing command context.

## Tasks

- [x] T1: Add `NoFilesystemError` and change `_get_fstype()` to raise it only when
  `blkid` exits 2 for an existing device, in
  `libs/worker-common/openrelik_worker_common/mount_utils.py` (R4).
- [x] T2: Add the LVM helpers `_is_lvm2_member`, `_required_lvm_tools_available`,
  `_get_vg_name`, `_activate_volume_group`, `_get_logical_volumes`,
  `_get_lvm_mount_targets`, and `_deactivate_volume_groups` in
  `mount_utils.py` (R1, R2, R3, R6, R8).
- [x] T3: Wire LVM detection into `_parse_partitions()` for the whole-disk and
  per-partition cases, probing LVM only on partitions at least
  `min_partition_size` (R1, R2, R3).
- [x] T4: Deactivate volume groups in `umount()` before detaching the block
  device, and extend `setup()`'s failure path to clean up partial activation,
  the block device, the EWF mount, and the Redis lock (R5, R6).
- [x] T5: Add `lvm2` to the worker Dockerfiles that mount disk images:
  `workers/analyzer-logs/Dockerfile`, `workers/containers/Dockerfile`,
  `workers/extraction/Dockerfile`, `workers/yara/Dockerfile` (R7).
- [x] T6: Add unit and integration tests and synthetic LVM test images
  (`image_lvm_whole_ext4.img`, `image_lvm_partition_ext4.img`,
  `image_lvm_whole_ext4.qcow2`) in `libs/worker-common/tests/test_mount_utils.py`
  and `libs/worker-common/test_data/` (R1, R2, R3, R4, R6, R8).

## Tests

- R1: `test_MountLVMWholeDiskExt4` and `test_MountLVMWholeDiskQcow2` mount a
  whole-disk LVM image and assert the logical volume's files are reachable.
- R2: `test_MountLVMPartitionExt4` mounts a partition PV and asserts the logical
  volume's files are reachable.
- R3: `test_MountLVM2MemberUnformattedLV` and
  `test_GetLvmMountTargetsIgnoresUnformattedLogicalVolume` activate the VG and
  assert the unformatted LV is skipped without error.
- R4: `test_GetFsTypeNoFilesystem` and
  `test_GetFsTypeMissingDeviceIsNotNoFilesystemError` cover the exit-code-2
  distinction.
- R6: `test_DeactivateVolumeGroups`, the LVM mount tests' `umount()` assertions,
  and the EWF setup-cleanup tests cover VG deactivation and failure unwinding.
- R8: `test_GetVgNameError`, `test_ActivateVolumeGroupError`,
  `test_GetLogicalVolumesError`, `test_DeactivateVolumeGroupsError`, and
  `test_GetLvmMountTargetsPropagatesUnexpectedErrors` assert error propagation.
- `test_IsLvm2Member`, `test_RequiredLvmToolsAvailable_*`,
  `test_GetVgName`, `test_ActivateVolumeGroup`, `test_GetLogicalVolumes`, and
  `test_ParsePartitionsSkipsLvmProbeForSmallPartitions` cover the helpers.

## Rollout

Worker images that mount disk images are rebuilt with the `lvm2` package; no
database migration or server configuration change. The `BlockDevice` docstring
notes the `lvm2` requirement for the container.
