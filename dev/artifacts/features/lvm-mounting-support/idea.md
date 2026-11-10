---
slug: lvm-mounting-support
issue: https://github.com/openrelik/openrelik/issues/40
created: 2026-11-10
by: hacktobeer (Ramses de Beer)
---
# Add LVM2 mounting support

## Problem

Linux disk images often use LVM2. The physical volumes appear as `LVM2_member`
devices, either as the whole disk or as a partition, and the actual filesystems
live on logical volumes inside a volume group. `BlockDevice` in
`libs/worker-common/openrelik_worker_common/mount_utils.py` only mounts
filesystems it recognises on partitions, so an LVM2 physical volume is treated as
unsupported and the analyst gets nothing back from an otherwise mountable image.
They have to recover the files by hand outside OpenRelik.

## Proposal

Extend `BlockDevice` to recognise LVM2 physical volumes, activate their volume
groups, enumerate the logical volumes, and mount the ones with a supported
filesystem read-only. Add the `lvm2` package to the worker images that mount disk
images, and cover the behaviour with synthetic LVM test images and tests.

## Users

Forensic analysts processing Linux disk images (raw, QCOW2 and EWF) through the
workers that mount filesystems, such as extraction, YARA, analyzer-logs and
containers.

## Open questions

- None.
