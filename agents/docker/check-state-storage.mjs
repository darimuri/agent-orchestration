#!/usr/bin/env node
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

// statfs covers the backing filesystem, not du/free space in a host directory.
export function validateStateStorage(stats, bytes) {
  if (!/^[1-9][0-9]*$/.test(bytes)) throw new Error('invalid capacity');
  const capacity = BigInt(bytes);
  if (capacity < 64n * 1024n ** 2n || capacity > 64n * 1024n ** 3n || capacity % 4096n !== 0n)
    throw new Error('invalid capacity');
  const size = BigInt(stats.bsize) * BigInt(stats.blocks);
  if (BigInt(stats.type) !== 0xef53n || size > capacity || size < capacity * 3n / 4n)
    throw new Error('bounded ext4 storage required');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    validateStateStorage(fs.statfsSync(process.argv[2], { bigint: true }), process.argv[3]);
  } catch {
    console.error('state-storage: HOME filesystem type/capacity check failed');
    process.exitCode = 1;
  }
}
