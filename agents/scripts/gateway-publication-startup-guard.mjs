// Loaded through NODE_OPTIONS on every Gateway Node startup, including Docker restart.
// Standalone: does not alter the Gateway image, command, credentials or records.
import fs from 'node:fs';
export function validateStartup(stat,stats,entries,env,uid,gid) {
  const target='/run/gateway-publications', bytes=env.GATEWAY_PUBLICATION_CAPACITY_BYTES;
  const fail=()=>{throw Error('bounded Gateway publication mount required');};
  if(uid!==1000||gid!==1000||env.GATEWAY_PUBLICATION_RECORDS_DIRECTORY!==target || !/^[1-9][0-9]*$/.test(bytes??''))fail();
  const capacity=BigInt(bytes), size=BigInt(stats.bsize)*BigInt(stats.blocks);
  if(capacity<67108864n||capacity>68719476736n||capacity%4096n||BigInt(stats.type)!==0xef53n||size>capacity||size<capacity*3n/4n)fail();
  if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==1000||stat.gid!==1000||(stat.mode&0o7777)!==0o700)fail();
  const mounts=entries.filter(line=>line.split(' ')[4]===target);
  if(mounts.length!==1)fail();
  const [left,right]=mounts[0].split(' - '), fields=left.split(' '), fsfields=right?.split(' ');
  if(fields[3]!=='/'||fsfields?.[0]!=='ext4'||!/^\/dev\/loop[0-9]+$/.test(fsfields[1])||!['rw','nosuid','nodev'].every(f=>fields[5].split(',').includes(f)))fail();
}
if(process.env.GATEWAY_PUBLICATION_STARTUP_GUARD==='1') {
  try {
    validateStartup(fs.lstatSync('/run/gateway-publications'),fs.statfsSync('/run/gateway-publications',{bigint:true}),fs.readFileSync('/proc/self/mountinfo','utf8').trim().split('\n'),process.env,process.getuid(),process.getgid());
  } catch { console.error('Gateway startup blocked: bounded publication mount unavailable; retain all records'); process.exit(1); }
}
