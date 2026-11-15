#!/usr/bin/python3
"""Owner fixture recorder. NEW instrumentation; internal driver execs UNOBSERVED.

No response expansion, shell, PATH tool selection, compiler flags or retries.
The read-only control manifest is the only authority for roles and executables.
"""
import base64
import hashlib
import json
import os
import queue
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

SCHEMA = 'buzz.approval-capture/v1'
ENV_KEYS = {'PATH', 'LANG', 'LC_ALL', 'TZ', 'SOURCE_DATE_EPOCH', 'CC', 'CXX', 'LINK'}
FIXED_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
             'SOURCE_DATE_EPOCH': '0', 'CC': '/control/cc', 'CXX': '/control/cxx', 'LINK': '/control/link'}
CEILINGS = {'args': 10000, 'argvBytes': 1048576, 'responseFile': 1048576,
            'responseTotal': 16777216, 'stream': 67108864, 'text': 134217728,
            'seconds': 30, 'records': 20000}


class Blocked(Exception):
    pass


class Relay:
    """One bounded writer per caller stream, with no shared-fd flag changes.

    A slow stdout cannot block stderr draining. At most eight 64KiB chunks per
    stream are queued (plus one in-flight write). The supervising read loop owns
    the deadline; stuck daemon writers cannot prevent an incomplete process exit.
    """
    def __init__(self, caller_fd):
        self.fd = os.dup(caller_fd)
        self.queue = queue.Queue(maxsize=8)
        self.stopped = threading.Event()
        self.error = None
        self.bytes = 0
        self.hash = hashlib.sha256()
        self.thread = threading.Thread(target=self.write, daemon=True)
        self.thread.start()

    def write(self):
        try:
            while True:
                chunk = self.queue.get()
                try:
                    if chunk is None:
                        return
                    view = memoryview(chunk)
                    while view:
                        require(not self.stopped.is_set(), 'relay stopped')
                        try:
                            n = os.write(self.fd, view)
                        except BlockingIOError:
                            self.stopped.wait(0.01)
                            continue
                        require(n > 0, 'relay short write')
                        self.bytes += n
                        self.hash.update(view[:n])
                        view = view[n:]
                finally:
                    self.queue.task_done()
        except Exception as exc:
            self.error = exc
        finally:
            os.close(self.fd)

    def pending(self):
        with self.queue.all_tasks_done:
            return self.queue.unfinished_tasks

    def finish(self, deadline):
        require(not self.pending() and self.error is None, 'relay not drained')
        self.queue.put_nowait(None)
        self.thread.join(max(0, deadline - time.monotonic()))
        require(not self.thread.is_alive() and self.error is None, 'relay completion deadline/error')


def require(ok, message):
    if not ok:
        raise Blocked(message)


def b64(value):
    return base64.b64encode(value).decode('ascii')


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def canonical(p):
    require(os.path.isabs(p) and os.path.realpath(p) == p, 'noncanonical path')
    return p


def snapshot(p, limit):
    """Retain bytes from one O_NOFOLLOW descriptor, never normalize inputs."""
    canonical(p)
    before = os.lstat(p)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'nonordinary supplied file')
    require(before.st_size <= limit, 'input bound')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(identity(os.fstat(fd)) == identity(before), 'input replaced before open')
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            require(total <= limit, 'input overflow')
            chunks.append(chunk)
        data = b''.join(chunks)
        require(len(data) == before.st_size, 'input size changed')
        require(identity(os.fstat(fd)) == identity(before) == identity(os.lstat(p)), 'input mutated')
        return data, {'pathBase64': b64(os.fsencode(p)), 'identity': list(identity(before)),
                      'sha256': hashlib.sha256(data).hexdigest(), 'size': total}
    finally:
        os.close(fd)


def unchanged(record):
    p = os.fsdecode(base64.b64decode(record['pathBase64'], validate=True))
    data, current = snapshot(p, max(record['size'], 1))
    require(current == record, 'input identity or bytes changed during capture')


def syncdir(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable(p, data):
    """Exclusive temp + fsync + exclusive final hardlink + directory fsync."""
    tmp = p + '.tmp-' + uuid.uuid4().hex
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            require(n > 0, 'short evidence write')
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(tmp, p, follow_symlinks=False)  # Never replaces an existing record.
    finally:
        os.unlink(tmp)
    syncdir(os.path.dirname(p))


# Admission-only native policy. No native tool, make or Docker launch is exposed.
NATIVE_PURPOSE = 'owner-nodev8-prerequisite-measurement/v1'
NATIVE_POLICY = json.loads(r'''{
  "infrastructureBase": "2630a768e0617a6599376d7a92baf663a689d337",
  "infrastructureTree": "d3e1fde2b2599df0e15d99d86a9517ced0120f17",
  "approvalSource": "1312e7a9dec6fac055b61993c145be7f6847e216",
  "approvalTree": "3868efaef2c500a13d2bde30cd645d5aa372ab59",
  "archiveSha256": "a7f6204ff63b6a2cd274d48903285abb86ed53a99070e532d4c2fd787457d9e6",
  "lockSha256": "0dbfd0064f4afbd32ceef751d3d1b75685f8a511cd50d394b21232d02ff29307",
  "sourceAdmissionSha256": "62c5eb0af7c71d8d21838f3442433e8ca16b9350ff6edd5f54332157446bb63d",
  "contextSha256": "a76bd9260f09bfd877a07e28a056e90ee82ce2cac8d5e09a223a71ca95bcd5f0",
  "graphReportSha256": "d5cf17ce74fa607abe246e3b4e88438d081d757b6193a9f6e0274cbfb7c56276",
  "decisionSha256": "34c7e4affc4cf8cc53c95e864f5ae020c69f7c4f2909f81749f4f214701e278c",
  "correctionSha256": "ed137291897adfbd9887191f01fbd1cd5f9eca382f2fc5dd06a0453eed664a8d",
  "repository": "127.0.0.1:5007/age20/approval-builder@sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31",
  "b0Sha256": "f6a2b2cf5781a8a4bbd6ab13c3fd11566c3448c7123cc30ed095fc19f2378e7d",
  "manifestDigest": "sha256:b2ed7cea3b936b4054afd8157944dffc0110ae61988b3644716ddaef5214ed31",
  "imageId": "sha256:4088bab6dd858541a6ef1702ef856faf485a8052f06cc997003f14383fd1aa06",
  "platform": "linux/amd64",
  "goal": "Release/obj.target/v8_base_without_compiler/deps/v8/src/wasm/wasm-disassembler.o",
  "jobs": 1,
  "actionMaximum": 256,
  "deadlines": {
    "workload": 1500,
    "cc": 300,
    "cxx": 300,
    "generator": 120,
    "link": 120,
    "admission": 120
  },
  "resources": {
    "cpus": 2,
    "memory": 8589934592,
    "pids": 256,
    "seconds": 1800,
    "work": 17179869184,
    "output": 2147483648,
    "stream": 67108864,
    "text": 134217728
  }
}''')


def native_keys(value, expected, reason):
    require(isinstance(value, dict), reason+': object required')
    require(set(value) == set(expected), reason+': missing='+','.join(sorted(set(expected)-set(value)))+' unexpected='+','.join(sorted(set(value)-set(expected))))


def native_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def native_metadata(m):
    p = NATIVE_POLICY
    require(m.get('schema') == SCHEMA and m.get('purpose') == NATIVE_PURPOSE, 'native purpose/version')
    n = m.get('native')
    native_keys(n, ['identity', 'goal', 'jobs', 'command', 'deadlines', 'taskCount', 'evidence'], 'native profile keys')
    expected = {k: v for k, v in p.items() if k not in {'goal', 'jobs', 'actionMaximum', 'deadlines', 'resources'}}
    require(n['identity'] == expected, 'native immutable identity tuple')
    require(n['goal'] == p['goal'] and type(n['jobs']) is int and n['jobs'] == 1 and n['command'] == [
        '/usr/bin/make', '-C', '/work/node/out', 'BUILDTYPE=Release', 'V=1', '-j1', p['goal']], 'native fixed goal/-j1 command')
    resources = m.get('resources')
    native_keys(resources, p['resources'], 'native resource keys')
    for key, ceiling in p['resources'].items():
        require(type(resources[key]) is int and 0 < resources[key] <= ceiling, 'native resource '+key)
    require(resources['cpus'] == 2 and resources['memory'] == 8589934592 and resources['pids'] == 256, 'native CPU/RAM/pids identity')
    native_keys(n['deadlines'], p['deadlines'], 'native deadlines')
    for key, ceiling in p['deadlines'].items():
        require(type(n['deadlines'][key]) is int and 0 < n['deadlines'][key] <= min(ceiling, resources['seconds']), 'native stage deadline')
    require(type(n['taskCount']) is int and 0 < n['taskCount'] <= 256, 'native exact action count')
    native_keys(n['evidence'], ['b0', 'allowlist', 'lock', 'archive', 'tools', 'context', 'sourceAdmission', 'graphReport', 'decision', 'correction'], 'native evidence keys')
    for key, ref in n['evidence'].items():
        native_keys(ref, ['path', 'sha256'], 'native evidence reference')
        require(isinstance(ref['path'], str) and os.path.isabs(ref['path']) and os.path.normpath(ref['path']) == ref['path'] and native_sha(ref['sha256']), 'native evidence path/hash')
    for key, pin in [('b0', 'b0Sha256'), ('lock', 'lockSha256'), ('archive', 'archiveSha256'), ('context', 'contextSha256'), ('sourceAdmission', 'sourceAdmissionSha256'), ('graphReport', 'graphReportSha256'), ('decision', 'decisionSha256'), ('correction', 'correctionSha256')]:
        require(n['evidence'][key]['sha256'] == p[pin], 'native frozen evidence '+key)
    require('fixtureArgvBase64' not in m, 'native rejects fixture argv')
    require(m.get('environment') == FIXED_ENV and m.get('work') == '/work' and m.get('output') == '/output', 'native fixed environment/roots')
    native_keys(m['roles'], ['cc', 'cxx', 'link', 'generator', 'workload'], 'native role set')
    for tool in m['roles'].values():
        native_keys(tool, ['path', 'sha256'], 'native tool keys')
        require(isinstance(tool['path'], str) and re.fullmatch(r'/usr/[A-Za-z0-9_+./-]+', tool['path']) is not None and os.path.normpath(tool['path']) == tool['path'] and native_sha(tool['sha256']), 'native canonical tool/hash')
    require(m['roles']['workload']['path'] == '/usr/bin/make', 'native fixed make tool')
    native_keys(m['limits'], CEILINGS, 'native recorder limits')
    for key, ceiling in CEILINGS.items():
        cap = n['deadlines']['workload'] if key == 'seconds' else ceiling
        require(type(m['limits'][key]) is int and 0 < m['limits'][key] <= cap, 'native recorder bound')
    require(m['limits']['seconds'] == n['deadlines']['workload'] and m['limits']['records'] >= n['taskCount'] + 1, 'native task/record/workload bound')
    require(m['limits']['stream'] <= resources['stream'] and m['limits']['text'] <= resources['text'], 'native stream resource mapping')
    return m


def native_actions(doc, m):
    n = m['native']
    native_keys(doc, ['schema', 'b0Sha256', 'goal', 'taskCount', 'actions', 'unresolved', 'context'], 'supplemental action schema')
    require(doc['schema'] == 'buzz.native-microtarget-actions/v1' and doc['b0Sha256'] == NATIVE_POLICY['b0Sha256'] and doc['goal'] == NATIVE_POLICY['goal'], 'supplemental B0/goal binding')
    require(doc['unresolved'] == [], 'STOP_UNRESOLVED_TRANSITIVE_CLOSURE')
    require(type(doc['taskCount']) is int and doc['taskCount'] == n['taskCount'] and isinstance(doc['actions'], list) and len(doc['actions']) == n['taskCount'], 'supplemental exact task count')
    def work_path(p):
        return isinstance(p, str) and p.startswith('/work/node/') and os.path.normpath(p) == p and '$' not in p
    require(isinstance(doc['context'], list) and 0 < len(doc['context']) <= 20000 and all(isinstance(f, dict) and work_path(f.get('path')) and native_sha(f.get('sha256')) for f in doc['context']), 'supplemental retained context hashes')
    require(len({f['path'] for f in doc['context']}) == len(doc['context']), 'duplicate context path')
    seen, outputs = set(), set()
    for a in doc['actions']:
        native_keys(a, ['id', 'role', 'tool', 'argvBase64', 'cwd', 'inputs', 'outputs', 'dependencies', 'orderOnly', 'ruleSha256', 'seconds'], 'supplemental action keys')
        require(isinstance(a['id'], str) and 0 < len(a['id']) <= 64 and a['id'][0] in 'abcdefghijklmnopqrstuvwxyz' and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in a['id']) and a['id'] not in seen, 'unique action ID')
        require(a['role'] in {'cc', 'cxx', 'generator', 'link'}, 'STOP_UNLISTED_ACTION_TYPE')
        require(a['tool'] == m['roles'][a['role']] and native_sha(a['ruleSha256']) and any(f['sha256'] == a['ruleSha256'] for f in doc['context']), 'action tool/rule identity')
        require(type(a['seconds']) is int and 0 < a['seconds'] <= n['deadlines'][a['role']], 'action deadline')
        require(work_path(a['cwd']) and isinstance(a['argvBase64'], list) and 0 < len(a['argvBase64']) <= 10000, 'action cwd/argv')
        args = [base64.b64decode(v, validate=True) for v in a['argvBase64']]
        require(all(b64(v) == text and bytes([0]) not in v and bytes([36]) not in v for v, text in zip(args, a['argvBase64'])) and sum(len(v)+1 for v in args) <= 1048576, 'action canonical argv bound')
        require(args[0] == os.fsencode(a['tool']['path']), 'action executable argv0')
        require(isinstance(a['inputs'], list) and 0 < len(a['inputs']) <= 10000, 'action inputs')
        for item in a['inputs']:
            native_keys(item, ['path', 'sha256'], 'action input')
            require(work_path(item['path']) and native_sha(item['sha256']) and item in doc['context'], 'action input/context hash')
        require(isinstance(a['outputs'], list) and 0 < len(a['outputs']) <= 10000, 'action outputs')
        for out in a['outputs']:
            require(work_path(out) and out not in outputs and not any(x == 'mksnapshot' or x.startswith('mksnapshot.') for x in out.split('/')), 'no duplicate/mksnapshot output')
            outputs.add(out)
        for deps in [a['dependencies'], a['orderOnly']]:
            require(isinstance(deps, list) and len(set(deps)) == len(deps) and all(d in seen for d in deps), 'missing/unresolved/transitive edge or cycle')
        seen.add(a['id'])
    terminal = next((a for a in doc['actions'] if '/work/node/out/'+NATIVE_POLICY['goal'] in a['outputs']), None)
    require(terminal is not None, 'missing fixed object output')
    closure = set()
    def visit(action):
        if action['id'] in closure:
            return
        closure.add(action['id'])
        for dep in action['dependencies'] + action['orderOnly']:
            visit(next(a for a in doc['actions'] if a['id'] == dep))
    visit(terminal)
    require(len(closure) == len(doc['actions']), 'extraneous action outside fixed goal closure')
    return doc


def native_admission(m):
    """Returns STOP even with complete synthetic data; never starts a child."""
    reason, detail = 'STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED', 'No reviewed descendant/action-boundary enforcement'
    try:
        native_metadata(m)
        raw = {}
        for key, ref in m['native']['evidence'].items():
            raw[key], item = snapshot(ref['path'], 536870912 if key == 'archive' else 67108864)
            require(item['sha256'] == ref['sha256'], 'native raw evidence hash '+key)
        b0, lock, tools = (json.loads(raw[key]) for key in ['b0', 'lock', 'tools'])
        require(b0.get('schema') == 'darimuri.age20.solution2-b0-closure/v1' and b0.get('goal') == NATIVE_POLICY['goal'] and b0.get('classification') == 'NEW_REPRODUCTION_NOT_RECOVERED_R2' and b0.get('status') == 'B0_READ_ONLY_CLOSURE_COMPLETE_NATIVE_EXECUTION_BLOCKED', 'native B0 dossier')
        p = NATIVE_POLICY
        require(lock.get('nodeVersion') == '26.13.1' and lock.get('nodeSourceSha256') == p['archiveSha256'] and lock.get('builderImage') == p['repository'] and lock.get('platform') == p['platform'] and lock.get('gccVersion') == '13.3.0' and lock.get('target') == {'commit': p['approvalSource'], 'tree': p['approvalTree']}, 'native lock tuple')
        require(isinstance(lock.get('packages'), dict) and len(lock['packages']) == 200 and tools.get('packages') == lock['packages'] and tools.get('gccVersion') == '13.3.0' and tools.get('toolchain') == 'gcc-13.3.0;x86_64-linux-gnu;python-3.12.3;make-4.3' and isinstance(tools.get('records'), list), 'native package/tool inventory')
        require(all(any(t.get('realpath') == tool['path'] and t.get('sha256') == tool['sha256'] for t in tools['records']) for tool in m['roles'].values()), 'native missing canonical tool hash')
        native_actions(json.loads(raw['allowlist']), m)
    except Exception as exc:
        reason, detail = 'STOP_NATIVE_ADMISSION', str(exc)
    return {'schema': SCHEMA, 'purpose': NATIVE_PURPOSE, 'status': reason, 'blocker': detail,
            'nativeExecution': 'NOT_STARTED', 'capture': 'NOT_STARTED', 'qualification': 'NOT_EVALUATED',
            'R1': 'INCOMPLETE', 'R2': 'BLOCKED', 'internalCollect2LdArgv': 'UNOBSERVED', 'nodeFidelity': 'NOT_PROVEN'}


def manifest(p):
    raw, evidence = snapshot(canonical(p), 1048576)
    m = json.loads(raw)
    require(m.get('schema') == SCHEMA, 'manifest schema')
    if m.get('purpose') == NATIVE_PURPOSE:
        return native_metadata(m), evidence
    require(set(m['limits']) == set(CEILINGS), 'limit keys')
    for k, cap in CEILINGS.items():
        require(type(m['limits'][k]) is int and 0 < m['limits'][k] <= cap, 'limit '+k)
    require(m['environment'] == FIXED_ENV, 'environment allowlist/value mismatch')
    require(set(m['roles']) == {'cc', 'cxx', 'link', 'workload'}, 'fixed roles')
    require(m.get('purpose') == 'owner-synthetic-fixture', 'fixture authority only')
    require(canonical(m['work']) == '/work' and canonical(m['output']) == '/output', 'container roots')
    for role, tool in m['roles'].items():
        canonical(tool['path'])
        require(tool['path'].startswith('/usr/'), 'real system tool required')
        require(isinstance(tool['sha256'], str) and len(tool['sha256']) == 64 and
                all(c in '0123456789abcdef' for c in tool['sha256']), 'tool digest')
    return m, evidence


def tool_identity(tool):
    # Installed tools may have multiple hardlinks; supplied evidence may not.
    p = canonical(tool['path'])
    before = os.stat(p, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_mode & 0o111, 'tool not executable')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(identity(os.fstat(fd)) == identity(before), 'tool replaced')
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        require(identity(os.fstat(fd)) == identity(before) == identity(os.stat(p)), 'tool mutated')
        require(digest.hexdigest() == tool['sha256'], 'tool hash mismatch')
        return {'path': p, 'sha256': digest.hexdigest(), 'identity': list(identity(before))}
    finally:
        os.close(fd)


def response_snapshots(args, cwd, limits, record_dir, work='/work'):
    result, total = [], 0
    for position, arg in enumerate(args):
        if b'@' not in arg:
            continue
        require(arg.startswith(b'@') and arg.count(b'@') == 1 and len(arg) > 1,
                'unsupported response transport')
        received = os.fsdecode(arg[1:])
        # No aliases/traversal; resolving a path never silently rewrites forwarded argv.
        require(all(x not in ('', '.', '..') for x in received.lstrip('/').split('/')), 'response alias')
        p = received if os.path.isabs(received) else os.path.join(cwd, received)
        canonical(p)
        require(p.startswith(work+'/'), 'response outside work')
        data, item = snapshot(p, limits['responseFile'])
        total += len(data)
        require(total <= limits['responseTotal'], 'response aggregate bound')
        require(b'@' not in data, 'nested/ambiguous response reference')
        require(not any(token in data for token in (b'-B', b'-specs', b'--specs', b'-fplugin',
                    b'-wrapper', b'--wrapper', b'-fuse-ld')), 'response tool-selection control')
        name = 'response-%06d.bin' % position
        durable(os.path.join(record_dir, name), data)
        result.append(dict(item, position=position, artifact=name, cwdBase64=b64(os.fsencode(cwd))))
    return result


def validate_args(args, limits):
    require(len(args) <= limits['args'] and sum(len(a)+1 for a in args) <= limits['argvBytes'], 'argv bound')
    for a in args:
        require(b'\0' not in a, 'NUL argv')
        require(not a.startswith((b'-B', b'-specs', b'--specs', b'-fplugin', b'-wrapper', b'--wrapper', b'-fuse-ld')),
                'forbidden tool-selection option')


def execute(m, manifest_evidence, role, received, output=None):
    require(not isinstance(m.get('purpose'), str) or not m['purpose'].startswith('owner-nodev8-prerequisite-measurement'), 'STOP_NATIVE_ACTION_BOUNDARY_UNIMPLEMENTED')
    require(role in m['roles'], 'denied role')
    limits = m['limits']
    validate_args(received, limits)
    require(received and received[0] == os.fsencode('/control/'+role), 'fixed wrapper argv0')
    cwd = canonical(os.getcwd())
    require(cwd == m['work'] or cwd.startswith(m['work']+'/'), 'cwd outside work')
    # Never forward inherited values. Unknown controls fail before any tool execution.
    require(not any(k.startswith(('LD_', 'ASAN_', 'LSAN_', 'UBSAN_', 'GCC_', 'COMPILER_')) or
                    k in {'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'CPATH', 'LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME'}
                    for k in os.environ), 'denied inherited control')
    tool = tool_identity(m['roles'][role])
    forwarded = [os.fsencode(tool['path'])] + received[1:]
    root = canonical(output or m['output'])
    require(root == m['output'], 'output root')
    records = os.path.join(root, 'records')
    os.makedirs(records, mode=0o700, exist_ok=True)
    require(os.path.realpath(records) == records and os.path.isdir(records), 'records directory')
    require(len(os.listdir(records)) < limits['records'], 'record count bound')
    run = os.path.join(records, uuid.uuid4().hex)
    os.mkdir(run, 0o700)  # Exclusive ID; no reuse, even when completion is absent.
    syncdir(records)
    start = {'schema': SCHEMA, 'status': 'STARTED', 'role': role,
             'receivedArgvBase64': [b64(x) for x in received],
             'forwardedArgvBase64': [b64(x) for x in forwarded], 'cwdBase64': b64(os.fsencode(cwd)),
             'environment': FIXED_ENV, 'tool': tool, 'manifest': manifest_evidence,
             'instrumentation': 'NEW supervised wrapper/process topology; CC/CXX/LINK=/control/{cc,cxx,link}',
             'internalCollect2LdArgv': 'UNOBSERVED', 'nodeFidelity': 'NOT_PROVEN',
             'recorderPid': os.getpid(),
             'startedMonotonicNs': time.monotonic_ns()}
    # A durable intent exists even if snapshotting or spawning subsequently fails.
    durable(os.path.join(run, 'start.json'), json.dumps(start, sort_keys=True).encode()+b'\n')
    child, streams, cancel = None, {}, []
    select = None
    old_handlers = {}
    outcome = {'schema': SCHEMA, 'status': 'CAPTURE_INCOMPLETE', 'returncode': None,
               'signal': None, 'blocker': 'missing completion', 'internalCollect2LdArgv': 'UNOBSERVED'}
    def cancelled(signum, _frame):
        cancel.append(signum)
    try:
        responses = response_snapshots(received[1:], cwd, limits, run, m['work'])
        durable(os.path.join(run, 'responses.json'), json.dumps(responses, sort_keys=True).encode()+b'\n')
        unchanged(manifest_evidence)
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, cancelled)
        # No preexec shell or inherited descriptors/environment. NEW process group.
        child = subprocess.Popen(forwarded, executable=os.fsencode(tool['path']), shell=False,
                                 env=FIXED_ENV, cwd=cwd, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        durable(os.path.join(run, 'spawn.json'), json.dumps({'pid': child.pid, 'processGroup': child.pid}).encode()+b'\n')
        select = selectors.DefaultSelector()
        for name, pipe, caller in [('stdout', child.stdout, 1), ('stderr', child.stderr, 2)]:
            fd = os.open(os.path.join(run, name+'.bin'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            streams[name] = {'fd': fd, 'bytes': 0, 'hash': hashlib.sha256(), 'relay': Relay(caller),
                             'pipe': pipe, 'paused': False, 'eof': False}
            os.set_blocking(pipe.fileno(), False)
            select.register(pipe, selectors.EVENT_READ, name)
        deadline = time.monotonic() + limits['seconds']
        while any(not s['eof'] or s['relay'].pending() for s in streams.values()) or child.poll() is None:
            require(not cancel, 'capture cancelled')
            require(time.monotonic() < deadline, 'capture deadline')
            for name, stream in streams.items():
                require(stream['relay'].error is None, 'caller relay write failure')
                if stream['paused'] and not stream['relay'].queue.full():
                    select.register(stream['pipe'], selectors.EVENT_READ, name)
                    stream['paused'] = False
            for key, _mask in select.select(0.05):
                stream = streams[key.data]
                if stream['relay'].queue.full():
                    select.unregister(key.fileobj)
                    stream['paused'] = True
                    continue
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    select.unregister(key.fileobj)
                    key.fileobj.close()
                    stream['eof'] = True
                    continue
                require(stream['bytes'] + len(chunk) <= limits['stream'], 'stream overflow')
                require(sum(x['bytes'] for x in streams.values()) + len(chunk) <= limits['text'], 'text overflow')
                view = memoryview(chunk)
                while view:
                    n = os.write(stream['fd'], view)
                    require(n > 0, 'logger short write')
                    view = view[n:]
                stream['bytes'] += len(chunk)
                stream['hash'].update(chunk)
                # Spool first; caller never receives an unrecorded chunk. Queue
                # capacity was checked before reading; only this thread enqueues.
                stream['relay'].queue.put_nowait(chunk)
        for stream in streams.values():
            relay = stream['relay']
            relay.finish(deadline)
            require(relay.bytes == stream['bytes'] and relay.hash.digest() == stream['hash'].digest(),
                    'caller/evidence byte mismatch')
        rc = child.wait(timeout=1)
        for item in responses:
            unchanged({k: item[k] for k in ('pathBase64', 'identity', 'sha256', 'size')})
        unchanged(manifest_evidence)
        require(tool_identity(m['roles'][role]) == tool, 'tool changed during invocation')
        outcome.update(status='CAPTURE_COMPLETE', blocker=None, returncode=rc,
                       signal=-rc if rc < 0 else None)
    except Exception as exc:
        outcome['blocker'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if select is not None:
            select.close()
        for stream in streams.values():
            stream['relay'].stopped.set()
        if child is not None:
            # Descendants may outlive a failed parent or keep pipes open; kill group.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                outcome['returncode'] = child.wait(timeout=2)
                outcome['signal'] = -child.returncode if child.returncode < 0 else None
            except subprocess.TimeoutExpired:
                outcome.update(status='CAPTURE_INCOMPLETE', blocker='child reap timeout')
        outcome['cancelSignal'] = cancel[0] if cancel else None
        outcome['streams'] = {}
        try:
            for name, stream in streams.items():
                os.fsync(stream['fd'])
                os.close(stream['fd'])
                outcome['streams'][name] = {'bytes': stream['bytes'], 'sha256': stream['hash'].hexdigest(),
                                           'relayedBytes': stream['relay'].bytes,
                                           'relayedSha256': stream['relay'].hash.hexdigest()}
            outcome['finishedMonotonicNs'] = time.monotonic_ns()
            durable(os.path.join(run, 'completion.json'), json.dumps(outcome, sort_keys=True).encode()+b'\n')
        finally:
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
    if cancel:
        signal.signal(cancel[0], signal.SIG_DFL)
        os.kill(os.getpid(), cancel[0])
    if outcome['status'] != 'CAPTURE_COMPLETE':
        return 125
    rc = outcome['returncode']
    if rc < 0:
        signal.signal(-rc, signal.SIG_DFL)
        os.kill(os.getpid(), -rc)
    return rc


def main():
    if len(sys.argv) == 3 and sys.argv[1] == 'native-admission':
        raw, _ = snapshot(canonical(sys.argv[2]), 1048576)
        m = json.loads(raw)
        print(json.dumps(native_admission(m), sort_keys=True))
        return 125
    if len(sys.argv) == 3 and sys.argv[1] == 'fixture':
        m, evidence = manifest(sys.argv[2])
        args = m.get('fixtureArgvBase64')
        require(isinstance(args, list), 'fixture argv required')
        decoded = [base64.b64decode(a, validate=True) for a in args]
        require(all(b64(a) == b for a, b in zip(decoded, args)), 'canonical base64')
        return execute(m, evidence, 'workload', [b'/control/workload'] + decoded)
    require(len(sys.argv) >= 5 and sys.argv[1] == 'record', 'record manifest role argv0 [args] only')
    m, evidence = manifest(sys.argv[2])
    return execute(m, evidence, sys.argv[3], [os.fsencode(a) for a in sys.argv[4:]])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        # No argv/env/file bytes in diagnostics; missing completion remains blocked.
        print('CAPTURE_INCOMPLETE: '+type(exc).__name__, file=sys.stderr)
        sys.exit(125)
