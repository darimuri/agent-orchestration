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


def manifest(p):
    raw, evidence = snapshot(canonical(p), 1048576)
    m = json.loads(raw)
    require(m.get('schema') == SCHEMA, 'manifest schema')
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
