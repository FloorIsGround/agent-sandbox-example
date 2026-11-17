# Security boundaries and limitations

This is a Linux/Docker reference example, **not a VM security guarantee** or a
multi-tenant service. Container escape vulnerabilities, a compromised daemon or
trusted base image, privileged host users, malicious registered callbacks, and
physical/side-channel attacks are outside the boundary. Do not run sensitive
host workloads beside hostile jobs based only on this example.

The trusted application owns Docker, the immutable local image ID, Scope,
callback registry and store. Job code and every job-supplied callback argument,
path, frame and output byte are untrusted. A caller-supplied Scope is not
authentication; a dishonest host caller can choose another namespace. Output
artifacts are untrusted text, not safe HTML or safe spreadsheet formulas. Treat
CSV cells beginning with formula characters appropriately in downstream apps.

## Enforced profile

- Fixed Python command and image chosen by operator. No job-selected shell,
  image, command line, arbitrary host path, volume or Docker flags.
- `--pull=never`, network none, no host binds, read-only image, UID/GID 65534,
  all capabilities dropped, no new privileges, default Docker seccomp.
- 256 MiB memory and memory+swap, one CPU, 32 PIDs, 64 file descriptors,
  1 MiB per-file size; workspace tmpfs 16 MiB/256 inodes and temporary tmpfs
  8 MiB/128 inodes, both noexec/nosuid/nodev. noexec does not prevent Python
  from interpreting code. Image/base contents remain readable by the job.
- Linux supervisor disables dumpability before reading a fresh 256-bit key.
  Only the supervisor owns host-facing pipes. Job stdout/stderr are captured;
  a Unix helper accepts only callback request shapes. It never signs arbitrary
  file/done/stream frames from code. HMAC-SHA256, strict JSON, exact fields,
  monotonic sequence numbers, 128 frames and 4 MiB wire bytes per direction
  prevent unauthenticated/replayed IPC from gaining authority. The key
  authenticates this owned channel, not the user or truth of generated content.
- Host-side environment is explicitly replaced; no dotenv, shell profiles,
  user Docker config or ambient provider keys. Child environment is also fixed.
  The trusted image can itself define environment defaults; review it.
- At most 8,000 code bytes, four inputs of 128 KiB, four selected outputs of
  256 KiB, and 64 KiB combined UTF-8 stdout/stderr. Output names are flat
  `.txt`, `.csv`, `.json` allowlisted names. NUL, invalid UTF-8 and common ZIP,
  gzip and tar signatures are refused. This is not full content/MIME validation.
- Collector opens the selected directory/file using O_NOFOLLOW, rejects
  non-regular files and multiple hardlinks, and reads with a byte cap. The host
  independently rechecks names, selection, duplication, type declarations and
  received bytes. The declarations are supervisor statements, not host-side
  filesystem attestation. Background child mutation can make contents unstable;
  no claim of a filesystem snapshot is made.
- Callback batches have 1..4 entries, 12,000 argument bytes per call and 16,000
  UTF-8 response bytes per call. All names/argument envelope shapes are checked
  before dispatch; a failed batch spends its reservation. Total limit defaults
  to 8, maximum 16 per run. Helper requests cap at 50,000 bytes, four concurrent
  connections, sixteen total connections. Returned text is not truncated.

## Lifecycle

Host wall deadline is at most 30 seconds, including startup and callback work;
supervisor/child CPU rlimit is 10 seconds per process, plus cgroup CPU throttling.
Trusted callbacks must use bounded, cancellation-cooperative async operations.
Python cannot preempt a callback that blocks its event loop or suppresses
cancellation. Do not register such callbacks. Use external isolation for them.

Container creation completes before its attach CLI is exposed. On success,
protocol failure, callback failure, deadline, abort or caller cancellation, the
host joins callback work, kills/reaps its attach process and removes only its
exact generated container name after matching example/owner labels. It verifies
absence; daemon failures are not interpreted as absence. Repeated cancellation
cannot detach this cleanup. Cleanup commands have 3-second deadlines, bounded
output and a 5-second CLI reaping allowance; these can extend the run deadline.
Cleanup verification failure suppresses all outputs and raises CleanupError.

No global sweep or crash-recovery monitor is installed. SIGKILL, host/daemon
failure, a Docker create request completing after a control-command timeout, or
an indefinitely stalled process spawn can defeat normal cleanup. In these cases
operator inspection is required; this package does not claim crash-proof
resource reclamation. The driver's in-memory owned-name set can help a trusted
operator diagnose a failed run but is not durable recovery state. Never remove
unrelated containers. Resource limits depend on a correctly configured daemon
and Linux cgroups; inspect the actual container on the target host.

Artifacts commit only after successful execution **and verified cleanup**.
They are immutable bytes retained only in memory, globally bounded per store
(default 16 files/2 MB), expiring lazily (default one hour, maximum one day).
They are not encrypted or durable. Expiry is checked on access, not by a timer.
The store and Sandbox are designed for one event loop/thread. Multiple Sandbox
instances and daemon logs/image caches need separate operator concurrency and
storage policies. Do not include secrets in job code, inputs or base images;
this example provides no secret-management or remote authorization system.
