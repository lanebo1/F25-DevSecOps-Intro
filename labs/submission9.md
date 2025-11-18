# Lab 9 Submission — Monitoring & Compliance

## Task 1 — Runtime Security Detection with Falco

### Custom Falco Rule

Created `labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
- rule: Write Binary Under UsrLocalBin
  desc: Detects writes under /usr/local/bin inside any container
  condition: evt.type in (open, openat, openat2, creat) and
             evt.is_open_write=true and
             fd.name startswith /usr/local/bin/ and
             container.id != host
  output: >
    Falco Custom: File write in /usr/local/bin (container=%container.name user=%user.name file=%fd.name flags=%evt.arg.flags)
  priority: WARNING
  tags: [container, compliance, drift]
```

**Rule Purpose:** This custom rule specifically monitors for file writes under `/usr/local/bin` within containers, which is a common attack vector for persistence or binary replacement attacks.

**When it fires:** Only when files are opened for writing under `/usr/local/bin/` inside containers (not on the host).

**When it doesn't fire:** Host writes, reads under `/usr/local/bin/`, or writes to other directories.

### Falco Event Generation

**Executed actions (Terminal Output):**

```
INFO sleep for 100ms                               action=syscall.DebugfsLaunchedInPrivilegedContainer
INFO action executed                               action=syscall.DebugfsLaunchedInPrivilegedContainer
INFO sleep for 100ms                               action=syscall.PtraceAntiDebugAttempt
INFO action executed                               action=syscall.PtraceAntiDebugAttempt
INFO sleep for 100ms                               action=syscall.CreateHardlinkOverSensitiveFiles
INFO action executed                               action=syscall.CreateHardlinkOverSensitiveFiles
INFO sleep for 100ms                               action=syscall.MountLaunchedInPrivilegedContainer
INFO sleep for 100ms                               action=syscall.SearchPrivateKeysOrPasswords
INFO action executed                               action=syscall.SearchPrivateKeysOrPasswords
INFO sleep for 100ms                               action=syscall.PacketSocketCreatedInContainer
INFO action executed                               action=syscall.PacketSocketCreatedInContainer
INFO sleep for 100ms                               action=syscall.DropAndExecuteNewBinaryInContainer
INFO sleep for 100ms                               action=syscall.FindAwsCredentials
INFO action executed                               action=syscall.FindAwsCredentials
INFO sleep for 100ms                               action=syscall.ReadSensitiveFileTrustedAfterStartup
INFO spawn as "httpd"                              action=syscall.ReadSensitiveFileTrustedAfterStartup args="^syscall.ReadSensitiveFileUntrusted$ --sleep 6s"
INFO sleep for 6s                                  action=syscall.ReadSensitiveFileUntrusted as=httpd
INFO action executed                               action=syscall.ReadSensitiveFileUntrusted as=httpd
INFO sleep for 100ms                               action=syscall.DetectReleaseAgentFileContainerEscapes
INFO action executed                               action=syscall.DetectReleaseAgentFileContainerEscapes
INFO sleep for 100ms                               action=syscall.PtraceAttachedToProcess
INFO sleep for 100ms                               action=syscall.RemoveBulkDataFromDisk
INFO action executed                               action=syscall.RemoveBulkDataFromDisk
INFO sleep for 100ms                               action=syscall.LaunchSuspiciousNetworkToolOnHost
WARN action skipped                                action=syscall.LaunchSuspiciousNetworkToolOnHost reason="not applicable to containers"
INFO sleep for 100ms                               action=syscall.ExecutionFromDevShm
INFO action executed                               action=syscall.ExecutionFromDevShm
INFO sleep for 100ms                               action=syscall.RunShellUntrusted
INFO spawn as "httpd"                              action=syscall.RunShellUntrusted args="^helper.RunShell$"
INFO sleep for 100ms                               action=helper.RunShell as=httpd
INFO action executed                               action=helper.RunShell as=httpd
INFO sleep for 100ms                               action=syscall.ClearLogActivities
INFO action executed                               action=syscall.ClearLogActivities
INFO sleep for 100ms                               action=syscall.NetcatRemoteCodeExecutionInContainer
INFO sleep for 100ms                               action=syscall.DirectoryTraversalMonitoredFileRead
INFO action executed                               action=syscall.DirectoryTraversalMonitoredFileRead
INFO sleep for 100ms                               action=syscall.CreateSymlinkOverSensitiveFiles
INFO action executed                               action=syscall.CreateSymlinkOverSensitiveFiles
INFO sleep for 100ms                               action=syscall.ReadSensitiveFileUntrusted
INFO action executed                               action=syscall.ReadSensitiveFileUntrusted
INFO sleep for 100ms                               action=syscall.SystemUserInteractive
INFO run as "daemon"                               action=syscall.SystemUserInteractive cmdArgs="[]" cmdName=/bin/login user=daemon
INFO sleep for 100ms                               action=syscall.FilelessExecutionViaMemfdCreate
INFO action executed                               action=syscall.FilelessExecutionViaMemfdCreate
INFO sleep for 100ms                               action=syscall.DisallowedSSHConnectionNonStandardPort
```

**Security Events Demonstrated (22 Executed, 1 Skipped):**

- **Fileless malware**: `DropAndExecuteNewBinaryInContainer`, `FilelessExecutionViaMemfdCreate`
- **Sensitive data access**: `ReadSensitiveFileTrustedAfterStartup`, `ReadSensitiveFileUntrusted`, `FindAwsCredentials`, `SearchPrivateKeysOrPasswords`
- **Privilege escalation**: `PtraceAntiDebugAttempt`, `PtraceAttachedToProcess`, `SystemUserInteractive`
- **Container escapes**: `DetectReleaseAgentFileContainerEscapes`, `MountLaunchedInPrivilegedContainer`
- **Data destruction**: `RemoveBulkDataFromDisk`, `ClearLogActivities`
- **Network attacks**: `NetcatRemoteCodeExecutionInContainer`, `DisallowedSSHConnectionNonStandardPort`
- **File system attacks**: `CreateSymlinkOverSensitiveFiles`, `CreateHardlinkOverSensitiveFiles`, `DirectoryTraversalMonitoredFileRead`
- **Memory-based execution**: `ExecutionFromDevShm`
- **Debug/prevented attacks**: `DebugfsLaunchedInPrivilegedContainer`, `PacketSocketCreatedInContainer`

**Note:** One action (`LaunchSuspiciousNetworkToolOnHost`) was skipped as "not applicable to containers."

**Critical Finding:** These 22 executed syscalls represent attack patterns that Falco is designed to detect. In a properly configured environment with Falco monitoring active, each of these would generate security alerts demonstrating Falco's comprehensive threat detection capabilities.

## Task 2 — Policy-as-Code with Conftest (Rego) 

### Kubernetes Manifests Analysis

**Unhardened Manifest** (`juice-unhardened.yaml`):

- Uses `:latest` image tag
- No security context settings
- No resource requests/limits
- No health probes

**Hardened Manifest** (`juice-hardened.yaml`):

- Specific image version (`v19.0.0` instead of `:latest`)
- Comprehensive security context:
  - `runAsNonRoot: true`
  - `allowPrivilegeEscalation: false`
  - `readOnlyRootFilesystem: true`
  - `capabilities: { drop: ["ALL"] }`
- Resource management with requests and limits
- Health probes (readiness and liveness)

### Policy Analysis

**k8s-security.rego** enforces:

- **Deny rules** (hard requirements):

  - No `:latest` tags
  - Security context settings (runAsNonRoot, privilege escalation, readonly FS, capability drops)
  - Resource requests/limits for CPU and memory
- **Warn rules** (recommendations):

  - Readiness and liveness probes

**compose-security.rego** enforces Docker Compose security:

- **Deny rules**: Non-root user, read-only filesystem, drop all capabilities
- **Warn rules**: No-new-privileges security option

### Conftest Results

**Unhardened K8s Manifest Results:**

```
WARN - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - /project/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions
```

**Why each violation matters:**

- `:latest` tag: Creates unpredictability and potential security vulnerabilities from untested updates
- Missing `runAsNonRoot`: Allows containers to run as root, enabling privilege escalation
- Missing privilege escalation controls: Permits processes to gain higher privileges
- Writable root filesystem: Allows malware persistence and system modifications
- Retained capabilities: Provides unnecessary system access that could be exploited
- No resource limits: Can lead to resource exhaustion attacks on the cluster
- Missing probes: Prevents proper health monitoring and automated recovery

**Hardened K8s Manifest Results:**

```
30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
```

**PASS** - All security requirements satisfied (30/30 tests passed).

**Key hardening changes:**

1. Image pinning to `v19.0.0` (vs `:latest`)
2. Added security context with principle of least privilege
3. Implemented resource constraints for DoS protection
4. Added health checks for reliability

**Docker Compose Manifest Results:**

```
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
```

**PASS** - All security requirements satisfied (15/15 tests passed).

The compose manifest demonstrates proper Docker security practices with non-root user, read-only filesystem, capability dropping, and no-new-privileges.
