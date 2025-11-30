# Lab 7 Submission — Container Security: Image Scanning & Deployment Hardening

## Task 1 — Image Vulnerability & Configuration Analysis

### 1.1 Vulnerability Scanning Results

**Docker Scout Summary:**
- **Target Image:** `bkimminich/juice-shop:v19.0.0`
- **Total Vulnerabilities:** 61
  - Critical: 9
  - High: 20
  - Medium: 24
  - Low: 1
  - Unspecified: 7
- **Base Image:** `gcr.io/distroless/nodejs22-debian12:latest`
- **Image Size:** 158 MB
- **Total Packages:** 1004

### 1.2 Top 5 Critical/High Vulnerabilities

1. **CVE-2023-37903 (CRITICAL - 9.8 CVSS)** - vm2 package
   - **Issue:** OS Command Injection vulnerability
   - **Affected Package:** vm2 v3.9.17
   - **Impact:** Allows remote code execution through command injection
   - **Status:** No fix available

2. **CVE-2023-37466 (CRITICAL - 9.8 CVSS)** - vm2 package
   - **Issue:** Code Injection vulnerability
   - **Affected Package:** vm2 v3.9.17
   - **Impact:** Allows arbitrary code execution
   - **Status:** No fix available

3. **CVE-2023-32314 (CRITICAL - 9.8 CVSS)** - vm2 package
   - **Issue:** Command Injection vulnerability
   - **Affected Package:** vm2 v3.9.17
   - **Impact:** Allows command injection attacks
   - **Fixed Version:** 3.9.18

4. **CVE-2019-10744 (CRITICAL - 9.1 CVSS)** - lodash package
   - **Issue:** Prototype Pollution vulnerability
   - **Affected Package:** lodash v2.4.2
   - **Impact:** Allows modification of object prototypes
   - **Fixed Version:** 4.17.12

5. **CVE-2023-46233 (CRITICAL - 9.1 CVSS)** - crypto-js package
   - **Issue:** Use of Broken Cryptographic Algorithm
   - **Affected Package:** crypto-js v3.3.0
   - **Impact:** Weak cryptographic implementation
   - **Fixed Version:** 4.2.0

### 1.3 Dockle Configuration Findings

**Summary:** Dockle found no FATAL or WARN issues, only INFO level findings.

**Configuration Findings:**
1. **CIS-DI-0005 (INFO):** Content trust not enabled
   - **Security Concern:** Without content trust, images could be tampered with during transit
   - **Impact:** Potential man-in-the-middle attacks on image pulls

2. **CIS-DI-0006 (INFO):** Missing HEALTHCHECK instruction
   - **Security Concern:** No automatic health monitoring of container processes
   - **Impact:** Failed containers may not be detected automatically

3. **DKL-LI-0003 (INFO):** Unnecessary files present
   - **Files Found:** `.DS_Store` files in node_modules
   - **Security Concern:** Unnecessary files increase attack surface and image size
   - **Impact:** Potential information disclosure, larger attack surface

### 1.4 Security Posture Assessment

**Root User Analysis:**
- The image does NOT run as root by default (uses non-root user 65532)
- **Positive:** Follows principle of least privilege

**Security Recommendations:**
1. **Update Dependencies:** Critical vulnerabilities in vm2, lodash, and crypto-js require immediate updates
2. **Add Health Checks:** Implement HEALTHCHECK instructions for automatic monitoring
3. **Clean Build:** Remove unnecessary files during image build process
4. **Regular Scanning:** Implement continuous vulnerability scanning in CI/CD pipeline

---

## Task 2 — Docker Host Security Benchmarking

### 2.1 CIS Benchmark Summary

**Overall Results:**
- **Total Checks:** 74
- **Score:** 4/100 (indicating significant security gaps)
- **PASS:** 39 checks
- **WARN:** 15 checks
- **FAIL:** 0 checks
- **INFO:** 20 checks

### 2.2 Analysis of Failures and Warnings

**Critical Security Gaps:**

1. **Host Configuration Issues:**
   - **WARN 1.1:** No separate partition for containers
     - **Impact:** Container escape could compromise entire host
     - **Remediation:** Create dedicated partition for `/var/lib/docker`

   - **WARN 1.5:** No auditing for Docker daemon
     - **Impact:** Security events not logged
     - **Remediation:** Configure audit rules for Docker daemon

   - **WARN 1.6:** No auditing for Docker files/directories
     - **Impact:** File system changes not monitored
     - **Remediation:** Add audit rules for `/var/lib/docker`

2. **Docker Daemon Configuration Issues:**
   - **WARN 2.1:** Inter-container communication not restricted
     - **Impact:** Containers can communicate freely on default bridge
     - **Remediation:** Configure `--icc=false` or use custom networks

   - **WARN 2.6:** No TLS authentication for Docker daemon
     - **Impact:** Unencrypted daemon communication
     - **Remediation:** Configure TLS certificates for daemon

   - **WARN 2.8:** User namespace support not enabled
     - **Impact:** Reduced isolation between host and containers
     - **Remediation:** Enable user namespaces

   - **WARN 2.11:** No authorization plugin configured
     - **Impact:** No access control for Docker API
     - **Remediation:** Implement authorization plugin

   - **WARN 2.12:** No centralized logging
     - **Impact:** Logs not aggregated or monitored
     - **Remediation:** Configure remote logging

   - **WARN 2.14:** Live restore not enabled
     - **Impact:** Containers stop during daemon restart
     - **Remediation:** Enable live restore

   - **WARN 2.15:** Userland proxy not disabled
     - **Impact:** Performance overhead and potential security issues
     - **Remediation:** Disable userland proxy

   - **WARN 2.18:** Containers can acquire new privileges
     - **Impact:** Privilege escalation possible
     - **Remediation:** Set `--no-new-privileges` by default

3. **Configuration File Issues:**
   - **WARN 3.15:** Incorrect Docker socket ownership
     - **Impact:** Unauthorized users may access Docker daemon
     - **Remediation:** Set ownership to `root:docker`

4. **Image Security Issues:**
   - **WARN 4.5:** Content trust not enabled
     - **Impact:** Image tampering not prevented
     - **Remediation:** Enable Docker Content Trust

   - **WARN 4.6:** No HEALTHCHECK in container images
     - **Impact:** Container health not monitored
     - **Remediation:** Add HEALTHCHECK instructions to Dockerfiles

---

## Task 3 — Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

| Security Feature | Default | Hardened | Production |
|------------------|---------|----------|------------|
| **Capabilities** | All capabilities retained | `--cap-drop=ALL` | `--cap-drop=ALL`, `--cap-add=NET_BIND_SERVICE` |
| **Security Options** | None | `--security-opt=no-new-privileges` | `--security-opt=no-new-privileges` |
| **Memory Limit** | Unlimited | 512MB | 512MB + 512MB swap |
| **CPU Limit** | Unlimited | 1.0 cores | 1.0 cores |
| **PID Limit** | Unlimited | Unlimited | 100 processes |
| **Restart Policy** | No restart | No restart | `on-failure:3` |

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

**Linux Capabilities Overview:**
Linux capabilities divide the privileges traditionally associated with the root user into distinct units. Each capability represents a specific privilege that can be granted or revoked independently.

**Attack Vector Prevention:**
- `--cap-drop=ALL` removes all capabilities from the container
- Prevents privilege escalation attacks that rely on specific capabilities
- Blocks common attack vectors like:
  - Creating raw sockets (`CAP_NET_RAW`)
  - Loading kernel modules (`CAP_SYS_MODULE`)
  - Changing system time (`CAP_SYS_TIME`)

**NET_BIND_SERVICE Requirement:**
- Required for binding to privileged ports (< 1024)
- Juice Shop runs on port 3000, which requires this capability
- **Security Trade-off:** Minimal additional privilege needed for legitimate functionality

#### b) `--security-opt=no-new-privileges`

**Functionality:**
Prevents a process from gaining new privileges through `execve()` system calls. Even if a process has `setuid` binaries or capabilities, it cannot elevate privileges.

**Attack Prevention:**
- Blocks privilege escalation via setuid binaries
- Prevents exploitation of vulnerabilities that rely on privilege elevation
- Complements capability dropping for defense in depth

**Downsides:**
- May break applications that legitimately need privilege elevation
- Can cause issues with certain system utilities
- Requires careful testing during deployment

#### c) `--memory=512m` and `--cpus=1.0`

**Resource Limit Importance:**
Without limits, containers can exhaust host resources, leading to:
- **DoS attacks:** Malicious containers consume all available resources
- **Host instability:** System becomes unresponsive due to resource starvation
- **Noisy neighbor problems:** One container affects others on the same host

**Memory Limiting Benefits:**
- Prevents out-of-memory situations
- Enables better resource planning and cost optimization
- Provides predictable performance

**Risk of Setting Limits Too Low:**
- Application crashes during peak loads
- Degraded performance under normal conditions
- Requires monitoring and tuning based on actual usage patterns

#### d) `--pids-limit=100`

**Fork Bomb Explanation:**
A fork bomb is a process that recursively creates copies of itself, rapidly consuming all available process IDs and causing system deadlock.

**PID Limiting Protection:**
- Restricts maximum number of processes a container can create
- Prevents fork bomb attacks that could crash the host
- Provides granular control over container resource usage

**Determining Right Limit:**
- **Method 1:** Monitor normal application behavior and set limit 2-3x higher
- **Method 2:** Use `docker stats` or monitoring tools to observe PID usage
- **Method 3:** Start conservative (50-100) and increase based on needs

#### e) `--restart=on-failure:3`

**Policy Behavior:**
- Automatically restarts container if it exits with non-zero status
- Limits restart attempts to 3 failures
- Stops restarting after maximum attempts reached

**When Beneficial:**
- **Production:** Ensures service availability despite transient failures
- **Network issues:** Recovers from temporary connectivity problems
- **Resource constraints:** Handles temporary out-of-memory situations

**Risks:**
- **Security:** Could restart compromised containers
- **Resource waste:** Endless restart loops consume resources
- **Debugging:** Automatic restarts mask underlying issues

**on-failure vs always:**
- `on-failure`: Only restarts on actual failures (recommended)
- `always`: Always restarts, even on intentional stops (riskier)

### 3.3 Critical Thinking Questions

#### 1. Which profile for DEVELOPMENT?
**Hardened profile** is most appropriate for development because:
- Provides security without being overly restrictive
- Allows developers to test applications under realistic security constraints
- Balances security with development productivity
- Prevents most common attacks while maintaining functionality

#### 2. Which profile for PRODUCTION?
**Production profile** is required for production deployment because:
- Implements defense in depth with all security controls
- Prevents resource exhaustion through comprehensive limits
- Ensures high availability with restart policies
- Provides maximum protection against attacks and abuse

#### 3. Real-world Problem Solved by Resource Limits
Resource limits solve the "noisy neighbor" and DoS attack problems in multi-tenant environments. Without limits, a single misbehaving container can:
- Consume all available memory, causing other services to crash
- Use excessive CPU, slowing down all applications on the host
- Create thousands of processes, leading to system-wide instability
- Exhaust disk space or network bandwidth

#### 4. Attacker Capabilities: Default vs Production
In a **Default** deployment, an attacker could:
- Escalate privileges using dropped capabilities
- Execute fork bombs to crash the system
- Exhaust memory and CPU resources
- Access host network unrestricted

In a **Production** deployment, these actions are blocked:
- Capability restrictions prevent privilege escalation
- PID limits stop fork bomb attacks
- Memory/CPU limits prevent resource exhaustion
- Network isolation restricts inter-container communication

#### 5. Additional Hardening Recommendations
- **Read-only filesystems:** `--read-only` with `--tmpfs` for temporary data
- **Network isolation:** `--network` with custom networks instead of default bridge
- **Security profiles:** AppArmor or SELinux profiles
- **Log aggregation:** Centralized logging with monitoring
- **Secrets management:** External secret storage instead of environment variables
- **Image signing:** Require signed images with `--require-content-trust`
- **Runtime scanning:** Integrate with tools like Falco for runtime threat detection

