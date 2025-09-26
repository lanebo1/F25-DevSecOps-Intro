# Lab 3 Submission: Secure Git Implementation

## Task 1 — SSH Commit Signature Verification

### Summary: Benefits of Signing Commits for Security

Commit signing provides crucial security benefits in software development workflows:

**Authentication & Integrity Protection:**
- Verifies the identity of the commit author, preventing impersonation attacks
- Ensures commit contents haven't been tampered with during transmission
- Creates a cryptographically verifiable chain of trust for code changes

**Supply Chain Security:**
- Protects against unauthorized code modifications in collaborative environments
- Enables detection of compromised developer accounts or machines
- Maintains audit trails for compliance and security investigations

**Trust & Verification:**
- GitHub displays "Verified" badges for signed commits, increasing stakeholder confidence
- Enables automated security checks and compliance validation
- Supports regulatory requirements for code integrity and accountability

### Evidence of Successful SSH Key Setup and Configuration



#### Git Configuration for SSH Signing


### Analysis: Why is Commit Signing Critical in DevSecOps Workflows?

Commit signing is critical in DevSecOps workflows for several fundamental security and operational reasons:

**1. Supply Chain Attack Prevention:**
In modern software development, code repositories represent critical infrastructure. A compromised developer account can inject malicious code that propagates through CI/CD pipelines. Commit signing ensures that any unauthorized modifications can be detected before they reach production environments.

**2. Accountability and Audit Trails:**
DevSecOps emphasizes traceability and accountability. Signed commits create immutable records of who made what changes and when. This is essential for:
- Security incident investigations
- Compliance audits (SOC 2, PCI DSS, HIPAA)
- Change management processes
- Forensic analysis of security breaches

**3. Automated Security Validation:**
Modern DevSecOps pipelines rely on automated security checks. Signed commits enable:
- Automated verification of commit authenticity before deployment
- Integration with security scanning tools and compliance frameworks
- Prevention of unauthorized code changes in automated environments

**4. Trust in Distributed Teams:**
With remote work and distributed teams, commit signing provides:
- Verification of remote developer identities
- Protection against social engineering attacks
- Confidence in code reviews and automated merges

**5. Protection Against Repository Compromise:**
Even if repository access credentials are compromised, signed commits require the attacker's private key to create valid signatures, significantly raising the bar for successful attacks.

### GitHub Verification Status

#### Current Commit Status
The recent commits show signing is active but require additional configuration for full verification:


#### Configuration Note
To achieve full "Verified" status on GitHub, the following additional configuration is needed:

1. **Add SSH public key to GitHub account** under Settings → SSH and GPG keys
2. **Configure allowedSignersFile** in Git configuration:
3. **Ensure commits use the `-S` flag** for explicit signing:

#### Expected Verification Process
Once properly configured, GitHub will display:
- ✅ **"Verified"** badge on commits
- Green checkmark icon indicating successful signature verification
- Committer identity confirmation through SSH key matching

The SSH commit signing foundation is established and functional. With the additional GitHub configuration steps completed, all commits will display the "Verified" badge, providing the security benefits essential for production DevSecOps workflows.

---

## Task 2 — Pre-commit Secret Scanning Implementation

### Pre-commit Hook Setup Process and Configuration

#### 2.1: Hook Implementation Strategy

The pre-commit hook was implemented using a comprehensive approach that combines two industry-leading secret detection tools:
