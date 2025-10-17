# Lab 6 Submission: Infrastructure-as-Code Security Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1: Terraform Tool Comparison

| Tool | Findings Count | Key Strengths | Limitations |
|------|----------------|---------------|-------------|
| **tfsec** | 53 findings | Fast scanning, detailed reports, good for quick checks | Limited to Terraform only |
| **Checkov** | 78 findings | Most comprehensive detection, supports multiple frameworks | Network timeouts during scanning |
| **Terrascan** | 22 findings | Good for policy enforcement | Registry connection issues during scan |

**Analysis:** Checkov detected the most vulnerabilities, followed by tfsec and Terrascan. Checkov appears to be the most thorough tool, detecting a wider range of security issues including compliance violations and best practices.

### 1.2: Critical Terraform Findings

The most critical issues found across all tools include:

1. **Public RDS Database Access** - RDS instances configured with `publicly_accessible = true`
2. **Overly Permissive Security Groups** - Security groups allowing ingress from `0.0.0.0/0`
3. **Unencrypted Storage** - S3 buckets without encryption
4. **IAM Privilege Escalation** - IAM policies with wildcard permissions (`*`)
5. **Hardcoded Secrets** - Database passwords and API keys in plaintext

### 1.3: Pulumi Security Analysis with KICS

KICS scanned the Pulumi YAML configuration and found **6 vulnerabilities**:

- **HIGH severity:** 2 findings
  - Generic password detection (hardcoded database password)
  - DynamoDB table not encrypted
- **MEDIUM severity:** 2 findings
  - RDS instance publicly accessible
  - EC2 instance monitoring disabled
- **INFO severity:** 2 findings
  - EC2 not EBS optimized
  - DynamoDB point-in-time recovery disabled

### 1.4: Terraform vs. Pulumi Comparison

| Aspect | Terraform (HCL) | Pulumi (YAML) |
|--------|-----------------|---------------|
| **Vulnerabilities Found** | 53-78 (varies by tool) | 6 (KICS only) |
| **Detection Tools** | Multiple specialized tools | Primarily KICS |
| **Configuration Style** | Declarative, resource-focused | Declarative with some programmability |
| **Security Issues** | Broad range: IAM, networking, encryption | Focused on secrets and basic misconfigurations |

**KICS Pulumi Support Evaluation:** KICS provides excellent support for Pulumi YAML manifests with dedicated queries for AWS, Azure, GCP, and Kubernetes resources. However, it detected fewer issues than the specialized Terraform tools.


## Task 2 — Ansible Security Scanning with KICS

### 2.1: Ansible Security Issues Found

KICS identified **9 vulnerabilities** in the Ansible playbooks:

- **HIGH severity (8 findings):**
  - Passwords and secrets in URLs (2 instances)
  - Generic password detection (6 instances)
- **LOW severity (1 finding):**
  - Unpinned package version

### 2.2: Best Practice Violations

1. **Hardcoded Secrets in Playbooks** - Database passwords and API keys stored directly in YAML files
2. **Secrets in Inventory Files** - SSH passwords and database credentials in plaintext
3. **Unpinned Package Versions** - Using `state: latest` instead of specific versions
4. **Weak Authentication** - Using root user with default SSH port

### 2.3: KICS Ansible Queries Evaluation

KICS demonstrates strong capabilities for Ansible security scanning with comprehensive query coverage including:
- Secrets management issues
- Authentication vulnerabilities
- File permissions and access control
- Command execution security
- Configuration best practices


### 2.4: Remediation Steps

*Instead of hardcoded passwords -> Use Ansible Vault*

*Instead of root user ->*
ansible_user: appuser
ansible_become: yes
ansible_become_user: root

*Instead of latest ->*
- name: Install nginx
  apt:
    name: nginx=1.18.0-0ubuntu1  # Pin specific version
    state: present

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1: Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 15 (Pulumi + Ansible) |
| **Scan Speed** | Fast | Medium | Medium | Fast |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | Multiple | Multiple | Multiple |
| **Output Formats** | JSON, text, SARIF | JSON, CLI, SARIF | JSON, human | JSON, HTML, text |
| **CI/CD Integration** | Easy | Easy | Medium | Easy |
| **Unique Strengths** | Terraform specialization | Comprehensive checks | Policy as code | Multi-framework support |

### 3.2: Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|-------------------|-------|---------|-----------|---------------|----------------|-----------|
| **Encryption Issues** | ✅ | ✅ | ✅ | ✅ | ❌ | Checkov |
| **Network Security** | ✅ | ✅ | ✅ | ✅ | ❌ | tfsec |
| **Secrets Management** | ❌ | ✅ | ❌ | ✅ | ✅ | KICS |
| **IAM/Permissions** | ✅ | ✅ | ✅ | ❌ | ❌ | Checkov |
| **Access Control** | ✅ | ✅ | ✅ | ❌ | ✅ | Checkov |
| **Compliance/Best Practices** | ✅ | ✅ | ✅ | ✅ | ✅ | Checkov |

### 3.3: Top 5 Critical Findings

1. **Public RDS Database Access** (CRITICAL)
   - **Issue:** RDS instances configured with `publicly_accessible = true`
   - **Impact:** Database exposed to internet, potential data breach
   - **Remediation:** Set `publicly_accessible = false` and use private subnets

2. **Overly Permissive Security Groups** (CRITICAL)
   - **Issue:** Security groups allowing ingress from `0.0.0.0/0`
   - **Impact:** All ports open to internet
   - **Remediation:** Restrict CIDR blocks to specific IP ranges or security groups

3. **Hardcoded Database Passwords** (HIGH)
   - **Issue:** Database credentials in plaintext configuration files
   - **Impact:** Credential exposure, potential unauthorized access
   - **Remediation:** Use secret management (Vault, AWS Secrets Manager, etc.)

4. **Unencrypted Storage** (HIGH)
   - **Issue:** S3 buckets and DynamoDB tables without encryption
   - **Impact:** Data at rest not protected
   - **Remediation:** Enable `server_side_encryption_configuration` for S3 and `serverSideEncryption` for DynamoDB

5. **IAM Wildcard Permissions** (HIGH)
   - **Issue:** IAM policies with `*` permissions
   - **Impact:** Privilege escalation, excessive access
   - **Remediation:** Follow principle of least privilege, use specific resource ARNs

### 3.4: Tool Selection Guide

**For Terraform-focused teams:**
- **Primary:** Checkov (comprehensive detection)
- **Secondary:** tfsec (fast feedback)
- **CI/CD:** Terrascan (policy enforcement)

**For Multi-framework IaC:**
- **Primary:** KICS (broad platform support)
- **Secondary:** Checkov (deep Terraform analysis)

**For Enterprise/Compliance:**
- **Primary:** Checkov + Terrascan (policy as code)
- **Secondary:** KICS (multi-cloud support)

### 3.5: Lessons Learned

1. **Tool Complementarity:** Different tools excel at different types of vulnerabilities - using multiple tools provides comprehensive coverage
2. **False Positives:** All tools generated some false positives, particularly around default configurations
3. **Performance Trade-offs:** Faster tools (tfsec) provide quick feedback but may miss complex issues
4. **Platform Maturity:** Terraform has more mature tooling ecosystem compared to newer frameworks like Pulumi
5. **Secrets Detection:** KICS excels at secrets detection across multiple IaC frameworks

### 3.6: CI/CD Integration Strategy

Run tfsec first for fast feedback, then Checkov for comprehensive scanning, Terrascan for policy enforcement, and KICS for Pulumi security checks.

### 3.7: Justification for Recommendations

My tool selection strategy prioritizes:
- **Coverage:** Using tools that complement each other to maximize vulnerability detection
- **Integration:** Tools with strong CI/CD support for automated security gates
- **Maintenance:** Tools with active development and good documentation
- **Cost-effectiveness:** Open-source tools to avoid vendor lock-in

The recommended pipeline provides layered security scanning with fast feedback (tfsec) followed by comprehensive analysis (Checkov/KICS), ensuring both developer experience and security coverage.
