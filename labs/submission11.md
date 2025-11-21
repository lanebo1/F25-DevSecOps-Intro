# Lab 11 Submission — Reverse Proxy Hardening

## Task 1 — Reverse Proxy Compose Setup (2 pts)

### Docker Compose Setup Results

**Certificate Generation:**

```bash
# Generated self-signed certificate with SAN for localhost
docker run --rm -v "$(pwd)/reverse-proxy/certs":/certs alpine:latest sh -c "apk add --no-cache openssl && cat > /tmp/san.cnf << 'EOF' && cat /tmp/san.cnf && openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /certs/localhost.key -out /certs/localhost.crt -config /tmp/san.cnf -extensions v3_req
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = localhost

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF"
```

**Service Status:**

```bash
$ docker compose ps
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     11 seconds ago   Up 10 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     10 seconds ago   Up 9 seconds    0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

**HTTP Redirect Verification:**

```bash
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/
HTTP 308
```

### Analysis

**Reverse Proxy Value:**
Reverse proxies are valuable for security because they provide:

- **TLS termination**: Handle SSL/TLS encryption at the proxy level
- **Security headers injection**: Add security headers without changing application code
- **Request filtering**: Filter and rate-limit requests before they reach the application
- **Single access point**: Only one service exposed to the internet, hiding internal architecture

**Attack Surface Reduction:**
Hiding direct app ports reduces attack surface by:

- Preventing direct access to application ports (3000/tcp in this case)
- Forcing all traffic through the hardened proxy layer

## Task 2 — Security Headers (3 pts)

### HTTP Headers (Redirect Response)

```bash
$ curl -sI http://localhost:8080/ | tee analysis/headers-http.txt
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 21 Nov 2025 13:53:33 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), geolocation=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### HTTPS Headers (Application Response)

```bash
$ curl -skI https://localhost:8443/ | tee analysis/headers-https.txt
HTTP/2 200
server: nginx
date: Fri, 21 Nov 2025 13:53:36 GMT
content-type: text/html; charset=UTF-8
content-length: 75002
feature-policy: payment 'self'
x-recruiting: /#/jobs
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Fri, 21 Nov 2025 13:53:25 GMT
etag: W/"124fa-19aa6b0f2e1"
vary: Accept-Encoding
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### Security Header Analysis

- **X-Frame-Options: DENY**: Prevents clickjacking attacks by denying the page from being embedded in frames/iframes
- **X-Content-Type-Options: nosniff**: Prevents MIME type sniffing, protecting against certain XSS attacks
- **Strict-Transport-Security (HSTS)**: Forces browsers to use HTTPS only, protects against protocol downgrade attacks
- **Referrer-Policy: strict-origin-when-cross-origin**: Controls referrer information sent with requests for privacy and security
- **Permissions-Policy: camera=(), geolocation=(), microphone=()**: Restricts access to sensitive browser APIs
- **COOP/CORP (Cross-Origin-Opener-Policy/Cross-Origin-Resource-Policy)**: Controls cross-origin resource sharing and opener policies
- **CSP-Report-Only**: Content Security Policy in report-only mode to monitor potential violations without blocking

## Task 3 — TLS, HSTS, Rate Limiting & Timeouts (5 pts)

### TLS/testssl Analysis

**Protocol Support:**

- SSLv2: not offered (OK)
- SSLv3: not offered (OK)
- TLS 1.0: not offered
- TLS 1.1: not offered
- TLS 1.2: offered (OK)
- TLS 1.3: offered (OK)

**Supported Cipher Suites:**

- TLSv1.2: ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256
- TLSv1.3: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256

**TLSv1.2+ Requirement Rationale:**
TLSv1.2+ is required because:

- TLS 1.0/1.1 have known security vulnerabilities (BEAST, POODLE, etc.)
- TLS 1.3 provides the strongest security with forward secrecy and modern cipher suites
- Older protocols can be exploited for man-in-the-middle attacks

**Testssl Warnings:**

- Chain of trust: NOT ok (self-signed) - expected for local development
- OCSP/CRL/CT/CAA: Not offered - expected without public CA certificate
- OCSP stapling: not offered - disabled in nginx.conf for self-signed cert

**HSTS Verification:**
HSTS header appears only on HTTPS responses: `strict-transport-security: max-age=31536000; includeSubDomains; preload`

### Rate Limiting & Timeouts

**Rate Limit Test Results:**

```bash
$ for i in $(seq 1 12); do curl -sk -o /dev/null -w "%{http_code}\n" -H 'Content-Type: application/json' -X POST https://localhost:8443/rest/user/login -d '{"email":"a@a","password":"a"}'; done | tee analysis/rate-limit-test.txt
401
401
401
401
401
401
429
429
429
429
429
429
```

**Rate Limit Analysis:**

- **Configuration**: `rate=10r/m`, `burst=5`
- **Behavior**: First 6 requests return 401 (invalid credentials), next 6 return 429 (rate limited)
- **Balance**: 10 requests/minute with burst allowance of 5 provides good security vs usability balance - prevents brute force attacks while allowing legitimate login attempts

**Timeout Settings Analysis:**
From nginx.conf:

- `client_body_timeout 10s`: Prevents slowloris attacks by limiting time to send request body
- `client_header_timeout 10s`: Prevents slowloris by limiting header transmission time
- `proxy_read_timeout 30s`: Reasonable timeout for upstream response reading
- `proxy_send_timeout 30s`: Reasonable timeout for sending data to upstream
- `keepalive_timeout 10s`: Balances connection reuse with resource management

**Trade-offs:**

- Shorter timeouts improve security against DoS but may cause issues with slow clients/networks
- Longer timeouts improve compatibility but increase resource consumption
- Current settings provide good balance for this application scenario

**Access Log Evidence:**

```bash
$ grep "429" logs/access.log | tail -6
172.19.0.1 - - [21/Nov/2025:13:54:50 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [21/Nov/2025:13:54:50 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [21/Nov/2025:13:54:50 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [21/Nov/2025:13:54:50 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [21/Nov/2025:13:54:50 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
172.19.0.1 - - [21/Nov/2025:13:54:50 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.5.0" rt=0.000 uct=- urt=-
```
