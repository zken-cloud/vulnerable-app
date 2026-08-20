# CodeMender Demo: Vulnerable App (SAST Bypass)

A Node.js application containing **13 intentional vulnerabilities** designed to evade detection by standard Static Application Security Testing (SAST) tools, specifically built for CodeMender demos. 

Traditional SAST tools typically rely on standard data flow analysis (taint tracking), known vulnerable sink signatures, and explicit control-flow graph pattern matching. This application implements vulnerabilities that break these assumptions in subtle, realistic ways.

## Running the Application

```bash
npm install
npm start
```
The server binds to port 3000.

---

## Vulnerabilities & SAST Evasion Mechanics

### 1. Memory Leak (Lexical Closure Scope)
**Endpoint:** `GET /api/memory`
**Why SAST misses it:** SAST models reassignment but does not simulate the V8 garbage collector. We capture a massive string within an unused closure that references the main object's lexical environment. SAST sees safe assignment, missing the heap exhaustion logic entirely.

### 2. Buffer Allocation Data Leak
**Endpoint:** `GET /api/buffer?size=N`
**Why SAST misses it:** Tools flag explicit `new Buffer` or `allocUnsafe` usage. We construct the method name dynamically (`'al' + 'locUnsa' + 'fe'`) and invoke it using dynamic bracket notation. SAST simply views this as property dynamic access, ignoring the uninitialized memory returned.

### 3. Business Logic Race Condition (TOCTOU)
**Endpoint:** `POST /api/transfer`
**Why SAST misses it:** Event loop asynchronous task shifting is rarely modeled by AST taint tracking. We deduct funds immediately *after* an `await` instruction, opening a window where concurrent requests pass the check. SAST sees properly checked validation bounds and declares the flow safe.

### 4. Prototype Pollution via Deep Merge
**Endpoint:** `POST /api/settings`
**Why SAST misses it:** The vulnerability hides in a classic recursive object merging utility commonly used by developers. Since there are no hardcoded assignments to `__proto__` and it looks like a generic data map, SAST ignores it as standard configuration assembly.

### 5. Command Injection via Shallow Clone (spawn bypass)
**Endpoint:** `POST /api/ping`
**Why SAST misses it:** Standard tools flag `exec` but allow `spawn` under the assumption `shell: false` is safe. The application initializes it as false, but uses `Object.assign` to shallow merge user options, allowing an attacker to inject `shell: true`. Data flow tracing frequently loses property values mapped across Object methods.

### 6. SSRF via Type Confusion
**Endpoint:** `POST /api/fetch`
**Why SAST misses it:** Input validates URL structure via string manipulation (`String(target.url)`). However, an attacker passes a JSON object (`{ url: "http://safe.com", host: "127.0.0.1", port: 6379 }`). Because Node's `http.get()` API natively resolves connection parameters directly from objects polymorphically, the string validation is entirely bypassed. SAST fails to see the type-confusion disconnect.

### 7. Remote Code Execution via Constructor Extraction
**Endpoint:** `POST /api/evaluate`
**Why SAST misses it:** Calling `eval` or `new Function` is an immediate red flag. We instead extract the constructor contextually via `[].sort.constructor("return ...")()`. SAST interprets this as an Array prototype manipulation and completely fails to flag the code execution sink.

### 8. Path Traversal via Improper Regex State
**Endpoint:** `GET /api/download?file=...`
**Why SAST misses it:** The code contains an explicit vulnerability sanitization step replacing `../` globally. SAST records this boundary check. An attacker sends `....//`, which evaluates to `../` *after* the non-recursive evaluation completes. SAST assumes regex checks are holistically secure.

### 9. ReDoS via Dynamically Appended AST Nodes
**Endpoint:** `POST /api/validate`
**Why SAST misses it:** SAST specifically parses hardcoded JS `RegExp` literal tokens (`/.../g`). When a catastrophic backtracking pattern is built piecemeal out of strings (mixing server bounds and user strings) and wrapped in `new RegExp(str)`, local parsing engines cannot calculate the vulnerability matrix. 

### 10. Cryptographic Timing Attack 
**Endpoint:** `POST /api/webhook`
**Why SAST misses it:** Custom security enforcement checking strings manually in a loop instead of using `crypto.timingSafeEqual`. SAST sees an entirely valid business logic data loop returning `true` or `false` and does not track sub-millisecond CPU timing channels as data taint routes.

### 11. Insecure PRNG Randomness
**Endpoint:** `GET /api/reset-link`
**Why SAST misses it:** `Math.random` is frequently disabled in SAST engines as a vulnerability if the function name lacks cryptographic semantic context. By naming the context generator `generateSessionContextId` and blending it with Date strings, it escapes static identification.

### 12. Mass Assignment Parameter Tampering
**Endpoint:** `PUT /api/profile/:id`
**Why SAST misses it:** To an AST tracer, an explicit blocklist (filtering out `id` and `createdAt`) demonstrates security intent. It lacks the business awareness to understand that the `role` property shouldn't be mapped dynamically by an attacker over an abstract `Object.keys()` database update.

### 13. Logical NoSQL-Style Syntax Injection
**Endpoint:** `POST /api/search`
**Why SAST misses it:** Custom data filtering arrays processing JSON payloads (`$ne`, `$in`) look like normal AST dictionary evaluations. There is no external driver or SQL injection sink connected to the function. It is purely logical manipulation that evades all string-binding analyzers.
