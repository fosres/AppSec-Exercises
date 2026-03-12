Case 1:

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

Case 2:

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
Case 3

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

modify template.

2. Below is sample payload:
