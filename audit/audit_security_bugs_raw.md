1. Backend (FastAPI):

```
# main.py
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from sqlalchemy import text

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/user")
async def get_user(request: Request):
	user = request.query_params.get("username")

	# Missing Authentication

	# SQL Injection vulnerability below

	query = f"SELECT * FROM users WHERE username = '{user}'"

	result = db.session.execute(text(query)).fetchall()
	return templates.TemplateResponse("results.html", {"request": request, "results": result})
```

```
// UserSearch.jsx
import { useState } from 'react';

export default function UserSearch() {
		const [username, setUsername] = useState('');

		const searchUser = async () => {

			# DOM XSS bug below

			# IDOR bug below. Attacker can retrieve someone

			# else's username without authentication

			const response = await fetch(`/user?username=${username}`);
			const html = await response.text();
			document.getElementById('results').innerHTML = html;
		};

		return (
			<div>
				<input
					type="text"
					value={username}
					onChange={(e) => setUsername(e.target.value)}
					placeholder="Enter username"
				/>
				<button onClick={searchUser}>Search</button>
				<div id="results"></div>
			</div>
		);
}
```

```
<!-- templates/results.html -->
<h1>Results</h1>
<ul>
	{% for row in results %}
		<li>{{ row }}</li>
	{% endfor %}
</ul>
```
