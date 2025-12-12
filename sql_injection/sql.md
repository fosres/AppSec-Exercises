NOTE: You shouldn't tell me which lines are vulnerable in the code

snippets for the questions :)

Ans to Exercise 12:

1. Yes

2. No

3. This question is not fair since I have not yet learned DELETE

statements yet for Week 1. You asked me to learn the first six lessons

from `sqlbolt.com` remember?

4. Below is the fix:

```
query = "DELETE FROM posts WHERE id = ? AND user_id = ?"

cursor.execute(query,(post_id,user_id))
```

Ans to Exercise 13:

1. Yes

2. No, the attacker can enclose the query with single quote and ')'

followed by a UNION Injection Attack.

3. Payload:

```
1) UNION SELECT id, username, password_hash from admin_users--
```

4. I don't think this is a fair question for Week 1? Still, here is

my best guess:

```
query = f"SELECT id, name, price FROM products WHERE category_id IN (%s,%s,%s)"
	
cursor.execute(query,(category_ids,))
```

Ans to Exercise 14:

1. `get_author_comments()` for now

2. The following line in `get_author_comments()` is vulnerable:

```
query = f"SELECT comment_text, created_at FROM comments WHERE author_name = '{author_name_from_db}' ORDER BY created_at DESC"
```

3. Payload:

```
Hemingway' UNION SELECT id, title from posts--
```

4. Fix:

```
	query = "SELECT comment_text, created_at FROM comments WHERE author_name = %s ORDER BY created_at DESC"
	cursor.execute(query,(author_name_from_db,))
```
