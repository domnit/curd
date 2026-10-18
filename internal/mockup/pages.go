package mockup

import "fmt"

func dashboardPage(authed bool) string {
	head := `<!doctype html><html><head><meta charset="utf-8"><title>Mock Dashboard</title></head><body>`
	nav := `<nav><a id="items-link" href="/items">Items</a> <a href="/settings">Settings</a></nav>`
	greet := `<a id="login-link" href="/login">Log in</a>`
	if authed {
		greet = `<h1 id="greeting">Hello alice</h1>`
	}
	return fmt.Sprintf(`%s%s%s<pre id="me"></pre>
<script>
fetch('/api/me').then(r => r.text()).then(t => { document.getElementById('me').textContent = t; });
</script></body></html>`, head, nav, greet)
}

const itemsPage = `<!doctype html><html><head><meta charset="utf-8"><title>Mock Items</title></head><body>
<h1>Items</h1><ul id="items"></ul>
<script>
fetch('/api/items/123').then(r => r.json()).then(i => {
  const li = document.createElement('li'); li.textContent = i.name;
  document.getElementById('items').appendChild(li);
});
</script></body></html>`

const loginPage = `<!doctype html><html><head><meta charset="utf-8"><title>Mock Login</title></head><body>
<form method="POST" action="/login">
<input id="username" name="username"><input id="password" name="password" type="password">
<button id="login-button" type="submit">Log in</button>
</form></body></html>`

const settingsPage = `<!doctype html><html><head><meta charset="utf-8"><title>Mock Settings</title>
<meta name="csrf-token" content="{{TOKEN}}"></head><body>
<h1>Settings</h1><button id="save">Save</button><pre id="result"></pre>
<script>
const token = document.querySelector('meta[name=csrf-token]').content;
document.getElementById('save').addEventListener('click', () => {
  fetch('/api/settings', {method: 'POST',
    headers: {'X-CSRF-Token': token, 'Content-Type': 'application/json'},
    body: JSON.stringify({theme: 'dark'})})
  .then(r => r.text().then(t => { document.getElementById('result').textContent = r.status + ' ' + t; }));
});
</script></body></html>`

const lsPage = `<!doctype html><html><head><meta charset="utf-8"><title>Mock LocalStorage</title></head><body>
<pre id="out"></pre>
<script>
const token = localStorage.authToken;
fetch('{{SCHEME}}://api.example.com:{{PORT}}/v1/me', {headers: {Authorization: 'Bearer ' + token}})
  .then(r => r.text().then(t => { document.getElementById('out').textContent = r.status + ' ' + t; }))
  .catch(e => { document.getElementById('out').textContent = 'error ' + e; });
</script></body></html>`
