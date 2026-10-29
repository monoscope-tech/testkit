# Stand-in for Claude: the first reply is malformed so testkit has to retry with the error.
import json, sys
q = json.load(sys.stdin)
assert "textbox \"Email\"" in q["context"], q["context"]
if not q["error"]:
    print('- click: button "Sign in')
else:
    print('''```yaml
- fill: field "Email" with "admin@acme.com"
- fill: field "Password" with "hunter22"
- click: button exactly "Sign in"
- expect: heading "Dashboard" is visible
```''')
