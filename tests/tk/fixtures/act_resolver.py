# Stand-in for Claude: a malformed reply, then a failing step, then the fix, so both retry paths run.
import json, sys
q = json.load(sys.stdin)
assert "textbox \"Email\"" in q["context"], q["context"]
err = q["error"] or ""
if not err:
    print('- click: button "Sign in')
elif "reply was" in err:
    print('- expect: heading "Welcome aboard" is visible\n  timeout: 300ms')
else:
    print('''```yaml
- fill: field "Email" with "admin@acme.com"
- fill: field "Password" with "hunter22"
- click: button exactly "Sign in"
- expect: heading "Dashboard" is visible
```''')
