# elagoht/basicauth

A collage plugin that puts HTTP Basic authentication in front of a site — a
staging deployment, a preview, a site not launched yet. Registering it is the
whole of it: every request then needs a name and password, and the browser asks
for them.

```go
app, err := collage.New(&collage.Config{
	Plugins: []collage.Plugin{basicauth.New(basicauth.Options{
		Users: map[string]string{"team": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
	})},
})
```

Requires collage v0.24.0 or later.

## Users

`Users` maps a name to a password, written one of three ways:

| Written as | |
| --- | --- |
| `open sesame` | In plain text |
| `sha256:9f86d0…` | The hex of the password's SHA-256 — `printf %s 'pw' \| shasum -a 256` |
| `$2a$10$…` | A bcrypt hash (`$2a$`, `$2b$` or `$2y$`) — `htpasswd -bnBC 10 "" 'pw' \| tr -d ':'` |

A plain password that happens to begin with `sha256:` or `$2` is written with
`plain:` in front of it.

Every comparison takes the same time whether it fails early or late, and a name
nobody has is checked against a password nobody has: how long a refusal takes
says nothing about which names exist.

bcrypt is slow on purpose — tens of milliseconds a check. A reader who signed in
sends the password again with every request, so a successful check is remembered
for the life of the process (up to 1024 of them, under a key made at startup)
rather than paid for on every page. A failed one is paid for every time, which is
the point of bcrypt and also a way to spend the server's CPU; put
[elagoht/ratelimit](https://github.com/Elagoht/collage-ratelimit) in front of it
if the site is exposed.

The application will not start with no users: a site nobody can sign in to is a
mistake, not a configuration.

## Keeping secrets out of files

`COLLAGE_BASICAUTH_USERS` adds users from the environment, and wins over a user of
the same name in the options:

```sh
COLLAGE_BASICAUTH_USERS='team:sha256:9f86d0…,ops:$2a$10$…'
```

The name ends at the first colon. A password in it cannot contain a comma; give
such a password as a hash.

## One binary, open in production

`Disabled` turns the plugin off — from the plugin configuration of the deployment
that should be open, or with `COLLAGE_BASICAUTH_DISABLED=true` in its environment.
A disabled plugin needs no users, and logs once that the site is open.

```json
{ "elagoht/basicauth": { "disabled": true } }
```

## Which paths

`Protect` lists the path prefixes that need a sign-in, by default `/`, everything.
`Skip` lists those that never do, even under `Protect`, by default `/healthz` and
`/_collage/`: a load balancer's health check has no password, and neither does
collage's development reload stream.

A prefix covers whole segments: `/healthz` covers `/healthz` and `/healthz/db`, not
`/healthz-report`. collage redirects a path with dot segments or doubled slashes
to its clean spelling before any middleware runs, so `/_collage/../admin` arrives
as `/admin` and is asked for a password like any other. The plugin does not rely on
that alone: a path with dot segments or doubled slashes is never skipped.

A request without the right name and password is answered `401` with
`WWW-Authenticate: Basic realm="Restricted", charset="UTF-8"`, a one-line text
body and `Cache-Control: no-store`. `Realm` names the dialog.

## Caches in between

collage's page cache is in the server, behind this plugin: a request that did not
sign in is refused before the cache is asked, so the cache holding a page does not
put it in front of anyone.

A CDN is another matter. A shared cache must not store a response to a request
that carried `Authorization` — **unless the response says it may**, and `public`
says so. collage sends `Cache-Control: public, …` on every cached page, which is
right for a public site and exactly wrong behind a password: the first reader to
sign in would fill the CDN, and it would hand the page to the next reader without
asking.

So every authenticated response leaves with `public` and `s-maxage` replaced by
`private` — `public, max-age=0, must-revalidate` becomes `private, max-age=0,
must-revalidate` — and with `Vary: Authorization`, for any cache that reads that
rather than the directives. The browser still caches as it would; only shared
caches are shut out. A response already `no-store` is left alone.

## Configuration

```json
{
  "elagoht/basicauth": {
    "users": { "team": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" },
    "realm": "Staging",
    "protect": ["/"],
    "skip": ["/healthz", "/_collage/"],
    "disabled": false
  }
}
```

A name with a colon, an empty password, a `sha256:` value that is not 64 hex
digits, a bcrypt hash bcrypt cannot read, a realm with quotes in it, a prefix
without a leading `/` — each stops the application from starting.

## Limitations

- **Basic authentication sends the password with every request**, encoded, not
  encrypted. Serve the site over HTTPS, or anyone on the network reads it.
- There is no signing out: a browser keeps sending the credentials until it is
  closed. It is a gate for a staging site, not an account system.
- The plugin wraps requests, and a static build makes none: a built site carries
  no password. Protect it where it is served.
- A CDN that ignores both `private` and `Vary` — some can be configured to cache
  everything — defeats any origin's headers. Do not tell the CDN in front of a
  protected site to cache regardless of them.
- It applies in development too, unless disabled there: registering it with
  users is taken to mean you want the gate.

## Changes

### v0.1.1

- README: collage v0.24.0 cleans paths before middleware; the plugin keeps refusing to skip a path with dot segments or doubled slashes as a second line.
- Requires collage v0.24.0.
