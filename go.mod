// A collage plugin that puts HTTP Basic authentication in front of a staging or
// preview site, with plain, SHA-256 or bcrypt passwords, and keeps a CDN from
// handing a protected page to someone who never signed in.
module github.com/Elagoht/collage-basicauth

go 1.26.0

require github.com/Elagoht/collage v0.23.0

require golang.org/x/crypto v0.57.0
