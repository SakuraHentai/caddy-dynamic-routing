# Caddy dynamic routing & certificate plugin

### Usage

xcaddy build --with github.com/SakuraHentai/caddy-dynamic-routing

### Caddyfile Example

See [Caddyfile](Caddyfile)

### Dev build

Run `./build.sh`

### Redis Data Structure

Use `Hash` with key `${prefix}:${host}`, and field by `tokenKey` & `certKey`

### Motivation

In the Saas business model, a tenant identifies their site by token, for example `abc.example.com`.

At this point, we would allow them to bind their own domain to their site, establishing a relationship between `www.self-domain.com` -> `abc.example.com`.

This is what **routing** does.

Using dynamic certificates instead of acme is more of a business model, such as selling ssl certificates.
