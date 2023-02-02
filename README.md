# Caddy dynamic routing & certificate plugin

### Usage

xcaddy build --with=https://github.com/SakuraHentai/caddy-dynamic-routing

### Caddyfile Example

See [Caddyfile](Caddyfile)

### Dev build

Run `./build.sh`

### Redis Data Structure

Use `Hash` with key `${prefix}:${host}`, and field by `tokenKey` & `certKey`
