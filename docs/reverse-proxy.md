# Running behind an external reverse proxy

Touchstone bundles Caddy by default. When you want to terminate TLS or route
multiple services through one edge — typically with OPNsense / Traefik /
nginx / a separate Caddy — start the stack with the `external-proxy`
profile:

```bash
docker compose --profile external-proxy up -d
```

That **omits the bundled Caddy** and binds the API + UI directly on the
host.

## Make the ports reachable

By default the host-side ports bind to `127.0.0.1` only so a misconfigured
firewall never accidentally exposes Touchstone to the public internet. When
your reverse proxy is on a different machine, set these in `.env`:

```dotenv
TOUCHSTONE_UI_EXPOSE=0.0.0.0
TOUCHSTONE_API_EXPOSE=0.0.0.0
```

Or pin to the LAN interface IP if you prefer tighter scoping.

After editing `.env`, recreate so the new bind takes effect:

```bash
docker compose up -d
```

`docker compose ps` should now show `0.0.0.0:3010->3000/tcp` (and similarly
for the API). If it still shows `127.0.0.1:...` the env var wasn't picked
up.

## Default ports

| Service | Default host port |
|---------|-------------------|
| UI      | **3010**          |
| API     | **8090**          |
| Grafana | 3011              |
| Authentik (optional profile) | 9010 |

These are offset from Crucible IAP's defaults (3000 / 8080 / 3001 / 9000)
so both products can run on a single host.

## Reverse-proxy routing

Touchstone exposes **three distinct path prefixes** from the API + a
catch-all for the UI. Your reverse proxy must route them correctly:

| Path | Goes to | Why |
|------|---------|-----|
| `/api/*` | API (default port 8090) | REST API. Path is **not** stripped — Echo expects the full `/api/v1/...`. |
| `/auth/*` | API (default port 8090) | Login, logout, OIDC callback. Same rule — keep the prefix. |
| `/healthz` | API (default port 8090) | Liveness probe. |
| `/grafana/*` | Grafana (default port 3011), prefix **stripped** | Grafana is configured with `GF_SERVER_SERVE_FROM_SUB_PATH=true` so it expects to receive requests rooted at `/`. |
| everything else | UI (default port 3010) | SvelteKit SSR catch-all. |

### Example: Caddy

```caddyfile
touchstone.example.com {
    handle /api/* {
        reverse_proxy touchstone-host:8090
    }
    handle /auth/* {
        reverse_proxy touchstone-host:8090
    }
    handle /healthz {
        reverse_proxy touchstone-host:8090
    }
    handle_path /grafana/* {
        reverse_proxy touchstone-host:3011
    }
    handle {
        reverse_proxy touchstone-host:3010
    }
}
```

Note `handle` (preserves the path) for API / auth / healthz, and
`handle_path` (strips the prefix) for `/grafana/*`.

### Example: nginx

```nginx
server {
    listen 443 ssl http2;
    server_name touchstone.example.com;

    # Note: NO trailing slash on the API proxy_pass — nginx must forward
    # the full path including /api/ or /auth/ to Echo.
    location /api/    { proxy_pass http://touchstone-host:8090; }
    location /auth/   { proxy_pass http://touchstone-host:8090; }
    location = /healthz { proxy_pass http://touchstone-host:8090; }

    # Trailing slash on Grafana — that strips the /grafana prefix.
    location /grafana/ { proxy_pass http://touchstone-host:3011/; }

    location /        { proxy_pass http://touchstone-host:3010; }

    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Real-IP $remote_addr;
    # Recommended for SSE / long polling (Touchstone doesn't use them yet
    # but workers may surface scan log streams in a future release).
    proxy_buffering off;
    proxy_read_timeout 300s;
}
```

### Example: Traefik (Docker labels)

Touchstone's services are not Traefik-aware out of the box, but if you
already run Traefik on the same Docker network you can attach labels via a
compose override. Drop this into `compose.override.yml` next to your
`docker-compose.yml`:

```yaml
services:
  touchstone-ui:
    networks: [traefik]
    labels:
      traefik.enable: "true"
      traefik.http.routers.touchstone-ui.rule: "Host(`touchstone.example.com`)"
      traefik.http.routers.touchstone-ui.entrypoints: "websecure"
      traefik.http.routers.touchstone-ui.tls.certresolver: "le"
      traefik.http.services.touchstone-ui.loadbalancer.server.port: "3000"

  touchstone-api:
    networks: [traefik]
    labels:
      traefik.enable: "true"
      traefik.http.routers.touchstone-api.rule: "Host(`touchstone.example.com`) && (PathPrefix(`/api`) || PathPrefix(`/auth`) || Path(`/healthz`))"
      traefik.http.routers.touchstone-api.entrypoints: "websecure"
      traefik.http.routers.touchstone-api.tls.certresolver: "le"
      traefik.http.routers.touchstone-api.priority: "10"
      traefik.http.services.touchstone-api.loadbalancer.server.port: "8080"

networks:
  traefik:
    external: true
```

The API router has a higher `priority` so the path-prefix match wins over
the UI catch-all. Both services use their **internal container ports**
(8080 / 3000), not the host-side bumped ports, because Traefik attaches
on the Docker network.

### Example: HAProxy (OPNsense, pfSense, standalone)

OPNsense ships HAProxy out of the box; the GUI generates a config behind
the scenes. The relevant fragment:

```haproxy
frontend touchstone_https
    bind *:443 ssl crt /var/etc/touchstone.pem
    mode http
    http-request set-header X-Forwarded-Proto https

    acl is_touchstone   hdr(host) -i touchstone.example.com
    acl path_api        path_beg /api/
    acl path_auth       path_beg /auth/
    acl path_healthz    path /healthz
    acl path_grafana    path_beg /grafana/

    use_backend touchstone_api      if is_touchstone path_api
    use_backend touchstone_api      if is_touchstone path_auth
    use_backend touchstone_api      if is_touchstone path_healthz
    use_backend touchstone_grafana  if is_touchstone path_grafana
    use_backend touchstone_ui       if is_touchstone

backend touchstone_api
    mode http
    server touchstone touchstone-host:8090 check

backend touchstone_grafana
    mode http
    # Trailing slash + http-request set-path strips the /grafana prefix.
    http-request set-path %[path,regsub(^/grafana,)]
    server touchstone touchstone-host:3011 check

backend touchstone_ui
    mode http
    server touchstone touchstone-host:3010 check
```

In the OPNsense web UI: **Services → HAProxy → Settings → Conditions** for
the ACLs, **Real Servers** for the three backends, **Public Services** to
bind 443. Tedious but reliable.

### Example: Apache HTTPD

```apache
<VirtualHost *:443>
    ServerName touchstone.example.com
    SSLEngine on
    # ...your usual cert config...

    ProxyPreserveHost On
    ProxyRequests Off

    ProxyPass        /api/     http://touchstone-host:8090/api/
    ProxyPassReverse /api/     http://touchstone-host:8090/api/

    ProxyPass        /auth/    http://touchstone-host:8090/auth/
    ProxyPassReverse /auth/    http://touchstone-host:8090/auth/

    ProxyPass        /healthz  http://touchstone-host:8090/healthz
    ProxyPassReverse /healthz  http://touchstone-host:8090/healthz

    ProxyPass        /grafana/ http://touchstone-host:3011/
    ProxyPassReverse /grafana/ http://touchstone-host:3011/

    ProxyPass        /         http://touchstone-host:3010/
    ProxyPassReverse /         http://touchstone-host:3010/

    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

`mod_proxy_http` + `mod_proxy` + `mod_ssl` + `mod_headers` enabled.

## Headers your proxy must forward

Every reverse-proxy snippet above sets at minimum these three:

| Header | Why |
| ------ | --- |
| `Host` | SvelteKit checks the incoming Host against `ORIGIN` (= `TOUCHSTONE_BASE_URL`). If the proxy rewrites or drops this, the UI returns 502 / 403. |
| `X-Forwarded-Proto` | The UI uses this to decide cookie `Secure` attribute and OIDC redirect URLs. **Must be `https`** if TLS terminates at the edge. |
| `X-Forwarded-For` (or `X-Real-IP`) | Audit log entries record the client IP via Echo's `c.RealIP()`. Without forwarding, every audit row stamps the proxy's IP instead of the real client. |

Echo trusts `X-Forwarded-For` by default — operators with stricter
threat models can tighten via `echo.IPExtractor` config, but that's a
deployment-specific decision out of scope for this doc.

## Cookies / SameSite

Touchstone uses a single HttpOnly session cookie (`touchstone_session`)
set by `POST /auth/login` or the OIDC callback. The cookie is:

- `HttpOnly: true`
- `Secure: true` when `TOUCHSTONE_ENV=production` (the Compose default)
- `SameSite: Lax`
- `Path: /`

This works correctly when **the UI and API are served from the same
public origin** — i.e. the reverse proxy routes both `/` and `/api/`
under one hostname. That is the only supported topology for v0.1.x.

Cross-origin setups (UI on `app.example.com`, API on `api.example.com`)
need a `SameSite=None` cookie + CORS configuration; not currently
supported. If you need it, file an issue and we'll prioritize it.

## TLS termination model

Touchstone assumes **TLS terminates at the edge** (your reverse proxy)
and that the connection from proxy → Touchstone is HTTP. The UI and API
listen plain HTTP on their respective ports.

If you need end-to-end TLS (proxy → Touchstone over HTTPS), the
recommended path is:

1. Drop a sidecar Caddy (or stunnel) in front of `touchstone-ui` +
   `touchstone-api` on the same Docker network, terminating internal
   TLS with a private CA-issued cert.
2. Have your edge proxy talk to the sidecar over HTTPS.

This is a self-imposed constraint, not a Touchstone limitation — the
binaries themselves don't refuse HTTPS, but the Compose stack isn't
shipped with internal TLS plumbing.

## Sub-path deployment (not supported)

Touchstone must be served at the **root of its hostname**. Serving from
`https://example.com/touchstone/` would require the UI's SSR + asset
prefix and the API's route base to be reconfigurable, which they
currently are not. Use a dedicated hostname.

## TOUCHSTONE_BASE_URL must match the public URL

SvelteKit's `adapter-node` (the UI runtime) checks the `ORIGIN` env var on
every request. The Compose file feeds `TOUCHSTONE_BASE_URL` straight into
`ORIGIN`. Mismatch shows up as a 502 / 403 from the UI.

Set it to the **public URL** scheme + host, no path:

```dotenv
TOUCHSTONE_BASE_URL=https://touchstone.example.com
```

Not `http://...` if you're behind TLS at the edge; not the LAN IP; not
trailing slash.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| 502 from upstream, no log entries in API/UI | UI port still bound to `127.0.0.1` — reverse proxy can't reach it. Set `TOUCHSTONE_UI_EXPOSE=0.0.0.0`. |
| `{"message":"Not Found"}` returned as JSON on `/` | Reverse proxy is sending `/` to the API instead of the UI. Re-check `handle` vs default routing. |
| `/api/v1/me` returns 404 | Reverse proxy is stripping the `/api` prefix. Use `handle` (not `handle_path`) in Caddy, or omit the trailing slash on the proxy_pass target in nginx. |
| Login form posts, page reloads, no session cookie set | Mismatched `TOUCHSTONE_BASE_URL` vs the URL in the browser. Update `.env` and `docker compose up -d` to refresh `ORIGIN`. |
