"""Password-protected HTML administration; payloads are brokered over a Unix socket."""

import json
import math
import re
from html import escape
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from urllib.parse import parse_qs, quote, urlencode

from admin_enrollment import routes as enrollment_routes
from admin_sessions import COOKIE, Sessions
from archive_rpc import ArchiveError, Client
from control_rpc import Client as ProvisioningClient
from control_rpc import ControlError

CSS = """body{font:16px system-ui,sans-serif;color:#172536;background:#f4f6f9;margin:0}
main{max-width:1200px;margin:3rem auto;padding:0 1.25rem}a{color:#1456a0}header{display:flex;align-items:center;justify-content:space-between;gap:1rem}
form{display:flex;flex-wrap:wrap;align-items:center;gap:.7rem;margin:1rem 0}input,button,.button{font:inherit;padding:.6rem .8rem;border:1px solid #bac5d0;border-radius:5px}
button,.button{background:#1456a0;color:white;cursor:pointer;text-decoration:none}input{min-width:12rem}table{border-collapse:collapse;width:100%;background:white}
th,td{padding:.9rem;text-align:left;border-bottom:1px solid #dce2e9}th{background:#e9eef5}.scroll{overflow-x:auto}code{font-size:.8rem;overflow-wrap:anywhere}
.error{color:#a51d25}.muted{color:#526477}nav{display:flex;gap:1rem;margin:1.5rem 0}.login{max-width:30rem}label{font-weight:600}
"""


def audit(event, **fields):
    print(json.dumps(dict(event=event, **fields), sort_keys=True), flush=True)


def human_size(size):
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{size} B"
        value /= 1024


class Application:
    def __init__(self, sessions=None, reader=None, provisioner=None):
        self.sessions, self.reader = sessions or Sessions(), reader or Client()
        self.provisioner = provisioner or ProvisioningClient()

    def __call__(self, environ, start_response):
        try:
            return self.dispatch(environ, start_response)
        except (ArchiveError, ControlError) as error:
            return self.respond(
                start_response,
                error.status,
                self.page(
                    "Backup unavailable",
                    '<p class="error">' + escape(str(error)) + '</p><p><a href="/admin/">Return to routers</a></p>',
                ),
            )
        except Exception:
            audit("admin_request_failed")
            return self.respond(start_response, 503, self.page("Console unavailable", "<p>Please retry shortly.</p>"))

    @staticmethod
    def respond(start, status, body=b"", kind="text/html; charset=utf-8", extra=()):
        if isinstance(body, str):
            body = body.encode()
        headers = [
            ("Content-Type", kind),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store, private"),
            ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            (
                "Content-Security-Policy",
                "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            ),
            ("X-Frame-Options", "DENY"),
        ]
        start(f"{status} {HTTPStatus(status).phrase}", headers + list(extra))
        return [body]

    @staticmethod
    def page(title, content):
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            "<title>"
            + escape(title)
            + ' · mkbackup</title><link rel="stylesheet" href="/admin/assets/style.css"></head><body><main>'
            + content
            + "</main></body></html>"
        )

    def redirect(self, start, location, cookie=None):
        extra = [("Location", location)]
        if cookie is not None:
            extra.append(
                (
                    "Set-Cookie",
                    f"{COOKIE}={cookie}; Path=/admin/; Secure; HttpOnly; SameSite=Strict"
                    + ("; Max-Age=0" if not cookie else ""),
                )
            )
        return self.respond(start, 303, extra=extra)

    @staticmethod
    def cookie(environ):
        cookies = SimpleCookie()
        try:
            cookies.load(environ.get("HTTP_COOKIE", ""))
            return cookies[COOKIE].value if COOKIE in cookies else ""
        except CookieError:
            return ""

    def form(self, environ):
        if environ.get("CONTENT_TYPE", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
            raise ArchiveError(400, "Invalid form")
        try:
            length = int(environ.get("CONTENT_LENGTH", "0"))
        except ValueError:
            raise ArchiveError(400, "Invalid form") from None
        if not 1 <= length <= 4096:
            raise ArchiveError(400, "Invalid form")
        try:
            raw = environ["wsgi.input"].read(length)
            if len(raw) != length:
                raise ValueError()
            value = parse_qs(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=8)
        except (ValueError, UnicodeError):
            raise ArchiveError(400, "Invalid form") from None
        if any(len(items) != 1 for items in value.values()):
            raise ArchiveError(400, "Invalid form")
        return {key: items[0] for key, items in value.items()}

    @staticmethod
    def navigation(total, page, base, query=None):
        pages = max(1, math.ceil(total / 50))
        links = []
        for number, label in ((page - 1, "Previous"), (page + 1, "Next")):
            if 1 <= number <= pages:
                params = dict(query or {}, page=number)
                links.append('<a href="' + escape(base + "?" + urlencode(params), quote=True) + '">' + label + "</a>")
        return (
            '<nav aria-label="Pagination">'
            + f"<span>Page {page} of {pages} · {total} results</span>"
            + "".join(links)
            + "</nav>"
        )

    def dispatch(self, environ, start):
        path, method = environ.get("PATH_INFO", ""), environ.get("REQUEST_METHOD", "GET")
        if path == "/healthz" and method == "GET":
            self.reader.request("health")
            return self.respond(start, 200, b"ok\n", "text/plain")
        if path == "/admin/assets/style.css" and method == "GET":
            return self.respond(start, 200, CSS, "text/css; charset=utf-8")
        token = self.cookie(environ)
        session = self.sessions.get(token)
        if path == "/admin/login":
            if method == "GET":
                if session and session["authenticated"]:
                    return self.redirect(start, "/admin/")
                token, csrf = self.sessions.create(replace=token)
                body = self.page(
                    "Admin login",
                    '<section class="login"><h1>mkbackup administration</h1><p>Sign in to browse and download managed backups.</p>'
                    '<form action="/admin/login" method="post"><input type="hidden" name="csrf" value="' + csrf + '">'
                    '<label for="password">Admin password</label><input id="password" name="password" type="password" autocomplete="current-password" required>'
                    '<button type="submit">Sign in</button></form></section>',
                )
                return self.respond(
                    start,
                    200,
                    body,
                    extra=[("Set-Cookie", f"{COOKIE}={token}; Path=/admin/; Secure; HttpOnly; SameSite=Strict")],
                )
            if method == "POST":
                form = self.form(environ)
                if not self.sessions.csrf_valid(session, form.get("csrf", "")):
                    return self.respond(
                        start,
                        403,
                        self.page("Request rejected", '<p>Invalid form. <a href="/admin/login">Sign in again</a>.</p>'),
                    )
                if not self.sessions.check_password(form.get("password", "")):
                    audit("admin_login_failed")
                    self.sessions.revoke(token)
                    return self.respond(
                        start,
                        401,
                        self.page(
                            "Sign-in failed",
                            '<p class="error">Incorrect password.</p><a href="/admin/login">Try again</a>',
                        ),
                        extra=[
                            ("Set-Cookie", f"{COOKIE}=; Path=/admin/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
                        ],
                    )
                token, _ = self.sessions.create(authenticated=True, replace=token)
                audit("admin_login_succeeded")
                return self.redirect(start, "/admin/", token)
        if not session or not session["authenticated"]:
            if path.endswith("/download"):
                return self.respond(start, 401, "Authentication required\n", "text/plain")
            return self.redirect(start, "/admin/login")
        if path == "/admin/logout" and method == "POST":
            form = self.form(environ)
            if not self.sessions.csrf_valid(session, form.get("csrf", "")):
                return self.respond(start, 403, self.page("Request rejected", "<p>Invalid form.</p>"))
            self.sessions.revoke(token)
            audit("admin_logout")
            return self.redirect(start, "/admin/login", "")
        enrollment = enrollment_routes(self, path, method, environ, start, token, session)
        if enrollment is not None:
            return enrollment
        if method != "GET":
            return self.respond(start, 405, "Method not allowed\n", "text/plain", [("Allow", "GET")])
        if path == "/admin":
            return self.redirect(start, "/admin/")
        try:
            query = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True, max_num_fields=2)
            if set(query) - {"q", "page"} or any(len(values) != 1 for values in query.values()):
                raise ValueError()
            page = int(query.get("page", ["1"])[0])
            search = query.get("q", [""])[0].strip()
            if not 1 <= page <= 1000000 or len(search) > 128:
                raise ValueError()
        except ValueError:
            raise ArchiveError(400, "Invalid search or page") from None
        download = re.fullmatch(r"/admin/routers/([^/]+)/files/([^/]+)/download", path)
        if download:
            router, filename = download.groups()
            body = self.reader.request("download", router=router, filename=filename)
            try:
                metadata = body.metadata
                headers = [
                    ("Content-Type", "application/octet-stream"),
                    ("Content-Length", str(metadata["size"])),
                    ("Content-Disposition", f'attachment; filename="{metadata["filename"]}"'),
                    ("Cache-Control", "no-store, private"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Referrer-Policy", "no-referrer"),
                ]
                start("200 OK", headers)
                audit("admin_download_started", router=router, filename=metadata["filename"])
                return body
            except Exception:
                body.close()
                raise
        csrf = self.sessions.csrf_token(token)
        header = (
            '<header><h1><a href="/admin/">mkbackup</a></h1><a href="/admin/enrollments">Enroll routers</a><form action="/admin/logout" method="post">'
            '<input type="hidden" name="csrf" value="'
            + csrf
            + '"><button type="submit">Sign out</button></form></header>'
        )
        if path == "/admin/":
            result = self.reader.request("routers", query=search, page=page)
            content = (
                header
                + '<h2>Routers</h2><form action="/admin/" method="get"><label for="q">Router name</label><input id="q" name="q" value="'
                + escape(search, quote=True)
                + '"><button>Search</button></form>'
            )
            content += '<div class="scroll"><table><thead><tr><th>Router</th><th>Available backups</th><th>Latest archive (UTC)</th></tr></thead><tbody>'
            for row in result["items"]:
                content += (
                    '<tr><td><a href="/admin/routers/'
                    + quote(row["name"], safe="")
                    + '">'
                    + escape(row["name"])
                    + "</a></td><td>"
                    + ("Unavailable" if row["error"] else str(row["count"]))
                    + "</td><td>"
                    + escape(row["latest"] or "—")
                    + "</td></tr>"
                )
            if not result["items"]:
                content += '<tr><td colspan="3">No routers found.</td></tr>'
            content += "</tbody></table></div>" + self.navigation(result["total"], page, "/admin/", dict(q=search))
            return self.respond(start, 200, self.page("Routers", content))
        route = re.fullmatch(r"/admin/routers/([^/]+)", path)
        if route:
            router = route.group(1)
            result = self.reader.request("files", router=router, page=page)
            content = (
                header
                + '<p><a href="/admin/">All routers</a></p><h2>'
                + escape(router)
                + '</h2><p class="muted">Server archive timestamps are UTC.</p>'
            )
            content += '<div class="scroll"><table><thead><tr><th>Filename</th><th>Archived (UTC)</th><th>Size</th><th>SHA-256</th><th>Download</th></tr></thead><tbody>'
            for row in result["items"]:
                href = (
                    "/admin/routers/"
                    + quote(router, safe="")
                    + "/files/"
                    + quote(row["filename"], safe="")
                    + "/download"
                )
                content += (
                    "<tr><td>"
                    + escape(row["filename"])
                    + "</td><td>"
                    + escape(row["archived_at"])
                    + "</td><td>"
                    + human_size(row["size"])
                    + "</td><td><code>"
                    + escape(row["sha256"])
                    + '</code></td><td><a class="button" href="'
                    + href
                    + '">Download</a></td></tr>'
                )
            if not result["items"]:
                content += '<tr><td colspan="5">No available backups.</td></tr>'
            content += "</tbody></table></div>" + self.navigation(result["total"], page, path)
            return self.respond(start, 200, self.page(router, content))
        return self.respond(start, 404, self.page("Not found", "<p>Page not found.</p>"))


application = None


def app(environ, start_response):
    global application
    if application is None:
        application = Application()
    return application(environ, start_response)
