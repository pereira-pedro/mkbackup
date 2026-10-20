"""Server-rendered enrollment forms; no secrets in URLs or client-side storage."""

import hashlib
import re
import secrets
from datetime import datetime, timezone
from html import escape
from urllib.parse import parse_qs, quote

from control_rpc import ControlError


def routes(app, path, method, environ, start, token, session):
    if not (path in ("/admin/enroll", "/admin/enrollments") or path.startswith("/admin/enrollments/")):
        return None
    owner = hashlib.sha256(token.encode()).hexdigest()
    csrf = app.sessions.csrf_token(token)
    field = '<input type="hidden" name="csrf" value="' + csrf + '">'
    navigation = '<p><a href="/admin/">Backups</a> · <a href="/admin/enrollments">Enrollments</a> · <a href="/admin/enroll">Enroll router</a></p>'
    if method == "POST":
        form = app.form(environ)
        if not app.sessions.csrf_valid(session, form.get("csrf", "")):
            raise ControlError("Invalid form; refresh and try again", 403)
    elif method != "GET":
        raise ControlError("Method not allowed", 405)
    if path == "/admin/enrollments" and method == "GET":
        result = app.provisioner.request("list")
        body = (
            navigation
            + "<h1>Router enrollment</h1><p>Installer delivery and successful backup archival are separate states.</p><table><tr><th>Router</th><th>Enrollment status</th><th>Action</th></tr>"
        )
        for row in result["routers"]:
            action = (
                '<a href="/admin/enroll?router=' + quote(row["name"], safe="") + '">Reissue unused installer</a>'
                if row["reissuable"]
                else "Delivered/imported — use CLI recovery"
            )
            body += (
                "<tr><td>"
                + escape(row["name"])
                + "</td><td>"
                + ("Awaiting installer delivery" if row["reissuable"] else "Delivery locked")
                + "</td><td>"
                + action
                + "</td></tr>"
            )
        body += "</table><h2>Recent enrollment jobs</h2><table><tr><th>Router</th><th>Status</th></tr>"
        for row in result["jobs"]:
            body += (
                "<tr><td>"
                + escape(row["router"])
                + '</td><td><a href="/admin/enrollments/'
                + row["id"]
                + '">'
                + escape(row["state"])
                + "</a></td></tr>"
            )
        body += "</table>"
        return app.respond(start, 200, app.page("Enrollment", body))
    if path == "/admin/enroll":
        if method == "GET":
            try:
                query = parse_qs(environ.get("QUERY_STRING", ""), max_num_fields=2)
                if set(query) - {"major", "router"} or any(len(value) != 1 for value in query.values()):
                    raise ValueError()
                major = int(query.get("major", ["6"])[0])
                if major not in (6, 7):
                    raise ValueError()
            except ValueError:
                raise ControlError("Invalid enrollment query") from None
            result = app.provisioner.request("list")
            defaults = result["defaults"]
            name = query.get("router", [""])[0]
            action = "create"
            if name:
                router = next((row for row in result["routers"] if row["name"] == name), None)
                if router is None or not router["reissuable"]:
                    raise ControlError("Router is imported or its installer was delivered; use CLI recovery", 409)
                major, action = router["major"], "reissue"
            label = "RouterOS 6.49.x — plaintext FTP" if major == 6 else "Compatible RouterOS 7 — SFTP"
            body = navigation + "<h1>" + ("Reissue unused installer" if name else "Enroll router") + "</h1>"
            if not name:
                body += '<p>Profile: <a href="/admin/enroll?major=6">RouterOS 6.49.x</a> · <a href="/admin/enroll?major=7">RouterOS 7 SFTP</a></p>'
            body += "<p>" + label + "</p>"
            if major == 6:
                body += '<p class="error">FTP exposes credentials and exports in transit. HTTPS protects enrollment and receipts only.</p>'
            body += '<form method="post" action="/admin/enroll">' + field
            for key, value in (("major", major), ("action", action), ("request", secrets.token_hex(32))):
                body += '<input type="hidden" name="' + key + '" value="' + str(value) + '">'
            for key, label, value, kind in (
                ("name", "Stable router name", name, "text"),
                ("host", "Router-reachable server IPv4", defaults["host"], "text"),
                ("port", "Published transport port", defaults["ftp_port" if major == 6 else "sftp_port"], "number"),
                ("job_owner", "RouterOS installing job owner", "admin", "text"),
            ):
                body += (
                    "<label>"
                    + label
                    + '<input name="'
                    + key
                    + '" type="'
                    + kind
                    + '" value="'
                    + escape(str(value), quote=True)
                    + '" required'
                    + (" readonly" if key == "name" and name else "")
                    + "></label>"
                )
            body += (
                '<button type="submit">Prepare installer</button></form><p>The address and port must reach this instance. They do not change server listeners or firewall rules. HTTPS download origin: '
                + escape(defaults["base_url"])
                + "</p>"
            )
            return app.respond(start, 200, app.page("Enroll router", body))
        if set(form) != {"csrf", "major", "action", "request", "name", "host", "port", "job_owner"} or form[
            "action"
        ] not in ("create", "reissue"):
            raise ControlError("Invalid enrollment fields")
        try:
            major, port = int(form["major"]), int(form["port"])
        except ValueError:
            raise ControlError("Invalid profile or port") from None
        spec = dict(name=form["name"], major=major, host=form["host"], port=port, job_owner=form["job_owner"])
        job = app.provisioner.request(form["action"], spec=spec, owner=owner, request=form["request"])
        return app.redirect(start, "/admin/enrollments/" + job["id"])
    match = re.fullmatch(r"/admin/enrollments/([a-f0-9]{64})(/instructions)?", path)
    if not match:
        raise ControlError("Enrollment not found", 404)
    job = match.group(1)
    if match.group(2):
        if method != "POST" or set(form) != {"csrf"}:
            raise ControlError("POST required", 405)
        result = app.provisioner.request("instructions", id=job, owner=owner)
        commands = (
            '/tool fetch url="'
            + result["base_url"]
            + '/" check-certificate=yes http-header-field="Authorization: Bearer '
            + result["token"]
            + '" dst-path=mkbackup-install.rsc\n/import file-name=mkbackup-install.rsc'
        )
        body = (
            navigation
            + "<h1>Private installation commands</h1><p>Shown once. Paste both commands into the configured RouterOS administrator context. Do not share or retain this credential-bearing page.</p><pre><code>"
            + escape(commands)
            + "</code></pre><p>Expires at "
            + datetime.fromtimestamp(result["expires_at"], timezone.utc).isoformat()
            + " UTC. Initial archival still needs to succeed on the router.</p>"
        )
        return app.respond(start, 200, app.page("Installation commands", body))
    if method != "GET":
        raise ControlError("GET required", 405)
    state = app.provisioner.request("job", id=job, owner=owner)
    body = (
        navigation
        + "<h1>Enrollment: "
        + escape(state["router"])
        + "</h1><p>Status: <strong>"
        + escape(state["state"])
        + "</strong></p>"
    )
    if state["error"]:
        body += '<p class="error">' + escape(state["error"]) + "</p>"
    if state["instructions_available"]:
        body += (
            '<form method="post" action="/admin/enrollments/'
            + job
            + '/instructions">'
            + field
            + "<button>Show installation commands once</button></form>"
        )
    body += (
        '<p><a href="/admin/enrollments/'
        + job
        + '">Refresh status</a> · <a href="/admin/routers/'
        + quote(state["router"], safe="")
        + '">View archived backups</a></p><p>Enrollment readiness does not confirm a backup. Run the commands and verify archival.</p>'
    )
    return app.respond(start, 200, app.page("Enrollment status", body))
