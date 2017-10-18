import traceback

from flask import render_template, request, g, jsonify, current_app


def error_403(e):
    return jsonify({"error": f"You're not allowed to access the page at {request.path}."}), 403


def error_404(e):
    return jsonify({"error": f"{request.path} could not be found."}), 404


def error_500(e):
    res = {
        "error": "Internal Server Error"
    }
    is_admin = False

    if "sentry" in current_app.extensions:
        current_app.extensions["sentry"].captureException()

    # Add the Sentry ID if we can.
    if hasattr(g, "sentry_event_id"):
        res["internal_id"] = g.sentry_event_id

    # Add the real exception info if we are an admin.
    if hasattr(g, "user") and g.user:
        admin = g.user.is_admin

    if admin:
        res["exception"] = traceback.format_exc()
        res["you_are_not_supposed_to_see_this"] = "https://i.imgur.com/GEbaQ8I.gif"

    return jsonify(res), 500

