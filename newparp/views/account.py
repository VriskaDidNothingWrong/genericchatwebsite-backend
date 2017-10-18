from bcrypt import gensalt, hashpw
from flask import abort, g, jsonify, render_template, redirect, request, url_for
from sqlalchemy import func
from sqlalchemy.orm.exc import NoResultFound
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from newparp.helpers import alt_formats
from newparp.helpers.auth import not_logged_in_required
from newparp.helpers.email import send_email
from newparp.model import User
from newparp.model.connections import use_db
from newparp.model.validators import username_validator, email_validator, reserved_usernames


def referer_or_home():
    if "Referer" in request.headers:
        r = urlparse(request.headers["Referer"])
        return r.scheme + "://" + r.netloc + r.path
    return url_for("home")


@use_db
def get_user():
    res = {
        "token": g.csrf_token,
        "logged_in": False
    }

    if g.user:
        res["profile"] = g.user.to_dict(include_options=True)
        res["logged_in"] = True

    return jsonify(res)


@alt_formats({"json"})
@not_logged_in_required
@use_db
def log_in_post(fmt="json"):

    # Check username, lowercase to make it case-insensitive.
    try:
        user = g.db.query(User).filter(
            func.lower(User.username) == request.form["username"].lower()
        ).one()
    except NoResultFound:
        return jsonify({"error": "login_no_user"}), 400

    # Check password.
    if not user.check_password(request.form["password"]):
        return jsonify({"error": "login_wrong_password"}), 400

    g.redis.set("session:" + g.session_id, user.id, 2592000)

    return jsonify({
        "profile": user.to_dict(include_options=True)
    })


def log_out():
    if "newparp" in request.cookies:
        g.redis.delete("session:" + request.cookies["newparp"])
        # XXX/TODO CONSTANTS FILE
        g.redis.expire("session:%s:csrf" % g.session_id, 3600)

    res = {
        "token": g.csrf_token,
        "logged_in": False,
        "profile": {}
    }

    return jsonify(res)


@not_logged_in_required
@use_db
def register_post():

    if g.redis.exists("register:" + request.headers.get("X-Forwarded-For", request.remote_addr)):
        return jsonify({"error": "register_ip"}), 400

    # Don't accept blank fields.
    if request.form["username"] == "" or request.form["password"] == "":
        return jsonify({"error": "register_blank"}), 400

    # Make sure the two passwords match.
    if request.form["password"] != request.form["password_again"]:
        return jsonify({"error": "register_passwords_didnt_match"}), 400

    # Check email address against email_validator.
    # Silently truncate it because the only way it can be longer is if they've hacked the front end.
    email_address = request.form.get("email_address").strip()[:100]
    if not email_address:
        return jsonify({"error": "register_blank_email"}), 400
    if email_validator.match(email_address) is None:
        return jsonify({"error": "register_invalid_email"}), 400

    # Make sure this email address hasn't been taken before.
    if g.db.query(User.id).filter(
        func.lower(User.email_address) == email_address.lower()
    ).count() != 0:
        return jsonify({"error": "register_email_taken"}), 400

    # Check username against username_validator.
    # Silently truncate it because the only way it can be longer is if they've hacked the front end.
    username = request.form["username"][:50]
    if username_validator.match(username) is None:
        return jsonify({"error": "register_invalid_username"}), 400

    # Make sure this username hasn't been taken before.
    # Also check against reserved usernames.
    if username.startswith("guest_") or g.db.query(User.id).filter(
        func.lower(User.username) == username.lower()
    ).count() == 1 or username.lower() in reserved_usernames:
        return jsonify({"error": "register_username_taken"}), 400

    new_user = User(
        username=username,
        email_address=email_address,
        group="new",
        last_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
    )
    new_user.set_password(request.form["password"])
    g.db.add(new_user)
    g.db.flush()
    g.redis.set("session:" + g.session_id, new_user.id, 2592000)
    g.redis.setex("register:" + request.headers.get("X-Forwarded-For", request.remote_addr), 86400, 1)

    g.user = new_user
    send_email("welcome", email_address)

    g.db.commit()

    return jsonify({
        "profile": new_user.to_dict(include_options=True)
    })

