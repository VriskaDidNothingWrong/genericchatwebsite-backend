import paginate, re

from flask import abort, g, jsonify, redirect, render_template, request, url_for
from sqlalchemy import func
from sqlalchemy.orm import joinedload

from charat2.helpers import alt_formats
from charat2.helpers.auth import permission_required
from charat2.model import AdminLogEntry, Message, SpamlessFilter
from charat2.model.connections import use_db


@alt_formats({"json"})
@use_db
@permission_required("spamless")
def home(fmt=None, page=1):

    messages = (
        g.db.query(Message)
        .filter(Message.spam_flag != None)
        .order_by(Message.id.desc())
        .options(
            joinedload(Message.chat),
            joinedload(Message.user),
            joinedload(Message.chat_user)
        )
        .offset((page - 1) * 50).limit(50).all()
    )

    if len(messages) == 0 and page != 1:
        abort(404)

    message_count = (
        g.db.query(func.count('*'))
        .select_from(Message)
        .filter(Message.spam_flag != None)
        .scalar()
    )

    if fmt == "json":
        return jsonify({
            "total": message_count,
            "messages": [_.to_dict(include_spam_flag=True) for _ in messages],
        })

    paginator = paginate.Page(
        [],
        page=page,
        items_per_page=50,
        item_count=message_count,
        url_maker=lambda page: url_for("spamless_home", page=page),
    )

    return render_template(
        "admin/spamless/home.html",
        messages=messages,
        paginator=paginator,
    )

def _list(spamlist, **kwargs):
    if spamlist not in ("banned_names", "blacklist", "warnlist"):
        spamlist = "warnlist"

    if spamlist == "warnlist":
        title = "Warnlist"
    elif spamlist == "blacklist":
        title = "Blacklist"
    else:
        title = "Banned names"

    return render_template(
        "admin/spamless/list.html",
        title=title,
        phrases=g.db.query(SpamlessFilter).filter(SpamlessFilter.type == spamlist).all(),
        spamless_list=spamlist,
        **kwargs
    )

def _list_post(spamlist, **kwargs):
    if spamlist not in ("banned_names", "blacklist", "warnlist"):
        spamlist = "warnlist"

    # Validate the command is either adding or removing.
    if request.form["command"] not in ("add", "remove"):
        return _list(spamlist)

    # Consume and validate the arguments.
    phrase = log_message = request.form["phrase"].strip().lower()
    score = request.form.get("score")
    if not phrase:
        abort(400)

    try:
        re.compile(phrase)
    except re.error as e:
        return _list(
            spamlist,
            error=e.args[0]
        )

    if spamlist == "blacklist":
        if request.form["command"] == "add":
            log_message = "%s (%s)" % (phrase, score)

    g.db.add(AdminLogEntry(
        action_user=g.user,
        type="spamless:%s:%s" % (spamlist, request.form["command"]),
        description=log_message
    ))

    handle_command(request.form["command"], phrase, spamlist, score)

    g.redis.publish("spamless:reload", 1)

    return redirect(url_for("spamless_" + spamlist))


@use_db
@permission_required("spamless")
def banned_names():
    return _list("banned_names")


@use_db
@permission_required("spamless")
def banned_names_post():
    return _list_post("banned_names")


@use_db
@permission_required("spamless")
def blacklist():
    return _list("blacklist")


@use_db
@permission_required("spamless")
def blacklist_post():
    return _list_post("blacklist")


@use_db
@permission_required("spamless")
def warnlist():
    return _list("warnlist")


@use_db
@permission_required("spamless")
def warnlist_post():
    return _list_post("warnlist")


# Helper functions
def handle_command(command, phrase, filtertype, points=0):
    try:
        points = int(points.strip())
    except ValueError:
        abort(400)
    except AttributeError:
        pass

    if command == "add":
        g.db.add(SpamlessFilter(
            type=filtertype,
            regex=phrase,
            points=points
        ))
    else:
        g.db.query(SpamlessFilter).filter(SpamlessFilter.type == filtertype).filter(SpamlessFilter.regex == phrase).delete()

    g.db.commit()

