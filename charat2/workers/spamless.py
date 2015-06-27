#!/usr/bin/python

import json
import signal

from redis import StrictRedis
from sqlalchemy import and_

from charat2.helpers.chat import send_message
from charat2.model import sm, ChatUser, Message
from charat2.model.connections import redis_pool


db = sm()
redis = StrictRedis(connection_pool=redis_pool)


class Silence(Exception):
    pass


def on_ps(ps_message):

    try:
        chat_id = int(ps_message["channel"].split(":")[1])
        data = json.loads(ps_message["data"])
    except (IndexError, KeyError, ValueError):
        return

    if "messages" not in data or len(data["messages"]) == 0:
        return

    for message in data["messages"]:

        if message["user_number"] is None:
            continue

        try:
            check_connection_spam(chat_id, message)
        except Silence, e:
            db.query(ChatUser).filter(and_(
                ChatUser.chat_id == chat_id,
                ChatUser.number == message["user_number"]
            )).update({"group": "silent"})
            send_message(db, redis, Message(
                chat_id=chat_id,
                type="spamless",
                name="The Spamless",
                acronym=u"\u264b",
                text="Spam has been detected and silenced.",
                color="626262"
            ), True)
            db.commit()


def check_connection_spam(chat_id, message):
    if message["type"] not in ("join", "disconnect", "timeout", "user_info"):
        return
    attempts = increx("antispam:join:%s:%s" % (chat_id, message["user_number"]), expire=5)
    if attempts <= 10:
        return
    raise Silence("connection_spam")


def increx(key, expire=60, incr=1):
    result = redis.incr(key, incr)
    redis.expire(key, expire)
    return result


def halt(signal=None, frame=None):
    print "Caught signal %s" % signal
    ps_thread.stop()


if __name__ == "__main__":

    signal.signal(signal.SIGTERM, halt)
    signal.signal(signal.SIGINT, halt)

    ps = redis.pubsub(ignore_subscribe_messages=True)
    ps.psubscribe(**{"channel:*": on_ps})
    ps_thread = ps.run_in_thread()

    while ps_thread.is_alive():
        redis.setex("spamless:alive", 10, "alive")
        ps_thread.join(3)
