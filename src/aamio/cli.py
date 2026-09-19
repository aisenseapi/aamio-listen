"""Command line for aamio.

    aamio init [--tags a,b]        make a key and an inbox, print your identity
    aamio whoami                   your key, hash prefix and inbox
    aamio partner add NAME KEY     add a partner from the contract
    aamio partner list
    aamio partner remove NAME
    aamio lookup [NAME ...]        who is online now
    aamio send NAME TEXT           encrypt, sign, send
    aamio read [--wait 25]         read new messages
    aamio receipt [--channel inbox] [--anchor]
    aamio scope new NAME           a scope with a key from the system's secure generator
    aamio scope add NAME --key KEY | --address ADDRESS
    aamio scope list               names, addresses and whether each can read
    aamio scope key NAME           the key, to pass on by hand
    aamio scope share NAME PARTNER --access read|write
    aamio scope remove NAME
    aamio serve                    MCP server on stdio


Environment: AAMIO_HOME (default ~/.aamio) and AAMIO_TAGS, and AAMIO_HOST, AAMIO_BOARD
and AAMIO_VERIFYUM over the hosts at the top of aamio/client.py.
"""

import argparse
import json
import sys

from . import __version__
from .gate import GateStop
from .runtime import Runtime, SendFailed, send_advice, BOARD_TTL


def out(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def send_failed(error, operation):
    """A send that stored nothing, as JSON and not as a traceback.

    One command is one process, so an exception that escaped was a traceback on
    stderr, and the message id a retry needs was nowhere in it. Unknown is not
    failure: the message may be on the other side, and sending it again as a
    new message makes a second one. What goes again is the stored bytes, and
    here there is a command for that.
    """
    retryable, _ = send_advice(error.outcome, error.status)

    if error.outcome == "unknown":
        fix = ("No answer came back, so this message may already have been delivered. Do not send it again as a new message: "
               "`aamio outbox retry --id %s` sends the same stored bytes again, and a copy that did land is marked a replay where it arrives. "
               "`aamio outbox pending` lists what has no settled outcome on this machine." % error.message_id)
    elif retryable:
        fix = ("aamio declined this for now, not because of the message: %s is a rate window or a busy service. Do not change the content. "
               "Wait, then run `aamio outbox retry --id %s`, which sends the stored bytes again." % (error.status, error.message_id))
    else:
        fix = send_advice(error.outcome, error.status)[1]

    out({"error": str(error), "error_code": "send_" + error.outcome, "operation": operation, "outcome": error.outcome, "message_id": error.message_id, "status": error.status, "retryable": retryable, "fix": fix})

    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aamio", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--home", default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--no-archive", action="store_true", help="do not keep decrypted messages and receipts locally")
    parser.add_argument("--version", action="version", version="aamio " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init")
    p.add_argument("--tags", default=None, help="comma separated presence tags")
    sub.add_parser("whoami")
    p = sub.add_parser("partner")
    ps = p.add_subparsers(dest="action", required=True)
    pa = ps.add_parser("add")
    pa.add_argument("name")
    pa.add_argument("key")
    ps.add_parser("list")
    pr = ps.add_parser("remove")
    pr.add_argument("name")
    p = sub.add_parser("lookup")
    p.add_argument("names", nargs="*")
    p.add_argument("--wait", type=int, default=0)
    p = sub.add_parser("send")
    p.add_argument("to")
    p.add_argument("text")
    p.add_argument("--data", default=None, help="JSON object")
    p = sub.add_parser("read")
    p.add_argument("--wait", type=int, default=0)
    p = sub.add_parser("receipt")
    p.add_argument("--channel", default="inbox")
    p.add_argument("--anchor", action="store_true")
    p = sub.add_parser("channel")
    cs = p.add_subparsers(dest="action", required=True)
    co = cs.add_parser("open")
    co.add_argument("label")
    co.add_argument("--ttl", type=int, default=600)
    co.add_argument("--allow", default=None, help="comma separated partner names")
    cs.add_parser("list")
    cc = cs.add_parser("close")
    cc.add_argument("label")
    p = sub.add_parser("board")
    bs = p.add_subparsers(dest="board_command", required=True)
    bp = bs.add_parser("post")
    bp.add_argument("kind", choices=["need", "offer"])
    bp.add_argument("title")
    bp.add_argument("text")
    bp.add_argument("--tags", default="")
    bp.add_argument("--ttl", type=int, default=BOARD_TTL)
    bp.add_argument("--lang")
    bp.add_argument("--deadline")
    bp.add_argument("--scope", help="the name of one of your scopes: the post is then unlisted, and unlisted is not private")
    bf = bs.add_parser("find")
    bf.add_argument("--kind", choices=["need", "offer"])
    bf.add_argument("--tags", default="")
    bf.add_argument("--lang")
    bf.add_argument("--after", type=int, default=0)
    bf.add_argument("--wait", type=int, default=0)
    bf.add_argument("--min-work-bits", type=int, default=0, help="keep only posts whose work_bits is at least this; 1 means any work, 16 is what the board advises")
    bf.add_argument("--scope", help="the name of a scope you hold with its key: read that scope instead of the public board")
    bs.add_parser("tags")
    ba = bs.add_parser("answer")
    ba.add_argument("post")
    ba.add_argument("text")
    ba.add_argument("--scope", help="the name of the scope the post is in")
    br = bs.add_parser("replies", help="answers to your posts. This filters. read shows everything on the inbox, including messages that name no post and bodies that could not be opened")
    br.add_argument("--post")
    br.add_argument("--wait", type=int, default=0)
    bw = bs.add_parser("withdraw")
    bw.add_argument("post")
    bc = bs.add_parser("channel")
    bc.add_argument("key")
    bc.add_argument("--ttl", type=int, default=900)
    bc.add_argument("--reply-to")
    bc.add_argument("--note")

    p = sub.add_parser("scope")
    ss = p.add_subparsers(dest="scope_command", required=True)
    sn = ss.add_parser("new")
    sn.add_argument("name")
    sa = ss.add_parser("add")
    sa.add_argument("name")
    sa.add_argument("--key", help="26 to 64 characters of a-z and 0-9: read and post. A key typed here stays in the shell history, so scope share from runtime to runtime is better")
    sa.add_argument("--address", help="the 20 characters that go on a post: post only")
    ss.add_parser("list")
    sk = ss.add_parser("key")
    sk.add_argument("name")
    sh = ss.add_parser("share")
    sh.add_argument("name")
    sh.add_argument("partner")
    sh.add_argument("--access", choices=["read", "write"], required=True)
    sr = ss.add_parser("remove")
    sr.add_argument("name")

    p = sub.add_parser("outbox")
    os_ = p.add_subparsers(dest="outbox_command", required=True)
    os_.add_parser("pending")
    orr = os_.add_parser("retry")
    orr.add_argument("--id")
    ofg = os_.add_parser("forget")
    ofg.add_argument("id")

    sub.add_parser("serve")

    args = parser.parse_args(argv)
    tags = [t for t in args.tags.split(",") if t] if getattr(args, "tags", None) else None
    try:
        runtime = Runtime(home=args.home, host=args.host, tags=tags, archive=not args.no_archive, log=lambda line: print(line, file=sys.stderr))
    except RuntimeError as error:
        # Another runtime holds the home, or a file in it cannot be read. The
        # reason is the whole message, and it is not a crash.
        print("aamio: %s" % error, file=sys.stderr)
        return 1
    try:
        return run(args, runtime)
    finally:
        # One command, one process: the lock goes with it, as in aamio-php.
        # Left behind, the next command had to guess from a pid whether an
        # old owner still lived, and on Windows pids come back quickly. Only
        # the lock: every command saves what it changed as it goes, and a
        # save on the way out would write files a command only read.
        runtime.release()


def run(args, runtime):
    if args.command == "init":
        runtime.ensure_inbox()
        runtime.save_state()
        out(runtime.whoami())
    elif args.command == "whoami":
        out(runtime.whoami())
    elif args.command == "partner":
        if args.action == "add":
            runtime.partner_add(args.name, args.key)
        elif args.action == "remove":
            runtime.partner_remove(args.name)
        out({"partners": runtime.partner_list()})
    elif args.command == "lookup":
        runtime.ensure_inbox()
        out(runtime.lookup(args.names or None, args.wait))
    elif args.command == "send":
        data = json.loads(args.data) if args.data else None
        try:
            out(runtime.send(args.to, args.text, data))
        except SendFailed as failed:
            return send_failed(failed, "send")
        except GateStop as stop:
            # Not a crash: the inbox asked for something this client does not
            # do, nothing was sent, and the reader needs the reason and the way on.
            out({"error": stop.reason, "error_code": "gate", "fix": stop.fix})
            return 1
    elif args.command == "read":
        # attention carries what the read could not do. Without it an expired
        # thread and a service that did not answer both read as "no messages".
        messages = runtime.read(args.wait)
        out({"messages": messages, "count": len(messages), "attention": runtime.attention_taken()})
    elif args.command == "receipt":
        out(runtime.receipt(args.channel, args.anchor))
    elif args.command == "channel":
        if args.action == "open":
            out(runtime.open_channel(args.label, args.ttl, [n for n in args.allow.split(",") if n] if args.allow else None))
        elif args.action == "list":
            out({"channels": runtime.channel_list()})
        else:
            out(runtime.close_channel(args.label))
    elif args.command == "board":
        tags = [t for t in getattr(args, "tags", "").split(",") if t]
        if args.board_command == "post":
            out(runtime.board_post(args.kind, args.title, args.text, tags, args.ttl, args.lang, args.deadline, args.scope))
        elif args.board_command == "find":
            out(runtime.board_find(args.kind, tags, args.lang, None, args.after, args.wait, args.min_work_bits, args.scope))
        elif args.board_command == "tags":
            out(runtime.board_tags())
        elif args.board_command == "answer":
            try:
                out(runtime.board_answer(args.post, args.text, scope=args.scope))
            except SendFailed as failed:
                return send_failed(failed, "board_answer")
            except GateStop as stop:
                out({"error": stop.reason, "error_code": "gate", "fix": stop.fix})
                return 1
        elif args.board_command == "replies":
            if args.wait:
                runtime.read(args.wait)
            # The address comes with the answers. An empty list means one of
            # two very different things, and only this tells them apart.
            replies = runtime.board_replies(args.post)
            # How many messages this left out, every time and not only when it
            # found nothing: an answer that names no post is still somebody
            # answering, and a list of two with a third left out said nothing
            # about the third.
            left_out = getattr(runtime, "board_replies_left_out", 0)
            answer = {"replies": replies, "left_out": left_out, "reply_address": runtime.board_reply_address()}
            if left_out:
                answer["note"] = "%d message(s) on your inboxes are not listed here, because they name no post of yours and did not arrive on a board inbox. aamio read shows every message." % left_out
            if args.post is not None:
                # What else is on the board inbox, so an empty list for one
                # post is never read as an empty inbox.
                everything = runtime.board_replies()
                answer["others_on_the_board_inbox"] = len(everything) - len(replies)
            # Last, so it carries what both calls above had to say.
            answer["attention"] = runtime.attention_taken()
            out(answer)
        elif args.board_command == "withdraw":
            out(runtime.board_withdraw(args.post))
        else:
            out(runtime.open_channel_with(args.key, args.ttl, None, args.reply_to, args.note))
    elif args.command == "scope":
        if args.scope_command == "new":
            out(runtime.scope_new(args.name))
        elif args.scope_command == "add":
            out(runtime.scope_add(args.name, args.key, args.address))
        elif args.scope_command == "list":
            out({"scopes": runtime.scope_list()})
        elif args.scope_command == "key":
            out(runtime.scope_key(args.name))
        elif args.scope_command == "share":
            out(runtime.scope_share(args.name, args.partner, args.access))
        else:
            out(runtime.scope_remove(args.name))
    elif args.command == "outbox":
        if args.outbox_command == "pending":
            out({"pending": runtime.outbox_pending()})
        elif args.outbox_command == "retry":
            out({"retried": runtime.outbox_retry(args.id)})
        else:
            out(runtime.outbox_forget(args.id))
    elif args.command == "serve":
        from .mcp_server import serve

        serve(runtime)
    return 0


if __name__ == "__main__":
    sys.exit(main())
