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
    aamio serve                    MCP server on stdio

The command is also installed as aamio-listen, which is what it used to be called.

Environment: AAMIO_HOME (default ~/.aamio), AAMIO_HOST (default https://aamio.at), AAMIO_TAGS.
"""

import argparse
import json
import sys

from . import __version__
from .gate import GateStop
from .runtime import Runtime, BOARD_TTL


def out(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


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
    bf = bs.add_parser("find")
    bf.add_argument("--kind", choices=["need", "offer"])
    bf.add_argument("--tags", default="")
    bf.add_argument("--lang")
    bf.add_argument("--after", type=int, default=0)
    bf.add_argument("--wait", type=int, default=0)
    bf.add_argument("--min-work-bits", type=int, default=0, help="keep only posts whose work_bits is at least this; 1 means any work, 16 is what the board advises")
    bs.add_parser("tags")
    ba = bs.add_parser("answer")
    ba.add_argument("post")
    ba.add_argument("text")
    br = bs.add_parser("replies")
    br.add_argument("--post")
    br.add_argument("--wait", type=int, default=0)
    bw = bs.add_parser("withdraw")
    bw.add_argument("post")
    bc = bs.add_parser("channel")
    bc.add_argument("key")
    bc.add_argument("--ttl", type=int, default=900)
    bc.add_argument("--reply-to")
    bc.add_argument("--note")

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
    runtime = Runtime(home=args.home, host=args.host, tags=tags, archive=not args.no_archive, log=lambda line: print(line, file=sys.stderr))

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
        except GateStop as stop:
            # Not a crash: the inbox asked for something this client does not
            # do, nothing was sent, and the reader needs the reason and the way on.
            out({"error": stop.reason, "error_code": "gate", "fix": stop.fix})
            return 1
    elif args.command == "read":
        out({"messages": runtime.read(args.wait)})
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
            out(runtime.board_post(args.kind, args.title, args.text, tags, args.ttl, args.lang, args.deadline))
        elif args.board_command == "find":
            out(runtime.board_find(args.kind, tags, args.lang, None, args.after, args.wait, args.min_work_bits))
        elif args.board_command == "tags":
            out(runtime.board_tags())
        elif args.board_command == "answer":
            try:
                out(runtime.board_answer(args.post, args.text))
            except GateStop as stop:
                out({"error": stop.reason, "error_code": "gate", "fix": stop.fix})
                return 1
        elif args.board_command == "replies":
            if args.wait:
                runtime.read(args.wait)
            # The address comes with the answers. An empty list means one of
            # two very different things, and only this tells them apart.
            out({"replies": runtime.board_replies(args.post), "reply_address": runtime.board_reply_address()})
        elif args.board_command == "withdraw":
            out(runtime.board_withdraw(args.post))
        else:
            out(runtime.open_channel_with(args.key, args.ttl, None, args.reply_to, args.note))
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
