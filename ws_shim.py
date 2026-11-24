#!/usr/bin/env python3
"""WS event shim for the lvmtest drill.

Chain bug: this v6.1.9 devnet stops delivering APP-attribute WS subscriptions
(e.g. new_report.reporter_power > 0) within ~4 min of boot, while
tm.event='Tx' keeps working. LVM subscribes with the attribute query, so we
put a shim in front of quistis:26257 that:

- serves /websocket: acks any subscribe request from LVM, then forwards
  every tm.event='Tx' frame from upstream verbatim (frames carry the full
  result.events dict, which is what LVM parses; LVM ignores non-new_report
  frames itself);
- closes the LVM connection if the upstream subscription dies (node restart)
  so LVM's own reconnect + catch-up path fires;
- proxies plain HTTP through to the node RPC unchanged (LVM also uses
  http://{URI}/health and RPC via the same URI).

Run:  .venv/bin/python ws_shim.py   (listens on 0.0.0.0:26157)
"""
import asyncio
import json
import logging
import time

import aiohttp
import websockets
from aiohttp import web

UPSTREAM_RPC = "http://localhost:26257"
UPSTREAM_WS = "ws://localhost:26257/websocket"
LISTEN = ("0.0.0.0", 26157)

logging.basicConfig(level=logging.INFO, format="%(asctime)s shim %(message)s")
log = logging.getLogger("shim")


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    """Serve LVM's /websocket: ack subscribes, forward expanded tx events."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    out: asyncio.Queue = asyncio.Queue()

    async def upstream() -> None:
        """Hold a rotating tm.event='Tx' upstream sub, feeding the out queue."""
        # The node's WS event bus wedges per-subscription after a few minutes
        # (chain-side bug), so rotate the upstream subscription every ROTATE_S.
        ROTATE_S, last_rotate = 60.0, 0.0
        u = None
        try:
            while True:
                # make-before-break: subscribe the new connection before
                # closing the old one so rotations never drop events
                nu = await websockets.connect(UPSTREAM_WS, ping_interval=20, open_timeout=10)
                await nu.send(json.dumps({
                    "jsonrpc": "2.0", "method": "subscribe", "id": "shim",
                    "params": {"query": "tm.event='Tx'"},
                }))
                if u is not None:
                    await u.close()
                    log.info("rotated: old sub closed")
                u = nu
                last_rotate = time.monotonic()
                log.info("upstream subscribed (tm.event='Tx')")
                while True:
                        if time.monotonic() - last_rotate > ROTATE_S:
                            log.info("rotating upstream sub (tx_seen=%d sent=%d)", upstream.tx_seen, upstream.sent)
                            break
                        try:
                            msg = await asyncio.wait_for(u.recv(), timeout=2.0)
                        except TimeoutError:
                            continue
                        frame = json.loads(msg)
                        ev = (frame.get("result") or {}).get("events") or {}
                        txhash = (ev.get("tx.hash") or [None])[0]
                        height = (ev.get("tx.height") or [None])[0]
                        if not txhash:
                            continue
                        upstream.tx_seen += 1
                        log.info("tx#%d %s h=%s", upstream.tx_seen, txhash[:12], height)
                        flat = await expand_tx_events(txhash, height)
                        if flat is not None:
                            upstream.sent += 1
                            log.info("forward %s h=%s keys=%d", txhash[:12], height, len(flat))
                            await out.put(json.dumps({"jsonrpc": "2.0", "id": "shim", "result": {
                                "query": "new_report.reporter_power > 0",
                                "data": {"type": "tendermint/event/NewBlockEvents"},
                                "events": flat,
                            }}))
                        elif upstream.tx_seen % 25 == 0:
                            log.info("tx_seen=%d (no new_report in latest)", upstream.tx_seen)
        except Exception as e:  # noqa: BLE001
            log.warning("upstream died: %s", e)
        finally:
            await out.put(None)  # poison pill -> close client

    async def expand_tx_events(txhash: str, height: str | int | None) -> dict | None:
        """Return flat new_report.* events dict for the block, else None.

        Uses block_results (indexed at commit) because tx?hash relies on the
        lagging tx index.
        """
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as sess:
                async with sess.get(f"{UPSTREAM_RPC}/block_results",
                                    params={"height": str(height)}) as r:
                    if r.status != 200:
                        return None
                    body = await r.json()
        except Exception as ex:  # noqa: BLE001
            log.warning("expand http fail %s: %s", txhash[:12], ex)
            return None
        results = (body.get("result") or {}).get("txs_results") or []
        flat: dict = {}
        for res in results:
            for e in res.get("events") or []:
                etype = e.get("type", "")
                if etype != "new_report":
                    continue
                for attr in e.get("attributes") or []:
                    k, v = attr.get("key"), attr.get("value")
                    if k is None:
                        continue
                    flat.setdefault(f"{etype}.{k}", []).append(v)
        if not flat:
            return None
        flat["tx.hash"] = [txhash]
        flat["tx.height"] = [str(height)]
        return flat

    upstream.tx_seen = 0
    upstream.sent = 0
    task = asyncio.create_task(upstream())
    try:
        while True:
            recv = asyncio.ensure_future(ws.receive())
            get = asyncio.ensure_future(out.get())
            done, pending = await asyncio.wait({recv, get}, return_when=asyncio.FIRST_COMPLETED)
            if recv in done:
                msg = recv.result()
                if msg.type in (web.WSMsgType.CLOSE, web.WSMsgType.CLOSING, web.WSMsgType.CLOSED):
                    get.cancel()
                    break
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        req = json.loads(msg.data)
                    except json.JSONDecodeError:
                        continue
                    if req.get("method") in ("subscribe", "unsubscribe"):
                        # Echo an ack in CometBFT shape; we always serve Tx events.
                        await ws.send_json({"jsonrpc": "2.0", "id": req.get("id"), "result": {}})
                    else:
                        await ws.send_json({"jsonrpc": "2.0", "id": req.get("id"), "result": {}})
                elif msg.type == web.WSMsgType.ERROR:
                    break
            else:
                recv.cancel()
                payload = get.result()
                if payload is None:
                    break
                await ws.send_str(payload)
    finally:
        task.cancel()
        await ws.close()
    return ws


async def http_proxy(request: web.Request) -> web.Response:
    """Proxy any non-WS request through to the node RPC unchanged."""
    url = UPSTREAM_RPC + request.path_qs
    body = await request.read()
    async with aiohttp.ClientSession() as sess:
        async with sess.request(request.method, url, data=body or None) as up:
            data = await up.read()
            return web.Response(status=up.status, body=data,
                                content_type="application/json")


def main() -> None:
    """Run the shim (WS handler + catch-all HTTP proxy) on LISTEN."""
    app = web.Application()
    app.router.add_get("/websocket", ws_handler)
    app.router.add_route("*", "/{tail:.*}", http_proxy)
    web.run_app(app, host=LISTEN[0], port=LISTEN[1], print=lambda *_: log.info("listening on %s:%s", *LISTEN))


if __name__ == "__main__":
    main()
