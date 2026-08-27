import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

from layer_values_monitor.catchup import HeightTracker
from layer_values_monitor.monitor import (
    WS_PING_INTERVAL_SECONDS,
    WS_PING_TIMEOUT_SECONDS,
    WebSocketSubscriptionError,
    _subscribe_to_queries,
    listen_to_websocket_events,
)

import pytest
import websockets

mock_logger = MagicMock(spec=logging.Logger)


@pytest.mark.asyncio
async def test_websocket_connection(mock_websockets_connect, mock_websocket, event_queue):
    uri = "test-server.com"
    expected_query = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "subscribe",
            "id": 1,
            "params": {"query": "new_report.reporter_power > 0"},
        }
    )

    mock_websocket.recv.side_effect = websockets.ConnectionClosed(None, None)

    queries = ["new_report.reporter_power > 0"]
    listener_task = asyncio.create_task(listen_to_websocket_events(uri, queries, event_queue, mock_logger, HeightTracker()))
    await asyncio.sleep(0.1)

    mock_websockets_connect.assert_called_once_with(
        "ws://test-server.com/websocket",
        ping_interval=WS_PING_INTERVAL_SECONDS,
        ping_timeout=WS_PING_TIMEOUT_SECONDS,
    )
    mock_websocket.send.assert_called_once_with(expected_query)

    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_message_processing(mock_websockets_connect, mock_websocket, event_queue, test_report_messages):
    uri = "test-server.com"
    test_messages = test_report_messages[:3]
    message_index = 0

    async def mock_recv():
        nonlocal message_index
        if message_index < len(test_messages):
            message = test_messages[message_index]
            message_index += 1
            return message
        else:
            raise websockets.ConnectionClosed(None, None)

    mock_websocket.recv.side_effect = mock_recv

    queries = ["new_report.reporter_power > 0"]
    listener_task = asyncio.create_task(listen_to_websocket_events(uri, queries, event_queue, mock_logger, HeightTracker()))
    await asyncio.sleep(0.1)

    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass

    expected_events = test_messages[1:]
    assert event_queue.qsize() == len(expected_events)

    for expected_message in expected_events:
        message = await event_queue.get()
        assert message == json.loads(expected_message)


@pytest.mark.asyncio
async def test_connection_closed_handling(mock_websockets_connect, mock_websocket, event_queue):
    uri = "test-server.com"

    mock_websocket.recv.side_effect = websockets.ConnectionClosed(None, None)

    with patch("layer_values_monitor.main.logger") as patched_logger:
        queries = ["new_report.reporter_power > 0"]
        height_tracker = HeightTracker()
        listener_task = asyncio.create_task(
            listen_to_websocket_events(uri, queries, event_queue, patched_logger, height_tracker)
        )
        await asyncio.sleep(0.1)

        listener_task.cancel()
        try:
            await listener_task
        except asyncio.CancelledError:
            pass

        patched_logger.warning.assert_called_with("WebSocket connection closed: no close frame received or sent")

        patched_logger.info.assert_any_call("going through the retry phase since connection was closed")


@pytest.mark.asyncio
async def test_multiple_messages_before_close(mock_websockets_connect, mock_websocket, event_queue, test_report_messages):
    uri = "test-server.com"
    test_messages = test_report_messages

    mock_websocket.recv.side_effect = test_messages + [websockets.ConnectionClosed(None, None)]
    queries = ["new_report.reporter_power > 0"]
    listener_task = asyncio.create_task(listen_to_websocket_events(uri, queries, event_queue, mock_logger, HeightTracker()))
    await asyncio.sleep(0.1)

    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass
    expected_events = test_messages[1:]
    assert event_queue.qsize() == len(expected_events)

    for expected_message in expected_events:
        message = await event_queue.get()
        assert message == json.loads(expected_message)


@pytest.mark.asyncio
async def test_subscription_retries_after_rejection(event_queue):
    websocket = AsyncMock()
    websocket.recv.side_effect = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "invalid query"}}),
        json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}),
    ]
    logger = MagicMock(spec=logging.Logger)
    query = "new_report.reporter_power > 0"

    await _subscribe_to_queries(
        websocket,
        [query],
        event_queue,
        logger,
        max_attempts=3,
        ack_timeout=0.1,
        retry_delay=0,
    )

    assert websocket.send.await_count == 2
    logger.error.assert_called_once()
    logger.info.assert_called_once_with(f"WebSocket subscription confirmed: {query}")


@pytest.mark.asyncio
async def test_subscription_errors_after_retry_limit(event_queue):
    websocket = AsyncMock()
    rejection = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "invalid query"}})
    websocket.recv.side_effect = [rejection, rejection, rejection]
    logger = MagicMock(spec=logging.Logger)

    with pytest.raises(WebSocketSubscriptionError, match="after 3 attempts"):
        await _subscribe_to_queries(
            websocket,
            ["invalid query"],
            event_queue,
            logger,
            max_attempts=3,
            ack_timeout=0.1,
            retry_delay=0,
        )

    assert websocket.send.await_count == 3
    assert logger.error.call_count == 3
