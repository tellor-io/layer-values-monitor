import asyncio
import json
import logging
from unittest.mock import MagicMock, patch

from layer_values_monitor.monitor import listen_to_new_report_events

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

    listener_task = asyncio.create_task(listen_to_new_report_events(uri, event_queue, mock_logger))
    await asyncio.sleep(0.1)

    mock_websockets_connect.assert_called_once_with("ws://test-server.com/websocket")
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

    listener_task = asyncio.create_task(listen_to_new_report_events(uri, event_queue, mock_logger))
    await asyncio.sleep(0.1)

    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass

    assert event_queue.qsize() == len(test_messages)

    for expected_message in test_messages:
        message = await event_queue.get()
        assert message == json.loads(expected_message)


@pytest.mark.asyncio
async def test_connection_closed_handling(mock_websockets_connect, mock_websocket, event_queue):
    uri = "test-server.com"

    mock_websocket.recv.side_effect = websockets.ConnectionClosed(None, None)

    with patch("layer_values_monitor.main.logger") as patched_logger:
        listener_task = asyncio.create_task(listen_to_new_report_events(uri, event_queue, patched_logger))
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
    listener_task = asyncio.create_task(listen_to_new_report_events(uri, event_queue, mock_logger))
    await asyncio.sleep(0.1)

    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        pass
    assert event_queue.qsize() == len(test_messages)

    for expected_message in test_messages:
        message = await event_queue.get()
        assert message == json.loads(expected_message)
