import json
from unittest.mock import patch

from layer_values_monitor.monitor import listen_to_new_report_events

import pytest
import websockets


@pytest.mark.asyncio
async def test_websocket_connection(mock_websockets_connect, mock_websocket, event_queue):
    uri = "ws://test-server.com/ws"
    expected_query = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "subscribe",
            "id": 1,
            "params": {"query": "new_report.reporter_power > 0"},
        }
    )

    mock_websocket.recv.side_effect = websockets.ConnectionClosed(None, None)

    await listen_to_new_report_events(uri, event_queue)

    mock_websockets_connect.assert_called_once_with(uri)
    mock_websocket.send.assert_called_once_with(expected_query)


@pytest.mark.asyncio
async def test_message_processing(mock_websockets_connect, mock_websocket, event_queue, test_report_messages):
    uri = "ws://test-server.com/ws"
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

    await listen_to_new_report_events(uri, event_queue)

    assert event_queue.qsize() == len(test_messages)

    for expected_message in test_messages:
        message = await event_queue.get()
        assert message == expected_message


@pytest.mark.asyncio
async def test_connection_closed_handling(mock_websockets_connect, mock_websocket, event_queue):
    uri = "ws://test-server.com/ws"

    mock_websocket.recv.side_effect = websockets.ConnectionClosed(None, None)

    with patch("builtins.print") as mock_print:
        await listen_to_new_report_events(uri, event_queue)

        mock_print.assert_any_call("WebSocket connection closed.")


@pytest.mark.asyncio
async def test_multiple_messages_before_close(mock_websockets_connect, mock_websocket, event_queue, test_report_messages):
    uri = "ws://test-server.com/ws"
    test_messages = test_report_messages

    mock_websocket.recv.side_effect = test_messages + [websockets.ConnectionClosed(None, None)]

    await listen_to_new_report_events(uri, event_queue)

    assert event_queue.qsize() == len(test_messages)

    for expected_message in test_messages:
        message = await event_queue.get()
        assert message == expected_message
