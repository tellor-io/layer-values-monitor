import asyncio
import time

from layer_values_monitor.main import ConfigWatcher, watch_config

import pytest


def test_init(config_file, config_watcher):
    """Test the initialization of ConfigWatcher."""
    assert isinstance(config_watcher, ConfigWatcher)
    assert config_watcher.config_path == config_file
    assert config_watcher.last_modified_time > 0


def test_get_config(config_watcher):
    """Test that config is correctly loaded and accessible."""
    config = config_watcher.get_config()
    assert "feed" in config
    assert config["feed"]["test"] == "initial_value"
    assert "settings" in config
    assert config["settings"]["interval"] == 5


def test_reload_config_when_changed(config_file, config_watcher):
    """Test that config is reloaded when file changes."""
    # Record initial timestamp
    initial_timestamp = config_watcher.last_modified_time

    # Wait a bit to ensure file timestamp will be different
    time.sleep(0.1)

    # Modify config file
    with open(config_file, "w") as f:
        f.write("""
            [Feed]
            test = "updated_value"
            new_key = "new_value"
            
            [Settings]
            interval = 10
        """)

    # Reload config
    reloaded = config_watcher.reload_config()

    # Check that reload happened
    assert reloaded is True
    assert config_watcher.last_modified_time > initial_timestamp

    # Check that config was updated
    config = config_watcher.get_config()
    assert config["feed"]["test"] == "updated_value"
    assert config["feed"]["new_key"] == "new_value"
    assert config["settings"]["interval"] == 10


def test_reload_config_when_unchanged(config_watcher):
    """Test that reload returns False when file hasn't changed."""
    # Call reload_config once to set initial state
    config_watcher.reload_config()

    # Call again without changing the file
    reloaded = config_watcher.reload_config()

    # Should return False as file hasn't changed
    assert reloaded is False


@pytest.mark.asyncio
async def test_watch_config(config_file, config_watcher):
    """Test the watch_config async function."""
    # Set a very short check interval for testing
    check_interval = 0.1

    # Create a task for watch_config with a short timeout
    task = asyncio.create_task(watch_config(config_watcher, check_interval))

    # Wait a bit to let watch_config run
    await asyncio.sleep(check_interval * 2)

    # Record the current state
    initial_timestamp = config_watcher.last_modified_time
    initial_config = config_watcher.get_config()

    # Modify config file
    with open(config_file, "w") as f:
        f.write("""
            [Feed]
            test = "auto_updated"
            
            [Settings]
            interval = 15
        """)

    # Wait for watch_config to detect the change
    await asyncio.sleep(check_interval * 2)

    # Cancel the task
    task.cancel()

    try:
        await task
    except asyncio.CancelledError:
        pass

    # Verify that config was automatically updated
    assert config_watcher.last_modified_time > initial_timestamp
    assert config_watcher.get_config() != initial_config
    assert config_watcher.get_config()["feed"]["test"] == "auto_updated"
    assert config_watcher.get_config()["settings"]["interval"] == 15
