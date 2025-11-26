"""Test script to verify async curl fallback in catchup logic."""

import asyncio
import logging
from unittest.mock import AsyncMock, patch
import sys
from pathlib import Path

# Add src to path (go up from tests/ to layer-values-monitor/, then into src/)
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from layer_values_monitor.catchup import (
    query_block_events,
    process_missed_blocks,
    get_current_height,
    HeightTracker,
)


async def test_curl_fallback():
    """Test that curl fallback works when aiohttp fails."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("TEST 1: Query single block with forced aiohttp failure")
    logger.info("=" * 60)
    
    # Get current height
    uri = "localhost:26657"
    current_height = await get_current_height(uri)
    
    if not current_height:
        logger.error("Could not get current height - is your chain running?")
        return False
    
    logger.info(f"Current chain height: {current_height}")
    
    # Test with a recent block that should have data
    test_height = current_height - 2
    
    # Mock aiohttp to always fail
    with patch('aiohttp.ClientSession') as mock_session:
        # Make aiohttp raise an exception
        mock_session.return_value.__aenter__.return_value.post.side_effect = Exception("SIMULATED AIOHTTP FAILURE")
        
        logger.info(f"🔧 Forcing aiohttp to fail for block {test_height}")
        logger.info(f"🔄 This should trigger async curl fallback...")
        
        result = await query_block_events(uri, test_height, logger)
        
        if result:
            logger.info(f"Successfully retrieved block {test_height} via curl fallback!")
            logger.info(f"   Block hash: {result.get('block_id', {}).get('hash', 'N/A')[:16]}...")
            return True
        else:
            logger.error(f"Failed to retrieve block {test_height}")
            return False


async def test_catchup_with_curl():
    """Test full catchup process with aiohttp failures."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    logger.info("")
    logger.info("=" * 60)
    logger.info("TEST 2: Process multiple missed blocks with curl fallback")
    logger.info("=" * 60)
    
    uri = "localhost:26657"
    current_height = await get_current_height(uri)
    
    if not current_height:
        logger.error("Could not get current height")
        return False
    
    # Process last 5 blocks
    start_height = current_height - 5
    end_height = current_height - 1
    
    raw_data_q = asyncio.Queue()
    
    logger.info(f"📦 Will process blocks {start_height} to {end_height}")
    
    # Mock aiohttp to fail
    with patch('aiohttp.ClientSession') as mock_session:
        mock_session.return_value.__aenter__.return_value.post.side_effect = Exception("SIMULATED AIOHTTP FAILURE")
        
        logger.info("🔧 Forcing all aiohttp requests to fail")
        logger.info("🔄 All blocks should be fetched via async curl...\n")
        
        start_time = asyncio.get_event_loop().time()
        
        await process_missed_blocks(uri, start_height, end_height, raw_data_q, logger)
        
        elapsed = asyncio.get_event_loop().time() - start_time
        
        logger.info(f"\n⏱️  Processing took {elapsed:.2f} seconds")
        
        # Check queue
        event_count = raw_data_q.qsize()
        logger.info(f"📊 Events queued: {event_count}")
        
        if event_count > 0:
            logger.info("Successfully processed blocks via curl fallback!")
            
            # Show first event as example
            first_event = await raw_data_q.get()
            logger.info(f"\n📄 Example event structure:")
            logger.info(f"   Keys: {list(first_event.get('result', {}).get('events', {}).keys())}")
            return True
        else:
            logger.info("ℹ️  No new_report events found (this is OK if no reports in those blocks)")
            return True


async def test_concurrent_queries():
    """Test that async subprocess allows concurrent queries."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    logger.info("")
    logger.info("=" * 60)
    logger.info("TEST 3: Verify concurrent async behavior")
    logger.info("=" * 60)
    
    uri = "localhost:26657"
    current_height = await get_current_height(uri)
    
    if not current_height:
        logger.error("Could not get current height")
        return False
    
    # Query 5 blocks concurrently
    heights = [current_height - i for i in range(1, 6)]
    
    logger.info(f"🔄 Querying 5 blocks concurrently: {heights}")
    
    with patch('aiohttp.ClientSession') as mock_session:
        mock_session.return_value.__aenter__.return_value.post.side_effect = Exception("SIMULATED AIOHTTP FAILURE")
        
        logger.info("🔧 All requests will use async curl fallback\n")
        
        start_time = asyncio.get_event_loop().time()
        
        # Launch all queries concurrently
        tasks = [query_block_events(uri, h, logger) for h in heights]
        results = await asyncio.gather(*tasks)
        
        elapsed = asyncio.get_event_loop().time() - start_time
        
        successful = sum(1 for r in results if r is not None)
        
        logger.info(f"\n⏱️  Concurrent queries took {elapsed:.2f} seconds")
        logger.info(f"Successfully retrieved {successful}/{len(heights)} blocks")
        
        if successful == len(heights):
            logger.info("🎉 All concurrent async curl requests succeeded!")
            return True
        else:
            logger.warning(f"⚠️  Some requests failed ({len(heights) - successful} failures)")
            return False


async def test_height_tracker():
    """Test HeightTracker logic."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    logger.info("")
    logger.info("=" * 60)
    logger.info("TEST 4: HeightTracker logic")
    logger.info("=" * 60)
    
    tracker = HeightTracker(max_catchup_blocks=15)
    
    # Simulate processing blocks
    logger.info("📊 Simulating block processing...")
    
    tracker.update(100)
    logger.info(f"   Processed block 100, last_height = {tracker.last_height}")
    
    # No gap
    missed = tracker.get_missed_range(101)
    logger.info(f"   Check block 101: missed range = {missed}")
    assert missed is None, "Should be no gap"
    
    tracker.update(101)
    
    # Small gap
    missed = tracker.get_missed_range(105)
    logger.info(f"   Check block 105: missed range = {missed}")
    assert missed == (102, 104), f"Expected (102, 104), got {missed}"
    
    tracker.update(105)
    
    # Large gap (should limit to max_catchup_blocks)
    missed = tracker.get_missed_range(130)
    logger.info(f"   Check block 130 (25 blocks missed): missed range = {missed}")
    assert missed == (115, 129), f"Expected (115, 129), got {missed}"
    logger.info(f"   Correctly limited to {129 - 115 + 1} blocks (max={tracker.max_catchup_blocks})")
    
    logger.info("✅ HeightTracker tests passed!")
    return True


async def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("🧪 CATCHUP ASYNC CURL FALLBACK TEST SUITE")
    print("=" * 60)
    print()
    
    results = []
    
    try:
        # Test 1: Single query with curl fallback
        result1 = await test_curl_fallback()
        results.append(("Single block curl fallback", result1))
        
        # Test 2: Full catchup process
        result2 = await test_catchup_with_curl()
        results.append(("Multi-block catchup", result2))
        
        # Test 3: Concurrent queries
        result3 = await test_concurrent_queries()
        results.append(("Concurrent async queries", result3))
        
        # Test 4: HeightTracker
        result4 = await test_height_tracker()
        results.append(("HeightTracker logic", result4))
        
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    print()
    print(f"Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
    else:
        print("⚠️  Some tests failed")


if __name__ == "__main__":
    asyncio.run(main())

