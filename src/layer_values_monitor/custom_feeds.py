"""Custom price feeds for tokens not supported by telliot-feeds."""

import logging
import os

import aiohttp


async def get_custom_trusted_value(query_id: str, logger: logging.Logger) -> float | None:
    """Get trusted price value for query IDs not supported by telliot feeds.
    
    Args:
        query_id: The query ID to fetch price for
        logger: Logger instance
        
    Returns:
        float: The averaged trusted price value from multiple sources or None if unable to fetch

    """
    # Normalize query_id to lowercase for comparison
    query_id_lower = query_id.lower()
    
    # Define unsupported query IDs that need custom price lookup
    UNSUPPORTED_QUERY_IDS = {
        "c444759b83c7bb0f6694306e1f719e65679d48ad754a31d3a366856becf1e71e",  # FBTC/USD
        "74c9cfdfd2e4a00a9437bf93bf6051e18e604a976f3fa37faafe0bb5a039431d",  # SAGA/USD
    }
    
    if query_id_lower not in UNSUPPORTED_QUERY_IDS:
        logger.error(f"Query ID {query_id} is not configured for custom price lookup")
        return None
    
    try:
        if query_id_lower == "c444759b83c7bb0f6694306e1f719e65679d48ad754a31d3a366856becf1e71e":
            return await _fetch_fbtc_price(logger)
        elif query_id_lower == "74c9cfdfd2e4a00a9437bf93bf6051e18e604a976f3fa37faafe0bb5a039431d":
            return await _fetch_saga_price(logger)
            
    except Exception as e:
        logger.error(f"Error fetching custom trusted value for query {query_id}: {e}")
        return None
    
    return None


async def _fetch_fbtc_price(logger: logging.Logger) -> float | None:
    """Fetch FBTC/USD price from both CoinMarketCap and CoinGecko, then average."""
    logger.info("Fetching FBTC/USD price from both CoinMarketCap and CoinGecko")
    
    prices = []
    sources_used = []
    
    # Try CoinMarketCap
    cmc_price = await _fetch_price_from_cmc("FBTC", logger)
    if cmc_price is not None and cmc_price > 0:
        prices.append(cmc_price)
        sources_used.append("CMC")
        logger.info(f"Successfully fetched FBTC/USD price from CMC: ${cmc_price}")
    
    # Try CoinGecko
    cg_price = await _fetch_price_from_coingecko("ignition-fbtc", logger)
    if cg_price is not None and cg_price > 0:
        prices.append(cg_price)
        sources_used.append("CoinGecko")
        logger.info(f"Successfully fetched FBTC/USD price from CoinGecko: ${cg_price}")
    
    # Calculate average if we have valid prices
    if len(prices) > 0:
        average_price = sum(prices) / len(prices)
        individual_prices = [f'${p:.6f}' for p in prices]
        logger.info(f"FBTC/USD average price: ${average_price:.6f} from sources: {', '.join(sources_used)} "
                   f"(individual prices: {individual_prices})")
        return average_price
    else:
        logger.error("No valid FBTC/USD prices obtained from any source")
        return None


async def _fetch_saga_price(logger: logging.Logger) -> float | None:
    """Fetch SAGA/USD price from both CoinMarketCap and CoinGecko, then average."""
    logger.info("Fetching SAGA/USD price from both CoinMarketCap and CoinGecko")
    
    prices = []
    sources_used = []
    
    # Try CoinMarketCap
    cmc_price = await _fetch_price_from_cmc("SAGA", logger)
    if cmc_price is not None and cmc_price > 0:
        prices.append(cmc_price)
        sources_used.append("CMC")
        logger.info(f"Successfully fetched SAGA/USD price from CMC: ${cmc_price}")
    
    # Try CoinGecko
    cg_price = await _fetch_price_from_coingecko("saga-2", logger)
    if cg_price is not None and cg_price > 0:
        prices.append(cg_price)
        sources_used.append("CoinGecko")
        logger.info(f"Successfully fetched SAGA/USD price from CoinGecko: ${cg_price}")
    
    # Calculate average if we have valid prices
    if len(prices) > 0:
        average_price = sum(prices) / len(prices)
        individual_prices = [f'${p:.6f}' for p in prices]
        logger.info(f"SAGA/USD average price: ${average_price:.6f} from sources: {', '.join(sources_used)} "
                   f"(individual prices: {individual_prices})")
        return average_price
    else:
        logger.error("No valid SAGA/USD prices obtained from any source")
        return None


async def _fetch_price_from_cmc(symbol: str, logger: logging.Logger) -> float | None:
    """Fetch price from CoinMarketCap API."""
    cmc_api_key = os.getenv("CMC_API_KEY")
    if not cmc_api_key:
        logger.info("CMC_API_KEY not set, skipping CoinMarketCap")
        return None
    
    url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest"
    params = {
        "symbol": symbol,
        "convert": "USD"
    }
    headers = {
        "accept": "application/json",
        "X-CMC_PRO_API_KEY": cmc_api_key
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status", {}).get("error_code") == 0:
                        token_data = data.get("data", {}).get(symbol)
                        if token_data and len(token_data) > 0:
                            price = token_data[0].get("quote", {}).get("USD", {}).get("price")
                            if price is not None and float(price) > 0:
                                return float(price)
                            else:
                                logger.warning(f"{symbol} price from CMC is None or zero")
                        else:
                            logger.warning(f"{symbol} data not found in CoinMarketCap response")
                    else:
                        logger.warning("CoinMarketCap API returned error status")
                else:
                    logger.warning(f"CoinMarketCap API request failed with status {response.status}")
    except Exception as e:
        logger.warning(f"Error fetching {symbol} price from CoinMarketCap: {e}")
    
    return None


async def _fetch_price_from_coingecko(coin_id: str, logger: logging.Logger) -> float | None:
    """Fetch price from CoinGecko API."""
    cg_api_key = os.getenv("CG_API_KEY")
    if not cg_api_key:
        logger.info("CG_API_KEY not set, skipping CoinGecko")
        return None
    
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {
        "vs_currencies": "usd",
        "ids": coin_id
    }
    headers = {
        "accept": "application/json",
        "x-cg-demo-api-key": cg_api_key
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    price = data.get(coin_id, {}).get("usd")
                    if price is not None and float(price) > 0:
                        return float(price)
                    else:
                        logger.warning(f"{coin_id} price from CoinGecko is None or zero")
                else:
                    logger.warning(f"CoinGecko API request failed with status {response.status}")
    except Exception as e:
        logger.warning(f"Error fetching {coin_id} price from CoinGecko: {e}")
    
    return None