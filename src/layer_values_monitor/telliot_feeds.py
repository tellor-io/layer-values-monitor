"""Telliot Feeds helper functions."""

import logging

from clamfig.base import Registry
from eth_abi import decode
from telliot_feeds.datafeed import DataFeed
from telliot_feeds.datasource import DataSource
from telliot_feeds.dtypes.datapoint import OptionalDataPoint
from telliot_feeds.feeds import CATALOG_FEEDS, DATAFEED_BUILDER_MAPPING
from telliot_feeds.queries.abi_query import AbiQuery
from telliot_feeds.queries.json_query import JsonQuery
from telliot_feeds.queries.query_catalog import query_catalog


def get_query_from_data(query_data: bytes) -> AbiQuery | JsonQuery | None:
    """Get query give query data from telliot-feeds."""
    for q_type in (JsonQuery, AbiQuery):
        try:
            return q_type.get_query_from_data(query_data)
        except ValueError:
            pass
    return None


def get_query(query_data: str) -> AbiQuery | JsonQuery | None:
    """Fetch the registered query object from telliot-feeds.

    query_data: used to identifying the query
    return: AbiQuery or JsonQuery object
    """
    query_data_bytes = bytes.fromhex(query_data)
    query = get_query_from_data(query_data_bytes)
    return query


def get_feed_from_catalog(tag: str) -> DataFeed | None:
    """Get feed from telliot-feeds mapping if exists."""
    return CATALOG_FEEDS.get(tag)


def get_source_from_data(query_data: bytes, logger: logging) -> DataSource | None:
    """Recreate data source using query type thats decoded from query data field."""
    try:
        query_type, encoded_param_values = decode(["string", "bytes"], query_data)
    except OverflowError:
        logger.error("OverflowError while decoding query data.")
        return None
    try:
        cls = Registry.registry[query_type]
    except KeyError:
        logger.error(f"Unsupported query type: {query_type}")
        return None
    try:
        params_abi = cls.abi
    except AttributeError:
        logger.error(f"query type {query_type} doesn't have abi attirbute to decode params")
        return None
    param_names = [p["name"] for p in params_abi]
    param_types = [p["type"] for p in params_abi]
    param_values = decode(param_types, encoded_param_values)

    feed_builder = DATAFEED_BUILDER_MAPPING.get(query_type)
    if feed_builder is None:
        logger.error(f"query type {query_type} not supported by datafeed builder")
        return None
    source = feed_builder.source
    for key, value in zip(param_names, param_values, strict=False):
        setattr(source, key, value)
    return source


async def get_feed(query_id: str, query: AbiQuery | JsonQuery, logger: logging) -> DataFeed | None:
    """Get the current value for a query from API sources available in telliot-feeds.

    query_id: the hash of the query data used to fetch the value.
    quer: query object that has the source and feed used to get value from relevant API.
    """
    catalog_entry = query_catalog.find(query_id=query_id)
    if len(catalog_entry) == 0:
        source = get_source_from_data(query_data=query.query_data)
        if source is None:
            logger.warning("no source found in telliot feeds found for query")
            return None
        return DataFeed(query=query, source=source)
    else:
        return get_feed_from_catalog(catalog_entry[0].tag)


async def fetch_value(feed: DataFeed) -> OptionalDataPoint:
    """Fetch the value from the data source in telliot-feeds."""
    return await feed.source.fetch_new_datapoint()
