# ruff: noqa


"""if alert all and dispute all don't use config, also use global threshold here.
if alert all and dispute all but some with different threshold and others with global.
if alert all use global threshold and dispute some check config for what to dispute and fine threshold
if alert config then dispute must be config only so use fine threshold
whats the global metric? some could be percentage and others could be equality and others could be range.
what if the value is a list of numbers, are they equal? or each within a range? or what?
should the global threshold should a file path that is by queryType, may be a toml ie

[SpotPrice]
metric = percentage
alert_threshold = 0.75
dispute_threshold = 0.9

[CustomSpotPrice]
metric = range
alert_threshold = 200
dispute_threshold = 300


disputable = is_disputable(metric, report.query_type, threshold, reported_value, trusted_value)
    print("is disputable: ", disputable, reported_value, trusted_value)
    if disputable:
        # send dispute
        micro_report_dict = {
            "reporter": report.reporter,
            "power": report.power,
            "query_type": report.query_type,
            "query_id": query_id,
            "aggregate_method": events['new_report.aggregate_method'][0],
            "value": report.value,
            "timestamp": events['new_report.timestamp'][0],
            "cycle_list": events['new_report.cyclelist'][0],
            "block_number": events['new_report.block.number'][0],
            "meta_id": events['new_report.meta_id'][0],
        }
        micro_report = json.dumps(micro_report_dict)
        tx_hash = propose_msg(report=micro_report)
        print("tx hash: ", tx_hash)
    # if its disputable then dispute which means send a transaction to the chain, need key to sign and send transaction
    # if report.query_type == "SpotPrice":
    #     # if entry exists in catalog then use that else use manual feed

    #     # TODO: should just be uint256?
    #     reported_value = query.value_type.decode(bytes.fromhex(report.value))
    #     trusted_value, _ = await feed.source.fetch_new_datapoint()
    # else:

    #     source = get_source_from_data(query_data_bytes)

    #     if source is None:
    #         # logger.error(f"Unable to form source from queryData of query type {new_report.query_type}")
    #         return None

    #     feed = DataFeed(query=query, source=source)
    #     reported_value = query.value_type.decode(bytes.fromhex(report.value))
    #     trusted_value, _ = await feed.source.fetch_new_datapoint()

if alert_all and not dispute_all:
    alert_threshold = global_threshold
    # check if alertable if not continue else next step
    # check query_id exists in config to determine if you should dispute

if custom_config:
    # check if alertable if not continue else next step
    # check query_id exists in config to determine if you should dispute
    pass
"""
