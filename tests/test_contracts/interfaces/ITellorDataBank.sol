// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

interface ITellorDataBank {
    struct AggregateData {
        bytes value; // the value of the asset
        uint256 power; // the aggregate power of the reporters
        uint256 aggregateTimestamp; // the timestamp of the aggregate
        uint256 attestationTimestamp; // the timestamp of the attestation
        uint256 relayTimestamp; // the timestamp of the relay
    }

    function getCurrentAggregateData(bytes32 _queryId) external view returns (AggregateData memory _aggregateData);
    function getAggregateByIndex(bytes32 _queryId, uint256 _index) external view returns (AggregateData memory _aggregateData);
    function getAggregateValueCount(bytes32 _queryId) external view returns (uint256);
}