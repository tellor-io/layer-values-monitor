// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title TellorEncoding - DepositId EVMCall Helper
 * @dev Minimal contract for encoding/decoding depositId EVMCall queries on Ethereum mainnet
 * Contract: 0x5589e306b1920F009979a50B88caE32aecD471E4 (TRB Bridge)
 */
contract TellorEncoding {
    
    // ============================================
    // CORE ENCODING FUNCTIONS
    // ============================================
    
    /**
     * @dev Encode EVMCall query data
     * @param _chainId Chain ID where the contract is deployed
     * @param _contractAddress Address of the contract to call
     * @param _calldata Encoded function call
     * @return Encoded query data
     */
    function encodeEVMCallQueryData(
        uint256 _chainId,
        address _contractAddress,
        bytes memory _calldata
    ) public pure returns (bytes memory) {
        return abi.encode(
            "EVMCall",
            abi.encode(_chainId, _contractAddress, _calldata)
        );
    }
    
    /**
     * @dev Generate query ID from query data
     * @param _queryData The encoded query data
     * @return Query ID (keccak256 hash of query data)
     */
    function getQueryId(bytes memory _queryData) public pure returns (bytes32) {
        return keccak256(_queryData);
    }
    
    /**
     * @dev Encode EVMCall response value
     * @param _result The result bytes from the contract call
     * @param _timestamp Timestamp when the call was made
     * @return Encoded value
     */
    function encodeEVMCallValue(
        bytes memory _result,
        uint256 _timestamp
    ) public pure returns (bytes memory) {
        return abi.encode(
            abi.encode(_result),
            _timestamp
        );
    }
    
    // ============================================
    // DEPOSIT ID FUNCTIONS (Mainnet TRB Bridge)
    // ============================================
    
    /**
     * @dev Create EVMCall query for depositId() function on Ethereum mainnet
     * Contract: 0x5589e306b1920F009979a50B88caE32aecD471E4 (TRB Bridge)
     * Chain ID: 1 (Ethereum mainnet)
     * @return queryData The encoded query data
     * @return queryId The query ID
     */
    function createDepositIdQuery() 
        public 
        pure 
        returns (bytes memory queryData, bytes32 queryId) 
    {
        bytes memory calldata_ = abi.encodeWithSignature("depositId()");
        queryData = encodeEVMCallQueryData(
            1, // Ethereum mainnet chain ID
            0x5589e306b1920F009979a50B88caE32aecD471E4, // TRB Bridge contract address
            calldata_
        );
        queryId = getQueryId(queryData);
    }
    
    /**
     * @dev Encode EVMCall value for depositId response
     * @param _depositId The depositId value returned from the contract
     * @param _blockTimestamp The block timestamp when the call was made
     * @return value The encoded EVMCall value
     */
    function encodeDepositIdValue(
        uint256 _depositId,
        uint256 _blockTimestamp
    ) public pure returns (bytes memory value) {
        bytes memory result = abi.encode(_depositId);
        value = encodeEVMCallValue(result, _blockTimestamp);
    }
    
    /**
     * @dev Complete workflow: Generate queryData, queryId, and encoded value
     * @param _depositIdResult The depositId value returned (e.g., 80)
     * @param _blockTimestamp The block timestamp (e.g., 1704067200)
     * @return queryData The encoded query data
     * @return queryId The query ID
     * @return encodedValue The encoded value ready to submit
     */
    function depositIdCompleteExample(
        uint256 _depositIdResult,
        uint256 _blockTimestamp
    ) public pure returns (
        bytes memory queryData,
        bytes32 queryId,
        bytes memory encodedValue
    ) {
        (queryData, queryId) = createDepositIdQuery();
        encodedValue = encodeDepositIdValue(_depositIdResult, _blockTimestamp);
    }
    
    // ============================================
    // DECODING FUNCTIONS (for verification)
    // ============================================
    
    /**
     * @dev Decode EVMCall query data
     * @param _queryData The encoded query data
     * @return queryType The query type string (should be "EVMCall")
     * @return chainId Chain ID
     * @return contractAddress Contract address
     * @return calldata_ The calldata
     */
    function decodeEVMCallQueryData(bytes memory _queryData) 
        public 
        pure 
        returns (
            string memory queryType,
            uint256 chainId,
            address contractAddress,
            bytes memory calldata_
        ) 
    {
        bytes memory _encodedParams;
        (queryType, _encodedParams) = abi.decode(_queryData, (string, bytes));
        (chainId, contractAddress, calldata_) = abi.decode(_encodedParams, (uint256, address, bytes));
    }
    
    /**
     * @dev Decode EVMCall response value
     * @param _value The encoded value
     * @return result The result bytes
     * @return timestamp The timestamp
     */
    function decodeEVMCallValue(bytes memory _value) 
        public 
        pure 
        returns (bytes memory result, uint256 timestamp) 
    {
        bytes memory encodedResult;
        (encodedResult, timestamp) = abi.decode(_value, (bytes, uint256));
        result = abi.decode(encodedResult, (bytes));
    }
    
    /**
     * @dev Decode EVMCall value to get depositId and timestamp
     * @param _value The encoded EVMCall value
     * @return depositId The decoded depositId
     * @return timestamp The block timestamp
     */
    function decodeDepositIdValue(bytes memory _value) 
        public 
        pure 
        returns (uint256 depositId, uint256 timestamp) 
    {
        bytes memory result;
        (result, timestamp) = decodeEVMCallValue(_value);
        depositId = abi.decode(result, (uint256));
    }
}
