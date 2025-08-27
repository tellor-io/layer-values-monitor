// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 @author Tellor Inc.
 @title GuardedPausable
 @dev This contract acts as a pausable parent contract. It allows
 * guardians to pause the contract in case of emergencies or attacks. 
 * The contract maintains a list of guardian addresses who can each manage 
 * the pause state. An admin address can add/remove guardians. 
 * Child contracts should add the _onlyUnpaused() function to any functions 
 * they wish to be pausable.
*/
contract GuardedPausable {
    // Storage
    mapping(address => bool) public guardians; // mapping of guardian addresses to their status
    bool public paused; // whether the contract is currently paused
    uint256 public guardianCount; // total number of active guardians
    address public admin; // address of the admin who can add/remove guardians

    // Events
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event AdminRemoved();
    event Paused();
    event Unpaused();

    // Functions
    /**
     * @dev Initializes the GuardedPausable with an admin address
     * @param _admin address of the initial admin who can add/remove guardians
     */
    constructor(address _admin) {
        guardians[_admin] = true;
        guardianCount++;
        admin = _admin;
    }

    /**
     * @dev Allows admin to add a new guardian
     * @param _newGuardian address of the new guardian to add
     */
    function addGuardian(address _newGuardian) public {
        require(msg.sender == admin, "GuardedPausable: Not an admin");
        require(!guardians[_newGuardian], "GuardedPausable: Guardian already exists");
        guardians[_newGuardian] = true;
        guardianCount++;
        emit GuardianAdded(_newGuardian);
    }

    /**
     * @dev Allows admin to remove a guardian
     * @param _guardian address of the guardian to remove
     */
    function removeGuardian(address _guardian) public {
        require(msg.sender == admin, "GuardedPausable: Not an admin");
        require(guardians[_guardian], "GuardedPausable: Guardian does not exist");
        if (_guardian == admin) {
            require(guardianCount == 1, "GuardedPausable: Cannot remove admin if there are other guardians");
            admin = address(0);
            emit AdminRemoved();
        }
        guardians[_guardian] = false;
        guardianCount--;
        emit GuardianRemoved(_guardian);
    }

    /**
     * @dev Allows a guardian to pause the contract, preventing oracle calls
     */
    function pause() public {
        require(guardians[msg.sender], "GuardedPausable: Not a guardian");
        require(!paused, "GuardedPausable: Already paused");
        paused = true;
        emit Paused();
    }

    /**
     * @dev Allows a guardian to unpause the contract, resuming oracle calls
     */
    function unpause() public {
        require(guardians[msg.sender], "GuardedPausable: Not a guardian");
        require(paused, "GuardedPausable: Already unpaused");
        paused = false;
        emit Unpaused();
    }

    /**
     * @dev Reverts if the contract is paused
     */
    function _onlyUnpaused() internal view {
        require(!paused, "GuardedPausable: Tellor is paused");
    }
}