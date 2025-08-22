//SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { console2 } from "../lib/forge-std/src/console2.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";

contract SocialRecoveryWallet is AccessControl {
    error NOT_GUARDIAN();
    error NOT_OWNER();
    error ALREADY_GUARDIAN();
    error CALL_FAILED();
    error ALREADY_SIGNALED_ONCE();

    event NewOwnerSignaled(address by, address proposedOwner);
    event RecoveryExecuted(address newOwner);

    bytes32 public constant GUARDIAN = keccak256("GUARDIAN");
    uint256 public s_totalVotesRequired;
    uint256 public s_votesReceived;
    address public s_owner;
    address[] public s_signaled;

    constructor(address[] memory guardians) {
        s_owner = msg.sender;
        _grantRole(GUARDIAN, msg.sender);
        s_totalVotesRequired = guardians.length;
        for (uint256 i = 0; i < guardians.length; i++) {
            _grantRole(GUARDIAN, guardians[i]);
        }
    }

    modifier onlyOwner() {
        if (s_owner != msg.sender) {
            revert NOT_OWNER();
        }
        _;
    }

    receive() external payable { }

    function call(address callee, uint256 value, bytes calldata data) external payable onlyOwner {
        (bool success,) = callee.call{ value: value }(data);
        if (!success) {
            revert CALL_FAILED();
        }
    }

    function signalNewOwner(address _proposedOwner) external onlyRole(GUARDIAN) {
        uint256 len = s_signaled.length;
        for (uint256 i = 0; i < len; i++) {
            if (msg.sender == s_signaled[i]) {
                revert ALREADY_SIGNALED_ONCE();
            }
        }

        s_votesReceived += 1;
        s_signaled.push(msg.sender);

        if (s_totalVotesRequired == s_votesReceived) {
            _changeOwner(_proposedOwner);
        }

        emit NewOwnerSignaled(msg.sender, _proposedOwner);
    }

    function addGuardian(address _guardian) external onlyOwner {
        if (!_grantRole(GUARDIAN, _guardian)) {
            revert ALREADY_GUARDIAN();
        }

        s_totalVotesRequired += 1;
    }

    function removeGuardian(address _guardian) external onlyOwner {
        if (!_revokeRole(GUARDIAN, _guardian)) {
            revert NOT_GUARDIAN();
        }

        s_totalVotesRequired -= 1;
    }

    function owner() external view returns (address) {
        return s_owner;
    }

    function isGuardian(address val) external view returns (bool) {
        return hasRole(GUARDIAN, val);
    }

    function _changeOwner(address _proposedOwner) internal {
        s_owner = _proposedOwner;
        s_votesReceived = 0;
        delete s_signaled;

        _revokeRole(GUARDIAN, _proposedOwner);

        emit RecoveryExecuted(_proposedOwner);
    }
}
