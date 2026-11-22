pragma solidity ^0.5.8;

/// Benchmark fixture ACCESS-002 (synthetic, original code for Contract Auditor Phase 14).
/// Safe counterpart of ACCESS-001: the protective control is an msg.sender
/// identity check instead of tx.origin, so an intermediary contract cannot
/// satisfy the authorization on behalf of the owner.
contract MsgSenderWallet {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function transferTo(address payable to, uint256 amount) public {
        require(to != address(0), "zero address");
        // Protective control: msg.sender identity check, not tx.origin.
        require(msg.sender == owner, "not owner");
        to.transfer(amount);
    }

    function() external payable {}
}
