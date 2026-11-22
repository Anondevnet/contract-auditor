pragma solidity ^0.5.8;

/// Benchmark fixture ACCESS-001 (synthetic, original code for Contract Auditor Phase 14).
/// Vulnerable behavior: transferTo() authorizes with tx.origin instead of
/// msg.sender. A phishing contract that the owner interacts with can forward
/// a call so that tx.origin is still the owner while msg.sender is the
/// attacker, moving the wallet's funds. Expected Slither detector: tx-origin.
contract TxOriginWallet {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function transferTo(address payable to, uint256 amount) public {
        require(to != address(0), "zero address");
        // Incorrect authorization: tx.origin identity check.
        require(tx.origin == owner, "not owner");
        to.transfer(amount);
    }

    function() external payable {}
}
