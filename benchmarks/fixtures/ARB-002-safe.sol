pragma solidity ^0.5.8;

/// Benchmark fixture ARB-002 (synthetic, original code for Contract Auditor Phase 15).
/// Only the owner can trigger the single withdrawal, and it always pays the fixed
/// owner address; no caller-supplied destination exists. Expected Slither detector
/// (must NOT fire): arbitrary-send-eth.
contract EscrowSafe {
    address payable public owner;

    constructor() public {
        owner = msg.sender;
    }

    function deposit() external payable {}

    function drain() external {
        require(msg.sender == owner, "not owner");
        owner.transfer(address(this).balance);
    }
}
