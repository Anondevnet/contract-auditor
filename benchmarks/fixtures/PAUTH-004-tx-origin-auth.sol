pragma solidity ^0.5.8;

/// Benchmark PAUTH-004: ownership change authorised via tx.origin (WEAK).
contract TxOriginAuth {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
