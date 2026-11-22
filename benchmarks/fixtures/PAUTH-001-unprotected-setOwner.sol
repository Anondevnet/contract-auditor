pragma solidity ^0.5.8;

/// Benchmark PAUTH-001: unprotected setOwner — any caller can seize ownership.
contract UnprotectedOwner {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function withdraw() external {
        require(msg.sender == owner, "not owner");
        msg.sender.transfer(address(this).balance);
    }

    function() external payable {}
}
