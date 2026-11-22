pragma solidity ^0.5.8;

/// Benchmark PAUTH-005: initialize callable by anyone (no initializer mod / auth).
contract UnprotectedInitialize {
    address public owner;
    bool public ready;

    function initialize(address newOwner) external {
        owner = newOwner;
        ready = true;
    }

    function withdraw() external {
        require(msg.sender == owner, "not owner");
        msg.sender.transfer(address(this).balance);
    }

    function() external payable {}
}
