pragma solidity ^0.5.8;

/// Benchmark PAUTH-006: Ownable-style onlyOwner guards setOwner (safe / TN).
contract OwnableProtected {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero");
        owner = newOwner;
    }

    function withdraw() external onlyOwner {
        msg.sender.transfer(address(this).balance);
    }

    function() external payable {}
}
