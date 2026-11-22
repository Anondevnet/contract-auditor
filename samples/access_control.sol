// Missing access control: anyone can take ownership.
pragma solidity ^0.8.0;

contract OpenOwner {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address next) external {
        owner = next;
    }

    function withdraw() external {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
