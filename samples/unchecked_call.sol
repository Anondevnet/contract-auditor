// Unchecked low-level call: a failed send is ignored.
pragma solidity ^0.8.0;

contract UncheckedPayout {
    function payout(address payable to, uint256 amount) external {
        to.call{value: amount}("");
    }

    receive() external payable {}
}
