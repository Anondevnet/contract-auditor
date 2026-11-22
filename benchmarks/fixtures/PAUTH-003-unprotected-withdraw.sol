pragma solidity ^0.5.8;

/// Benchmark PAUTH-003: unprotected withdraw of contract ETH by any caller.
contract UnprotectedWithdraw {
    function withdraw() external {
        msg.sender.transfer(address(this).balance);
    }

    function() external payable {}
}
