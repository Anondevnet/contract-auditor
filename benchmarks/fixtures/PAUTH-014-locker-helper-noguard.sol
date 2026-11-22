pragma solidity ^0.5.8;

/// Benchmark PAUTH-014: lookalike of PAUTH-013 whose helper only READS the
/// locker and never reverts, so anyone can drain the contract balance to any
/// address. Vulnerable / TP: unprotected fund withdrawal.
contract LockerFeesOpen {
    address private _locker;
    function _getLocker() internal view returns (address locker) { locker = _locker; }
    function lock() external { _locker = msg.sender; }
    function collectFees(address payable to) external returns (uint256 amount) {
        _getLocker();
        amount = address(this).balance;
        to.transfer(amount);
    }
}
