pragma solidity ^0.5.8;

/// Benchmark PAUTH-013: fee collection guarded by an internal helper that
/// reverts unless msg.sender is the current locker (Ekubo _requireLocker
/// shape). Fees are keyed by the caller. Safe / TN.
contract LockerFees {
    address private _locker;
    mapping(address => uint256) private _fees;
    function _requireLocker() internal view returns (address locker) {
        locker = _locker;
        if (locker != msg.sender) revert("LockerOnly");
    }
    function lock() external { _locker = msg.sender; }
    function collectFees(address payable to) external returns (uint256 amount) {
        address locker = _requireLocker();
        amount = _fees[locker];
        _fees[locker] = 0;
        to.transfer(address(this).balance >= amount ? amount : 0);
    }
}
