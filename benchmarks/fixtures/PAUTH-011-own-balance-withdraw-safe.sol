pragma solidity ^0.5.8;

/// Benchmark PAUTH-011: withdraw debits the caller's own _balances[msg.sender]
/// (bounded by require) and pays msg.sender. Pull payment, not a treasury
/// sweep (safe / TN). Shape of BlurPool.withdraw.
contract OwnBalancePool {
    mapping(address => uint256) private _balances;
    function deposit() external payable { _balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        uint256 balance = _balances[msg.sender];
        require(balance >= amount, "Insufficient funds");
        _balances[msg.sender] = balance - amount;
        (bool ok,) = msg.sender.call.value(amount)("");
        require(ok, "Transfer failed");
    }
}
