pragma solidity ^0.5.8;

/// Benchmark PAUTH-012: lookalike of PAUTH-011 whose withdraw pays any amount
/// of the pooled ETH to the caller without debiting the caller's balance
/// (vulnerable / TP: unprotected fund withdrawal).
contract DrainablePool {
    mapping(address => uint256) private _balances;
    function deposit() external payable { _balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(address(this).balance >= amount, "Insufficient pool");
        (bool ok,) = msg.sender.call.value(amount)("");
        require(ok, "Transfer failed");
    }
}
