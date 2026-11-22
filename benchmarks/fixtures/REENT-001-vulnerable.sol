pragma solidity ^0.5.8;

/// Benchmark fixture REENT-001 (synthetic, original code for Contract Auditor Phase 14).
/// Vulnerable behavior: withdraw() sends Ether to msg.sender (external call)
/// BEFORE zeroing the caller's balance, violating checks-effects-interactions.
/// A reentrant receive() can drain the contract: balance is still non-zero
/// during the callback, so withdraw() can be entered repeatedly.
contract ReentrancyVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        // External call before the state update (CEI violation).
        (bool ok, ) = msg.sender.call.value(amount)("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}
