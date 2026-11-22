pragma solidity ^0.5.8;

/// Benchmark fixture REENT-002 (synthetic, original code for Contract Auditor Phase 14).
/// Safe counterpart of REENT-001: same withdraw() flow, but the protective
/// control is the checks-effects-interactions pattern — the balance is zeroed
/// BEFORE the external call, so a reentrant callback sees amount == 0 and
/// cannot drain the vault.
contract ReentrancyVaultSafe {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        // Effect first: balance cleared before any external interaction.
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call.value(amount)("");
        require(ok, "transfer failed");
    }
}
