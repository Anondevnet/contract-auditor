pragma solidity ^0.5.8;

/// Benchmark fixture DELEG-002 (synthetic, original code for Contract Auditor Phase 15).
/// No attacker-controlled delegatecall destination exists: the destination is a
/// compile-time constant, so forward() can only ever delegatecall the one known
/// implementation. Expected Slither detector (must NOT fire): controlled-delegatecall.
contract DelegateVaultSafe {
    // Trusted implementation deployed alongside this contract.
    address private constant TRUSTED = address(0x1000000000000000000000000000000000000001);

    function forward(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = TRUSTED.delegatecall(data);
        require(ok, "forward failed");
        return ret;
    }
}
