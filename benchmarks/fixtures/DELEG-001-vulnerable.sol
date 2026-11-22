pragma solidity ^0.5.8;

/// Benchmark fixture DELEG-001 (synthetic, original code for Contract Auditor Phase 15).
/// Vulnerable behavior: setTarget() is callable by anyone, so an attacker points
/// target at attacker-controlled code and forward() delegatecalls into it with the
/// vault's storage context (full takeover of contract state). Expected Slither
/// detector: controlled-delegatecall (location: forward).
contract DelegateVault {
    address public target;

    function setTarget(address t) external {
        target = t;
    }

    function forward(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "forward failed");
        return ret;
    }
}
