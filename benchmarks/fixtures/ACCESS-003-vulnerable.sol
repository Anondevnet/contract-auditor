pragma solidity ^0.5.8;

/// Benchmark fixture ACCESS-003 (synthetic, original code for Contract Auditor Phase 14).
/// Vulnerable behavior: destroy() is callable by anyone and immediately
/// selfdestructs the contract, permanently destroying its state and sending
/// its balance to the caller. Expected Slither detector: suicidal.
contract KillSwitch {
    function destroy() public {
        // Missing authorization on an irreversible privileged operation.
        selfdestruct(msg.sender);
    }
}
