pragma solidity ^0.5.8;

/// Benchmark fixture ACCESS-004 (synthetic, original code for Contract Auditor Phase 14).
/// Safe counterpart of ACCESS-003: the protective control is an owner-only
/// guard on the selfdestruct path, so an arbitrary caller cannot destroy
/// the contract.
contract KillSwitchSafe {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function destroy() public {
        require(msg.sender == owner, "not owner");
        selfdestruct(msg.sender);
    }
}
