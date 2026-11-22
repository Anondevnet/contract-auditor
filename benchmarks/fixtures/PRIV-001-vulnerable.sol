pragma solidity ^0.5.8;

/// Benchmark fixture PRIV-001 (synthetic, original code for Contract Auditor Phase 14).
/// Vulnerable behavior: admin is declared as a write-protected variable
/// (NatSpec write-protection="adminGuard()"), yet setAdmin() writes admin
/// WITHOUT invoking the protection function — any caller can seize the admin
/// role and thereby control every privileged operation gated by adminGuard().
/// Expected Slither detector: protected-vars.
contract PrivilegedConfig {
    /// @custom:security write-protection="adminGuard()")
    address public admin;
    uint256 public feeBps;

    constructor() public {
        admin = msg.sender;
    }

    function adminGuard() internal view {
        require(msg.sender == admin, "not admin");
    }

    function setAdmin(address newAdmin) public {
        // Writes the protected variable without calling adminGuard().
        require(newAdmin != address(0), "zero address");
        admin = newAdmin;
    }

    function setFeeBps(uint256 newFeeBps) public {
        adminGuard();
        feeBps = newFeeBps;
    }
}
