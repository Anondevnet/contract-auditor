pragma solidity ^0.5.8;

/// Benchmark fixture PRIV-002 (synthetic, original code for Contract Auditor Phase 14).
/// Safe counterpart of PRIV-001: the protective control is that every write
/// to the write-protected admin variable first invokes adminGuard(), so only
/// the current admin can change the admin role.
contract PrivilegedConfigSafe {
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
        // Protective control: protection function invoked before the write.
        adminGuard();
        require(newAdmin != address(0), "zero address");
        admin = newAdmin;
    }

    function setFeeBps(uint256 newFeeBps) public {
        adminGuard();
        feeBps = newFeeBps;
    }
}
