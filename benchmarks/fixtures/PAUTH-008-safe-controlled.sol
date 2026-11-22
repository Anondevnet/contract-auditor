pragma solidity ^0.5.8;

/// Benchmark PAUTH-008: privileged withdraw gated by onlyOwner (TN for
/// unprotected channel). On-chain, owner may be a Safe m-of-n; the analyzer
/// reports that as an INFORMATIONAL privileged-auth-protected centralization
/// note when a trust map / eth reader is supplied — not as a vulnerability.
contract SafeControlledVault {
    address public owner;

    constructor(address safeOwner) public {
        owner = safeOwner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function withdraw(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0), "zero");
        to.transfer(amount);
    }

    function() external payable {}
}
