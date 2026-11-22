pragma solidity ^0.5.8;

/// Benchmark PAUTH-009: setFeeRecipient guarded by
/// require(count == 0 || hasRole(OPERATOR, msg.sender)) (safe / TN).
contract OrHasRoleProtected {
    bytes32 public constant OPERATOR = keccak256("OPERATOR");
    mapping(bytes32 => mapping(address => bool)) internal roles;
    uint256 public operatorCount;
    address public feeRecipient;

    constructor() public { roles[OPERATOR][msg.sender] = true; operatorCount = 1; }

    function hasRole(bytes32 role, address account) public view returns (bool) { return roles[role][account]; }

    function setFeeRecipient(address r) external {
        require(operatorCount == 0 || hasRole(OPERATOR, msg.sender), "unauthorized");
        feeRecipient = r;
    }
}
