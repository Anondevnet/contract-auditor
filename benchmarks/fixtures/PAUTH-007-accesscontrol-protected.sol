pragma solidity ^0.5.8;

/// Benchmark PAUTH-007: AccessControl-style onlyRole guards mint (safe / TN).
contract AccessControlProtected {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    mapping(bytes32 => mapping(address => bool)) private _roles;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() public {
        _roles[MINTER_ROLE][msg.sender] = true;
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "missing role");
        _;
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return _roles[role][account];
    }
}
