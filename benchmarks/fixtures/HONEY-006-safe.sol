pragma solidity ^0.5.8;

// Synthetic fixture (Phase 26): ERC-7540-style async vault. mint(shares,
// receiver) only claims shares from the caller's own settled deposit request;
// the controller overload is operator-gated. Not an owner mint.
contract AsyncClaimVault {
    address public safe;
    uint256 public totalSupply;
    uint256 public totalAssets;
    uint40 public depositEpochId;
    uint40 public lastDepositEpochIdSettled;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint40) public lastDepositRequestId;
    mapping(uint40 => mapping(address => uint256)) public depositRequest;
    mapping(address => mapping(address => bool)) public isOperator;

    constructor() public { safe = msg.sender; }

    modifier onlyOperator(address controller) {
        require(msg.sender == controller || isOperator[controller][msg.sender], "op");
        _;
    }

    function claimableDepositRequest(address controller) public view returns (uint256) {
        uint40 id = lastDepositRequestId[controller];
        return id <= lastDepositEpochIdSettled ? depositRequest[id][controller] : 0;
    }

    function mint(uint256 shares, address receiver) external returns (uint256) {
        return _mint(shares, receiver, msg.sender);
    }

    function mint(uint256 shares, address receiver, address controller)
        external onlyOperator(controller) returns (uint256)
    {
        return _mint(shares, receiver, controller);
    }

    function _mint(uint256 shares, address receiver, address controller) internal returns (uint256 assets) {
        uint40 requestId = lastDepositRequestId[controller];
        require(requestId <= lastDepositEpochIdSettled, "not settled");
        assets = shares; // 1:1 for the fixture
        require(depositRequest[requestId][controller] >= assets, "exceeds claimable");
        depositRequest[requestId][controller] -= assets;
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }
}
