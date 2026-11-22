pragma solidity ^0.5.8;

// Synthetic fixture (Phase 26): owner can mint any amount to any address with
// no cap. Must still be flagged as unlimited-owner-mint.
contract InflatableToken {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor() public { owner = msg.sender; }

    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
