pragma solidity ^0.5.8;

// Synthetic fixture (Phase 19): transfer-blocking token. The owner can add
// any holder to a blocklist and, until trading is opened, only the owner may
// transfer, so buyers cannot sell.
contract BaitToken {
    mapping(address => uint256) private _balances;
    mapping(address => bool) public isBlocked;
    address public owner;
    bool public tradingOpen;
    uint256 public totalSupply;

    constructor() public {
        owner = msg.sender;
        totalSupply = 1000000 ether;
        _balances[msg.sender] = totalSupply;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function setBlocked(address account, bool value) public onlyOwner {
        isBlocked[account] = value;
    }

    function openTrading(bool value) public onlyOwner {
        tradingOpen = value;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(!isBlocked[from]);
        require(tradingOpen || from == owner);
        require(_balances[from] >= amount);
        _balances[from] -= amount;
        _balances[to] += amount;
    }
}
