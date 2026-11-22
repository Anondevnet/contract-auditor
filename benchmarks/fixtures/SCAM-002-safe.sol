pragma solidity ^0.5.8;

// Synthetic fixture (Phase 19): clean counterpart. Plain fixed-supply token,
// no privileged transfer controls.
contract PlainToken {
    mapping(address => uint256) private _balances;
    uint256 public totalSupply;

    constructor() public {
        totalSupply = 1000000 ether;
        _balances[msg.sender] = totalSupply;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0));
        require(_balances[from] >= amount);
        _balances[from] -= amount;
        _balances[to] += amount;
    }
}
