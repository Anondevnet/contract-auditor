// SPDX-License-Identifier: UNLICENSED
// Local-deploy smoke fixtures for the invariant generator (never deployed to a chain).
pragma solidity ^0.8.20;

contract MockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    function decimals() external pure returns (uint8) { return 18; }
    function approve(address s, uint256 x) external returns (bool) { allowance[msg.sender][s] = x; return true; }
    function transfer(address t, uint256 x) external returns (bool) { balanceOf[msg.sender] -= x; balanceOf[t] += x; return true; }
    function transferFrom(address f, address t, uint256 x) external returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max) allowance[f][msg.sender] -= x;
        balanceOf[f] -= x; balanceOf[t] += x; return true;
    }
}

/// Share vault; `offset` = virtual shares/assets (0 => classic inflation-prone, 1e6 => OZ-style defence).
/// `leakBps` > 0 adds a deliberate redeem bonus bug (pays out more than share value).
contract MockVault {
    MockToken public immutable token;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    uint256 public immutable offset;
    uint256 public immutable leakBps;
    constructor(MockToken t, uint256 offset_, uint256 leakBps_) { token = t; offset = offset_; leakBps = leakBps_; }
    function asset() external view returns (address) { return address(token); }
    function totalAssets() public view returns (uint256) { return token.balanceOf(address(this)); }
    function convertToShares(uint256 x) public view returns (uint256) { return x * (totalSupply + offset) / (totalAssets() + (offset == 0 ? 0 : 1)) ; }
    function convertToAssets(uint256 s) public view returns (uint256) { return totalSupply == 0 ? s : s * (totalAssets() + (offset == 0 ? 0 : 1)) / (totalSupply + offset); }
    function maxRedeem(address o) external view returns (uint256) { return balanceOf[o]; }
    function deposit(uint256 x, address r) external returns (uint256 s) {
        s = totalSupply == 0 && offset == 0 ? x : convertToShares(x);
        require(s > 0, "zero shares");
        token.transferFrom(msg.sender, address(this), x);
        totalSupply += s; balanceOf[r] += s;
    }
    function mint(uint256 s, address r) external returns (uint256 x) {
        x = totalSupply == 0 ? s : (s * totalAssets() + totalSupply - 1) / totalSupply;
        token.transferFrom(msg.sender, address(this), x);
        totalSupply += s; balanceOf[r] += s;
    }
    function redeem(uint256 s, address r, address o) public returns (uint256 x) {
        require(msg.sender == o, "owner");
        x = convertToAssets(s);
        x += x * leakBps / 10000;
        if (x > totalAssets()) x = totalAssets();
        balanceOf[o] -= s; totalSupply -= s;
        token.transfer(r, x);
    }
    function withdraw(uint256 x, address r, address o) external returns (uint256 s) {
        s = (x * totalSupply + totalAssets() - 1) / totalAssets();
        redeem(s, r, o);
    }
}
