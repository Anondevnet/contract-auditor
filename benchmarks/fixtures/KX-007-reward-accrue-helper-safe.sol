pragma solidity ^0.5.8;
/// Benchmark KX-007: staking that books rewards through a private _accrue helper
/// (which settles rewardPerShare) before every stake change. Safe; regression
/// for a false positive on a live contract shaped like this.
contract AccrueStaking {
    mapping(address => uint256) public staked;
    mapping(address => uint256) private _paidPerShare;
    mapping(address => uint256) private _accrued;
    uint256 public rewardPerShare; uint256 public totalStaked; uint256 public lastUpdate; uint256 public rate;
    function _settle() private {
        if (totalStaked > 0) rewardPerShare = rewardPerShare + (now - lastUpdate) * rate / totalStaked;
        lastUpdate = now;
    }
    function _accrue(address u) private {
        _settle();
        _accrued[u] += staked[u] * (rewardPerShare - _paidPerShare[u]);
        _paidPerShare[u] = rewardPerShare;
    }
    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount);
        _accrue(msg.sender);
        staked[msg.sender] -= amount;
        totalStaked -= amount;
    }
}
