pragma solidity ^0.5.8;
/// Benchmark KX-004: same staking, but updatePool runs and pending rewards settle
/// before user.amount changes. Safe.
contract ChefOk {
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    mapping(address => UserInfo) public userInfo;
    uint256 public accRewardPerShare; uint256 public lastRewardBlock; uint256 public totalStaked;
    function updatePool() public {
        if (totalStaked > 0) accRewardPerShare += (block.number - lastRewardBlock) * 1e12 / totalStaked;
        lastRewardBlock = block.number;
    }
    function deposit(uint256 amt) external {
        updatePool();
        UserInfo storage user = userInfo[msg.sender];
        user.amount += amt;
        totalStaked += amt;
        user.rewardDebt = user.amount * accRewardPerShare / 1e12;
    }
}
