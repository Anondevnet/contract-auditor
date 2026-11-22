pragma solidity ^0.5.8;
/// Benchmark KX-003: MasterChef-style staking whose deposit changes user.amount
/// before updatePool runs, so rewards are computed on the new stake. Vulnerable.
contract ChefBug {
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    mapping(address => UserInfo) public userInfo;
    uint256 public accRewardPerShare; uint256 public lastRewardBlock; uint256 public totalStaked;
    function updatePool() public {
        if (totalStaked > 0) accRewardPerShare += (block.number - lastRewardBlock) * 1e12 / totalStaked;
        lastRewardBlock = block.number;
    }
    function deposit(uint256 amt) external {
        UserInfo storage user = userInfo[msg.sender];
        user.amount += amt;
        totalStaked += amt;
        updatePool();
        user.rewardDebt = user.amount * accRewardPerShare / 1e12;
    }
}
