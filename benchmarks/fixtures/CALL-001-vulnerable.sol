pragma solidity ^0.5.8;

/// Benchmark fixture CALL-001 (synthetic, original code for Contract Auditor Phase 14).
/// Vulnerable behavior: pushReward() forwards Ether with a low-level call and
/// IGNORES the returned success flag. If the recipient rejects the call, the
/// Ether stays in the contract while the caller believes the reward was
/// delivered. Expected Slither detector: unchecked-lowlevel.
contract RewardPusher {
    event RewardPushed(address indexed to, uint256 amount);

    function pushReward(address payable to, uint256 amount) public payable {
        require(to != address(0), "zero address");
        require(amount <= address(this).balance, "insufficient balance");
        // Return value of the low-level call is discarded.
        to.call.value(amount)("");
        emit RewardPushed(to, amount);
    }
}
