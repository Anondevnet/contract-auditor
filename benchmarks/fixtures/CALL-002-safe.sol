pragma solidity ^0.5.8;

/// Benchmark fixture CALL-002 (synthetic, original code for Contract Auditor Phase 14).
/// Safe counterpart of CALL-001: the protective control is checking the
/// low-level call's success flag (and reverting on failure), so a failed
/// delivery is not silently treated as success.
contract RewardPusherSafe {
    event RewardPushed(address indexed to, uint256 amount);

    function pushReward(address payable to, uint256 amount) public payable {
        require(to != address(0), "zero address");
        require(amount <= address(this).balance, "insufficient balance");
        (bool success, ) = to.call.value(amount)("");
        require(success, "reward transfer failed");
        emit RewardPushed(to, amount);
    }
}
