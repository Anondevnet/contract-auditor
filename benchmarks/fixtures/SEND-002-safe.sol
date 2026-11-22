pragma solidity ^0.5.8;

/// Benchmark fixture SEND-002 (synthetic, original code for Contract Auditor Phase 15).
/// The .send() result is checked: a failed delivery reverts, so the credit is never
/// consumed without payout. Expected Slither detector (must NOT fire): unchecked-send.
contract RewardDistributorSafe {
    mapping(address => uint256) public credits;

    function credit(address account, uint256 amount) external {
        credits[account] += amount;
    }

    function claim() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0, "nothing to claim");
        credits[msg.sender] = 0;
        require(msg.sender.send(amount), "transfer failed");
    }
}
