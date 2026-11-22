pragma solidity ^0.5.8;

/// Benchmark fixture SEND-001 (synthetic, original code for Contract Auditor Phase 15).
/// Vulnerable behavior: claim() forwards Ether with .send() and IGNORES the boolean
/// result; if the recipient's fallback runs out of gas or reverts, the claim is lost
/// silently while balances are already decremented. Expected Slither detector:
/// unchecked-send (location: claim).
contract RewardDistributor {
    mapping(address => uint256) public credits;

    function credit(address account, uint256 amount) external {
        credits[account] += amount;
    }

    function claim() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0, "nothing to claim");
        credits[msg.sender] = 0;
        // Return value of .send() is discarded.
        msg.sender.send(amount);
    }
}
