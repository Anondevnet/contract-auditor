pragma solidity ^0.5.8;

/// Benchmark fixture ARITH-001 (synthetic, original code for Contract Auditor Phase 14).
/// Vulnerable behavior: computeFee() divides BEFORE multiplying
/// ((amount / divisor) * bps). With integer (truncating) division in solc
/// 0.5.8 — which has NO built-in overflow/underflow protection — any amount
/// smaller than divisor truncates to 0 and all fractional precision is lost
/// before the multiplication, systematically undercounting the fee share.
/// Expected Slither detector: divide-before-multiply.
contract FeeCalculator {
    uint256 public totalFees;
    uint256 public lastShare;

    function computeFee(uint256 amount, uint256 divisor, uint256 bps) public {
        // Division executes first; precision is lost before multiplying.
        lastShare = (amount / divisor) * bps;
        totalFees += lastShare;
    }
}
