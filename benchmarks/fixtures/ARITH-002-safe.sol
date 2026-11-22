pragma solidity ^0.5.8;

/// Benchmark fixture ARITH-002 (synthetic, original code for Contract Auditor Phase 14).
/// Safe counterpart of ARITH-001: the protective control is reordering the
/// operations so the multiplication happens BEFORE the single division, so
/// no intermediate truncation can occur. Assumes amount * bps does not
/// overflow for the value ranges used (documented assumption for solc 0.5.8).
contract FeeCalculatorSafe {
    uint256 public totalFees;
    uint256 public lastShare;

    function computeFee(uint256 amount, uint256 divisor, uint256 bps) public {
        // Multiplication first; one division at the end preserves precision.
        lastShare = (amount * bps) / divisor;
        totalFees += lastShare;
    }
}
