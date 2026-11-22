pragma solidity ^0.5.8;

/// Benchmark fixture ARB-001 (synthetic, original code for Contract Auditor Phase 15).
/// Vulnerable behavior: drain() is callable by ANYONE and forwards the ENTIRE
/// contract balance to a caller-supplied address, so any user can empty the
/// escrow. Expected Slither detector: arbitrary-send-eth (location: drain).
contract Escrow {
    function deposit() external payable {}

    function drain(address payable to) external {
        to.transfer(address(this).balance);
    }
}
