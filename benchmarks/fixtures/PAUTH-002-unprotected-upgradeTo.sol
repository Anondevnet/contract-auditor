pragma solidity ^0.5.8;

/// Benchmark PAUTH-002: unprotected upgradeTo — any caller can replace implementation.
contract UnprotectedUpgrade {
    address public implementation;

    event Upgraded(address indexed implementation);

    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }
}
