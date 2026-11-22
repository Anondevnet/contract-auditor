pragma solidity ^0.5.8;

/// Benchmark PAUTH-010: initializer-guarded initialize on an implementation whose
/// *base* constructor calls _disableInitializers() (safe / TN).
contract MiniInitializable {
    bool internal _initialized;
    modifier initializer() { require(!_initialized, "init"); _initialized = true; _; }
    function _disableInitializers() internal { _initialized = true; }
}

contract AccessControlledBase is MiniInitializable {
    constructor() public { _disableInitializers(); }
}

contract TrancheImpl is AccessControlledBase {
    address public owner;
    function initialize(address o) external initializer { owner = o; }
}
