pragma solidity ^0.5.8;
/// Benchmark KX-005: bridge receiver that mints from any caller's payload with
/// no endpoint or trusted-remote check. Vulnerable.
contract BridgeTokenOpen {
    mapping(address => uint256) public balanceOf;
    function _mint(address to, uint256 a) internal { balanceOf[to] += a; }
    function lzReceive(uint16, bytes calldata, uint64, bytes calldata payload) external {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        _mint(to, amount);
    }
}
