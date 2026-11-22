pragma solidity ^0.5.8;
/// Benchmark KX-006: same receiver, but only the endpoint may call and the source
/// must be the trusted remote. Safe.
contract BridgeTokenChecked {
    address public endpoint; mapping(uint16 => bytes) public trustedRemote;
    mapping(address => uint256) public balanceOf;
    constructor(address e) public { endpoint = e; }
    function _mint(address to, uint256 a) internal { balanceOf[to] += a; }
    function lzReceive(uint16 src, bytes calldata srcAddress, uint64, bytes calldata payload) external {
        require(msg.sender == endpoint, "endpoint");
        require(keccak256(srcAddress) == keccak256(trustedRemote[src]), "remote");
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        _mint(to, amount);
    }
}
