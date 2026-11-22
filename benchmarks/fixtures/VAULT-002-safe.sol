pragma solidity ^0.5.8;

// Synthetic Phase 16 fixture: same vault with a virtual-share offset
// (OpenZeppelin-style decimals offset) so a donation cannot round a
// later depositor down to zero shares.
contract OffsetVault {
    mapping(address => uint256) public sharesOf;
    uint256 private _totalSupply;
    uint256 internal constant DECIMALS_OFFSET = 3;

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function totalAssets() public view returns (uint256) {
        return address(this).balance;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply() + 10 ** DECIMALS_OFFSET) / (totalAssets() + 1);
    }

    function deposit() external payable returns (uint256 shares) {
        shares = convertToShares(msg.value);
        sharesOf[msg.sender] += shares;
        _totalSupply += shares;
    }
}
