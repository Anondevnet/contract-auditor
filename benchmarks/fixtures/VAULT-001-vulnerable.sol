pragma solidity ^0.5.8;

// Synthetic Phase 16 fixture: naive ERC-4626-style share math.
// First depositor mints 1:1, then a direct asset donation inflates
// totalAssets() so later deposits round down to zero shares.
contract NaiveVault {
    mapping(address => uint256) public sharesOf;
    uint256 private _totalSupply;

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function totalAssets() public view returns (uint256) {
        return address(this).balance;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        if (supply == 0) {
            return assets;
        }
        return assets * totalSupply() / totalAssets();
    }

    function deposit() external payable returns (uint256 shares) {
        shares = convertToShares(msg.value);
        sharesOf[msg.sender] += shares;
        _totalSupply += shares;
    }
}
