pragma solidity ^0.5.8;
/// Benchmark KX-002: same market, but listing mints MINIMUM_LIQUIDITY to a dead
/// address so totalSupply can never return to ~0. Safe.
interface IERC20 { function balanceOf(address) external view returns (uint256); }
contract CTokenSeeded {
    IERC20 public underlying; uint256 public totalSupply; uint256 public totalBorrows; uint256 public totalReserves;
    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    mapping(address => uint256) public accountTokens;
    constructor() public { totalSupply = MINIMUM_LIQUIDITY; accountTokens[address(0x000000000000000000000000000000000000dEaD)] = MINIMUM_LIQUIDITY; }
    function getCashPrior() internal view returns (uint256) { return underlying.balanceOf(address(this)); }
    function exchangeRateStored() public view returns (uint256) {
        return (getCashPrior() + totalBorrows - totalReserves) * 1e18 / totalSupply;
    }
}
