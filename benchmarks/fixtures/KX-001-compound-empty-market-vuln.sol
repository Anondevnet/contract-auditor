pragma solidity ^0.5.8;
/// Benchmark KX-001: Compound-v2-style market whose exchange rate is balance-based
/// cash / totalSupply with no minimum liquidity (empty-market donation). Vulnerable.
interface IERC20 { function balanceOf(address) external view returns (uint256); }
contract CTokenLike {
    IERC20 public underlying; uint256 public totalSupply; uint256 public totalBorrows; uint256 public totalReserves;
    uint256 internal initialExchangeRateMantissa = 2e26;
    function getCashPrior() internal view returns (uint256) { return underlying.balanceOf(address(this)); }
    function exchangeRateStored() public view returns (uint256) {
        if (totalSupply == 0) return initialExchangeRateMantissa;
        return (getCashPrior() + totalBorrows - totalReserves) * 1e18 / totalSupply;
    }
}
