pragma solidity ^0.5.8;

// Synthetic fixture: bank withdraw path emits a local event only — no external
// Log/TransferLog helper that can gate Collect.
contract FairBank {
    mapping(address => uint) public balances;
    event Withdraw(address indexed who, uint amount);

    function Deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function Collect(uint _am) public {
        require(balances[msg.sender] >= _am);
        balances[msg.sender] -= _am;
        msg.sender.transfer(_am);
        emit Withdraw(msg.sender, _am);
    }

    function() external payable {
        Deposit();
    }
}
