pragma solidity ^0.5.8;

// Synthetic fixture (Phase 19+): PrivateBank / ETH_FUND / Log honeypot shape.
// Withdraw path calls an external Log.AddMessage set from a constructor address.
// A malicious live Log can accept "Put" and revert on "Collect", trapping deposits.
contract Log {
    event Message(address indexed Sender, string Data, uint Val, uint Time);

    function AddMessage(address _adr, uint _val, string memory _data) public {
        emit Message(_adr, _data, _val, block.timestamp);
    }
}

contract PrivateBankHoneypot {
    mapping(address => uint) public balances;
    Log public LogFile;
    uint public MinSum = 1 ether;

    constructor(address log) public {
        LogFile = Log(log);
    }

    function Deposit() public payable {
        balances[msg.sender] += msg.value;
        LogFile.AddMessage(msg.sender, msg.value, "Put");
    }

    function Collect(uint _am) public {
        if (balances[msg.sender] >= MinSum && balances[msg.sender] >= _am) {
            (bool ok, ) = msg.sender.call.value(_am)("");
            if (ok) {
                balances[msg.sender] -= _am;
                LogFile.AddMessage(msg.sender, _am, "Collect");
            }
        }
    }

    function() external payable {
        Deposit();
    }
}
