pragma solidity ^0.5.8;

// Synthetic fixture (Phase 19): clean counterpart. The answer hash is fixed
// at deployment, nobody can change it, and there is no privileged withdraw:
// a correct guess is always paid.
contract FairQuiz {
    string public question;
    bytes32 public responseHash;

    constructor(string memory _question, bytes32 _responseHash) public payable {
        question = _question;
        responseHash = _responseHash;
    }

    function Try(string memory _response) public payable {
        require(msg.value >= 0.1 ether);
        if (responseHash == keccak256(abi.encode(_response))) {
            msg.sender.transfer(address(this).balance);
        }
    }
}
