
pragma solidity ^0.8.7;
contract Counter {
    event Hit(
        address indexed addr,
        uint256 total,
        uint256 timestamp
    );
    bool hitSwitch;
    address admin;
    mapping(address => uint256) ref;
    modifier isAdmin() {
        require(msg.sender == admin);
        _;
    }
    constructor(address Admin) {
        hitSwitch = true;
        admin = Admin;
    }
    modifier isSwitch() {
        require(hitSwitch);
        _;
    }
    function admin_switch(bool status) isAdmin() public {
        hitSwitch = status;
    }
    function hit() isSwitch() public returns (uint) {
        ref[msg.sender] += 1;
        emit Hit(msg.sender, ref[msg.sender], block.timestamp);
        return ref[msg.sender];
    }
}
