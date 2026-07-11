---
name: meme-coin-audit
description: Meme coin / token security audit and rug-pull detection — pre-dive kill signals, 8 token-specific bug classes (hidden mint, honeypot/transfer restriction, fee manipulation, LP drain, bonding-curve manipulation, Solana authority retention, fake renounce, sandwich amplification), EVM and Solana grep patterns, on-chain SPL/Token-2022 checks, and a Foundry PoC template. Use for any token audit, rug-pull assessment, or pre-investment due diligence.
---

# Meme Coin & Token Security Audit

Fast-kill rug-pull detection plus deeper token security analysis for EVM and Solana meme coins. Every rug pull requires a privileged operation — mint, blacklist, fee change, LP removal, or authority abuse. Check ALL authorities and owner functions: the retained authority IS the rug vector. If you find the privilege, you found the bug.

## Pre-Dive Kill Signals

Check before reading a single line of code.

Hard kills (skip immediately):
- Contract **not verified** on Etherscan/Solscan → cannot audit = cannot trust.
- Deployer wallet has a rug-pull history.
- **Mint authority retained** (Solana) with no cap → infinite mint = certain rug.
- **Freeze authority retained** (Solana) on a meme coin → honeypot confirmed.
- **Transfer hook** (Token-2022) with a mutable hook program → honeypot vector.
- **Permanent delegate** (Token-2022) → can steal all holder tokens.

Soft kills (extreme caution): top holder > 20% of supply (excluding DEX pools); LP not burned or locked in a verified contract; upgradeable/proxy with retained admin; < $5K liquidity; anonymous deployer with no history.

## 1. Hidden Mint / Unlimited Supply (35% of rugs)

Deployer mints tokens post-launch and dumps on the LP.

```bash
grep -rn "function mint\|_mint(\|_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|lib\|node_modules"
grep -rn "MintTo\|mint_to\|mint_authority" src/ --include="*.rs" | grep -v "test\|target"
```

Kill if: `MAX_SUPPLY` enforced in every mint path, or mint removed entirely.

## 2. Honeypot / Transfer Restriction (25% of scams)

Buy works, sell blocked.

```bash
grep -rn "blacklist\|isBlacklisted\|_bots\|maxTxAmount\|tradingEnabled" src/ --include="*.sol"
grep -rn "freeze_authority\|transfer_hook\|TransferHook\|permanent_delegate" src/ --include="*.rs"
```

Kill if: no blacklist mapping, no transfer hooks, no freeze authority.

## 3. Fee Manipulation (20% of rugs)

Sell fee set to 99% after initial buys.

```bash
grep -rn "setFee\|setSellFee\|_taxFee\|_sellFee" src/ --include="*.sol"
grep -rn "function set.*Fee" -A5 src/ --include="*.sol" | grep -v "require\|MAX\|<="
```

Kill if: fee setter has `require(fee <= MAX_FEE)` with `MAX_FEE <= 10%`.

## 4. Liquidity Pool Drain

LP removal, migration, or manipulation to crash price.

```bash
grep -rn "migrateLP\|emergencyWithdraw\|\.sync()\|setPair\|setRouter" src/ --include="*.sol"
```

Kill if: LP burned to a dead address, no migration function, no pair setter.

## 5. Bonding Curve Manipulation

Exploits in pump.fun-style bonding curves.

```bash
grep -rn "virtualReserve\|setCurve\|graduate\|bonding_curve" src/ --include="*.sol" --include="*.rs"
```

Kill if: curve parameters immutable, graduation permissionless.

## 6. Authority Retention (Solana)

```bash
grep -rn "mint_authority\|freeze_authority\|update_authority\|close_authority" src/ --include="*.rs"
grep -rn "set_authority.*None" src/ --include="*.rs"   # good sign: revocation
```

Kill if: all authorities = None, verified on-chain.

## 7. Fake Renounce / Hidden Ownership

Ownership appears renounced but a backdoor is retained.

```bash
grep -rn "renounceOwnership.*override\|_shadowAdmin\|_backupOwner\|selfdestruct" src/ --include="*.sol"
```

Kill if: `renounceOwnership` not overridden, no second admin role, no selfdestruct.

## 8. Sandwich Amplification by Design

Contract makes holders maximally sandwichable.

```bash
grep -rn "swapExactTokensForETH" -A5 src/ --include="*.sol" | grep "0,"   # zero minOut slippage
grep -rn "swapThreshold\|_rebase\|mandatoryPool" src/ --include="*.sol"
```

Kill if: auto-swap has proper slippage, no rebase mechanics.

## Solana On-Chain Checks (no source needed)

1. **Mint authority** — `solana account <MINT> --output json`; should be null. `Some(pubkey)` → CRITICAL, can mint infinite tokens.
2. **Freeze authority** — should be null; `Some(pubkey)` → CRITICAL honeypot.
3. **LP status** — burned (to `1111...1111`), locked in a verified locker with no backdoor, or held by deployer (→ CRITICAL instant rug)?
4. **Top holders** — top 10 < 30% of supply (excluding pools); check creator wallets via first transactions.
5. **Program upgradeability** — upgrade authority should be None for immutable programs.
6. **Token-2022 extensions** — any transfer hook (→ potential honeypot) or permanent delegate (→ CRITICAL)?

## Foundry PoC Template (token exploits)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Token.sol";

contract TokenExploitTest is Test {
    Token token;
    address owner = makeAddr("owner");
    address victim = makeAddr("victim");
    address constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D; // UniV2

    function setUp() public {
        vm.createSelectFork("mainnet");
        vm.startPrank(owner);
        token = new Token();
        // add liquidity...
        vm.stopPrank();
    }

    function test_hiddenMint_rug() public {
        vm.startPrank(owner);
        uint256 before = token.totalSupply();
        token.mint(owner, 1_000_000_000e18);
        assertGt(token.totalSupply(), before, "Supply should increase");
        // dump minted tokens → victim's holdings worthless
        vm.stopPrank();
    }

    function test_fee_manipulation_rug() public {
        assertEq(token.sellFee(), 3);
        vm.prank(owner);
        token.setFees(3, 99);         // buy 3%, sell 99%
        // victim sells → loses 99% to fees
    }
}
```
