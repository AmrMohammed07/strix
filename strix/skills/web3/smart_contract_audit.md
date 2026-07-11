---
name: smart-contract-audit
description: Smart contract / DeFi security audit — 10 high-frequency bug classes (accounting desync, access control, incomplete code path, off-by-one, oracle manipulation, ERC4626 vaults, reentrancy, flash loans, signature replay, proxy/upgrade), pre-dive kill signals, grep patterns per class, a Foundry PoC template, and real Immunefi paid examples. Use for any Solidity/Rust contract review or when deciding whether a DeFi target is worth hunting.
---

# Smart Contract Audit

Ten bug classes ordered by real-world frequency, pre-dive kill signals to avoid wasting hours on hardened targets, grep patterns to find each class fast, and a Foundry PoC template to prove impact. The single most productive habit: read ALL sibling functions. If `vote()` has a modifier, check `poke()`, `reset()`, `harvest()` — the missing modifier on the sibling is the bug. That one rule explains roughly 19% of all Critical findings.

## Pre-Dive Kill Signals

Check these BEFORE reading a single line. Large, well-audited bridges are extremely hard (a $322M-TVL, OZ-audited, 750K-LOC bridge can burn five sessions for zero findings).

Hard kills:
- **TVL < $500K** → max payout capped too low for the effort.
- **2+ top-tier audits** (Halborn, Trail of Bits, Cyfrin, OpenZeppelin) on a simple protocol → bugs already found.
- **Protocol < 500 lines, single A→B→C flow** → minimal attack surface.
- **Formula**: `max_realistic_payout = min(10% × TVL, program_cap)` — if < $10K, skip.

Target score (go if ≥ 6/10): TVL > $10M (+2); Immunefi Critical ≥ $50K (+2); no top-tier audit on current version (+2); < 30 days since deploy (+1); protocol you've hunted before (+1); source + natspec available (+1); upgradeable proxies (+1).

## 1. Accounting State Desynchronization (28% of Criticals)

Two state variables meant to stay in sync; one code path updates A but forgets B; later code reads both and makes decisions on stale B. `Real Value = A - B`; if A updates but B doesn't, real value appears larger → phantom value.

```solidity
// Variant: fast path skips state update (early return)
function claimRedemption(uint256 tokenId) external {
    if (transmuter.balance >= amount) {
        transmuter.transfer(user, amount);
        _burn(tokenId);
        return;  // EARLY RETURN — cumulativeEarmarked, _redemptionWeight, totalDebt never updated
    }
    alchemist.redeem(...);  // slow path updates all state correctly
}
```

Also watch: state updated in the wrong order (shares computed before `totalAssets` incremented → wrong rate).

```bash
grep -rn "totalSupply\|totalShares\|totalAssets\|totalDebt\|cumulativeReward\|rewardPerShare" contracts/
grep -rn "\breturn\b" contracts/ -B3 | grep -B3 "if\b"   # early returns — what state does the normal path update that this skips?
```

## 2. Access Control (19% of Criticals)

- **Missing modifier on a sibling function** — `vote()`/`reset()` guarded by `onlyNewEpoch`, but `poke()` has no guard → infinite inflation.
- **Wrong check (existence vs ownership)** — `_requireOwned(tokenId)` checks the token exists, not that the caller owns it.
- **Silent modifier (`if` vs `require`)** — `modifier onlyAdmin() { if (msg.sender == admin) { _; } }` lets non-admins through without reverting.
- **Uninitialized proxy** — `initialize()` missing the `initializer` modifier → anyone becomes owner.

```bash
grep -rn "function vote\|function poke\|function reset\|function claim\|function harvest" contracts/ -A2
grep -rn "_requireOwned\|ownerOf\|_isApprovedOrOwner\|_checkAuthorized" contracts/ -B5
grep -rn "function initialize\b" contracts/ -A3
grep -rn "_disableInitializers()" contracts/
```

Real paid: Wormhole $10M (uninitialized UUPS proxy → anyone calls `initialize()`); Parity $150M frozen (no access control on `initWallet()` in library).

## 3. Incomplete Code Path (17% of Criticals)

The function-family comparison test: list every state change and token transfer in function A (deposit/place/create); for each, confirm function B (withdraw/update/cancel) has the corresponding reverse/refund. If A does X but B doesn't undo X → bug.

- `update_order()` missing a refund when a sell price decreases → tokens stuck.
- `swapForETH()` refunds ETH excess only, not the ERC20.
- `mint()` bypasses the receipt validation that `deposit()` performs → mints without receiving assets.

```bash
grep -rn "function place_\|function create_\|function add_\|function open_" contracts/ -A5
grep -rn "function update_\|function modify_\|function cancel_" contracts/ -A5
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```

## 4. Off-By-One and Boundary Conditions (22% of Highs)

For every `if (A > B)`, ask what happens when `A == B`. Six locations to check: period/epoch boundaries (`>` vs `>=` at period end), time locks (`block.timestamp == deadline` locks or unlocks?), loop break conditions, array index bounds (`i <= array.length` should be `<`), amount/balance boundaries (exact full withdrawal allowed?), rounding/precision (can any input produce 0 output that should be non-zero?).

```bash
grep -rn "Period\|Epoch\|Round\|Deadline\|period\|epoch\|deadline" contracts/ -A3 | grep "[<>][^=]"
grep -rn "\.length\s*-\s*1\|i\s*<=\s*.*\.length\b" contracts/
```

## 5. Oracle / Price Manipulation (largest individual payouts)

- **Missing staleness check** — `latestRoundData()` without checking `updatedAt`; require `block.timestamp - updatedAt <= MAX_AGE` and `price > 0`.
- **Missing confidence interval (Pyth)** — `getPriceUnsafe()` ignoring `p.conf`; require `p.conf * 10 <= uint64(p.price)`.
- **TWAP too short** — a 60-second TWAP is flash-loan-manipulatable; want ≥ 1800s.
- **Single-source oracle** — Uniswap spot price only → flash-loan manipulatable; want Chainlink primary + TWAP fallback with a close-agreement check.

```bash
grep -rn "latestRoundData" contracts/ -A5 | grep -v "updatedAt\|timestamp"
grep -rn "getPriceUnsafe\|getPrice\b" contracts/ -A8 | grep -v "conf\|confidence"
grep -rn "secondsAgo\|TWAP\|cardinality\|getReserves\|slot0\b" contracts/ -A5
```

## 6. ERC4626 Vault Attacks

- **First-depositor / exchange-rate manipulation** — deposit 1 wei, donate a large amount directly (transfer, not deposit), victim's deposit rounds down to 0 shares. Fix: virtual shares (`_decimalsOffset` in OZ v4.9+).
- **Transfer moves shares but not lock/stake records** → shares stuck, can't redeem → permanent freeze.

```bash
grep -rn "function transfer\|function transferFrom" contracts/ -A15
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```

## 7. Reentrancy

Variants: single-function, cross-function (re-enter a sibling with stale state), cross-contract (via a callback), read-only (re-enter a view that returns stale data). Root cause: external interaction before the state effect. Enforce Checks-Effects-Interactions.

```solidity
// VULNERABLE: effect after interaction
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");   // INTERACTION first
    require(ok);
    balances[msg.sender] -= amount;                     // EFFECT after → reentrancy window
}
```

```bash
grep -rn "\.call{value\|safeTransfer\|transfer(" contracts/ -B10 | grep -v "require\|revert"
grep -rn "function withdraw\|function redeem\|function claim" contracts/ -A2 | grep -v "nonReentrant"
```

## 8. Flash Loan Attacks

Flow: borrow $100M from a flash loan → dump a token in a Uniswap pool to crash spot price → protocol reads spot → accepts undercollateralized loans → borrow max against cheap collateral → repay loan, keep profit. Any price read from `getReserves`/`getAmountsOut`/`slot0` is manipulatable within a single transaction.

```bash
grep -rn "getReserves\|getAmountsOut\|slot0\b" contracts/ -A5
```

## 9. Signature Replay

- **Missing nonce** — the signed hash omits a nonce → the same signature is reusable.
- **Missing chain ID** — hash omits `block.chainid` → the signature is valid on mainnet, testnet, and all forks.
- Confirm the signed hash includes nonce + chainId + contract address.

```bash
grep -rn "ecrecover\|ECDSA\.recover" contracts/ -B20
grep -rn "nonce\|_nonces\|nonces\[" contracts/
```

## 10. Proxy / Upgrade Issues

- **Storage collision** between proxy and implementation layouts.
- **Uninitialized implementation** — call `initialize()` on the implementation, then `upgradeTo()` to replace logic.
- **`delegatecall` to a user/owner-controlled address**.

```bash
grep -rn "function initialize\b\|_disableInitializers\|initializer" contracts/
grep -rn "delegatecall\b" contracts/ -B3 -A5
grep -rn "0x360894\|EIP1967\|_IMPLEMENTATION_SLOT" contracts/
```

## Foundry PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork("mainnet", BLOCK_NUMBER);
        target = VulnerableContract(TARGET_ADDRESS);
        deal(address(token), attacker, INITIAL_BALANCE);
    }

    function test_exploit() public {
        console.log("before:", token.balanceOf(attacker));
        vm.startPrank(attacker);
        // Step 1: setup conditions  Step 2: execute exploit  Step 3: verify impact
        vm.stopPrank();
        console.log("after:", token.balanceOf(attacker));
        assertGt(token.balanceOf(attacker), INITIAL_BALANCE, "Exploit failed");
    }
}
```

Key cheatcodes: `vm.prank`/`startPrank`, `deal(token, addr, amount)`, `vm.warp(ts)`, `vm.roll(block)`, `vm.createSelectFork("mainnet", block)`, `vm.expectRevert(bytes)`, `vm.assume(cond)`. Run: `forge test --match-test test_exploit -vvvv --fork-url $MAINNET_RPC`.
