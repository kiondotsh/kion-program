# KION Stealth: Technical Reference

> **Note**: For background information and conceptual explanations of stealth transactions, privacy on Solana, and the motivations behind KION Stealth, please visit the official documentation at [docs.kion.sh](https://docs.kion.sh). This README focuses on the technical details of this Anchor program.

---

## Overview

**KION Stealth** leverages secp256k1-based keys and ECDH operations to create **stealth addresses** on Solana.  
- Users register a **stealth meta-address** (comprised of a spending key and a viewing key).  
- Senders generate an **ephemeral keypair** and derive a one-time stealth address using the recipient’s meta-address.  
- Recipients detect incoming transactions by scanning on-chain announcements using their viewing key.  
- Recipients derive a unique stealth private key on-the-fly, enabling them to spend funds delivered to that stealth address.

The code in this repository demonstrates how to implement these workflows using Anchor’s Solana Rust framework.

---

## Program Instructions

### 1. `initialize`
Initializes a global configuration account for the program.

- **Purpose**:  
  Store top-level settings and the program’s authority.

- **Signature**:  
  ```rust
  pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()>;
  ```
- **Key Data**:  
  - `GlobalConfig` account with `authority` and `bump`.

---

### 2. `register_user`
Registers a user’s stealth meta-address on-chain. This associates:
- **`spending_pubkey`** (Secp256k1 compressed, 33 bytes)
- **`viewing_pubkey`** (Secp256k1 compressed, 33 bytes)

- **Signature**:  
  ```rust
  pub fn register_user(
      ctx: Context<RegisterUser>,
      spending_pubkey: [u8; 33],
      viewing_pubkey: [u8; 33],
  ) -> Result<()>;
  ```
- **Result**:  
  Writes user’s data into a `UserData` account keyed by their authority.

---

### 3. `generate_ephemeral_keypair`
Generates an **ephemeral keypair** directly on-chain.

- **Randomness Source**:  
  - Recent blockhash  
  - Current time (`unix_timestamp`)  
  - Authority’s public key

- **Signature**:  
  ```rust
  pub fn generate_ephemeral_keypair(ctx: Context<GenerateEphemeralKeypair>) -> Result<()>;
  ```
- **Result**:  
  Stores the ephemeral secret and its corresponding secp256k1 compressed public key in an `EphemeralKeys` account.

> **Note**: Storing ephemeral secrets on-chain is primarily for demonstration/testing. In a production system, ephemeral keys are often generated off-chain.

---

### 4. `announce_stealth`
Publishes an on-chain announcement for a stealth transaction.

- **Parameters**:  
  - `ephemeral_pubkey_external`: Optional `[u8; 33]`. If provided, the ephemeral public key is directly used without on-chain ephemeral data.

- **Core Steps**:  
  1. Retrieve ephemeral pubkey (either from `ephemeral_pubkey_external` or an `EphemeralKeys` account).  
  2. Compute a shared secret (`ECDH(ephemeral_sk, recipient.viewing_pubkey)`), then hash it.  
  3. Derive the stealth address = `recipient.spending_pubkey + (hashed_secret * G)`.  
  4. Extract a single-byte `view_tag` for quick scanning.  
  5. Store all relevant data in a `StealthAnnouncement` account and emit a `StealthAnnouncementEvent`.

- **Signature**:  
  ```rust
  pub fn announce_stealth(
      ctx: Context<AnnounceStealth>,
      ephemeral_pubkey_external: Option<[u8; 33]>,
  ) -> Result<()>;
  ```

---

### 5. `scan_announcement`
Allows recipients to verify if an announcement is relevant to their viewing key.

- **Process**:  
  1. Read the ephemeral public key from the `StealthAnnouncement`.  
  2. Perform ECDH with the recipient’s `viewing_private_key`.  
  3. Hash the result, check if the first byte (`view_tag`) matches the stored tag.  
  4. If it does **not** match, return `NotRelevant`. Otherwise, it belongs to the scanning recipient.

- **Signature**:  
  ```rust
  pub fn scan_announcement(
      ctx: Context<ScanAnnouncement>,
      viewing_private_key: [u8; 32],
  ) -> Result<()>;
  ```

---

### 6. `derive_stealth_private_key`
Computes the final stealth private key for spending from the stealth address.

- **Formula**:  
  \[
    \text{stealth\_privkey} = s + H(\text{ephemeral\_pubkey} * v) \mod n
  \]  
  Where:  
  - \( s \) = recipient’s spending private key  
  - \( v \) = recipient’s viewing private key  
  - \( H(\cdots) \) = keccak256 hash of the ECDH result

- **Signature**:  
  ```rust
  pub fn derive_stealth_private_key(
      ctx: Context<DeriveStealthPrivateKey>,
      spending_private_key: [u8; 32],
      ephemeral_pubkey_compressed: [u8; 33],
      viewing_private_key: [u8; 32],
  ) -> Result<()>;
  ```
- **Result**:  
  The derived key is logged as hex (for demonstration). In a production environment, you’d typically handle this off-chain or with secure key management.

---

## Data Accounts

### `GlobalConfig`
Stores top-level program settings.

```rust
#[account]
pub struct GlobalConfig {
    pub authority: Pubkey,
    pub bump: u8,
}
```
- **Size**: `8 + 32 + 1`

### `UserData`
Represents a user’s stealth meta-address.

```rust
#[account]
pub struct UserData {
    pub authority: Pubkey,
    pub spending_pubkey: [u8; 33],
    pub viewing_pubkey: [u8; 33],
}
```
- **Size**: `8 + 32 + 33 + 33`

### `EphemeralKeys`
Holds ephemeral private/public key pairs.  
> **Warning**: Storing private keys on-chain is only recommended for demonstration or testing.

```rust
#[account]
pub struct EphemeralKeys {
    pub authority: Pubkey,
    pub ephemeral_private_key: [u8; 32],
    pub ephemeral_pubkey_compressed: [u8; 33],
}
```
- **Size**: `8 + 32 + 32 + 33`

### `StealthAnnouncement`
Defines one stealth transaction announcement.

```rust
#[account]
pub struct StealthAnnouncement {
    pub authority: Pubkey,
    pub ephemeral_pubkey_compressed: [u8; 33],
    pub recipient_spending_pubkey: [u8; 33],
    pub recipient_viewing_pubkey: [u8; 33],
    pub stealth_address_compressed: [u8; 33],
    pub view_tag: u8,
    pub timestamp: i64,
}
```
- **Size**: `8 + 32 + (33 * 4) + 1 + 8`

---

## Events & Error Codes

### **`StealthAnnouncementEvent`**
Emitted upon a successful stealth announcement. Off-chain indexers can listen for:
- `ephemeral_pubkey`
- `stealth_address`
- `view_tag`
- `timestamp`

### **ErrorCode Enum**
Handles cryptographic and domain-specific errors:
- `InvalidPrivateKey`  
- `InvalidEphemeralPubkey`  
- `InvalidViewingKey`  
- `InvalidSpendingKey`  
- `CannotCombinePoints`  
- `NotRelevant`

---

## Building & Testing

1. **Install Dependencies**  
   ```bash
   yarn install
   ```
   or
   ```bash
   npm install
   ```
   
2. **Compile the Program**  
   ```bash
   anchor build
   ```

3. **Run Tests**  
   ```bash
   anchor test
   ```
   This uses a local validator, deploys the program, and runs the test suite.

4. **Deploy**  
   Update your `Anchor.toml` with the target cluster (devnet/mainnet) and run:  
   ```bash
   anchor deploy
   ```
   Ensure your wallet is funded with enough SOL for transaction fees.

---

## Example Flow (TypeScript)

> Below is a hypothetical flow. Adapt to your environment as needed.

```typescript
// 1. Initialize program
await program.methods
  .initialize(bump)
  .accounts({
    globalConfig: globalConfigPda,
    authority: user.publicKey,
    systemProgram: SystemProgram.programId,
  })
  .signers([user])
  .rpc();

// 2. Register user meta-address
await program.methods
  .registerUser(spendingPubkey, viewingPubkey)
  .accounts({
    authority: user.publicKey,
    userData: userDataPda,
    systemProgram: SystemProgram.programId,
  })
  .signers([user])
  .rpc();

// 3. Generate ephemeral keypair on-chain
await program.methods
  .generateEphemeralKeypair()
  .accounts({
    authority: user.publicKey,
    ephemeralKeys: ephemeralKeysPda,
    sysvarRecentBlockhashes: SYSVAR_RECENT_BLOCKHASHES_PUBKEY,
    systemProgram: SystemProgram.programId,
  })
  .signers([user])
  .rpc();

// 4. Announce stealth transaction
await program.methods
  .announceStealth(null) // or pass ephemeralPubkeyExternal
  .accounts({
    authority: user.publicKey,
    ephemeralKeys: ephemeralKeysPda,
    recipientUserData: recipientDataPda,
    announcement: announcementPda,
    systemProgram: SystemProgram.programId,
  })
  .signers([user])
  .rpc();

// 5. Scan for announcement with viewing key
await program.methods
  .scanAnnouncement(viewingPrivateKey)
  .accounts({
    announcement: announcementPda,
  })
  .rpc();

// 6. Derive stealth private key
await program.methods
  .deriveStealthPrivateKey(spendingPrivateKey, ephemeralPubkeyCompressed, viewingPrivateKey)
  .accounts({
    authority: user.publicKey,
  })
  .signers([user])
  .rpc();
// Program logs your stealth private key hex for demonstration.
```

---

## Security Notes

- Storing ephemeral secrets on-chain is not recommended for real-world usage.  
- Users should protect their private keys (spending, viewing) diligently.  
- False positives are possible with the 1-byte `view_tag`. Recipients handle mismatches gracefully.  
- Before production, audit the program and cryptographic logic.


---

**For more details, FAQs, and conceptual overviews, please visit**  
[docs.kion.sh](https://docs.kion.sh)
