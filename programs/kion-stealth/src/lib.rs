use anchor_lang::prelude::*;
use anchor_lang::system_program;
use anchor_lang::solana_program::{
    clock::Clock,
    hash::Hash as SolanaHash,
    keccak,
};
use secp256k1::{SecretKey, PublicKey, Secp256k1};
use rand::rngs::ChaChaRng;
use rand::SeedableRng;
use num_bigint::{BigUint, RandBigInt};
use hex::encode as hex_encode;

declare_id!("KionStealth11111111111111111111111111111111");

#[program]
pub mod kion_stealth {
    use super::*;

    /// Initialize the global config storing the program authority.
    /// This can store any top-level settings.
    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        let config = &mut ctx.accounts.global_config;
        config.authority = *ctx.accounts.authority.key;
        config.bump = bump;
        Ok(())
    }

    /// Register a user’s stealth meta-address on-chain:  
    /// - spending_pubkey (Secp256k1 compressed, 33 bytes)  
    /// - viewing_pubkey (Secp256k1 compressed, 33 bytes)  
    /// This is the “st:sol:<spending><viewing>” concept, minus the prefix.  
    pub fn register_user(
        ctx: Context<RegisterUser>,
        spending_pubkey: [u8; 33],
        viewing_pubkey: [u8; 33],
    ) -> Result<()> {
        let user_data = &mut ctx.accounts.user_data;
        user_data.authority = *ctx.accounts.authority.key;
        user_data.spending_pubkey = spending_pubkey;
        user_data.viewing_pubkey = viewing_pubkey;
        Ok(())
    }

    /// Generate an ephemeral keypair on-chain, purely for demonstration.  
    /// - We create ephemeral_private_key by randomly deriving from the recent blockhash.  
    /// - ephemeral_pubkey is ephemeral_private_key * G.  
    /// Both are stored in `EphemeralKeys` account.  
    /// This ephemeral key can be used by the sender for stealth transactions.  
    pub fn generate_ephemeral_keypair(ctx: Context<GenerateEphemeralKeypair>) -> Result<()> {
        let ephemeral_acc = &mut ctx.accounts.ephemeral_keys;
        ephemeral_acc.authority = *ctx.accounts.authority.key;

        let clock = Clock::get()?;
        let blockhash = ctx.accounts.sysvar_recent_blockhashes.data.borrow();
        let blockhash_bytes = &blockhash[0..32];

        // Build a random seed from blockhash + slot + authority pubkey
        let mut seed_data = Vec::new();
        seed_data.extend_from_slice(blockhash_bytes);
        seed_data.extend_from_slice(&clock.unix_timestamp.to_le_bytes());
        seed_data.extend_from_slice(ctx.accounts.authority.key.as_ref());

        // We create a ChaCha RNG from the seed_data
        // This is how we produce ephemeral_private_key
        let mut rng_source = [0u8; 32];
        let hash_output = keccak::hash(&seed_data);
        rng_source.copy_from_slice(&hash_output.0);
        let mut rng = ChaChaRng::from_seed(rng_source);

        // We choose ephemeral_private_key in secp256k1 field
        // We do random in [1..n-1]
        let n = BigUint::from_bytes_be(&secp256k1::constants::CURVE_ORDER);
        let ephemeral_sk_num = rng.gen_biguint_below(&n);
        let ephemeral_sk_bytes = {
            let mut big = ephemeral_sk_num.to_bytes_be();
            // pad to 32
            if big.len() < 32 {
                let mut padded = vec![0u8; 32 - big.len()];
                padded.extend_from_slice(&big);
                big = padded;
            } else if big.len() > 32 {
                big = big[big.len() - 32..].to_vec();
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&big[..32]);
            arr
        };
        let ephemeral_secret_key = SecretKey::from_slice(&ephemeral_sk_bytes)
            .map_err(|_| error!(ErrorCode::InvalidPrivateKey))?;

        let secp = Secp256k1::new();
        let ephemeral_public_key = PublicKey::from_secret_key(&secp, &ephemeral_secret_key);

        // Store ephemeral keypair in ephemeral_acc
        ephemeral_acc.ephemeral_private_key = ephemeral_sk_bytes;
        ephemeral_acc.ephemeral_pubkey_compressed = ephemeral_public_key.serialize();

        Ok(())
    }

    /// Announce a stealth transaction on-chain:
    /// The ephemeral_pubkey is either given or taken from EphemeralKeys account.
    /// The user must also specify the user_data reference for the **recipient** 
    /// (which has the recipient’s viewing_pubkey, etc.). We derive the stealth address 
    /// from ephemeral_private_key * recipient.viewing_pubkey => shared_secret => 
    /// + recipient.spending_pubkey => final stealth address. We store that in an Announcement.
    ///
    /// We also produce a single-byte view_tag from the hash of ephemeral secret.
    /// This view_tag is stored in the Announcement for quick scanning.
    pub fn announce_stealth(
        ctx: Context<AnnounceStealth>,
        ephemeral_pubkey_external: Option<[u8; 33]>,
    ) -> Result<()> {
        let announcement = &mut ctx.accounts.announcement;

        // If ephemeral_pubkey_external is Some, we use that. Otherwise, from ephemeral_keys
        let ephemeral_pubkey_compressed = match ephemeral_pubkey_external {
            Some(pubkey) => pubkey,
            None => ctx
                .accounts
                .ephemeral_keys
                .as_ref()
                .unwrap()
                .ephemeral_pubkey_compressed,
        };

        let ephemeral_private_key_bytes = match ephemeral_pubkey_external {
            // If ephemeral pubkey is external, we don't have the ephemeral private key here,
            // so we skip the ephemeral-based stealth derivation on chain. For demonstration, 
            // we'll require ephemeral_keys in that scenario as well if needed.
            Some(_) => {
                // We won't do the local ephemeral-based stealth derivation if the ephemeral private key 
                // isn't available. We'll produce an event only. 
                [0u8; 32]
            }
            None => ctx
                .accounts
                .ephemeral_keys
                .as_ref()
                .unwrap()
                .ephemeral_private_key,
        };

        // We'll fetch the recipient’s user data. We need their 
        // viewing_pubkey + spending_pubkey to derive a final stealth address.
        let recipient_data = &ctx.accounts.recipient_user_data;

        // ephemeral secret = ephemeral_private_key * recipient.viewing_pubkey 
        let ephemeral_secret_hashed = {
            let secp = Secp256k1::new();

            let ephemeral_sk = SecretKey::from_slice(&ephemeral_private_key_bytes)
                .map_err(|_| error!(ErrorCode::InvalidPrivateKey))?;

            let viewing_pubkey = PublicKey::from_slice(&recipient_data.viewing_pubkey)
                .map_err(|_| error!(ErrorCode::InvalidViewingKey))?;

            // ECDH: ephemeral_sk * viewing_pubkey => shared_point => hash
            let shared_point = secp.ecdh(&viewing_pubkey, &ephemeral_sk);
            let shared_hash = keccak::hash(&shared_point);
            shared_hash
        };

        // Extract a single byte for the view_tag
        let view_tag = ephemeral_secret_hashed.0[0];

        // Derive stealth address = recipient.spending_pubkey + (ephemeral_secret_hashed * G)
        // in typical stealth formula: R = S + (h * G), except on Solana we might store 
        // it in compressed form for the final stealth address. We'll do that now:
        let secp = Secp256k1::new();
        let spending_pubkey_point = PublicKey::from_slice(&recipient_data.spending_pubkey)
            .map_err(|_| error!(ErrorCode::InvalidSpendingKey))?;

        // Convert ephemeral_secret_hashed to scalar mod n
        let scalar_h = scalar_mod_order(&ephemeral_secret_hashed.0);
        let ephemeral_sk_for_stealth = SecretKey::from_slice(&scalar_h)
            .map_err(|_| error!(ErrorCode::InvalidPrivateKey))?;
        let ephemeral_pt_for_stealth = PublicKey::from_secret_key(&secp, &ephemeral_sk_for_stealth);

        // Now "add" these points: R = spending_pubkey_point + ephemeral_pt_for_stealth
        let combined_stealth_point = spending_pubkey_point.combine(&ephemeral_pt_for_stealth)
            .map_err(|_| error!(ErrorCode::CannotCombinePoints))?;
        let stealth_address_compressed = combined_stealth_point.serialize();

        // Store the announcement on-chain
        announcement.authority = *ctx.accounts.authority.key;
        announcement.ephemeral_pubkey_compressed = ephemeral_pubkey_compressed;
        announcement.recipient_spending_pubkey = recipient_data.spending_pubkey;
        announcement.recipient_viewing_pubkey = recipient_data.viewing_pubkey;
        announcement.stealth_address_compressed = stealth_address_compressed;
        announcement.view_tag = view_tag;
        announcement.timestamp = Clock::get()?.unix_timestamp;

        // Emit event for off-chain watchers
        emit!(StealthAnnouncementEvent {
            emitter: announcement.authority,
            ephemeral_pubkey: ephemeral_pubkey_compressed,
            stealth_address: stealth_address_compressed,
            view_tag,
            timestamp: announcement.timestamp,
        });

        Ok(())
    }

    /// Recipients can scan on-chain announcements to see if they are relevant.
    /// We do ephemeral_pubkey * viewing_private_key => check if the single-byte 
    /// view_tag matches. If it does, the user knows that this stealth address 
    /// belongs to them.
    pub fn scan_announcement(
        ctx: Context<ScanAnnouncement>,
        viewing_private_key: [u8; 32],
    ) -> Result<()> {
        let announcement = &ctx.accounts.announcement;
        let ephemeral_pubkey_compressed = announcement.ephemeral_pubkey_compressed;
        let stored_view_tag = announcement.view_tag;

        let secp = Secp256k1::new();
        let ephemeral_public_key = PublicKey::from_slice(&ephemeral_pubkey_compressed)
            .map_err(|_| error!(ErrorCode::InvalidEphemeralPubkey))?;
        let viewing_sk = SecretKey::from_slice(&viewing_private_key)
            .map_err(|_| error!(ErrorCode::InvalidViewingKey))?;

        // ECDH
        let shared_point = secp.ecdh(&ephemeral_public_key, &viewing_sk);
        let hashed = keccak::hash(&shared_point);
        let candidate_view_tag = hashed.0[0];

        if candidate_view_tag != stored_view_tag {
            return err!(ErrorCode::NotRelevant);
        }

        // If it matches, the user is the intended recipient. 
        // We can do further logic or simply return success.
        Ok(())
    }

    /// Compute the stealth private key on-chain (recipient side):
    /// stealth_privkey = s + h (mod n), where s is spending_private_key,
    /// h is scalar derived from ephemeral_public_key * viewing_private_key.
    pub fn derive_stealth_private_key(
        ctx: Context<DeriveStealthPrivateKey>,
        spending_private_key: [u8; 32],
        ephemeral_pubkey_compressed: [u8; 33],
        viewing_private_key: [u8; 32],
    ) -> Result<()> {
        let secp = Secp256k1::new();

        let ephemeral_public_key = PublicKey::from_slice(&ephemeral_pubkey_compressed)
            .map_err(|_| error!(ErrorCode::InvalidEphemeralPubkey))?;
        let viewing_sk = SecretKey::from_slice(&viewing_private_key)
            .map_err(|_| error!(ErrorCode::InvalidViewingKey))?;

        // shared_point = ephemeral_public_key * viewing_private_key (ECDH)
        let shared_point = secp.ecdh(&ephemeral_public_key, &viewing_sk);
        let hash_shared = keccak::hash(&shared_point);
        let scalar_h = scalar_mod_order(&hash_shared.0);

        // s_stealth = s + h mod n
        let s_big = BigUint::from_bytes_be(&spending_private_key);
        let h_big = BigUint::from_bytes_be(&scalar_h);

        let n_big = BigUint::from_bytes_be(&secp256k1::constants::CURVE_ORDER);
        let s_stealth_num = (s_big + h_big) % n_big;

        let mut s_stealth_bytes = s_stealth_num.to_bytes_be();
        if s_stealth_bytes.len() < 32 {
            let mut pad = vec![0u8; 32 - s_stealth_bytes.len()];
            pad.extend_from_slice(&s_stealth_bytes);
            s_stealth_bytes = pad;
        } else if s_stealth_bytes.len() > 32 {
            s_stealth_bytes = s_stealth_bytes[s_stealth_bytes.len() - 32..].to_vec();
        }
        let mut final_arr = [0u8; 32];
        final_arr.copy_from_slice(&s_stealth_bytes);

        // For demonstration, we log it
        let stealth_key_hex = hex_encode(final_arr);
        msg!("Derived stealth private key: {}", stealth_key_hex);

        // We can store it or simply finalize. 
        // This is the user's secret key to spend from stealth address R.
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = GlobalConfig::LEN, seeds = [b"kion-config"], bump)]
    pub global_config: Account<'info, GlobalConfig>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// System program for account creations
    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[account]
pub struct GlobalConfig {
    pub authority: Pubkey,
    pub bump: u8,
}

impl GlobalConfig {
    pub const LEN: usize = 8 + 32 + 1;
}

#[derive(Accounts)]
pub struct RegisterUser<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        // seeds could be user-specific, but for demonstration:
        seeds = [b"kion-user", authority.key().as_ref()],
        bump,
        space = UserData::LEN
    )]
    pub user_data: Account<'info, UserData>,

    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

/// Each user is identified by authority and holds spending/viewing keys for stealth usage.
#[account]
pub struct UserData {
    pub authority: Pubkey,
    pub spending_pubkey: [u8; 33],
    pub viewing_pubkey: [u8; 33],
}

impl UserData {
    pub const LEN: usize = 8 + 32 + 33 + 33;
}

/// Generate ephemeral keypair on-chain
#[derive(Accounts)]
pub struct GenerateEphemeralKeypair<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        seeds = [
            b"kion-ephemeral",
            authority.key().as_ref()
        ],
        bump,
        space = EphemeralKeys::LEN
    )]
    pub ephemeral_keys: Account<'info, EphemeralKeys>,

    /// Anchor automatically includes sysvars, but we specifically need RecentBlockhashes 
    /// for generating ephemeral randomness. 
    #[account(address = anchor_lang::solana_program::sysvar::recent_blockhashes::ID)]
    pub sysvar_recent_blockhashes: AccountInfo<'info>,

    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[account]
pub struct EphemeralKeys {
    pub authority: Pubkey,
    pub ephemeral_private_key: [u8; 32],
    pub ephemeral_pubkey_compressed: [u8; 33],
}

impl EphemeralKeys {
    pub const LEN: usize = 8 + 32 + 32 + 33;
}

/// Announce a stealth transaction
#[derive(Accounts)]
pub struct AnnounceStealth<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The ephemeral keypair if you want to use ephemeral_pubkey from chain
    /// Instead of ephemeral_pubkey_external
    #[account(
        constraint = ephemeral_keys.as_ref().map_or(true, |acc| acc.authority == authority.key()),
    )]
    pub ephemeral_keys: Option<Account<'info, EphemeralKeys>>,

    /// The recipient’s user data (which contains their stealth keys)
    pub recipient_user_data: Account<'info, UserData>,

    #[account(
        init,
        payer = authority,
        seeds = [
            b"kion-stealth-announcement",
            recipient_user_data.key().as_ref()
        ],
        bump,
        space = StealthAnnouncement::LEN
    )]
    pub announcement: Account<'info, StealthAnnouncement>,

    #[account(address = system_program::ID)]
    pub system_program: Program<'info, System>,
}

/// The stored announcement
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

impl StealthAnnouncement {
    pub const LEN: usize = 8 + 32 + (33 * 4) + 1 + 8;
}

/// Scan an existing announcement for relevancy
#[derive(Accounts)]
pub struct ScanAnnouncement<'info> {
    pub announcement: Account<'info, StealthAnnouncement>,
}

/// Derive the stealth private key on-chain
#[derive(Accounts)]
pub struct DeriveStealthPrivateKey<'info> {
    pub authority: Signer<'info>,
}

// ---------------------------------------------------------------------------
// EVENT
// ---------------------------------------------------------------------------
#[event]
pub struct StealthAnnouncementEvent {
    #[index]
    pub emitter: Pubkey,
    pub ephemeral_pubkey: [u8; 33],
    pub stealth_address: [u8; 33],
    pub view_tag: u8,
    pub timestamp: i64,
}

// ---------------------------------------------------------------------------
// ERROR CODE
// ---------------------------------------------------------------------------
#[error_code]
pub enum ErrorCode {
    #[msg("Invalid ephemeral private key")]
    InvalidPrivateKey,
    #[msg("Invalid ephemeral public key")]
    InvalidEphemeralPubkey,
    #[msg("Invalid viewing key")]
    InvalidViewingKey,
    #[msg("Invalid spending key")]
    InvalidSpendingKey,
    #[msg("Cannot combine secp256k1 points")]
    CannotCombinePoints,
    #[msg("Announcement not relevant for provided viewing key")]
    NotRelevant,
}

// ---------------------------------------------------------------------------
// HELPER: scalar_mod_order
// Takes a 32-byte array from e.g. a hash, mod it by secp256k1 curve order
// ---------------------------------------------------------------------------
fn scalar_mod_order(bytes: &[u8; 32]) -> [u8; 32] {
    let n = BigUint::from_bytes_be(&secp256k1::constants::CURVE_ORDER);
    let mut x = BigUint::from_bytes_be(bytes);
    x = x % n;
    let mut out = x.to_bytes_be();
    if out.len() < 32 {
        let mut padded = vec![0u8; 32 - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    } else if out.len() > 32 {
        out = out[out.len() - 32..].to_vec();
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out[..32]);
    arr
}
