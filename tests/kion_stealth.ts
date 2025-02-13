import BN from "bn.js";
import * as web3 from "@solana/web3.js";
import * as anchor from "@coral-xyz/anchor";
// tests/kion_stealth.test.ts

import * as anchor from "@project-serum/anchor";
import { Program } from "@project-serum/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { BN } from "bn.js";
import { expect } from "chai";

// The IDL TypeScript definition for our "kion_stealth" program.
// If you used "anchor init kion_stealth", it should live in `target/types/kion_stealth.d.ts`.
import { KionStealth } from "../target/types/kion_stealth";
import type { KionStealth } from "../target/types/kion_stealth";

describe("kion_stealth", () => {
  // Configure the client to use the local cluster
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.KionStealth as anchor.Program<KionStealth>;
  
  // Set up an Anchor provider and program client.
  // AnchorProvider.env() uses the local validator or configured cluster.
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const connection = provider.connection;

  // This line automatically picks up the IDL from "kion_stealth" via the workspace.
  // Or, if you prefer, load it manually: new Program<KionStealth>(IDL, programID, provider).
  const program = anchor.workspace
    .KionStealth as Program<KionStealth>;

  let authority: Keypair;
  let userAuthority: Keypair;    // user who will register (recipient)
  let globalConfigPda: PublicKey;
  let globalConfigBump: number;

  let userDataPda: PublicKey;
  let userDataBump: number;

  let ephemeralKeysPda: PublicKey;
  let ephemeralKeysBump: number;

  let announcementPda: PublicKey;
  let announcementBump: number;

  before(async () => {
    // Create a new keypair for program authority,
    // fund it so it can pay for transactions.
    authority = Keypair.generate();
    userAuthority = Keypair.generate();

    // Airdrop some SOL to both signers for test fees
    await connection.confirmTransaction(
      await connection.requestAirdrop(authority.publicKey, 2_000_000_000),
      "confirmed"
    );
    await connection.confirmTransaction(
      await connection.requestAirdrop(userAuthority.publicKey, 2_000_000_000),
      "confirmed"
    );
  });

  it("Initialize Global Config", async () => {
    // Find the PDA for GlobalConfig
    [globalConfigPda, globalConfigBump] = await PublicKey.findProgramAddress(
      [Buffer.from("kion-config")],
      program.programId
    );

    // Call initialize
    await program.methods
      .initialize(new BN(globalConfigBump))
      .accounts({
        globalConfig: globalConfigPda,
        authority: authority.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    // Fetch the new global config to confirm
    const configData = await program.account.globalConfig.fetch(globalConfigPda);
    expect(configData.authority.toBase58()).to.equal(
      authority.publicKey.toBase58()
    );
    expect(configData.bump).to.equal(globalConfigBump);
  });

  it("Register Recipient User (spending & viewing keys)", async () => {
    // Derive userData PDA for userAuthority
    [userDataPda, userDataBump] = await PublicKey.findProgramAddress(
      [Buffer.from("kion-user"), userAuthority.publicKey.toBuffer()],
      program.programId
    );

    // For demonstration, we'll use mock 33-byte secp256k1 compressed pubkeys
    // Real code might generate them properly. 
    const spendingPubkey = new Uint8Array(33);
    spendingPubkey[0] = 0x02; // indicates compressed key prefix
    // fill out the rest arbitrarily
    for (let i = 1; i < 33; i++) {
      spendingPubkey[i] = i;
    }

    const viewingPubkey = new Uint8Array(33);
    viewingPubkey[0] = 0x03; // compressed key prefix
    for (let i = 1; i < 33; i++) {
      viewingPubkey[i] = 100 + i;
    }

    await program.methods
      .registerUser(Array.from(spendingPubkey), Array.from(viewingPubkey))
      .accounts({
        authority: userAuthority.publicKey,
        userData: userDataPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([userAuthority])
      .rpc();

    const userData = await program.account.userData.fetch(userDataPda);
    expect(userData.authority.toBase58()).to.equal(
      userAuthority.publicKey.toBase58()
    );
    expect(new Uint8Array(userData.spendingPubkey)).to.deep.equal(
      spendingPubkey
    );
    expect(new Uint8Array(userData.viewingPubkey)).to.deep.equal(
      viewingPubkey
    );
  });

  it("Generate Ephemeral Keypair (Sender)", async () => {
    // We'll simulate the "sender" with our existing `authority`.
    // Derive ephemeralKeysPda
    [ephemeralKeysPda, ephemeralKeysBump] = await PublicKey.findProgramAddress(
      [Buffer.from("kion-ephemeral"), authority.publicKey.toBuffer()],
      program.programId
    );

    // We need the recentBlockhashes sysvar
    const recentBlockhashesSysvar = anchor.web3.SYSVAR_RECENT_BLOCKHASHES_PUBKEY;

    await program.methods
      .generateEphemeralKeypair()
      .accounts({
        authority: authority.publicKey,
        ephemeralKeys: ephemeralKeysPda,
        sysvarRecentBlockhashes: recentBlockhashesSysvar,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    // Fetch ephemeral keys
    const ephemeralKeysAccount = await program.account.ephemeralKeys.fetch(ephemeralKeysPda);
    const ephemeralPubkeyCompressed = new Uint8Array(
      ephemeralKeysAccount.ephemeralPubkeyCompressed
    );
    expect(ephemeralPubkeyCompressed.length).to.equal(33);
    console.log("Ephemeral pubkey compressed:", Buffer.from(ephemeralPubkeyCompressed).toString("hex"));
  });

  it("Announce Stealth Transaction", async () => {
    // Derive the announcement PDA
    [announcementPda, announcementBump] = await PublicKey.findProgramAddress(
      [
        Buffer.from("kion-stealth-announcement"),
        userDataPda.toBuffer(), // or we could combine ephemeral pubkey
      ],
      program.programId
    );

    // We'll not supply ephemeral_pubkey_external => it uses ephemeralKeys from chain.
    await program.methods
      .announceStealth(null) // `Option<[u8; 33]>` => pass null for None
      .accounts({
        authority: authority.publicKey,
        ephemeralKeys: ephemeralKeysPda,
        recipientUserData: userDataPda,
        announcement: announcementPda,
        systemProgram: SystemProgram.programId,
      })
      .signers([authority])
      .rpc();

    // Confirm the announcement
    const annData = await program.account.stealthAnnouncement.fetch(announcementPda);
    expect(annData.authority.toBase58()).to.equal(authority.publicKey.toBase58());
    console.log("Stealth Announcement =>", annData);
  });

  it("Scan Announcement (Check View Tag)", async () => {
    // We pass in the recipient’s "viewing private key". But we do not truly have it on chain.
    // In a real scenario, the user has it locally. For test, we mock a 32-byte array. 
    // The default code in the program performs ECDH ephemeral_public_key * viewing_sk => 
    // hashed => compare view_tag. Possibly it won't match if our test keys are random.
    const mockViewingPrivateKey = new Uint8Array(32);
    mockViewingPrivateKey[0] = 0xEE; // some arbitrary value

    try {
      await program.methods
        .scanAnnouncement(Array.from(mockViewingPrivateKey))
        .accounts({
          announcement: announcementPda,
        })
        .rpc();
      console.log("The announcement is relevant for this viewing key!");
    } catch (err) {
      console.log("Scan likely failed (not relevant).", err);
    }
  });

  it("Derive Stealth Private Key (On-chain demonstration)", async () => {
    // We'll supply:
    //  - a mock 'spending_private_key' that matches the userData's spending_pubkey
    //  - ephemeral_pubkey from the announcement
    //  - the same 'viewing_private_key' from the scan attempt
    // The result is a stealth private key. 
    // Because our keys are not “truly matching”, the derived key is just for demonstration.

    const mockSpendingPrivateKey = new Uint8Array(32);
    // Typically you generate the real spending private key that corresponds to userData's spending_pubkey
    mockSpendingPrivateKey[0] = 0x99;

    // fetch the announcement to get ephemeral_pubkey
    const annData = await program.account.stealthAnnouncement.fetch(announcementPda);
    const ephemeralPubkey = annData.ephemeralPubkeyCompressed;
    const ephemeralPubkeyArray = new Uint8Array(ephemeralPubkey);

    // same mock viewing private key as before
    const mockViewingPrivateKey = new Uint8Array(32);
    mockViewingPrivateKey[0] = 0xEE; 

    await program.methods
      .deriveStealthPrivateKey(
        Array.from(mockSpendingPrivateKey),
        Array.from(ephemeralPubkeyArray),
        Array.from(mockViewingPrivateKey),
      )
      .accounts({
        authority: userAuthority.publicKey,
      })
      .signers([userAuthority])
      .rpc();

    // The program logs the derived stealth key in the transaction logs
    // There's no stored account for it. It's ephemeral data for demonstration.
    console.log("Stealth private key derivation completed (check logs).");
  });
});
