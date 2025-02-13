// migrations/deploy.ts

// Migrations are an early feature of Anchor. By default, this script is
// invoked after running `anchor deploy`, if specified in your Anchor.toml
// under [scripts] deploy = "anchor run deploy".

import * as anchor from "@project-serum/anchor";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import fs from "fs";

// If you generated TypeScript definitions for your program, you can import them like this:
// import { KionStealth } from "../target/types/kion_stealth";

module.exports = async function (provider: anchor.AnchorProvider) {
  // 1. Set the Anchor provider
  anchor.setProvider(provider);

  // 2. Load the IDL (Interface Definition Language) for your program
  //    This assumes your program IDL was automatically generated at target/idl/kion_stealth.json
  const idlPath = "./target/idl/kion_stealth.json";
  const idlStr = fs.readFileSync(idlPath, "utf8");
  const idl = JSON.parse(idlStr);

  // 3. Program ID from your declare_id! in Rust (must match exactly)
  //    or read from the IDL metadata if it has "metadata.address"
  const programId = new PublicKey("KionStealth11111111111111111111111111111111");

  // 4. Instantiate the program client
  const program = new anchor.Program(idl, programId, provider);

  // Optional example:
  // Demonstrate calling an "initialize" instruction if your program has one
  // (e.g., `initialize` sets up a global config account).
  //
  // We attempt to create/find the program’s global config PDA.
  try {
    // Replace these seeds with what your actual program uses
    const seed = Buffer.from("kion-config");
    const [globalConfigPda, globalConfigBump] = await PublicKey.findProgramAddress(
      [seed],
      programId
    );

    // We'll do a simple RPC call to `initialize` if it exists in your program.
    // If your program does not have an `initialize` method or doesn't require
    // a global config, you can remove this block.
    const txSig = await program.methods
      .initialize(globalConfigBump) // or whatever arguments your init requires
      .accounts({
        globalConfig: globalConfigPda,
        authority: provider.wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log("Program initialized successfully. Tx signature:", txSig);
  } catch (err) {
    console.error("Initialize call failed:", err);
  }

  // If you just want to confirm that the program is deployed, you can stop here.
  // Any further instructions or setup can be added below if necessary.

  console.log("Deployment script has finished running.");
};
