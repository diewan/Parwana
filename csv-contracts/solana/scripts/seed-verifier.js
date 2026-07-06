#!/usr/bin/env node
// Seed / manage the CSV-Seal verifier registry on Solana (RFC-0012 §9.3).
//
// The verifier set lives in a PDA ["verifier_registry"] under the program. Mint
// is fail-closed until this PDA is initialized with at least one secp256k1
// verifier and a threshold >= 1. This helper wraps the Anchor instructions so an
// operator does not hand-roll a transaction.
//
// Usage (run from csv-contracts/solana/contracts, after `npm i @coral-xyz/anchor
// @solana/web3.js` and building the IDL to target/idl/csv_seal.json):
//
//   node ../scripts/seed-verifier.js init   <pubkey_hex> [threshold]   # first-time seed
//   node ../scripts/seed-verifier.js add    <pubkey_hex>               # add a verifier
//   node ../scripts/seed-verifier.js remove <pubkey_hex>              # remove a verifier
//   node ../scripts/seed-verifier.js threshold <M>                    # change threshold
//   node ../scripts/seed-verifier.js show                             # print current set
//
// <pubkey_hex> is the COMPRESSED 33-byte secp256k1 public key (66 hex chars,
// 0x optional) whose private half the runtime holds as CSV_MINT_VERIFIER_KEY.
//
// Env:
//   ANCHOR_PROVIDER_URL   RPC url          (default https://api.devnet.solana.com)
//   ANCHOR_WALLET         signer keypair   (default ~/.config/solana/id.json)
//   CSV_SEAL_IDL          IDL path         (default ./target/idl/csv_seal.json)
//
// The wallet MUST be the registry authority (the account that ran `init`).

const anchor = require("@coral-xyz/anchor");
const { Connection, PublicKey, Keypair, SystemProgram } = require("@solana/web3.js");
const fs = require("fs");
const os = require("os");

function parsePubkey(hex) {
  const b = Buffer.from(hex.replace(/^0x/, ""), "hex");
  if (b.length !== 33) throw new Error(`verifier pubkey must be 33 bytes, got ${b.length}`);
  return Array.from(b);
}

(async () => {
  const [cmd, arg] = process.argv.slice(2);
  if (!cmd) throw new Error("usage: seed-verifier.js <init|add|remove|threshold|show> [arg]");

  const idlPath = process.env.CSV_SEAL_IDL || "./target/idl/csv_seal.json";
  const idl = JSON.parse(fs.readFileSync(idlPath));
  const programId = new PublicKey(idl.address);

  const walletPath = process.env.ANCHOR_WALLET || `${os.homedir()}/.config/solana/id.json`;
  const kp = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(walletPath))));
  const url = process.env.ANCHOR_PROVIDER_URL || "https://api.devnet.solana.com";
  const conn = new Connection(url, "confirmed");
  const provider = new anchor.AnchorProvider(conn, new anchor.Wallet(kp), { commitment: "confirmed" });
  const program = new anchor.Program(idl, provider);

  const [registry] = PublicKey.findProgramAddressSync([Buffer.from("verifier_registry")], programId);
  console.log("program:  ", programId.toBase58());
  console.log("authority:", kp.publicKey.toBase58());
  console.log("registry: ", registry.toBase58());

  if (cmd === "show") {
    const reg = await program.account.verifierRegistry.fetch(registry);
    console.log("threshold:", reg.threshold);
    console.log("authority:", reg.authority.toBase58());
    console.log("verifiers:", reg.verifiers.map((v) => "0x" + Buffer.from(v).toString("hex")));
    return;
  }

  let sig;
  if (cmd === "init") {
    if (await conn.getAccountInfo(registry)) throw new Error("registry already initialized; use add/threshold");
    const threshold = arg ? parseInt(process.argv[4] || "1", 10) : 1;
    sig = await program.methods
      .initializeVerifierRegistry([parsePubkey(arg)], threshold)
      .accounts({ registry, authority: kp.publicKey, systemProgram: SystemProgram.programId })
      .rpc();
  } else if (cmd === "add") {
    sig = await program.methods.addVerifier(parsePubkey(arg))
      .accounts({ registry, authority: kp.publicKey }).rpc();
  } else if (cmd === "remove") {
    sig = await program.methods.removeVerifier(parsePubkey(arg))
      .accounts({ registry, authority: kp.publicKey }).rpc();
  } else if (cmd === "threshold") {
    sig = await program.methods.setThreshold(parseInt(arg, 10))
      .accounts({ registry, authority: kp.publicKey }).rpc();
  } else {
    throw new Error(`unknown command: ${cmd}`);
  }
  console.log("OK, tx:", sig);
})().catch((e) => { console.error("ERR:", e.message || e); process.exit(1); });
