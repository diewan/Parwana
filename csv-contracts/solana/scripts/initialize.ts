import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { CsvSeal } from "../target/types/csv_seal";

// Initialize the LockRegistry on the deployed program
async function main() {
  // Configure the client to use the local cluster
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.CsvSeal as Program<CsvSeal>;

  console.log("Initializing LockRegistry...");
  console.log("Program ID:", program.programId.toString());
  console.log("Authority:", provider.wallet.publicKey.toString());

  // Derive the LockRegistry PDA
  const [registryPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("lock_registry")],
    program.programId
  );

  console.log("Registry PDA:", registryPda.toString());

  try {
    // Check if already initialized
    const registryAccount = await program.account.lockRegistry.fetchNullable(registryPda);
    if (registryAccount) {
      console.log("LockRegistry already initialized!");
      console.log("Authority:", registryAccount.authority.toString());
      console.log("Refund timeout:", registryAccount.refundTimeout);
      console.log("Lock count:", registryAccount.lockCount);
      return;
    }

    // Initialize the registry
    const tx = await program.methods
      .initializeRegistry()
      .accounts({
        registry: registryPda,
        authority: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    console.log("Transaction signature:", tx);
    console.log("LockRegistry initialized successfully!");

  } catch (error) {
    console.error("Error initializing LockRegistry:", error);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
