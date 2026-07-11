#!/usr/bin/env bash
#
# ============================================================================
#  CSV Protocol — Off-chain (interactive) transfer, end-to-end, for beginners
# ============================================================================
#
#  What this demonstrates
#  ----------------------
#  The "send" transfer mode: an RGB-style, purely OFF-CHAIN handoff of a Sanad.
#  There is NO destination-chain transaction and NO attestor. The flow is:
#
#        RECIPIENT: invoice   ─┐  (names a seal the recipient controls)
#        SENDER:    send      ─┤→ produces a signed `consignment.cbor` file
#        RECIPIENT: accept    ─┘  (client-side validates it, records ownership)
#
#  Two parties, one machine
#  ------------------------
#  A real transfer has two wallets. We simulate the RECIPIENT as a *separate*
#  wallet by overriding $HOME — the CLI keeps its state at $HOME/.csv/ and reads
#  its config from $HOME/.csv/config.toml, so a fresh $HOME == a fresh wallet.
#  (There is deliberately no --data-dir flag; $HOME is the switch.)
#
#  The SENDER is just your EXISTING default wallet (~/.csv) — it already has a
#  funded, confirmed Bitcoin Sanad, which is what we transfer.
#
#  PREREQUISITES (read these — the script cannot create them for you)
#  -----------------------------------------------------------------
#   1. The `csv` binary is built:  cargo build -p csv-cli --release
#   2. Your default ~/.csv wallet exists and its ~/.csv/config.toml has a
#      WORKING Bitcoin signet RPC (source proofs + accept-freshness need it).
#   3. You have a confirmed Bitcoin Sanad in that wallet (we create a fresh one
#      below; it must reach on-chain confirmation before `send` can prove it —
#      Bitcoin's finality floor is 6 blocks and cannot be lowered).
#
#  Nothing here spends recipient funds: the recipient only needs an address.
# ----------------------------------------------------------------------------

set -euo pipefail

# ─── Fill these in ──────────────────────────────────────────────────────────
CSV="${CSV:-$(cd "$(dirname "$0")/../.." && pwd)/target/release/csv}"  # path to the csv binary
SENDER_PASS="${SENDER_PASS:-123456789012}"   # your existing ~/.csv state passphrase
RCP_PASS="${RCP_PASS:-recipient-pass}"       # a passphrase for the throwaway recipient wallet
WORK="${WORK:-$(pwd)/off-chain-test}"        # shared scratch dir for files that cross parties
RCP_HOME="$WORK/recipient-home"              # the recipient's isolated $HOME (fresh wallet)
# ────────────────────────────────────────────────────────────────────────────

mkdir -p "$WORK" "$RCP_HOME"
cd "$WORK"

if [ -f consignment.cbor ]; then
  echo ">>> WARNING: $WORK/consignment.cbor already exists; overwriting."
  rm consignment.cbor
fi


# Tiny helper: pull the value column out of a `key: value` CLI output line.
# (When output is captured in $(...) it is a pipe, so the CLI prints no colors,
#  and the value is always the last whitespace-separated token.)
field() { grep -F "$1" | awk '{print $NF}' | head -1; }


# ============================================================================
#  Sample off-chain content (only HASHES of these are bound into the Sanad;
#  the files themselves are delivered out-of-band and re-hashed by the receiver)
# ============================================================================
printf '{"invoice_no":"INV-42","amount":"100.00","currency":"USD"}' > payload.json
printf 'delivery note body'                 > note.txt
printf 'terms and conditions'               > terms.txt
printf '{"schema_hash":"%064x"}' 1          > schema.json          # 64-hex schema hash
printf '{"disclose":["invoice_no"]}'        > disclosure.json      # policy, bound by hash
printf '{"require":["inclusion","finality"]}' > proof-policy.json  # policy, bound by hash


# ============================================================================
#  PHASE 1 — SENDER (default ~/.csv wallet): create the Sanad on Bitcoin
# ============================================================================
#  --schema/--payload/--attachments/--disclosure-policy/--proof-policy each bind
#  only a hash/Merkle-root into the Sanad's content descriptor. Omit them all and
#  you still get a valid Sanad (deterministic default hashes are used).
echo "== PHASE 1: SENDER creates a Sanad on Bitcoin =="
CREATE_OUT=$(echo "$SENDER_PASS" | "$CSV" sanad create \
  --chain bitcoin \
  --value 10000 \
  --schema            schema.json \
  --payload           payload.json \
  --attachments       note.txt,terms.txt \
  --disclosure-policy disclosure.json \
  --proof-policy      proof-policy.json)
echo "$CREATE_OUT"

SANAD_ID=$(printf '%s\n' "$CREATE_OUT" | field 'Sanad ID:')
echo ">>> SANAD_ID = $SANAD_ID"
echo
echo "!! WAIT: this Sanad must confirm on-chain (>= 6 Bitcoin blocks) before PHASE 3."
echo "!! Re-run from PHASE 2 onward once it is confirmed, or reuse a confirmed Active Sanad."
echo


# ============================================================================
#  PHASE 2 — RECIPIENT (isolated $HOME): issue an invoice
# ============================================================================
#  The recipient names a single-use seal THEY control on the destination chain.
#  We use Aptos because control is provable OFFLINE (it's just their own account
#  address — no funding, no RPC, no UTXO scan). Bitcoin would also work but needs
#  a scanned UTXO the recipient owns.
echo "== PHASE 2: RECIPIENT sets up a throwaway wallet and issues an invoice =="

# One-time recipient wallet + config (config is COPIED from the sender so the
# recipient shares the same Bitcoin RPC that `accept` needs for its freshness
# check). Safe to re-run.
mkdir -p "$RCP_HOME/.csv"
if [ ! -f "$RCP_HOME/.csv/unified_storage.json" ]; then
  cp "$HOME/.csv/config.toml" "$RCP_HOME/.csv/config.toml"
  echo "$RCP_PASS" | HOME="$RCP_HOME" "$CSV" wallet init >/dev/null
fi

# The recipient's own Aptos account-0 address = the seal they can prove control of.
RCP_APTOS=$(echo "$RCP_PASS" | HOME="$RCP_HOME" "$CSV" wallet list aptos \
            | awk '/aptos \(account/{print $NF}')
echo ">>> recipient Aptos address = $RCP_APTOS"

#  --schema is a FREE-FORM type label (any non-empty string, or a 0x-hex hash).
#           It is NOT the Sanad's content schema — it's just "the kind of Sanad
#           I agree to accept". Leave it as-is.
#  --seal   is <chain>:<field>:<field>. For Aptos: aptos:<address>:<key_hex>,
#           where <address> must be the recipient's own account (verified above)
#           and <key_hex> is any hex tag (we use 01).
INV_OUT=$(echo "$RCP_PASS" | HOME="$RCP_HOME" "$CSV" cross-chain invoice \
  --schema "csv.invoice.v1" \
  --seal   "aptos:${RCP_APTOS}:01")
echo "$INV_OUT"

INVOICE_BLOB=$(printf '%s\n' "$INV_OUT" | field 'Invoice blob (hex):')
echo ">>> INVOICE_BLOB = ${INVOICE_BLOB:0:24}…"
echo
#  Reference — the other chains' seal formats:
#     bitcoin:  bitcoin:<txid_display_hex>:<vout>       (a UTXO in your wallet)
#     sui:      sui:<object_id_hex>:<version>           (fails closed offline)
#     ethereum: ethereum:<contract_hex>:<slot_hex>      (fails closed offline)


# ============================================================================
#  PHASE 3 — SENDER: send (assign to the invoice seal, close source, emit file)
# ============================================================================
#  This builds + signs the send-transition proof with the SENDER's Bitcoin
#  wallet key (RGB-style: no attestor). It needs source-chain RPC and the Sanad
#  to be confirmed. It writes consignment.cbor and prints the signer pubkey the
#  recipient must trust.
echo "== PHASE 3: SENDER produces the consignment =="
SEND_OUT=$(echo "$SENDER_PASS" | "$CSV" cross-chain send \
  --from bitcoin \
  --sanad-id "$SANAD_ID" \
  --invoice  "$INVOICE_BLOB" \
  --output   "$WORK/consignment.cbor")
echo "$SEND_OUT"

# The pubkey the recipient must add to their approved verifier set.
SIGNER_PUBKEY=$(printf '%s\n' "$SEND_OUT" | field 'signer pubkey')
echo ">>> SIGNER_PUBKEY = $SIGNER_PUBKEY"
echo ">>> consignment written to $WORK/consignment.cbor"
echo


# ============================================================================
#  PHASE 4 — RECIPIENT: trust the sender's key, then accept
# ============================================================================
#  `accept` fails closed unless the consignment's signature recovers to a key in
#  the recipient's [verifier] approved_keys. We add the sender's pubkey here
#  (in the real world you'd get it out-of-band and vet it).
echo "== PHASE 4: RECIPIENT approves the sender's key and accepts =="
RCP_CONFIG="$RCP_HOME/.csv/config.toml"
if grep -q '^\[verifier\]' "$RCP_CONFIG"; then
  echo "NOTE: [verifier] already present in $RCP_CONFIG."
  echo "      Set:  approved_keys = [\"$SIGNER_PUBKEY\"]  manually, then re-run this phase."
else
  printf '\n[verifier]\napproved_keys = ["%s"]\n' "$SIGNER_PUBKEY" >> "$RCP_CONFIG"
fi

#  accept runs the full client-side validation of the whole proof bundle:
#    1. canonical CBOR decode + version check
#    2. invoice-seal binding (proof is assigned to the recipient's seal)
#    3. replay rejection (sanad_id / dest seal not already owned)
#    4. signer binding (signature ∈ approved_keys)   ← why PHASE 4 matters
#    5. freshness (live source tip vs. anchor age)   ← needs Bitcoin RPC
#    6. domain-bound verify: transition DAG + inclusion + finality + nullifier
#    7. typestate acceptance, then records ownership
echo "$RCP_PASS" | HOME="$RCP_HOME" "$CSV" cross-chain accept "$WORK/consignment.cbor"

echo
echo "== DONE. The recipient now owns the Sanad in $RCP_HOME/.csv =="
echo "   Verify with:  echo '$RCP_PASS' | HOME='$RCP_HOME' '$CSV' sanad list"
