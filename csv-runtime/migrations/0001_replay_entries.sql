-- Migration: Create replay_entries table for PostgreSQL-backed ReplayDatabase
--
-- This migration supports the PostgresReplayDb implementation with server-side
-- CAS semantics using INSERT ... ON CONFLICT DO NOTHING.
--
-- The table structure supports all three ReplayEntryState variants:
--   'Pending'    - Insert recorded; mint has not yet been confirmed on-chain.
--   'Consumed'   - Mint confirmed on-chain. Terminal state.
--   'RolledBack' - Transfer failed after insert; recovery coordinator may retry.

CREATE TABLE IF NOT EXISTS replay_entries (
    id          TEXT        PRIMARY KEY,
    state       TEXT        NOT NULL CHECK (state IN ('Pending', 'Consumed', 'RolledBack')),
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_replay_state ON replay_entries (state);