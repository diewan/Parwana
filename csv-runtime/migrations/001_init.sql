-- Migration 001: Create replay_entries table for durable replay prevention
-- This table stores replay IDs with their current state for cross-chain transfer coordination.
-- Idempotent: uses IF NOT EXISTS and can be safely re-run.

CREATE TABLE IF NOT EXISTS replay_entries (
    replay_id BYTEA PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('Pending', 'Consumed', 'RolledBack')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for faster lookups by state (useful for recovery scans)
CREATE INDEX IF NOT EXISTS idx_replay_entries_state ON replay_entries(state);

-- Migration 002: Create transfer_leases table for distributed lease coordination
CREATE TABLE IF NOT EXISTS transfer_leases (
    transfer_id BYTEA PRIMARY KEY,
    epoch BIGINT NOT NULL,
    owner_runtime_id UUID NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_transfer_leases_expires_at ON transfer_leases(expires_at);

-- Migration 003: Create event_streams table for event sourcing
CREATE TABLE IF NOT EXISTS event_streams (
    stream_id BYTEA NOT NULL,
    version BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    payload BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (stream_id, version)
);

CREATE INDEX IF NOT EXISTS idx_event_streams_stream_id ON event_streams(stream_id);

-- Migration 004: Create aggregate_snapshots table for event sourcing snapshots
CREATE TABLE IF NOT EXISTS aggregate_snapshots (
    aggregate_id BYTEA PRIMARY KEY,
    version BIGINT NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Migration 005: Create global_replay_records table for cross-chain replay tracking
CREATE TABLE IF NOT EXISTS global_replay_records (
    seal_id BYTEA PRIMARY KEY,
    source_chain TEXT NOT NULL,
    destination_chain TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('Pending', 'Finalized', 'RolledBack', 'Tombstoned')),
    source_tx_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_global_replay_records_state ON global_replay_records(state);
