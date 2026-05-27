// Bounded Alloy model for replay registry state transitions.

sig ReplayId {}

abstract sig State {}
one sig Pending, Consumed, RolledBack extends State {}

sig Snapshot {
  entries: ReplayId -> lone State
}

pred insertIfAbsent[pre, post: Snapshot, id: ReplayId] {
  no pre.entries[id]
  post.entries = pre.entries + id -> Pending
}

pred confirmConsumed[pre, post: Snapshot, id: ReplayId] {
  pre.entries[id] = Pending
  post.entries = pre.entries ++ id -> Consumed
}

pred markRolledBack[pre, post: Snapshot, id: ReplayId] {
  pre.entries[id] = Pending
  post.entries = pre.entries ++ id -> RolledBack
}

assert OneStatePerReplayId {
  all snapshot: Snapshot, id: ReplayId | lone snapshot.entries[id]
}

assert InsertDoesNotOverwrite {
  all pre, post: Snapshot, id: ReplayId |
    insertIfAbsent[pre, post, id] implies no pre.entries[id]
}

assert ConsumeRequiresPending {
  all pre, post: Snapshot, id: ReplayId |
    confirmConsumed[pre, post, id] implies pre.entries[id] = Pending
}

assert RollbackRequiresPending {
  all pre, post: Snapshot, id: ReplayId |
    markRolledBack[pre, post, id] implies pre.entries[id] = Pending
}

run insertIfAbsent for 3 but exactly 2 Snapshot
run confirmConsumed for 3 but exactly 2 Snapshot
run markRolledBack for 3 but exactly 2 Snapshot

check OneStatePerReplayId for 5
check InsertDoesNotOverwrite for 5
check ConsumeRequiresPending for 5
check RollbackRequiresPending for 5
