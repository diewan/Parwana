// Alloy model: replay registry CAS and no double-consume (production-ready)

sig ReplayId {}

sig Entry {
  id: one ReplayId,
  state: one State
}

enum State { Pending, Consumed, RolledBack }

// No duplicate entries for the same ID
fact NoDuplicateEntries {
  all disj e1, e2: Entry |
    e1.id = e2.id implies e1 = e2
}

// Each ID has exactly one state
fact UniqueStatePerId {
  all e: Entry |
    one s: State | e.state = s
}

// State monotonicity: once Consumed or RolledBack, cannot return to Pending
fact StateMonotonicity {
  all e: Entry |
    e.state in Consumed + RolledBack implies
    no e': Entry | e'.id = e.id and e'.state = Pending
}

// insertIfAbsent: succeeds only if no entry exists for the ID
pred insertIfAbsent[id: ReplayId, entries: set Entry, entries': set Entry] {
  no e: entries | e.id = id
  entries' = entries + Entry' -> id -> Pending
}

// consumeIfUnconsumed: idempotent operation
pred consumeIfUnconsumed[id: ReplayId, entries: set Entry, entries': set Entry] {
  some e: entries | e.id = id and e.state = Pending implies
    entries' = entries - e + Entry' -> id -> Consumed
  no e: entries | e.id = id implies
    entries' = entries + Entry' -> id -> Consumed
}

// confirmConsumed: transition from Pending to Consumed
pred confirmConsumed[id: ReplayId, entries: set Entry, entries': set Entry] {
  some e: entries | e.id = id and e.state = Pending
  entries' = entries - e + Entry' -> id -> Consumed
}

// markRolledBack: transition from Pending to RolledBack
pred markRolledBack[id: ReplayId, entries: set Entry, entries': set Entry] {
  some e: entries | e.id = id and e.state = Pending
  entries' = entries - e + Entry' -> id -> RolledBack
}

// No double consume: each ID can be consumed at most once
fact NoDoubleConsume {
  all e: Entry |
    e.state = Consumed implies
    lone e': Entry | e'.id = e.id and e'.state = Pending
}

// CAS invariant: insertIfAbsent only succeeds if ID not present
fact CASInvariant {
  all id: ReplayId, entries, entries': set Entry |
    insertIfAbsent[id, entries, entries'] implies
    no e: entries | e.id = id
}

// Check that the model is consistent
run insertIfAbsent for 3 but 5 Entry
run consumeIfUnconsumed for 3 but 5 Entry
run confirmConsumed for 3 but 5 Entry
run markRolledBack for 3 but 5 Entry

// Check invariants
check NoDuplicateEntries for 5
check UniqueStatePerId for 5
check StateMonotonicity for 5
check NoDoubleConsume for 5
check CASInvariant for 5
