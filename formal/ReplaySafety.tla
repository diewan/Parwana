---------------------------- MODULE ReplaySafety ----------------------------
EXTENDS Naturals, FiniteSets

Ids == 1..3
Absent == "absent"
Pending == "pending"
Consumed == "consumed"
RolledBack == "rolled_back"
States == {Pending, Consumed, RolledBack}
StoreStates == States \cup {Absent}

VARIABLES replayStore, pendingMints, consumedIds
vars == <<replayStore, pendingMints, consumedIds>>

Init ==
  /\ replayStore = [id \in Ids |-> Absent]
  /\ pendingMints = {}
  /\ consumedIds = {}

InsertIfAbsent(id) ==
  /\ id \in Ids
  /\ replayStore[id] = Absent
  /\ replayStore' = [replayStore EXCEPT ![id] = Pending]
  /\ UNCHANGED <<pendingMints, consumedIds>>

ConfirmConsumed(id) ==
  /\ id \in Ids
  /\ replayStore[id] = Pending
  /\ replayStore' = [replayStore EXCEPT ![id] = Consumed]
  /\ pendingMints' = pendingMints \ {id}
  /\ consumedIds' = consumedIds \cup {id}

MarkRolledBack(id) ==
  /\ id \in Ids
  /\ replayStore[id] = Pending
  /\ replayStore' = [replayStore EXCEPT ![id] = RolledBack]
  /\ pendingMints' = pendingMints \ {id}
  /\ UNCHANGED consumedIds

QueueMint(id) ==
  /\ id \in Ids
  /\ replayStore[id] = Pending
  /\ id \notin pendingMints
  /\ pendingMints' = pendingMints \cup {id}
  /\ UNCHANGED <<replayStore, consumedIds>>

Next ==
  \/ \E id \in Ids: InsertIfAbsent(id)
  \/ \E id \in Ids: QueueMint(id)
  \/ \E id \in Ids: ConfirmConsumed(id)
  \/ \E id \in Ids: MarkRolledBack(id)

Spec == Init /\ [][Next]_vars

TypeInvariant ==
  /\ replayStore \in [Ids -> StoreStates]
  /\ pendingMints \subseteq Ids
  /\ consumedIds \subseteq Ids

NoDoubleConsume ==
  \A id \in consumedIds: replayStore[id] = Consumed

CASInvariant ==
  \A id \in Ids:
    \/ replayStore[id] = Absent
    \/ Cardinality({state \in States : replayStore[id] = state}) = 1

PendingMintsConsistency ==
  \A id \in pendingMints:
    /\ replayStore[id] = Pending

ConsumedIdsConsistency ==
  \A id \in consumedIds: replayStore[id] = Consumed

=============================================================================
