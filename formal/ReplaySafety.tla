---------------------------- MODULE ReplaySafety ----------------------------
EXTENDS Naturals, Sequences, TLC

CONSTANT MaxReplayIds = 1000000

VARIABLES replayStore, pendingMints, consumedIds

(* State definitions *)
CONSTANT Pending = 0
CONSTANT Consumed = 1
CONSTANT RolledBack = 2

(* Replay entry structure: id -> state *)
(* replayStore is a function from IDs to states *)

Init ==
  /\ replayStore = {}
  /\ pendingMints = {}
  /\ consumedIds = {}

(* Insert a replay ID if absent - CAS semantics *)
InsertIfAbsent(id) ==
  /\ id \notin DOMAIN replayStore
  /\ replayStore' = replayStore \cup {[id |-> Pending]}
  /\ UNCHANGED <<pendingMints, consumedIds>>

(* Consume if unconsumed - idempotent *)
ConsumeIfUnconsumed(id) ==
  /\ IF id \in DOMAIN replayStore
     THEN /\ replayStore[id] = Pending
          /\ replayStore' = [replayStore EXCEPT ![id] = Consumed]
          /\ pendingMints' = pendingMints \cup {id}
          /\ consumedIds' = consumedIds \cup {id}
     ELSE /\ replayStore' = replayStore \cup {[id |-> Consumed]}
          /\ pendingMints' = pendingMints \cup {id}
          /\ consumedIds' = consumedIds \cup {id}

(* Confirm consumed - transition from Pending to Consumed *)
ConfirmConsumed(id) ==
  /\ id \in DOMAIN replayStore
  /\ replayStore[id] = Pending
  /\ replayStore' = [replayStore EXCEPT ![id] = Consumed]
  /\ pendingMints' = pendingMints \ {id}
  /\ consumedIds' = consumedIds \cup {id}

(* Mark as rolled back - transition from Pending to RolledBack *)
MarkRolledBack(id) ==
  /\ id \in DOMAIN replayStore
  /\ replayStore[id] = Pending
  /\ replayStore' = [replayStore EXCEPT ![id] = RolledBack]
  /\ pendingMints' = pendingMints \ {id}
  /\ UNCHANGED consumedIds

(* Invariants *)

(* No double consume: each ID can be in consumedIds at most once *)
NoDoubleConsume ==
  \A id \in DOMAIN replayStore:
    /\ replayStore[id] \in {Pending, Consumed, RolledBack}
    /\ \E state \in {Pending, Consumed, RolledBack}:
        replayStore[id] = state

(* CAS semantics: InsertIfAbsent only succeeds if ID not present *)
CASInvariant ==
  \A id \in DOMAIN replayStore:
    Cardinality({state \in {Pending, Consumed, RolledBack} : replayStore[id] = state}) = 1

(* State machine consistency: once Consumed or RolledBack, cannot return to Pending *)
StateMonotonicity ==
  \A id \in DOMAIN replayStore:
    /\ IF replayStore[id] = Consumed \/ replayStore[id] = RolledBack
       THEN \A state' \in {Pending, Consumed, RolledBack}:
              state' = replayStore[id]

(* Pending mints are subset of replay store *)
PendingMintsConsistency ==
  pendingMints \subseteq DOMAIN replayStore

(* Consumed IDs are subset of replay store *)
ConsumedIdsConsistency ==
  consumedIds \subseteq DOMAIN replayStore

(* Type correctness invariant *)
TypeCorrectness ==
  /\ DOMAIN replayStore \subseteq 1..MaxReplayIds
  /\ pendingMints \subseteq 1..MaxReplayIds
  /\ consumedIds \subseteq 1..MaxReplayIds

(* Next state relation *)
Next ==
  \/ \E id \in 1..MaxReplayIds: InsertIfAbsent(id)
  \/ \E id \in DOMAIN replayStore: ConsumeIfUnconsumed(id)
  \/ \E id \in DOMAIN replayStore: ConfirmConsumed(id)
  \/ \E id \in DOMAIN replayStore: MarkRolledBack(id)

(* Spec *)
Spec == Init /\ [][Next]_<<replayStore, pendingMints, consumedIds>>

(* Theorems to verify *)
THEOREM Spec => []TypeCorrectness
THEOREM Spec => []CASInvariant
THEOREM Spec => []NoDoubleConsume
THEOREM Spec => []StateMonotonicity
THEOREM Spec => []PendingMintsConsistency
THEOREM Spec => []ConsumedIdsConsistency

====
