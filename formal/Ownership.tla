---------------------------- MODULE Ownership ----------------------------
EXTENDS Naturals

Ids == 1..3
Owners == {"alice", "bob"}
Unowned == "unowned"

VARIABLES sanads, ownership
vars == <<sanads, ownership>>

Init ==
  /\ sanads = {}
  /\ ownership = [id \in Ids |-> Unowned]

CreateSanad(id, owner) ==
  /\ id \in Ids \ sanads
  /\ owner \in Owners
  /\ sanads' = sanads \cup {id}
  /\ ownership' = [ownership EXCEPT ![id] = owner]

TransferSanad(id, from, to) ==
  /\ id \in sanads
  /\ from \in Owners
  /\ to \in Owners \ {from}
  /\ ownership[id] = from
  /\ ownership' = [ownership EXCEPT ![id] = to]
  /\ UNCHANGED sanads

ConsumeSanad(id) ==
  /\ id \in sanads
  /\ sanads' = sanads \ {id}
  /\ ownership' = [ownership EXCEPT ![id] = Unowned]

Next ==
  \/ \E id \in Ids, owner \in Owners: CreateSanad(id, owner)
  \/ \E id \in Ids, from \in Owners, to \in Owners:
       TransferSanad(id, from, to)
  \/ \E id \in Ids: ConsumeSanad(id)

Spec == Init /\ [][Next]_vars

TypeInvariant ==
  /\ sanads \subseteq Ids
  /\ ownership \in [Ids -> (Owners \cup {Unowned})]

OwnershipIntegrity ==
  \A id \in Ids:
    IF id \in sanads THEN ownership[id] \in Owners
    ELSE ownership[id] = Unowned

NoDoubleOwnership ==
  \A id \in sanads: ownership[id] # Unowned

=============================================================================
