---------------------------- MODULE Ownership ----------------------------
EXTENDS Naturals, Sequences

VARIABLES sanads, ownership

CONSTANT Owner = 0
CONSTANT Transferred = 1

Init ==
  /\ sanads = {}
  /\ ownership = {}

CreateSanad(id, owner) ==
  /\ id \notin sanads
  /\ sanads' = sanads \union {id}
  /\ ownership' = ownership \union {[id |-> owner]}
  /\ UNCHANGED <<sanads, ownership>>

TransferSanad(id, from, to) ==
  /\ id \in sanads
  /\ ownership[id] = from
  /\ from /= to
  /\ ownership' = [ownership EXCEPT ![id] = to]
  /\ UNCHANGED sanads

ConsumeSanad(id) ==
  /\ id \in sanads
  /\ sanads' = sanads \ {id}
  /\ ownership' = [owner \in DOMAIN ownership : owner /= id]
  /\ UNCHANGED <<ownership>>

NoDoubleOwnership ==
  \A id \in sanads:
    Cardinality({owner \in DOMAIN ownership : owner[id] = id}) <= 1

OwnershipIntegrity ==
  \A id \in sanads:
    \E owner \in DOMAIN ownership:
      ownership[id] = owner

====
