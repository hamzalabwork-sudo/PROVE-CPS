---------------------------- MODULE ProveCPS ----------------------------
(***************************************************************************)
(* Discrete-time model of the PROVE-CPS dispute protocol for one device,   *)
(* one gateway, one honest witness and the registry.                       *)
(*                                                                         *)
(* Time is integer block time. Every transaction lands on the ledger       *)
(* 1..DL ticks after it is sent (DL = worst-case inclusion delay). The     *)
(* witness sees checkpoints immediately (p = 1, T_w = 0) and device clocks *)
(* are exact (sigma = 0), so the paper's bounds specialise to              *)
(*   Delta_d <= NU + TAU + 1 + DL     Delta_a <= Delta_d + W               *)
(* (worst case: receipt just before the notice threshold, deadline then    *)
(* passes, CUSTODY lands DL later; +1 because "passed" is strict).         *)
(* TLC checks:                                                             *)
(*   NonFrameability  honest gateway never convicted   iff W > O + DL      *)
(*   Detection        within BD                        (tight at BD)       *)
(*   Attribution      within BA                        (tight at BA)       *)
(* with HONEST = FALSE meaning the gateway may do anything a corrupt one   *)
(* can: drop, delay or never receipt events, anchor late or never, and    *)
(* answer challenges late or never.                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    HONEST,   \* is the gateway honest?
    E,        \* number of device events
    GMAX,     \* last tick at which the device may generate an event
    T,        \* time horizon
    TAU,      \* anchoring deadline after a receipt
    NU,       \* notice threshold: a head unreceipted this long is noticed
    W,        \* response window
    O,        \* longest outage of an honest gateway
    DL,       \* worst-case inclusion delay
    BD, BA    \* detection and attribution bounds under test

INF == 1000
Ctr == 1..E
Min(a, b) == IF a < b THEN a ELSE b

VARIABLES
    now,      \* block time
    n,        \* events generated so far (counters 1..n)
    genT,     \* genT[c]: generation time of event c
    rcvd,     \* highest counter the gateway has receipted (a receipt for c covers 1..c)
    rcD,      \* rcD[c]: deadline written in the receipt that first covered c
    cov,      \* cov[c]: block time at which c became covered (anchored), INF if never
    outS,     \* start of the honest gateway's outage (INF: none)
    outL,     \* its length (<= O)
    pend,     \* transactions in flight: [k, c, kind, at]
    chal,     \* challenges on the ledger: [c, kind, op, ans]
    conv      \* has the registry convicted the gateway?

vars == <<now, n, genT, rcvd, rcD, cov, outS, outL, pend, chal, conv>>

Down(t) == outS <= t /\ t < outS + outL

Init ==
    /\ now = 0 /\ n = 0
    /\ genT = [c \in Ctr |-> INF] /\ rcD = [c \in Ctr |-> INF] /\ cov = [c \in Ctr |-> INF]
    /\ rcvd = 0 /\ pend = {} /\ chal = {} /\ conv = FALSE
    /\ IF HONEST THEN outS \in 0..T /\ outL \in 0..O ELSE outS = INF /\ outL = 0

Send(k, c, kind) ==
    \E d \in 1..DL : pend' = pend \cup {[k |-> k, c |-> c, kind |-> kind, at |-> now + d]}

\* ---------------------------------------------------------------- device
Emit ==
    /\ n < E /\ now <= GMAX
    /\ n' = n + 1 /\ genT' = [genT EXCEPT ![n + 1] = now]
    /\ UNCHANGED <<now, rcvd, rcD, cov, outS, outL, pend, chal, conv>>

\* ---------------------------------------------------------------- gateway
\* The device retransmits until receipted and rejects deadlines later than now + TAU.
Receipt(k) ==
    /\ ~Down(now) /\ rcvd < k /\ k <= n
    /\ rcvd' = k
    /\ rcD' = [c \in Ctr |-> IF rcvd < c /\ c <= k THEN now + TAU ELSE rcD[c]]
    /\ UNCHANGED <<now, n, genT, cov, outS, outL, pend, chal, conv>>

Anchor(k) ==
    /\ ~Down(now) /\ 1 <= k /\ k <= rcvd
    /\ Send("anchor", k, "none")
    /\ UNCHANGED <<now, n, genT, rcvd, rcD, cov, outS, outL, chal, conv>>

AnswerPending(ch) == \E p \in pend : p.k = "answer" /\ p.c = ch.c /\ p.kind = ch.kind

\* anchorAndRespond: anchors the challenged head (carried by the challenge) and answers in one transaction.
Answer(ch) ==
    /\ ~Down(now) /\ ch \in chal /\ ch.ans = INF /\ ~AnswerPending(ch)
    /\ Send("answer", ch.c, ch.kind)
    /\ UNCHANGED <<now, n, genT, rcvd, rcD, cov, outS, outL, chal, conv>>

\* ---------------------------------------------------------------- witness (honest)
Raised(c, kind) == (\E ch \in chal : ch.c = c /\ ch.kind = kind) \/ (\E p \in pend : p.k = kind /\ p.c = c)
CustodyDue == {c \in 1..rcvd : now > rcD[c] /\ cov[c] > rcD[c] /\ ~Raised(c, "custody")}
NoticeDue  == {c \in Ctr : genT[c] # INF /\ c > rcvd /\ now >= genT[c] + NU /\ cov[c] = INF /\ ~Raised(c, "notice")}

Challenge(c, kind) ==
    /\ \/ kind = "custody" /\ c \in CustodyDue
       \/ kind = "notice" /\ c \in NoticeDue
    /\ Send(kind, c, "none")
    /\ UNCHANGED <<now, n, genT, rcvd, rcD, cov, outS, outL, chal, conv>>

\* ---------------------------------------------------------------- time and the registry
Covering(c) == \E p \in pend : p.k \in {"anchor", "answer"} /\ p.c >= c
AnchorDue == \E c \in 1..rcvd : cov[c] = INF /\ ~Covering(c) /\ now + DL >= rcD[c]
Unanswered == {ch \in chal : ch.ans = INF /\ now < ch.op + W /\ ~AnswerPending(ch)}

\* Time advances only after the honest parties have done what is due at this instant.
HonestDone ==
    /\ CustodyDue = {} /\ NoticeDue = {}
    /\ HONEST /\ ~Down(now) => (rcvd = n /\ ~AnchorDue /\ Unanswered = {})

Tick ==
    /\ now < T /\ HonestDone
    /\ LET t == now + 1
           L == {p \in pend : p.at = t}
           cov2 == [c \in Ctr |-> IF \E p \in L : p.k \in {"anchor", "answer"} /\ p.c >= c
                                   THEN Min(cov[c], t) ELSE cov[c]]
           \* the registry rejects a CUSTODY covered by its deadline and a NOTICE below the proven frontier
           opened == {p \in L : \/ p.k = "custody" /\ cov2[p.c] > rcD[p.c]
                                \/ p.k = "notice" /\ cov[p.c] = INF}
           answered(ch) == /\ ch.ans = INF /\ t < ch.op + W
                           /\ \E p \in L : p.k = "answer" /\ p.c = ch.c /\ p.kind = ch.kind
           chal2 == {IF answered(ch) THEN [ch EXCEPT !.ans = t] ELSE ch : ch \in chal}
                    \cup {[c |-> p.c, kind |-> p.k, op |-> t, ans |-> INF] : p \in opened}
       IN /\ now' = t
          /\ cov' = cov2
          /\ chal' = chal2
          /\ pend' = pend \ L
          /\ conv' = (conv \/ \E ch \in chal2 : ch.ans = INF /\ t >= ch.op + W)
    /\ UNCHANGED <<n, genT, rcvd, rcD, outS, outL>>

Next ==
    \/ Emit
    \/ \E k \in Ctr : Receipt(k) \/ Anchor(k)
    \/ \E ch \in chal : Answer(ch)
    \/ \E c \in Ctr : Challenge(c, "custody") \/ Challenge(c, "notice")
    \/ Tick

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------- properties
NonFrameability == HONEST => ~conv

Detection ==
    ~HONEST => \A c \in Ctr :
        (genT[c] # INF /\ now >= genT[c] + BD) => (cov[c] <= now \/ \E ch \in chal : ch.c >= c)

Attribution ==
    ~HONEST => \A c \in Ctr :
        (genT[c] # INF /\ now >= genT[c] + BA) => (cov[c] <= now \/ conv)
=============================================================================
