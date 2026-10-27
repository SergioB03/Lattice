// Command lattice-go-engine is a reference Lattice policy engine written in Go.
//
// It speaks Lattice's command-engine protocol: one lattice.dev/policy-input/v1 document on
// stdin, one decision on stdout. It decodes the input the way Skylr decodes its own
// contracts: unknown fields are rejected and trailing data is an error. If anything is
// off, it exits non-zero, and Lattice fails closed (deny). It ports lattice-py/2's rules so
// `lattice eval --with-engine go=./lattice-go-engine` measures portability across languages.
// That's the path for Skylr to take over policy decisions.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type Ref struct {
	ID    string `json:"id"`
	Actor string `json:"actor"`
	Trust int    `json:"trust"`
}

type Match struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	ScoreBP int    `json:"score_bp"`
	Type    string `json:"type"`
}

type PlanItem struct {
	Index           int    `json:"index"`
	Op              string `json:"op"`
	Effect          string `json:"effect"`
	Target          string `json:"target"`
	HasSource       bool   `json:"has_source"`
	ConfidenceBP    int    `json:"confidence_bp"`
	Cardinality     string `json:"cardinality"`
	ValidFrom       string `json:"valid_from"`
	ValidFromGiven  bool   `json:"valid_from_given"`
	OwnerTrust      int    `json:"owner_trust"`
	Overlaps        []Ref  `json:"overlaps"`
	Closes          []Ref  `json:"closes"`
	BestMatch       Match  `json:"best_match"`
	InstructionLike bool   `json:"instruction_like"`
	Ref             string `json:"ref"`
}

type Actor struct {
	ID     string `json:"id"`
	Role   string `json:"role"`
	Trust  int    `json:"trust"`
	Vendor string `json:"vendor"`
}

type Role struct {
	Trust               int               `json:"trust"`
	Ops                 map[string]string `json:"ops"`
	MaxOpsPerProposal   int               `json:"max_ops_per_proposal"`
	MaxProposalsPerHour int               `json:"max_proposals_per_hour"`
	RequireSource       bool              `json:"require_source"`
	MinConfidenceBP     int               `json:"min_confidence_bp"`
}

type Ack struct {
	RuleID  string `json:"rule_id"`
	OpIndex int    `json:"op_index"`
}

type Approval struct {
	By           string `json:"by"`
	Role         string `json:"role"`
	Trust        int    `json:"trust"`
	Acknowledged []Ack  `json:"acknowledged"`
}

type Endorsement struct {
	Actor   string `json:"actor"`
	Verdict string `json:"verdict"`
	Plan    string `json:"plan"`
}

type Proposal struct {
	Kind           string            `json:"kind"`
	Actor          string            `json:"actor"`
	Ops            []map[string]any  `json:"ops"`
	Justification  string            `json:"justification"`
	IdempotencyKey string            `json:"idempotency_key"`
	Client         map[string]string `json:"client"`
}

type Input struct {
	Kind       string   `json:"kind"`
	ProposalID string   `json:"proposal_id"`
	Proposal   Proposal `json:"proposal"`
	Actor      Actor    `json:"actor"`
	Role       Role     `json:"role"`
	Resolution struct {
		DuplicateBP int `json:"duplicate_threshold_bp"`
		ReviewBP    int `json:"review_threshold_bp"`
	} `json:"resolution"`
	ConfigDigest string `json:"config_digest"`
	SchemaDigest string `json:"schema_digest"`
	LedgerHead   struct {
		Seq  int    `json:"seq"`
		Hash string `json:"hash"`
	} `json:"ledger_head"`
	Now        string            `json:"now"`
	Approval   Approval          `json:"approval"`
	Plan       []PlanItem        `json:"plan"`
	ReadSet    []json.RawMessage `json:"read_set"`
	Aggregates struct {
		ProposalsLastHour int `json:"proposals_last_hour"`
	} `json:"aggregates"`
	Endorsements []Endorsement     `json:"endorsements"`
	Voters       map[string]string `json:"voters"`
	PlanDigest   string            `json:"plan_digest"`
	Trigger      string            `json:"trigger"`
	Consensus    *struct {
		K        int      `json:"k"`
		Eligible []string `json:"eligible"`
	} `json:"consensus"`
}

type Finding struct {
	RuleID  string `json:"rule_id"`
	Outcome string `json:"outcome"`
	OpIndex int    `json:"op_index"`
	Detail  string `json:"detail"`
}

var rank = map[string]int{"allow": 0, "review": 1, "deny": 2}

func decode(r io.Reader) (*Input, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in Input
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("strict decode: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after input document")
	}
	if in.Kind != "lattice.dev/policy-input/v1" {
		return nil, fmt.Errorf("unsupported input kind %q", in.Kind)
	}
	if len(in.Plan) != len(in.Proposal.Ops) {
		return nil, fmt.Errorf("plan/ops length mismatch")
	}
	return &in, nil
}

func daysBefore(ts, now string) int {
	a, err1 := time.Parse("2006-01-02", ts[:10])
	b, err2 := time.Parse("2006-01-02", now[:10])
	if err1 != nil || err2 != nil {
		return 0
	}
	return int(b.Sub(a).Hours() / 24)
}

func decide(in *Input) []Finding {
	ack := map[string]bool{}
	if in.Approval.By != "" && (in.Approval.Trust > in.Actor.Trust || in.Approval.By == in.Actor.ID) {
		for _, a := range in.Approval.Acknowledged {
			ack[fmt.Sprintf("%s#%d", a.RuleID, a.OpIndex)] = true
		}
	}
	var fs []Finding
	find := func(rule, outcome string, idx int, detail string) {
		if outcome == "review" && ack[fmt.Sprintf("%s#%d", rule, idx)] {
			return
		}
		fs = append(fs, Finding{rule, outcome, idx, detail})
	}
	role, actor := in.Role, in.Actor
	if len(in.Proposal.Ops) > role.MaxOpsPerProposal {
		find("limits.ops", "deny", -1, "too many ops for this role")
	}
	if in.Aggregates.ProposalsLastHour >= role.MaxProposalsPerHour && in.Approval.By == "" &&
		(in.Trigger == "" || in.Trigger == "proposal") {
		find("limits.rate", "deny", -1, "hourly rate limit")
	}
	for _, it := range in.Plan {
		i := it.Index
		others := 0
		for _, c := range append(append([]Ref{}, it.Closes...), it.Overlaps...) {
			if c.Actor != actor.ID {
				others++
			}
		}
		own := it.Target == actor.ID && others == 0
		switch role.Ops[it.Op] {
		case "deny":
			find("role.op", "deny", i, "role may not "+it.Op)
		case "review":
			if !own {
				find("role.op", "review", i, "role needs review to "+it.Op)
			}
		case "allow":
		default:
			find("role.op", "deny", i, "op not configured for role")
		}
		if it.Op == "endorse" || it.Op == "withdraw" {
			if it.InstructionLike {
				find("text.instruction_like", "review", i, "endorsement reason reads like instructions")
			}
			continue
		}
		if it.Op == "assert" && it.Effect != "noop" {
			if role.RequireSource && !it.HasSource {
				find("evidence.source_required", "deny", i, "add a source")
			}
			if it.ConfidenceBP < role.MinConfidenceBP && !own {
				find("evidence.low_confidence", "review", i, "confidence below role minimum")
			}
		}
		if it.Op == "assert" && it.Effect == "insert" && it.Cardinality == "one" && !own && it.OwnerTrust > actor.Trust {
			find("trust.claim_slot", "review", i, "single-value fact on a higher-trust entity")
		}
		if it.ValidFrom != "" && it.Effect != "noop" && actor.Trust < 70 && daysBefore(it.ValidFrom, in.Now) > 365 {
			find("temporal.backdated", "review", i, "more than a year back")
		}
		if len(it.Overlaps) > 0 {
			find("temporal.overlap", "review", i, "lands inside an earlier interval")
		}
		for _, c := range it.Closes {
			if c.Trust > actor.Trust {
				find("trust.override", "review", i, "would close "+c.ID+" by higher-trust "+c.Actor)
			}
		}
		if it.Op == "create_entity" && it.BestMatch.ID != "" {
			sameType := fmt.Sprint(in.Proposal.Ops[i]["type"]) == it.BestMatch.Type
			if it.BestMatch.ScoreBP >= in.Resolution.DuplicateBP && sameType {
				find("entity.duplicate", "deny", i, "duplicate of "+it.BestMatch.ID)
			} else if it.BestMatch.ScoreBP >= in.Resolution.ReviewBP {
				find("entity.near_duplicate", "review", i, "close to "+it.BestMatch.ID)
			}
		}
		if it.InstructionLike {
			find("text.instruction_like", "review", i, "text reads like instructions to a model")
		}
	}
	return consensus(in, fs)
}

func consensus(in *Input, fs []Finding) []Finding {
	if in.Consensus == nil {
		return fs
	}
	var reviews []Finding
	for _, f := range fs {
		if f.Outcome == "deny" {
			return fs
		}
		if f.Outcome == "review" {
			reviews = append(reviews, f)
		}
	}
	if len(reviews) == 0 {
		return fs
	}
	eligible := map[string]bool{}
	for _, e := range in.Consensus.Eligible {
		eligible[e] = true
	}
	allEligible := true
	for _, f := range reviews {
		key := f.RuleID
		if key == "role.op" && f.OpIndex >= 0 && f.OpIndex < len(in.Proposal.Ops) {
			key = "role.op:" + fmt.Sprint(in.Proposal.Ops[f.OpIndex]["op"])
		}
		if !eligible[key] {
			allEligible = false
		}
	}
	proposerVendor, ok := in.Voters[in.Actor.ID]
	if !ok {
		proposerVendor = in.Actor.Vendor
	}
	var objectors []string
	vendors := map[string]bool{}
	for _, e := range in.Endorsements {
		vendor, registered := in.Voters[e.Actor]
		if !registered {
			continue // unregistered ids have no vote: actor ids aren't authenticated
		}
		if e.Verdict == "object" {
			objectors = append(objectors, e.Actor)
		} else if e.Verdict == "approve" && e.Plan == in.PlanDigest && vendor != proposerVendor {
			vendors[vendor] = true
		}
	}
	if len(objectors) > 0 {
		sort.Strings(objectors)
		return append(fs, Finding{"consensus.objection", "review", -1, "objected to by " + strings.Join(objectors, ", ")})
	}
	if allEligible && len(in.Voters) > 0 && len(vendors) >= in.Consensus.K {
		var out []Finding
		for _, f := range fs {
			if f.Outcome != "review" {
				out = append(out, f)
			}
		}
		return append(out, Finding{"consensus.reached", "allow", -1, "multi-vendor consensus"})
	}
	return fs
}

func main() {
	in, err := decode(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lattice-go-engine:", err)
		os.Exit(2)
	}
	fs := decide(in)
	sort.SliceStable(fs, func(a, b int) bool {
		if rank[fs[a].Outcome] != rank[fs[b].Outcome] {
			return rank[fs[a].Outcome] > rank[fs[b].Outcome]
		}
		if fs[a].OpIndex != fs[b].OpIndex {
			return fs[a].OpIndex < fs[b].OpIndex
		}
		return fs[a].RuleID < fs[b].RuleID
	})
	out := map[string]any{"outcome": "allow", "rule_id": "go.allow", "reason": "No rule objected.", "findings": fs}
	if len(fs) > 0 && fs[0].Outcome != "allow" {
		out["outcome"], out["rule_id"], out["reason"] = fs[0].Outcome, fs[0].RuleID, fs[0].Detail
	}
	if fs == nil {
		out["findings"] = []Finding{}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		os.Exit(3)
	}
}
