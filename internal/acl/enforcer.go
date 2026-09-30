package acl

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Runner interface {
	Run(input string, args ...string) (string, error)
}
type ExecRunner struct{}

func (ExecRunner) Run(input string, args ...string) (string, error) {
	cmd := exec.Command("iptables-legacy", append([]string{"-w"}, args...)...)
	cmd.Stdin = strings.NewReader(input)
	b, e := cmd.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("iptables-legacy %v: %w: %s", args, e, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}

type Enforcer struct {
	Runner Runner
	Dir    string
	Status Status
}

func (e *Enforcer) run(args ...string) (string, error) { return e.Runner.Run("", args...) }
func (e *Enforcer) rules(chain string, d Desired) ([][]string, error) {
	b, _ := json.Marshal(d.Rules)
	sum := sha256.Sum256(b)
	if d.Checksum != hex.EncodeToString(sum[:]) {
		return nil, errors.New("compiled policy checksum mismatch")
	}
	out := [][]string{}
	dropped := false
	for _, r := range d.Rules {
		args, err := r.Args()
		if err != nil {
			return nil, err
		}
		if r.Action == "ACCEPT" {
			if dropped || r.Source == "" {
				return nil, errors.New("unsafe allow rule order/source")
			}
		} else {
			dropped = true
			if r.Source != "" {
				return nil, errors.New("managed drop must cover all VPN peers")
			}
		}
		out = append(out, append([]string{"-A", chain}, args...))
	}
	out = append(out, []string{"-A", chain, "-j", "RETURN"})
	return out, nil
}
func chainName(revision int64) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "WGACL_" + strconv.FormatInt(revision, 36) + "_" + hex.EncodeToString(b)
}
func parseForward(s string) (lines []string, broad int, anchors []int, err error) {
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if !strings.HasPrefix(line, "-A FORWARD ") {
			continue
		}
		lines = append(lines, line)
		if line == "-A FORWARD -i wg0 -j ACCEPT" {
			if broad != 0 {
				return nil, 0, nil, errors.New("multiple wg-easy broad wg0 ACCEPT rules")
			}
			broad = len(lines)
		}
		if anchorChain(line) != "" {
			anchors = append(anchors, len(lines))
		}
	}
	return
}
func anchorChain(line string) string {
	parts := strings.Fields(line)
	if len(parts) == 6 && parts[0] == "-A" && parts[1] == "FORWARD" && parts[2] == "-i" && parts[3] == "wg0" && parts[4] == "-j" && strings.HasPrefix(parts[5], "WGACL_") {
		return parts[5]
	}
	return ""
}
func (e *Enforcer) inspect() (lines []string, broad int, anchors []int, err error) {
	s, err := e.run("-S", "FORWARD")
	if err != nil {
		return nil, 0, nil, err
	}
	return parseForward(s)
}
func (e *Enforcer) exact(chain string, d Desired) bool {
	expected, err := e.rules(chain, d)
	if err != nil {
		return false
	}
	output, err := e.run("-S", chain)
	if err != nil {
		return false
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	actual := []string{}
	for _, l := range lines {
		if strings.HasPrefix(l, "-A "+chain+" ") {
			actual = append(actual, l)
		}
	}
	if len(actual) != len(expected) {
		return false
	}
	for i, args := range expected {
		want := strings.Join(args, " ")
		got := strings.ReplaceAll(strings.ReplaceAll(actual[i], " -m tcp", ""), " -m udp", "")
		if got != want {
			return false
		}
	}
	return true
}
func (e *Enforcer) apply(d Desired) error {
	_, err := e.rules("WGACL_CHECK", d)
	if err != nil {
		return err
	}
	lines, broad, anchors, err := e.inspect()
	if err != nil {
		return err
	}
	if broad == 0 {
		return errors.New("wg-easy -i wg0 -j ACCEPT rule not found")
	}
	if len(anchors) == 1 && anchors[0] < broad {
		current := anchorChain(lines[anchors[0]-1])
		if current != "" && e.exact(current, d) {
			e.Status.Chain = current
			e.Status.AnchorPresent = true
			e.Status.AnchorBeforeAccept = true
			return nil
		}
	}
	chain := chainName(d.Revision)
	if _, err = e.run("-N", chain); err != nil {
		return err
	}
	staged := true
	defer func() {
		if staged {
			_, _ = e.run("-F", chain)
			_, _ = e.run("-X", chain)
		}
	}()
	ruleArgs, err := e.rules(chain, d)
	if err != nil {
		return err
	}
	for _, args := range ruleArgs {
		if _, err = e.run(args...); err != nil {
			return err
		}
	}
	if !e.exact(chain, d) {
		return errors.New("staged chain verification failed")
	}
	old := ""
	oldPos := 0
	if len(anchors) == 1 && anchors[0] < broad {
		oldPos = anchors[0]
		old = anchorChain(lines[oldPos-1])
		freshLines, freshBroad, freshAnchors, freshErr := e.inspect()
		if freshErr != nil || freshBroad <= oldPos || len(freshAnchors) != 1 || freshAnchors[0] != oldPos || anchorChain(freshLines[oldPos-1]) != old {
			return errors.New("FORWARD anchor changed during apply; retrying")
		}
		_, err = e.run("-R", "FORWARD", strconv.Itoa(oldPos), "-i", "wg0", "-j", chain)
	} else {
		_, err = e.run("-I", "FORWARD", strconv.Itoa(broad), "-i", "wg0", "-j", chain)
	}
	if err != nil {
		return err
	}
	newLines, newBroad, newAnchors, verifyErr := e.inspect()
	good := verifyErr == nil && len(newAnchors) > 0 && newAnchors[0] < newBroad && anchorChain(newLines[newAnchors[0]-1]) == chain && e.exact(chain, d)
	if !good {
		var rollbackErr error
		if old != "" {
			_, rollbackErr = e.run("-R", "FORWARD", strconv.Itoa(oldPos), "-i", "wg0", "-j", old)
		} else {
			_, rollbackErr = e.run("-D", "FORWARD", "-i", "wg0", "-j", chain)
		}
		_ = e.record("enforcement.rollback", chain, rollbackErr)
		if rollbackErr != nil {
			// Keep staged chain present if the anchor still refers to it.
			staged = false
			return fmt.Errorf("anchor verification and rollback failed: %w", rollbackErr)
		}
		return errors.New("anchor verification failed; previous chain restored")
	}
	staged = false
	// Remove obsolete anchors only after the new anchor is verified.
	obsolete := map[string]bool{}
	for _, line := range lines {
		prior := anchorChain(line)
		if prior != "" && prior != chain {
			obsolete[prior] = true
			if prior != old {
				if _, err = e.run("-D", "FORWARD", "-i", "wg0", "-j", prior); err != nil {
					return err
				}
			}
		}
	}
	for prior := range obsolete {
		if _, err = e.run("-F", prior); err != nil {
			return err
		}
		if _, err = e.run("-X", prior); err != nil {
			return err
		}
	}
	e.Status.Chain = chain
	e.Status.AnchorPresent = true
	e.Status.AnchorBeforeAccept = true
	return nil
}
func (e *Enforcer) BreakGlass() error {
	lines, _, _, err := e.inspect()
	if err != nil {
		return err
	}
	for _, line := range lines {
		if chain := anchorChain(line); chain != "" {
			if _, err = e.run("-D", "FORWARD", "-i", "wg0", "-j", chain); err != nil {
				return err
			}
		}
	}
	list, err := e.run("-S")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(list, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "-N" && strings.HasPrefix(parts[1], "WGACL_") {
			if _, err = e.run("-F", parts[1]); err != nil {
				return err
			}
			if _, err = e.run("-X", parts[1]); err != nil {
				return err
			}
		}
	}
	e.Status.Chain = ""
	e.Status.AnchorPresent = false
	e.Status.AnchorBeforeAccept = false
	if len(lines) > 0 {
		for _, line := range lines {
			if anchorChain(line) != "" {
				if err := e.record("enforcement.breakglass", "FORWARD", nil); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}
func (e *Enforcer) ManualBreakGlass() error {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if err := e.BreakGlass(); err != nil {
		return err
	}
	e.Status.State = "INACTIVE"
	e.Status.AppliedRevision = 0
	e.Status.Checksum = ""
	e.Status.LastError = "manual breakglass"
	e.Status.Heartbeat = now()
	return atomicJSON(filepath.Join(e.Dir, "status.json"), e.Status)
}
func (e *Enforcer) record(action, target string, reason error) error {
	event := struct{ At, Actor, Action, Target, Error string }{now(), "enforcer", action, target, ""}
	if reason != nil {
		event.Error = reason.Error()
	}
	b, _ := json.Marshal(event)
	f, err := os.OpenFile(filepath.Join(e.Dir, "enforcer-audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
func (e *Enforcer) Reconcile() (err error) {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	previous := e.Status
	defer func() {
		e.Status.Heartbeat = now()
		if err != nil {
			e.Status.State = "ERROR"
			e.Status.LastError = err.Error()
		}
		if e.Status.State != previous.State || e.Status.AppliedRevision != previous.AppliedRevision || e.Status.Chain != previous.Chain || e.Status.LastError != previous.LastError {
			action := "enforcement.apply"
			if err != nil {
				action = "enforcement.apply.failed"
			} else if e.Status.State == "INACTIVE" {
				action = "enforcement.inactive"
			}
			if auditErr := e.record(action, strconv.FormatInt(e.Status.DesiredRevision, 10), err); auditErr != nil && err == nil {
				err = auditErr
				e.Status.State = "ERROR"
				e.Status.LastError = auditErr.Error()
			}
		}
		if writeErr := atomicJSON(filepath.Join(e.Dir, "status.json"), e.Status); writeErr != nil && err == nil {
			err = writeErr
		}
	}()
	b, err := os.ReadFile(filepath.Join(e.Dir, "desired.json"))
	if err != nil {
		return err
	}
	var d Desired
	if err = json.Unmarshal(b, &d); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(b, &fields); err != nil {
		return err
	}
	for _, key := range []string{"revision", "activated", "checksum", "rules"} {
		if _, ok := fields[key]; !ok {
			return fmt.Errorf("desired policy missing %s", key)
		}
	}
	if d.Revision < 0 || d.Rules == nil {
		return errors.New("invalid desired policy revision/rules")
	}
	if _, err = e.rules("WGACL_CHECK", d); err != nil {
		return err
	}
	e.Status.DesiredRevision = d.Revision
	if !d.Activated {
		err = e.BreakGlass()
		if err == nil {
			_, broad, _, inspectErr := e.inspect()
			if inspectErr != nil {
				err = inspectErr
			} else if broad == 0 {
				err = errors.New("wg-easy -i wg0 -j ACCEPT rule not found")
			}
		}
		if err == nil {
			e.Status.State = "INACTIVE"
			e.Status.AppliedRevision = 0
			e.Status.Checksum = ""
			e.Status.LastError = ""
		}
	} else {
		e.Status.LastAttempt = now()
		err = e.apply(d)
		if err == nil {
			e.Status.State = "IN_SYNC"
			e.Status.AppliedRevision = d.Revision
			e.Status.Checksum = d.Checksum
			e.Status.LastSuccess = now()
			e.Status.LastError = ""
		}
	}
	return err
}
func (e *Enforcer) Loop() {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	hadInterface := false
	for {
		_, interfaceErr := net.InterfaceByName("wg0")
		if interfaceErr == nil {
			hadInterface = true
		}
		if hadInterface && interfaceErr != nil {
			fmt.Fprintln(os.Stderr, "wg0 namespace lost; restarting enforcer to rejoin wg-easy")
			os.Exit(1)
		}
		if err := e.Reconcile(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		time.Sleep(5 * time.Second)
	}
}
