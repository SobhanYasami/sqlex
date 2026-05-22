package payloads

import (
	"fmt"
	"math/rand"
	"strings"
)

// Token names used in payload templates.
const (
	TokRandNum   = "[RANDNUM]"
	TokInference = "[INFERENCE]"
	TokSleepTime = "[SLEEPTIME]"
	TokOrigValue = "[ORIGVALUE]"
	TokQuery     = "{query}"
	TokPosition  = "{position}"
	TokChar      = "{char}"
)

// RenderBoolean replaces [RANDNUM] with a random int for detection probes.
func RenderBoolean(template string) string {
	n := rand.Intn(9000) + 1000
	s := strings.ReplaceAll(template, TokRandNum, fmt.Sprintf("%d", n))
	return s
}

// RenderVector replaces [INFERENCE] in a vector template with the given
// boolean expression, and [SLEEPTIME] / [RANDNUM] / [ORIGVALUE] as needed.
func RenderVector(vector, inference, origValue string, sleepSec int) string {
	s := strings.ReplaceAll(vector, TokInference, inference)
	s = strings.ReplaceAll(s, TokSleepTime, fmt.Sprintf("%d", sleepSec))
	s = strings.ReplaceAll(s, TokOrigValue, origValue)
	n := rand.Intn(9000) + 1000
	s = strings.ReplaceAll(s, TokRandNum, fmt.Sprintf("%d", n))
	return s
}

// RenderProbe builds the boolean expression for a single character probe.
// queryable: SQL expression; template: DATA_EXTRACTION_PAYLOADS entry.
func RenderProbe(template, queryable string, position, char int) string {
	s := strings.ReplaceAll(template, TokQuery, queryable)
	s = strings.ReplaceAll(s, TokPosition, fmt.Sprintf("%d", position))
	s = strings.ReplaceAll(s, TokChar, fmt.Sprintf("%d", char))
	return s
}

// RenderLengthProbe builds a length extraction probe.
func RenderLengthProbe(template, queryable string, position, char int) string {
	return RenderProbe(template, queryable, position, char)
}

// RenderNOCProbe builds a number-of-characters (length digit count) probe.
func RenderNOCProbe(template, queryable string, char int) string {
	s := strings.ReplaceAll(template, TokQuery, queryable)
	s = strings.ReplaceAll(s, TokChar, fmt.Sprintf("%d", char))
	return s
}

// BuildPayload combines prefix + payload + suffix into the final injection string.
func BuildPayload(prefix, payload, suffix string) string {
	return prefix + payload + suffix
}

// RandomUA returns a random user-agent string from the embedded list.
func RandomUA() string {
	if len(UserAgents) == 0 {
		return "Mozilla/5.0 (compatible; Ghauri)"
	}
	return UserAgents[rand.Intn(len(UserAgents))]
}
