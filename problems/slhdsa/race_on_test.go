//go:build race

package slhdsa

// raceEnabled is set under -race, where sync.Pool randomly drops items.
const raceEnabled = true
