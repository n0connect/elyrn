//go:build test
// +build test

package store

// RetentionStepRowsForTesting is the most message rows one retention step (expired messages, or
// the orphans of one cycle) deletes per cycle, so a test can seed one row more and see the rest
// carried to the next cycle. SECURITY: compiled only with -tags test.
const RetentionStepRowsForTesting = retentionBatchRows * retentionBatchesPerStep
