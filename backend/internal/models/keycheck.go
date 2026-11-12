package models

// KeyCheck commits to a secret the database depends on, so startup can refuse a different
// one (a regenerated .env) instead of answering every account with errors. Value is an HMAC
// under a subkey of that secret: it reveals nothing about the secret itself. One row of this
// small name/value table is not a commitment: "retention-clock" holds when retention last ran
// (store.KeyRepository.RetentionMark), so a clock moved back can be told apart.
type KeyCheck struct {
	Name  string `gorm:"size:32;primaryKey"`
	Value string `gorm:"size:64;not null"`
}

func (KeyCheck) TableName() string {
	return "key_checks"
}
