package notmain

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
)

// revokerDB is the data-access surface bad-key-revoker needs. It keeps the
// revocation orchestration (batching, the maxRevocations guard, the RA calls)
// free of SQL. borpRevokerDB, below, is the implementation.
type revokerDB interface {
	// countUncheckedKeys returns the number of blockedKeys rows that are due to be
	// checked (older than now minus lagSeconds and not yet checked), up to limit.
	countUncheckedKeys(ctx context.Context, now time.Time, lagSeconds float64, limit int) (int, error)
	// selectUncheckedKey returns one blockedKeys row that is due to be checked, or
	// sql.ErrNoRows if there are none.
	selectUncheckedKey(ctx context.Context, now time.Time, lagSeconds float64) (uncheckedBlockedKey, error)
	// selectSerialBatch returns up to limit (id, certSerial) pairs from
	// keyHashToSerial for keyHash, with id greater than afterID and certNotAfter
	// after notAfterAfter, ordered by id.
	selectSerialBatch(ctx context.Context, keyHash []byte, afterID int, notAfterAfter time.Time, limit int) ([]serialBatchRow, error)
	// selectUnrevokedCertBySerial returns certificate metadata for serial, or
	// sql.ErrNoRows if there is no matching certificateStatus/precertificate.
	selectUnrevokedCertBySerial(ctx context.Context, serial string) (unrevokedCertificate, error)
	// markRowChecked marks the blockedKeys row for keyHash as checked.
	markRowChecked(ctx context.Context, keyHash []byte) error
	// revokeAccountByKeyHash revokes the single valid registration, if any, whose
	// jwk_sha256 matches the base64 encoding of keyHash.
	revokeAccountByKeyHash(ctx context.Context, keyHash []byte) error
}

// serialBatchRow is one (id, certSerial) pair from the keyHashToSerial table.
type serialBatchRow struct {
	ID         int
	CertSerial string
}

// borpRevokerDB implements revokerDB with borp. Its SQL is the same as
// bad-key-revoker issued before revokerDB existed.
type borpRevokerDB struct {
	dbMap *db.WrappedMap
}

func newBorpRevokerDB(dbMap *db.WrappedMap) *borpRevokerDB {
	return &borpRevokerDB{dbMap: dbMap}
}

func (d *borpRevokerDB) countUncheckedKeys(ctx context.Context, now time.Time, lagSeconds float64, limit int) (int, error) {
	var count int
	err := d.dbMap.SelectOne(
		ctx,
		&count,
		`SELECT COUNT(*)
		FROM (SELECT 1 FROM blockedKeys
		WHERE extantCertificatesChecked = false AND added < ? - INTERVAL ? SECOND
		LIMIT ?) AS a`,
		now,
		lagSeconds,
		limit,
	)
	return count, err
}

func (d *borpRevokerDB) selectUncheckedKey(ctx context.Context, now time.Time, lagSeconds float64) (uncheckedBlockedKey, error) {
	var row uncheckedBlockedKey
	err := d.dbMap.SelectOne(
		ctx,
		&row,
		`SELECT keyHash, revokedBy
		FROM blockedKeys
		WHERE extantCertificatesChecked = false AND added < ? - INTERVAL ? SECOND
		LIMIT 1`,
		now,
		lagSeconds,
	)
	return row, err
}

func (d *borpRevokerDB) selectSerialBatch(ctx context.Context, keyHash []byte, afterID int, notAfterAfter time.Time, limit int) ([]serialBatchRow, error) {
	var batch []serialBatchRow
	_, err := d.dbMap.Select(
		ctx,
		&batch,
		"SELECT id, certSerial FROM keyHashToSerial WHERE keyHash = ? AND id > ? AND certNotAfter > ? ORDER BY id LIMIT ?",
		keyHash,
		afterID,
		notAfterAfter,
		limit,
	)
	return batch, err
}

func (d *borpRevokerDB) selectUnrevokedCertBySerial(ctx context.Context, serial string) (unrevokedCertificate, error) {
	// NOTE: This has a `LIMIT 1` because the certificateStatus and precertificates
	// tables do not have a UNIQUE KEY on serial (for partitioning reasons). So it's
	// possible we could get multiple results for a single serial number, but they
	// would be duplicates.
	var cert unrevokedCertificate
	err := d.dbMap.SelectOne(
		ctx,
		&cert,
		`SELECT cs.id, cs.serial, c.registrationID, c.der, cs.status, cs.isExpired
		FROM certificateStatus AS cs
		JOIN precertificates AS c
		ON cs.serial = c.serial
		WHERE cs.serial = ?
		LIMIT 1`,
		serial,
	)
	return cert, err
}

func (d *borpRevokerDB) markRowChecked(ctx context.Context, keyHash []byte) error {
	_, err := d.dbMap.ExecContext(ctx, "UPDATE blockedKeys SET extantCertificatesChecked = true WHERE keyHash = ?", keyHash)
	return err
}

func (d *borpRevokerDB) revokeAccountByKeyHash(ctx context.Context, keyHash []byte) error {
	// The registrations table ensures that jwk_sha256 is unique. However, it
	// stores the jwk_sha256 column in base64, unlike the keyHashToSerial table.
	_, err := d.dbMap.ExecContext(
		ctx, "UPDATE registrations SET status = ? WHERE jwk_sha256 = ? AND status = ? LIMIT 1",
		string(core.StatusRevoked),
		base64.StdEncoding.EncodeToString(keyHash),
		string(core.StatusValid),
	)
	return err
}
