package notmain

import (
	"context"
	"time"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/sa"
)

// certReader is the set of read operations cert-checker performs against the
// certificate store. The retry and paging loops that drive these calls stay in
// certChecker, so they do not depend on how the store is queried.
type certReader interface {
	// minCertificateID returns the lowest certificate id issued in [begin, end),
	// or nil if the interval is empty (MIN() over no rows).
	minCertificateID(ctx context.Context, begin, end time.Time) (*int64, error)
	// selectCertificateBatch returns up to limit certificates with id > minID
	// issued in [begin, end) ordered by id, plus the highest id seen.
	selectCertificateBatch(ctx context.Context, minID int64, begin, end time.Time, limit int) ([]*corepb.Certificate, int64, error)
	// selectPrecertDER returns the DER bytes of the precertificate with serial.
	selectPrecertDER(ctx context.Context, serial string) ([]byte, error)
	// selectAuthzsMatchingIssuance returns the authorizations plausibly relied
	// upon to issue to regID at the given time for the given identifiers.
	selectAuthzsMatchingIssuance(ctx context.Context, regID int64, issued time.Time, idents identifier.ACMEIdentifiers) ([]*corepb.Authorization, error)
}

// certDB collects the borp.DbMap functions that borpCertReader relies on. Using
// this adapter shim allows tests to swap out the saDbMap implementation.
type certDB interface {
	Select(ctx context.Context, i any, query string, args ...any) ([]any, error)
	SelectOne(ctx context.Context, i any, query string, args ...any) error
}

// borpCertReader implements certReader with borp. Its SQL is the same as
// cert-checker issued before certReader existed.
type borpCertReader struct {
	dbMap certDB
}

func newBorpCertReader(dbMap certDB) *borpCertReader {
	return &borpCertReader{dbMap: dbMap}
}

func (r *borpCertReader) minCertificateID(ctx context.Context, begin, end time.Time) (*int64, error) {
	var out *int64
	err := r.dbMap.SelectOne(
		ctx,
		&out,
		`SELECT MIN(id) FROM certificates
			WHERE issued >= :begin AND
				  issued < :end`,
		map[string]any{
			"begin": begin,
			"end":   end,
		},
	)
	return out, err
}

func (r *borpCertReader) selectCertificateBatch(ctx context.Context, minID int64, begin, end time.Time, limit int) ([]*corepb.Certificate, int64, error) {
	return sa.SelectCertificates(
		ctx,
		r.dbMap,
		`WHERE id > :id AND
		       issued >= :begin AND
			   issued < :end
		 ORDER BY id LIMIT :limit`,
		map[string]any{
			"begin": begin,
			"end":   end,
			"limit": limit,
			"id":    minID,
		},
	)
}

func (r *borpCertReader) selectPrecertDER(ctx context.Context, serial string) ([]byte, error) {
	precertPb, err := sa.SelectPrecertificate(ctx, r.dbMap, serial)
	if err != nil {
		return nil, err
	}
	return precertPb.Der, nil
}

func (r *borpCertReader) selectAuthzsMatchingIssuance(ctx context.Context, regID int64, issued time.Time, idents identifier.ACMEIdentifiers) ([]*corepb.Authorization, error) {
	return sa.SelectAuthzsMatchingIssuance(ctx, r.dbMap, regID, issued, idents)
}
