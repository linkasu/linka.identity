package store

import (
	"context"
	"strings"
	"time"
	"unicode"

	"github.com/linka-cloud/linka.identity/internal/domain"
	"github.com/linka-cloud/linka.identity/internal/ids"
	"github.com/ydb-platform/ydb-go-sdk/v3/query"
)

func (s *Store) AuditProductDirectory(ctx context.Context, actor, product, action string, at time.Time) error {
	if actor == "" || len(actor) > 100 || strings.Contains(actor, "@") || strings.IndexFunc(actor, unicode.IsControl) != -1 || !domain.ValidProductID(product) || at.IsZero() || (action != "directory.query" && action != "directory.check") {
		return domain.ErrInvalid
	}
	id, err := ids.NewUUID()
	if err != nil {
		return err
	}
	return s.serializable(ctx, func(ctx context.Context, tx query.TxActor) error {
		return appendPublicAccountAudit(ctx, tx, id, product, "", actor, action, product, at)
	})
}
