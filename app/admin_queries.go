package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/monjuik/shellty-passkey-server/passkeys"
)

const adminPageSize = 20

type adminFilter struct {
	Application, Subject, Credential, From, To string
	Cursor                                     adminCursor
}
type adminCursor struct {
	ID       string
	Time     time.Time
	Previous bool
}
type adminCredential struct {
	passkeys.Credential
	AAGUIDText string
}
type adminEvent struct {
	ID, Application, Subject, Credential, Kind, Result, Error, Details string
	Time                                                               time.Time
	CredentialExists                                                   bool
}
type adminStore interface {
	Credentials(context.Context, adminFilter) ([]adminCredential, error)
	Credential(context.Context, string) (adminCredential, error)
	History(context.Context, adminFilter) ([]adminEvent, error)
}
type adminPostgres struct{ pool *pgxpool.Pool }

func validUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}
func parseAdminFilter(q url.Values, history bool) (adminFilter, error) {
	f := adminFilter{Application: q.Get("application"), Subject: q.Get("subject"), Credential: q.Get("credential"), From: q.Get("from"), To: q.Get("to")}
	for k, v := range q {
		if len(v) != 1 {
			return f, fmt.Errorf("duplicate filter")
		}
		switch k {
		case "application", "subject", "cursor":
		case "credential", "from", "to":
			if !history {
				return f, fmt.Errorf("unknown filter")
			}
		default:
			return f, fmt.Errorf("unknown filter")
		}
	}
	if f.Application != "" && !passkeys.ValidApplicationCode(f.Application) {
		return f, fmt.Errorf("invalid application")
	}
	if len(f.Subject) > 256 || !utf8.ValidString(f.Subject) || strings.ContainsRune(f.Subject, 0) {
		return f, fmt.Errorf("invalid subject")
	}
	if f.Credential != "" && !validUUID(f.Credential) {
		return f, fmt.Errorf("invalid credential")
	}
	for _, date := range []string{f.From, f.To} {
		if date != "" {
			if _, err := time.Parse("2006-01-02", date); err != nil || len(date) != 10 {
				return f, fmt.Errorf("invalid date")
			}
		}
	}
	if f.From != "" && f.To != "" && f.From > f.To {
		return f, fmt.Errorf("invalid date range")
	}
	if raw := q.Get("cursor"); raw != "" {
		if len(raw) > 256 {
			return f, fmt.Errorf("invalid cursor")
		}
		b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
		parts := strings.Split(string(b), "|")
		if err != nil || len(parts) != 3 || (parts[0] != "next" && parts[0] != "previous") || !validUUID(parts[2]) {
			return f, fmt.Errorf("invalid cursor")
		}
		f.Cursor = adminCursor{ID: parts[2], Previous: parts[0] == "previous"}
		if history {
			f.Cursor.Time, err = time.Parse(time.RFC3339Nano, parts[1])
			if err != nil {
				return f, fmt.Errorf("invalid cursor time")
			}
		} else if parts[1] != "" {
			return f, fmt.Errorf("invalid cursor time")
		}
	}
	return f, nil
}
func cursorValue(id string, t time.Time, previous bool) string {
	direction := "next"
	if previous {
		direction = "previous"
	}
	stamp := ""
	if !t.IsZero() {
		stamp = t.UTC().Format(time.RFC3339Nano)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(direction + "|" + stamp + "|" + id))
}

// All predicates use placeholders; only fixed column names/operators enter SQL.
type adminSQL struct {
	clauses []string
	args    []any
}

func (s *adminSQL) add(column, op string, value any) {
	s.args = append(s.args, value)
	s.clauses = append(s.clauses, fmt.Sprintf("%s %s $%d", column, op, len(s.args)))
}
func (s *adminSQL) scope(f adminFilter, prefix string) {
	if f.Application != "" {
		s.add(prefix+"application", "=", f.Application)
	}
	if f.Subject != "" {
		s.add(prefix+"subject", "=", f.Subject)
	}
}
func (s *adminSQL) where() string {
	if len(s.clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(s.clauses, " AND ")
}

const adminCredentialColumns = `id::text,application,subject,rp_id,algorithm,sign_count,transports,encode(aaguid,'hex'),backup_eligible,backup_state,created_at,used_at`

func scanAdminCredential(row interface{ Scan(...any) error }) (adminCredential, error) {
	var c adminCredential
	var aaguid *string
	err := row.Scan(&c.ID, &c.Application, &c.Subject, &c.RPID, &c.Algorithm, &c.SignCount, &c.Transports, &aaguid, &c.BackupEligible, &c.BackupState, &c.CreatedAt, &c.UsedAt)
	if aaguid != nil {
		c.AAGUIDText = *aaguid
	}
	return c, err
}
func (p *adminPostgres) Credential(ctx context.Context, id string) (adminCredential, error) {
	return scanAdminCredential(p.pool.QueryRow(ctx, "SELECT "+adminCredentialColumns+" FROM credential WHERE id=$1", id))
}
func (p *adminPostgres) Credentials(ctx context.Context, f adminFilter) ([]adminCredential, error) {
	var s adminSQL
	s.scope(f, "")
	op, order := "<", " DESC"
	if f.Cursor.Previous {
		op, order = ">", " ASC"
	}
	if f.Cursor.ID != "" {
		s.add("id", op, f.Cursor.ID)
	}
	rows, err := p.pool.Query(ctx, "SELECT "+adminCredentialColumns+" FROM credential"+s.where()+" ORDER BY id"+order+" LIMIT "+strconv.Itoa(adminPageSize+1), s.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []adminCredential{}
	for rows.Next() {
		c, err := scanAdminCredential(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}
func (p *adminPostgres) History(ctx context.Context, f adminFilter) ([]adminEvent, error) {
	var s adminSQL
	s.scope(f, "h.")
	if f.Credential != "" {
		s.add("h.credential", "=", f.Credential)
	}
	if f.From != "" {
		t, _ := time.Parse("2006-01-02", f.From)
		s.add("h.occurred_at", ">=", t)
	}
	if f.To != "" {
		t, _ := time.Parse("2006-01-02", f.To)
		s.add("h.occurred_at", "<", t.AddDate(0, 0, 1))
	}
	op, order := "<", " DESC"
	if f.Cursor.Previous {
		op, order = ">", " ASC"
	}
	if f.Cursor.ID != "" {
		s.args = append(s.args, f.Cursor.Time, f.Cursor.ID)
		s.clauses = append(s.clauses, fmt.Sprintf("(h.occurred_at,h.id) %s ($%d,$%d)", op, len(s.args)-1, len(s.args)))
	}
	rows, err := p.pool.Query(ctx, `SELECT h.id::text,h.application,h.subject,COALESCE(h.credential::text,''),h.kind,h.result,COALESCE(h.error,''),h.details::text,h.occurred_at,EXISTS(SELECT 1 FROM credential c WHERE c.id=h.credential) FROM history h`+s.where()+" ORDER BY h.occurred_at"+order+",h.id"+order+" LIMIT "+strconv.Itoa(adminPageSize+1), s.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []adminEvent{}
	for rows.Next() {
		var e adminEvent
		var details []byte
		if err := rows.Scan(&e.ID, &e.Application, &e.Subject, &e.Credential, &e.Kind, &e.Result, &e.Error, &details, &e.Time, &e.CredentialExists); err != nil {
			return nil, err
		}
		if string(details) != "{}" {
			var formatted any
			if json.Unmarshal(details, &formatted) == nil {
				if pretty, err := json.MarshalIndent(formatted, "", "  "); err == nil {
					e.Details = string(pretty)
				}
			}
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// Queries return 21 rows in traversal order. Render at most 20 in newest-first order.
func adminPage[T any](rows []T, c adminCursor) ([]T, bool, bool) {
	more := len(rows) > adminPageSize
	if more {
		rows = rows[:adminPageSize]
	}
	previous, next := c.ID != "", more
	if c.Previous {
		slices.Reverse(rows)
		previous, next = more, c.ID != ""
	}
	return rows, previous, next
}

var _ adminStore = (*adminPostgres)(nil)
