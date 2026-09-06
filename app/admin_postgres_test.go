package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/monjuik/shellty-passkey-server/assets"
)

func adminTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}
	ctx := context.Background()
	root, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "admin_test_" + strings.ReplaceAll(uuid.NewV7().String(), "-", "")
	if _, err = root.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		root.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer root.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := root.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Reconstruct an existing iteration-one database, then upgrade it.
	core, err := assets.Migrations.ReadFile("migrations/001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(core)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "CREATE TABLE migration(version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "INSERT INTO migration(version,checksum) VALUES(1,$1)", fmt.Sprintf("%x", sha256.Sum256(core))); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, pool); err != nil {
		t.Fatal("migration repeat", err)
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM pg_indexes WHERE schemaname=$1 AND indexname IN ('history_order','history_application_order','history_subject_order','history_credential_order')", schema).Scan(&count); err != nil || count != 4 {
		t.Fatal("missing indexes", count, err)
	}
	return pool
}
func TestAdminPostgresQueries(t *testing.T) {
	pool := adminTestDatabase(t)
	ctx := context.Background()
	store := &adminPostgres{pool}
	stamp := time.Date(2026, 9, 6, 12, 0, 0, 123456000, time.UTC)
	id := func(i int) string { return fmt.Sprintf("019c0000-0000-7000-8000-%012d", i) }
	for i := 1; i <= 45; i++ {
		subject := "alice"
		if i == 45 {
			subject = "bob"
		}
		_, err := pool.Exec(ctx, `INSERT INTO credential(id,application,subject,rp_id,webauthn_id,public_key,algorithm,sign_count,transports,backup_eligible,backup_state,webauthn,created_at) VALUES($1,'removed',$2,'example.com',$3,'secret',-8,0,'{}',false,false,'secret',$4)`, id(i), subject, fmt.Appendf(nil, "authenticator-%d", i), stamp)
		if err != nil {
			t.Fatal(err)
		}
		_, err = pool.Exec(ctx, `INSERT INTO history(id,application,subject,credential,kind,result,occurred_at) VALUES($1,'removed',$2,$3,'authentication.finish','succeeded',$4)`, id(i), subject, id(1), stamp)
		if err != nil {
			t.Fatal(err)
		}
	}
	f := adminFilter{Application: "removed"}
	first, err := store.Credentials(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	first, previous, next := adminPage(first, f.Cursor)
	if len(first) != 20 || previous || !next || first[0].ID != id(45) || first[19].ID != id(26) {
		t.Fatal("first credentials page")
	}
	f.Cursor = adminCursor{ID: first[19].ID}
	second, err := store.Credentials(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	second, _, next = adminPage(second, f.Cursor)
	if len(second) != 20 || !next || second[0].ID != id(25) || second[19].ID != id(6) {
		t.Fatal("second credentials page")
	}
	f.Cursor = adminCursor{ID: second[0].ID, Previous: true}
	back, err := store.Credentials(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	back, previous, next = adminPage(back, f.Cursor)
	if len(back) != 20 || previous || !next || back[0].ID != first[0].ID {
		t.Fatal("back to first page")
	}
	f.Cursor = adminCursor{ID: second[19].ID}
	last, err := store.Credentials(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	last, previous, next = adminPage(last, f.Cursor)
	if len(last) != 5 || !previous || next {
		t.Fatal("last credentials page")
	}
	filtered, err := store.Credentials(ctx, adminFilter{Application: "removed", Subject: "bob"})
	if err != nil || len(filtered) != 1 || filtered[0].ID != id(45) {
		t.Fatal("subject filter", err)
	}
	filtered, err = store.Credentials(ctx, adminFilter{Subject: "' OR true --"})
	if err != nil || len(filtered) != 0 {
		t.Fatal("unsafe subject", err)
	}
	c, err := store.Credential(ctx, id(1))
	if err != nil || c.Subject != "alice" || len(c.PublicKey) != 0 || len(c.WebAuthn) != 0 || len(c.WebAuthnID) != 0 {
		t.Fatal("credential details", err)
	}
	hf := adminFilter{Application: "removed", From: "2026-09-06", To: "2026-09-06"}
	events, err := store.History(ctx, hf)
	if err != nil {
		t.Fatal(err)
	}
	events, _, _ = adminPage(events, hf.Cursor)
	if len(events) != 20 || events[0].ID != id(45) || events[19].ID != id(26) {
		t.Fatal("history stable order")
	}
	hf.Cursor = adminCursor{ID: events[19].ID, Time: events[19].Time}
	older, err := store.History(ctx, hf)
	if err != nil {
		t.Fatal(err)
	}
	older, _, _ = adminPage(older, hf.Cursor)
	if len(older) != 20 || older[0].ID != id(25) || older[19].ID != id(6) {
		t.Fatal("history cursor skipped equal timestamps")
	}
	hf.Cursor = adminCursor{ID: older[0].ID, Time: older[0].Time, Previous: true}
	newer, err := store.History(ctx, hf)
	if err != nil {
		t.Fatal(err)
	}
	newer, previous, next = adminPage(newer, hf.Cursor)
	if len(newer) != 20 || previous || !next || newer[0].ID != events[0].ID {
		t.Fatal("history previous page")
	}
	// Include both boundaries of the selected UTC date, exclude the next midnight.
	for i, at := range []time.Time{stamp.Truncate(24 * time.Hour), stamp.Truncate(24 * time.Hour).Add(24*time.Hour - time.Microsecond), stamp.Truncate(24 * time.Hour).Add(24 * time.Hour)} {
		if _, err = pool.Exec(ctx, `INSERT INTO history(id,application,subject,kind,result,occurred_at) VALUES($1,'shop','boundary','authentication.finish','failed',$2)`, id(100+i), at); err != nil {
			t.Fatal(err)
		}
	}
	boundary, err := store.History(ctx, adminFilter{Application: "shop", From: "2026-09-06", To: "2026-09-06"})
	if err != nil || len(boundary) != 2 {
		t.Fatal("UTC boundaries", len(boundary), err)
	}
	// Subject history includes failures without a credential, credential history does not.
	if _, err = pool.Exec(ctx, `INSERT INTO history(id,application,subject,kind,result,occurred_at) VALUES($1,'removed','alice','authentication.finish','failed',$2)`, id(200), stamp.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	linked, err := store.History(ctx, adminFilter{Credential: id(1)})
	if err != nil || linked[0].ID == id(200) || !linked[0].CredentialExists {
		t.Fatal("credential history", err)
	}
	subject, err := store.History(ctx, adminFilter{Application: "removed", Subject: "alice"})
	if err != nil || subject[0].ID != id(200) || subject[0].Credential != "" {
		t.Fatal("subject failure missing", err)
	}
	if _, err = pool.Exec(ctx, "DELETE FROM credential WHERE id=$1", id(1)); err != nil {
		t.Fatal(err)
	}
	linked, err = store.History(ctx, adminFilter{Credential: id(1)})
	if err != nil || len(linked) == 0 || linked[0].CredentialExists {
		t.Fatal("deleted credential history lost", err)
	}
}
