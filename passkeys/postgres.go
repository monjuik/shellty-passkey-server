package passkeys

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct{ pool *pgxpool.Pool }

func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool} }

type credentialReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func readCredentials(ctx context.Context, db credentialReader, application, subject string) ([]Credential, error) {
	rows, err := db.Query(ctx, `SELECT id::text,application,subject,rp_id,webauthn_id,public_key,algorithm,sign_count,transports,aaguid,backup_eligible,backup_state,webauthn,created_at,used_at FROM credential WHERE application=$1 AND subject=$2 ORDER BY id`, application, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Credential, 0)
	for rows.Next() {
		var c Credential
		if err = rows.Scan(
			&c.ID,
			&c.Application,
			&c.Subject,
			&c.RPID,
			&c.WebAuthnID,
			&c.PublicKey,
			&c.Algorithm,
			&c.SignCount,
			&c.Transports,
			&c.AAGUID,
			&c.BackupEligible,
			&c.BackupState,
			&c.WebAuthn,
			&c.CreatedAt,
			&c.UsedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}
func (p *Postgres) Credentials(ctx context.Context, application, subject string) ([]Credential, error) {
	return readCredentials(ctx, p.pool, application, subject)
}
func ceremonyTable(k Kind) (string, error) {
	switch k {
	case Registration:
		return "registration", nil
	case Authentication:
		return "authentication", nil
	}
	return "", InvalidRequest
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func event(ctx context.Context, tx pgx.Tx, application, subject, credential, kind, result string, code error) error {
	var id any
	if credential != "" {
		id = credential
	}
	var publicError any
	if code != nil {
		publicError = code.Error()
	}
	_, err := tx.Exec(
		ctx,
		`INSERT INTO history(id,application,subject,credential,kind,result,error) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		uuid.NewV7().String(),
		application,
		subject,
		id,
		kind,
		result,
		publicError,
	)
	return err
}
func (p *Postgres) Start(ctx context.Context, k Kind, c Ceremony) error {
	table, err := ceremonyTable(k)
	if err != nil {
		return err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	_, err = tx.Exec(
		ctx,
		`INSERT INTO `+table+`(id,application,subject,rp_id,token_hash,webauthn,state,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		c.ID,
		c.Application,
		c.Subject,
		c.RPID,
		c.TokenHash,
		c.WebAuthn,
		c.State,
		c.CreatedAt,
		c.ExpiresAt,
	)
	if err != nil {
		return err
	}
	if err = event(ctx, tx, c.Application, c.Subject, "", string(k)+".start", "succeeded", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Serialize credential writes for a subject, including deletion and independent
// authentication ceremonies. The stable advisory key works across all nodes.
func lockSubject(ctx context.Context, tx pgx.Tx, application, subject string) error {
	key := int64(binary.BigEndian.Uint64(UserHandle(application, subject)))
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", key)
	return err
}
func (p *Postgres) Finish(
	ctx context.Context,
	k Kind,
	hash []byte,
	authorize func(Ceremony) error,
	verify func(Ceremony, []Credential) (Credential, error),
) (Credential, error) {
	table, err := ceremonyTable(k)
	if err != nil {
		return Credential{}, err
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return Credential{}, err
	}
	defer rollback(tx)
	var c Ceremony
	err = tx.QueryRow(
		ctx,
		`SELECT id::text,application,subject,rp_id,token_hash,webauthn,state,created_at,expires_at FROM `+table+` WHERE token_hash=$1 FOR UPDATE`,
		hash,
	).Scan(&c.ID, &c.Application, &c.Subject, &c.RPID, &c.TokenHash, &c.WebAuthn, &c.State, &c.CreatedAt, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, k.NotFound()
	}
	if err != nil {
		return Credential{}, err
	}
	if err = authorize(c); err != nil {
		return Credential{}, err
	}
	if c.State != "pending" {
		return Credential{}, Conflict
	}
	if err = lockSubject(ctx, tx, c.Application, c.Subject); err != nil {
		return Credential{}, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return Credential{}, err
	}
	outcome := c.Check(k, now)
	var credential Credential
	if outcome == nil {
		credentials, e := readCredentials(ctx, tx, c.Application, c.Subject)
		if e != nil {
			return Credential{}, e
		}
		credential, outcome = verify(c, credentials)
		// Only expected verification errors consume a ceremony. Infrastructure or
		// corrupt persisted state errors roll back and may be retried.
		if outcome != nil && !errors.Is(outcome, k.Invalid()) {
			return Credential{}, outcome
		}
	}
	state := "succeeded"
	if outcome == nil {
		if k == Registration {
			credential.CreatedAt = now
			tag, e := tx.Exec(
				ctx,
				`INSERT INTO credential(id,application,subject,rp_id,webauthn_id,public_key,algorithm,sign_count,transports,aaguid,backup_eligible,backup_state,webauthn,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (rp_id,webauthn_id) DO NOTHING`,
				credential.ID,
				c.Application,
				c.Subject,
				c.RPID,
				credential.WebAuthnID,
				credential.PublicKey,
				credential.Algorithm,
				credential.SignCount,
				credential.Transports,
				credential.AAGUID,
				credential.BackupEligible,
				credential.BackupState,
				credential.WebAuthn,
				now,
			)
			if e != nil {
				return Credential{}, e
			}
			if tag.RowsAffected() != 1 {
				outcome = Conflict
			}
		} else {
			credential.UsedAt = &now
			tag, e := tx.Exec(
				ctx,
				`UPDATE credential SET sign_count=$1,backup_state=$2,webauthn=$3,used_at=$4 WHERE id=$5 AND application=$6 AND subject=$7 AND rp_id=$8`,
				credential.SignCount,
				credential.BackupState,
				credential.WebAuthn,
				now,
				credential.ID,
				c.Application,
				c.Subject,
				c.RPID,
			)
			if e != nil {
				return Credential{}, e
			}
			if tag.RowsAffected() != 1 {
				outcome = k.Invalid()
			}
		}
	}
	if outcome != nil {
		state = "failed"
		if errors.Is(outcome, k.Expired()) {
			state = "expired"
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE `+table+` SET state=$1 WHERE id=$2`, state, c.ID); err != nil {
		return Credential{}, err
	}
	credentialID := ""
	if outcome == nil {
		credentialID = credential.ID
	}
	if k == Authentication && outcome == nil {
		if _, err = tx.Exec(ctx, "UPDATE authentication SET credential=$1 WHERE id=$2", credentialID, c.ID); err != nil {
			return Credential{}, err
		}
	}
	if err = event(ctx, tx, c.Application, c.Subject, credentialID, string(k)+".finish", state, outcome); err != nil {
		return Credential{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Credential{}, err
	}
	return credential, outcome
}
func (p *Postgres) Delete(ctx context.Context, application, subject, id string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err = lockSubject(ctx, tx, application, subject); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, "DELETE FROM credential WHERE id=$1 AND application=$2 AND subject=$3", id, application, subject)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return CredentialNotFound
	}
	if err = event(ctx, tx, application, subject, id, "credential.delete", "succeeded", nil); err != nil {
		return fmt.Errorf("delete history: %w", err)
	}
	return tx.Commit(ctx)
}
