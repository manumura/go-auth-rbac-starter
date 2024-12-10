// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: oauth_provider.sql

package db

import (
	"context"
)

const getOauthProviders = `-- name: GetOauthProviders :many
SELECT id, name
FROM oauth_provider
`

func (q *Queries) GetOauthProviders(ctx context.Context) ([]OauthProvider, error) {
	rows, err := q.db.QueryContext(ctx, getOauthProviders)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OauthProvider{}
	for rows.Next() {
		var i OauthProvider
		if err := rows.Scan(&i.ID, &i.Name); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}