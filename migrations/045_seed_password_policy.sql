-- +goose Up
INSERT INTO settings (key, value)
VALUES (
    'password_policy',
    '{"min_length":8,"max_length":128,"require_uppercase":false,"require_lowercase":false,"require_digit":false,"require_symbol":false,"min_score":0}'
)
ON CONFLICT (key) DO NOTHING;

-- +goose Down
DELETE FROM settings WHERE key = 'password_policy';
