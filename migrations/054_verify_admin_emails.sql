-- +goose Up
-- Existing admins were seeded/created without a confirmed mailbox and may be
-- locked out by the email-verification login gate. Mark every user holding the
-- admin role as verified. Down is intentionally a no-op: we cannot know which
-- rows were already verified before this ran, so we don't un-verify anyone.
UPDATE users SET email_verified = TRUE
WHERE id IN (
    SELECT user_id FROM user_roles
    WHERE role_id = '00000000-0000-0000-0000-000000000001'
);

-- +goose Down
-- No-op: un-verifying could revoke a legitimately verified admin.
SELECT 1;
