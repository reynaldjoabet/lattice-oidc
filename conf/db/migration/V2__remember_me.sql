-- "Keep me signed in": such sessions have longer idle and lifetime limits
-- (lattice.session.remember-me).
ALTER TABLE sessions ADD COLUMN remember_me boolean NOT NULL DEFAULT false;
