-- speed up login lookups and enforce uniqueness
create unique index if not exists users_email_unique_idx on users (lower(email));