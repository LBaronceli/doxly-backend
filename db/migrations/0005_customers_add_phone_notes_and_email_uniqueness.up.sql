-- add the columns our code expects
alter table customers
  add column if not exists phone text,
  add column if not exists notes text;

-- make email uniqueness per-org (optional but recommended)
-- drop global unique(email) if present
do $$
begin
  if exists (
    select 1 from pg_indexes
    where schemaname = 'public'
      and indexname = 'customers_email_key'
  ) then
    alter table customers drop constraint if exists customers_email_key;
  end if;
end $$;

-- enforce unique (org_id, lower(email)) only when email is not null
-- note: citext already case-folds, but we’ll be explicit and future-proof
create unique index if not exists customers_org_email_unique
  on customers (org_id, lower(email))
  where email is not null;
