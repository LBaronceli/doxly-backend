-- Ensure attachments table has the columns our service expects.
-- Safe for re-runs: all are IF NOT EXISTS.

create extension if not exists "uuid-ossp";

create table if not exists attachments (
  id           uuid primary key default gen_random_uuid(),
  customer_id  uuid not null references customers(id) on delete cascade,
  object_key   text not null,
  filename     text not null,
  content_type text,
  size_bytes   bigint,
  etag         text,
  created_at   timestamptz not null default now()
);

-- If the table already existed, backfill missing columns:
alter table attachments add column if not exists object_key   text;
alter table attachments add column if not exists filename     text;
alter table attachments add column if not exists content_type text;
alter table attachments add column if not exists size_bytes   bigint;
alter table attachments add column if not exists etag         text;
alter table attachments add column if not exists created_at   timestamptz not null default now();

create index if not exists attachments_customer_id_idx on attachments (customer_id);
create index if not exists attachments_object_key_idx  on attachments (object_key);
