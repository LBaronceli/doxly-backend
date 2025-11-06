create table if not exists customers (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null references organizations(id) on delete cascade,
  name          text not null,
  email         text,
  phone         text,
  notes         text,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create index if not exists customers_org_id_idx on customers (org_id);
create index if not exists customers_email_idx  on customers (lower(email));

-- simple trigger to auto-update updated_at
create or replace function set_updated_at() returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists trg_customers_set_updated_at on customers;
create trigger trg_customers_set_updated_at
before update on customers
for each row execute function set_updated_at();
