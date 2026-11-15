-- DORIA Supabase schema (starter)
-- Run this entire file in Supabase Dashboard -> SQL Editor.
-- Security model: Supabase Auth owns passwords; RLS protects every user table.
-- Never put a service_role/secret key in the browser.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique
    check (username = lower(username) and username ~ '^[a-z0-9_]{3,24}$'),
  display_name text not null check (char_length(display_name) between 1 and 40),
  rules_accepted boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.blocks (
  blocker_id uuid not null references public.profiles(id) on delete cascade,
  blocked_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles(id) on delete cascade,
  receiver_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now(),
  check (sender_id <> receiver_id)
);

create table if not exists public.groups (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 60),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  is_public boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.group_members (
  group_id uuid not null references public.groups(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (group_id, user_id)
);

create table if not exists public.group_messages (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.groups(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now()
);

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references public.profiles(id) on delete cascade,
  reported_user_id uuid not null references public.profiles(id) on delete cascade,
  reason text not null check (char_length(reason) between 3 and 80),
  details text not null default '' check (char_length(details) <= 1000),
  status text not null default 'pending' check (status in ('pending','reviewed','closed')),
  created_at timestamptz not null default now(),
  check (reporter_id <> reported_user_id)
);

create index if not exists messages_pair_created_idx
  on public.messages (sender_id, receiver_id, created_at desc);
create index if not exists group_messages_group_created_idx
  on public.group_messages (group_id, created_at desc);
create index if not exists group_members_user_idx
  on public.group_members (user_id, group_id);
create index if not exists reports_status_created_idx
  on public.reports (status, created_at desc);

-- Create a profile automatically when a Supabase Auth user signs up.
create or replace function public.doria_handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  chosen_username text;
  chosen_display_name text;
begin
  chosen_username := lower(coalesce(new.raw_user_meta_data ->> 'username', ''));
  chosen_display_name := btrim(coalesce(new.raw_user_meta_data ->> 'display_name', chosen_username));
  if chosen_username !~ '^[a-z0-9_]{3,24}$' then
    raise exception 'نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا زیرخط باشد';
  end if;
  if char_length(chosen_display_name) < 1 or char_length(chosen_display_name) > 40 then
    raise exception 'نام نمایشی نامعتبر است';
  end if;
  insert into public.profiles (id, username, display_name, rules_accepted)
  values (new.id, chosen_username, chosen_display_name,
          coalesce((new.raw_user_meta_data ->> 'rules_accepted')::boolean, false));
  return new;
end;
$$;

drop trigger if exists doria_on_auth_user_created on auth.users;
create trigger doria_on_auth_user_created
after insert on auth.users
for each row execute procedure public.doria_handle_new_user();

-- Automatically add the group creator as its first member.
create or replace function public.doria_add_group_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.group_members (group_id, user_id)
  values (new.id, new.owner_id)
  on conflict do nothing;
  return new;
end;
$$;

drop trigger if exists doria_group_owner_member on public.groups;
create trigger doria_group_owner_member
after insert on public.groups
for each row execute procedure public.doria_add_group_owner();

alter table public.profiles enable row level security;
alter table public.blocks enable row level security;
alter table public.messages enable row level security;
alter table public.groups enable row level security;
alter table public.group_members enable row level security;
alter table public.group_messages enable row level security;
alter table public.reports enable row level security;

-- Profiles: authenticated users can discover public profile fields; only owner edits.
drop policy if exists "profiles_select_signed_in" on public.profiles;
create policy "profiles_select_signed_in" on public.profiles
for select to authenticated using (true);
drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own" on public.profiles
for update to authenticated using (id = (select auth.uid()))
with check (id = (select auth.uid()));

-- Blocks: only the blocker can inspect, create, or remove their own block records.
drop policy if exists "blocks_select_own" on public.blocks;
create policy "blocks_select_own" on public.blocks
for select to authenticated using (blocker_id = (select auth.uid()));
drop policy if exists "blocks_insert_own" on public.blocks;
create policy "blocks_insert_own" on public.blocks
for insert to authenticated with check (blocker_id = (select auth.uid()));
drop policy if exists "blocks_delete_own" on public.blocks;
create policy "blocks_delete_own" on public.blocks
for delete to authenticated using (blocker_id = (select auth.uid()));

-- Direct messages: only participants can read; sender must be the signed-in user.
drop policy if exists "messages_read_participant" on public.messages;
create policy "messages_read_participant" on public.messages
for select to authenticated using (
  (sender_id = (select auth.uid()) or receiver_id = (select auth.uid()))
  and not exists (
    select 1 from public.blocks b
    where (b.blocker_id = messages.sender_id and b.blocked_id = messages.receiver_id)
       or (b.blocker_id = messages.receiver_id and b.blocked_id = messages.sender_id)
  )
);
drop policy if exists "messages_send_own" on public.messages;
create policy "messages_send_own" on public.messages
for insert to authenticated with check (
  sender_id = (select auth.uid())
  and not exists (
    select 1 from public.blocks b
    where (b.blocker_id = messages.sender_id and b.blocked_id = messages.receiver_id)
       or (b.blocker_id = messages.receiver_id and b.blocked_id = messages.sender_id)
  )
);

-- Groups: public groups are discoverable; private groups are visible only to members.
drop policy if exists "groups_read_public_or_member" on public.groups;
create policy "groups_read_public_or_member" on public.groups
for select to authenticated using (
  is_public or exists (
    select 1 from public.group_members gm
    where gm.group_id = groups.id and gm.user_id = (select auth.uid())
  )
);
drop policy if exists "groups_create_as_owner" on public.groups;
create policy "groups_create_as_owner" on public.groups
for insert to authenticated with check (owner_id = (select auth.uid()));
drop policy if exists "groups_owner_update" on public.groups;
create policy "groups_owner_update" on public.groups
for update to authenticated using (owner_id = (select auth.uid()))
with check (owner_id = (select auth.uid()));

-- Members can see memberships in public groups or groups they belong to.
drop policy if exists "group_members_read_visible" on public.group_members;
create policy "group_members_read_visible" on public.group_members
for select to authenticated using (
  exists (
    select 1 from public.groups g
    where g.id = group_members.group_id
      and (g.is_public or exists (
        select 1 from public.group_members mine
        where mine.group_id = g.id and mine.user_id = (select auth.uid())
      ))
  )
);
drop policy if exists "group_members_join_public" on public.group_members;
create policy "group_members_join_public" on public.group_members
for insert to authenticated with check (
  user_id = (select auth.uid())
  and exists (select 1 from public.groups g where g.id = group_id and g.is_public)
);
drop policy if exists "group_members_leave_own" on public.group_members;
create policy "group_members_leave_own" on public.group_members
for delete to authenticated using (user_id = (select auth.uid()));

-- Group messages: members only.
drop policy if exists "group_messages_read_member" on public.group_messages;
create policy "group_messages_read_member" on public.group_messages
for select to authenticated using (
  exists (select 1 from public.group_members gm
          where gm.group_id = group_messages.group_id
            and gm.user_id = (select auth.uid()))
);
drop policy if exists "group_messages_send_member" on public.group_messages;
create policy "group_messages_send_member" on public.group_messages
for insert to authenticated with check (
  sender_id = (select auth.uid())
  and exists (select 1 from public.group_members gm
              where gm.group_id = group_messages.group_id
                and gm.user_id = (select auth.uid()))
);

-- Reports: a user can submit and inspect only their own reports.
drop policy if exists "reports_submit_own" on public.reports;
create policy "reports_submit_own" on public.reports
for insert to authenticated with check (
  reporter_id = (select auth.uid()) and reported_user_id <> (select auth.uid())
);
drop policy if exists "reports_read_own" on public.reports;
create policy "reports_read_own" on public.reports
for select to authenticated using (reporter_id = (select auth.uid()));

-- Enable database-change events for the chat UI.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'group_messages'
  ) then
    alter publication supabase_realtime add table public.group_messages;
  end if;
end $$;
