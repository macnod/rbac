--
-- schema
--

\c :database_name:

create extension if not exists "uuid-ossp";

--
-- role-based access control (rbac) tables
--

-- users
create table users (
    id uuid primary key default uuid_generate_v4(),
    created_at timestamp not null default now(),
    updated_at timestamp not null default now(),
    last_login timestamp,
    user_name text not null unique,
    password_hash text not null,
    email text not null
);

-- permissions
create table permissions (
    id uuid primary key default uuid_generate_v4(),
    created_at timestamp not null default now(),
    updated_at timestamp not null default now(),
    permission_name text not null unique,
    permission_description text
);

-- Roles. Permissions are associated with roles only, never directly with a
-- user. Each user has a role that is associated with that user only, that has a
-- role_name in the format "{user_name}:exclusive", that has a role_description
-- that reads "Exclusive role for user {user_name).", and that has the
-- exclusive field set to true.
create table roles (
    id uuid primary key default uuid_generate_v4(),
    created_at timestamp not null default now(),
    updated_at timestamp not null default now(),
    role_name text not null unique,
    role_description text,
    exclusive boolean not null default false
);

-- Resources. Things that require permissions for a user to be able to access
-- them.
create table resources (
    id uuid primary key default uuid_generate_v4(),
    created_at timestamp not null default now(),
    updated_at timestamp not null default now(),
    resource_name text not null unique,
    resource_description text
);

-- Permissions associated with each role
create table role_permissions(
    id uuid primary key default uuid_generate_v4(),
    created_at timestamp not null default now(),
    updated_at timestamp not null default now(),
    role_id uuid not null references roles(id) on delete cascade,
    permission_id uuid not null references permissions(id) on delete cascade,
    unique(role_id, permission_id)
);

-- Users associated with each role. A role with exclusive = true can have only
-- one user. Other roles can have unlimited users.
create table role_users (
    id uuid primary key default uuid_generate_v4(),
    created_at timestamp not null default now(),
    updated_at timestamp not null default now(),
    role_id uuid not null references roles(id) on delete cascade,
    user_id uuid not null references users(id) on delete cascade,
    unique(user_id, role_id)
);

-- Roles and permissions associated with a resource.
create table resource_roles (
    id uuid primary key default uuid_generate_v4(),
    created_at timestamp not null default now(),
    updated_at timestamp not null default now(),
    resource_id uuid not null references resources(id) on delete cascade,
    role_id uuid not null references roles(id) on delete cascade,
    unique(resource_id, role_id)
);


--
-- Triggers for updated_at column
--

-- Function for trigger that will set the updated_at column to the current time
-- whenever a row is updated in the table.
create or replace function set_updated_at_column()
returns trigger as $$
begin
    new.updated_at = now();
    return new;
end;
$$ language 'plpgsql';

-- users trigger
create trigger set_users_updated_at
before update on users
for each row
execute function set_updated_at_column();

-- permissions trigger
create trigger set_permissions_updated_at
before update on permissions
for each row
execute function set_updated_at_column();

-- roles trigger
create trigger set_roles_updated_at
before update on roles
for each row
execute function set_updated_at_column();

-- resources trigger
create trigger set_resources_updated_at
before update on resources
for each row
execute function set_updated_at_column();

-- role_permissions trigger
create trigger set_role_permissions_updated_at
before update on role_permissions
for each row
execute function set_updated_at_column();

-- role_users trigger
create trigger set_role_users_updated_at
before update on role_users
for each row
execute function set_updated_at_column();

-- resource_roles trigger
create trigger set_resource_roles_updated_at
before update on resource_roles
for each row
execute function set_updated_at_column();

-- Function to enforce exclusive role constraints:
-- 1. Only one user can be assigned to an exclusive role.
-- 2. Exclusive role names must follow the format '{user_name}:exclusive'.
-- 3. The role description must be 'Exclusive role for user {user_name}.'.
create or replace function enforce_exclusive_role()
returns trigger as $$
declare
    associated_user_name text;
    expected_role_name text;
    expected_role_description text;
begin
    -- Check if the role is exclusive
    if exists (select 1 from roles where id = new.role_id and exclusive = true) then
        -- ensure only one user is assigned to the exclusive role
        if exists (
            select 1
            from role_users ru
            where ru.role_id = new.role_id
            and ru.user_id != new.user_id
        ) then
            raise exception 'exclusive role % can only have one user', new.role_id;
        end if;
        -- Get the user_name of the associated user
        select u.user_name into associated_user_name
        from users u
        where u.id = new.user_id;
        if associated_user_name is null then
            raise exception 'no valid user found for user_id %', new.user_id;
        end if;
        -- Construct the expected role name and description
        expected_role_name := associated_user_name || ':exclusive';
        expected_role_description := 'Exclusive role for user ' || associated_user_name || '.';
        -- Check if the role_name and role_description match the expected format
        if not exists (
            select 1
            from roles r
            where r.id = new.role_id
            and r.role_name = expected_role_name
            and r.role_description = expected_role_description
            and r.exclusive = true
        ) then
            raise exception 'Exclusive role % must have role_name ''%'' and role_description ''%''',
                new.role_id, expected_role_name, expected_role_description;
        end if;
    end if;
    return new;
end;
$$ language plpgsql;

-- Trigger to enforce exclusive role constraints on role_users insert or update
create trigger enforce_exclusive_role_trigger
before insert or update on role_users
for each row
execute function enforce_exclusive_role();
