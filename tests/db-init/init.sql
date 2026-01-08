--
-- schema
--

\c rbac

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


--
-- insert users
--

insert into users (user_name, email, id, password_hash) values
    (
        'admin',                                -- user_name
        'no-email',                             -- email
        '0ed9f765-50ee-4e93-a711-f63db14b3cf5', -- id
        'a5ad2e9965d47e970d4d6b7e123dbdb5'      -- password_hash
    ),
    (
        'guest',                                -- user_name
        'no-email',                             -- email
        '78b52fdc-57db-95b7-3dea-101d1a7d4a83', -- id
        'ddc6cc21af9ae87db37962d28339d7b2'      -- password_hash
    );

--
-- insert roles
--

insert into roles (role_name, role_description, exclusive, id) values
    -- Admin role
    (
        'admin',
        'Role with God-like access, for administrative operations.',
        false,
        '200f91db-d0c8-43d1-9430-72f1fd03b285'
    ),
    (
        'logged-in',
        'Role for logged-in users.',
        false,
        '9ad10cfa-78fe-43af-a417-0f104b64766a'
    ),
    (
        'public',
        'Role for anonymous users that are not logged in.',
        false,
        'c9b6868a-0550-41eb-9c74-4d90e3ea03b5'
    ),
    -- Exclusive roles.
    (
        'admin:exclusive',
        'Exclusive role for user admin.',
        true,
        '5afef606-07f8-4c7d-afe3-da66f00ed015'
    ),
    (
        'guest:exclusive',
        'Exclusive role for user guest.',
        true,
        '89c55ba2-7568-cad8-c5ec-b843a41f51a9'
    );

--
-- insert permissions
--

insert into permissions (permission_name, permission_description, id) values
    (
        'create',
        'General create permission',
        '1d8f1218-7518-4c17-80f6-edb9987e8a20'
    ),
    (
        'read',
        'General read permission',
        '784c7460-134e-4b06-9c80-d6db197a1bdf'
    ),
    (
        'update',
        'General update permission',
        '8563f298-df16-490d-aac1-92fea8dd196d'
    ),
    (
        'delete',
        'General delete permission',
        'f77b0d67-330a-4b0d-8166-d73229547f5f'
    );

--
-- insert role-permissions
--

insert into role_permissions (role_id, permission_id) values
    --
    -- General role permissions
    --
    -- admin: create, read, update, delete
    (
        '200f91db-d0c8-43d1-9430-72f1fd03b285', -- admin role
        '1d8f1218-7518-4c17-80f6-edb9987e8a20'  -- create
    ),
    (
        '200f91db-d0c8-43d1-9430-72f1fd03b285', -- admin role
        '784c7460-134e-4b06-9c80-d6db197a1bdf'  -- read
    ),
    (
        '200f91db-d0c8-43d1-9430-72f1fd03b285', -- admin role
        '8563f298-df16-490d-aac1-92fea8dd196d'  -- update
    ),
    (
        '200f91db-d0c8-43d1-9430-72f1fd03b285', -- admin role
        'f77b0d67-330a-4b0d-8166-d73229547f5f'  -- delete
    ),
    --
    -- Exclusive role permissions
    --
    -- admin:exclusive
    (
        '5afef606-07f8-4c7d-afe3-da66f00ed015', -- admin:exclusive role
        '1d8f1218-7518-4c17-80f6-edb9987e8a20'  -- create
    ),
    (
        '5afef606-07f8-4c7d-afe3-da66f00ed015', -- admin:exclusive role
        '784c7460-134e-4b06-9c80-d6db197a1bdf'  -- read
    ),
    (
        '5afef606-07f8-4c7d-afe3-da66f00ed015', -- admin:exclusive role
        '8563f298-df16-490d-aac1-92fea8dd196d'  -- update
    ),
    (
        '5afef606-07f8-4c7d-afe3-da66f00ed015', -- admin:exclusive role
        'f77b0d67-330a-4b0d-8166-d73229547f5f'  -- delete
    ),
    -- guest:exclusive
    (
        '89c55ba2-7568-cad8-c5ec-b843a41f51a9', -- admin:exclusive role
        '784c7460-134e-4b06-9c80-d6db197a1bdf'  -- read
    ),
    --
    -- Public role permissions
    --
    -- public: read
    (
        'c9b6868a-0550-41eb-9c74-4d90e3ea03b5', -- public role
        '784c7460-134e-4b06-9c80-d6db197a1bdf'  -- read
    ),
    --
    -- Logged-in role permissions
    --
    -- logged-in: read
    --
    (
        '9ad10cfa-78fe-43af-a417-0f104b64766a', -- logged-in role
        '784c7460-134e-4b06-9c80-d6db197a1bdf'  -- read
    );


--
-- insert role users
--

insert into role_users (role_id, user_id) values
    -- Admin user roles
    (
        '200f91db-d0c8-43d1-9430-72f1fd03b285', -- admin role
        '0ed9f765-50ee-4e93-a711-f63db14b3cf5'  -- admin user
    ),
    (
        'c9b6868a-0550-41eb-9c74-4d90e3ea03b5', -- public role
        '0ed9f765-50ee-4e93-a711-f63db14b3cf5'  -- admin user
    ),
    (
        '9ad10cfa-78fe-43af-a417-0f104b64766a', -- logged-in role
        '0ed9f765-50ee-4e93-a711-f63db14b3cf5'  -- admin user
    ),
    (
        '5afef606-07f8-4c7d-afe3-da66f00ed015', -- admin:exclusive
        '0ed9f765-50ee-4e93-a711-f63db14b3cf5'  -- admin user
    ),
    -- Guest user roles. The guest user is the only one that
    -- should never have a logged-in role.
    (
        'c9b6868a-0550-41eb-9c74-4d90e3ea03b5', -- public role
        '78b52fdc-57db-95b7-3dea-101d1a7d4a83'  -- guest user
    ),
    (
        '89c55ba2-7568-cad8-c5ec-b843a41f51a9', -- guest:exclusive
        '78b52fdc-57db-95b7-3dea-101d1a7d4a83' -- guest user
    );
