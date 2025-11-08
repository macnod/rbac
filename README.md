# rbac

Simple RBAC Library in Common Lisp

## Overview

This library provides functions and initial SQL for supporting Role-Based Access Control.

The system provides users, roles, permissions, and resources. Users have roles. Roles have permissions. Resources also have roles. However, resources do not have users. To determine if user 'adam' has 'read' access to resource 'book', the user and the book must both have the same role and the role must have the 'read' permission.

A role can be exclusive, which means that it can be associated with only one user. Whenever a user is created, with the `d-add-user` or `add-user` function, the library creates the user's exclusive role. The user's exclusive role is also removed when the user is removed. Thus, the exclusive role represents that single user only, and represents only that user when associated with a resource. In this way, it's possible to give a specific user access to the resource.

All new users are created with default roles: 'logged-in' and 'public'. If a resource has these roles, then every user has access to the resource.

All new resources are created with default roles too: 'admin' and 'system'. The 'system' role should never be assigned to a user. The 'admin' role should give God-like powers to a user.

## Functions Overview

The library sometimes provides similar functionality via two separate functions. This is for convenience, as you'll see.

### List Functions

List functions allow you to list users, roles, permissions, resources, and other objects. These functions generally return lists of plists with keys and values that correspond loosely to rows in the database.  However, list functions that end in 'name' return a list of strings representing the names of the objects. Therefore, if you want a list of user names, you can use `list-usernames`. On the other hand, if you want details about the users, you can use `list-users`. All of the other list functions differ from these two in that they end in '-name' rather than just 'name'.

There are many list functions for retrieving user roles, user permissions, resource roles, and so forth.

### Add/Remove Functions

Add/Remove functions allow you to add and remove objects. They also have counterparts, just like the list functions do, but the counterpart functions start with a 'd-'. For example, the `add-role` function requires the following parameters: `rbac`, `role`, `description`, `exclusive`, `permissions`, and `actor`. The `d-add-role` provides defaults for most of these parameters, which can be optionally provided with keywords. Its required parameters are `rbac` and `role`.

### Summary

The alternate functions should suffice almost always.

## Usage

Create an RBAC instance:

```lisp
(defparameter *rbac* (make-instance 'rbac-pg
                        :dbname "your-db"
                        :username "db-user"
                        :password "db-pass"
                        :host "localhost"
                        :port 5432))
```

Add a role:

```lisp
(d-add-role *rbac* "worker")
```

Add a user:

```lisp
(d-add-user *rbac* "adam" "password"
    :email "adam@example.com"
    :roles '("worker"))
```

Add a resource:

```lisp
(d-add-resource *rbac* "/work/"
    :roles '("worker"))

Check access:

```lisp
(user-allowed *rbac* "adam" "read" "/worker/")
```

## Reference

Below is a reference for all exported symbols, grouped by category. For functions and generics, the signature is provided along with a brief description (drawn from the function's documentation where available).

### Functions

- **password-hash** `(username password)`
  Returns the hash of PASSWORD, using USERNAME as the salt. This is how RBAC stores the password in the database.

### Classes

- **rbac**
  Abstract base class for user database. For auditing purposes, methods that update the database require an actor parameter, which consists of a username that exists in the users database.

  Slots:
  - `resource-regex`: Defaults to an absolute directory path string that ends with a /
  - `resource-length-max`: 512
  - `username-length-max`: 64
  - `username-regex`: "^[a-zA-Z][-a-zA-Z0-9_.+]*$"
  - `password-length-min`: 6
  - `password-length-max`: 64
  - `password-regexes`: List of regexes for password validation
  - `email-length-max`: 128
  - `email-regex`: "^[-a-zA-Z0-9._%+]+@[-a-zA-Z0-9.]+\\.[a-zA-Z]{2,}$|^no-email$"
  - `role-length-max`: 64
  - `role-regex`: "^[a-z]([-a-z0-9_.+]*[a-z0-9])*(:[a-z]+)?$"
  - `permission-length-max`: 64
  - `permission-regex`: "^[a-z]([-a-z0-9_.+]*[a-z0-9])*(:[a-z]+)?$"

- **rbac-pg** (inherits from `rbac`)
  RBAC database class for PostgreSQL.

  Slots:
  - `dbname`: "rbac"
  - `username`: "cl-user"
  - `password`: ""
  - `host`: "postgres"
  - `port`: 5432

### Generic Functions

- **add-permission** `(rbac permission description actor)`
  Add a new permission and return its ID.

- **add-resource** `(rbac name description roles actor)`
  Add a new resource.

- **add-resource-role** `(rbac resource role actor)`
  Add a role permission to a resource.

- **add-role** `(rbac role description exclusive permissions actor)`
  Add a new role.

- **add-role-permission** `(rbac role permission actor)`
  Add a permission to a role.

- **add-role-user** `(rbac role user actor)`
  Add a user to a role.

- **add-user** `(rbac username email password roles actor)`
  Add a new user. This creates an exclusive role, which is for this user only, and adds the user to the public and logged-in roles (given by *default-user-roles*). Returns the new user's ID.

- **get-id** `(rbac table name)`
  Returns the ID associated with NAME in TABLE. TABLE can be one of `users`, `roles`, `permissions`, or `resources`. NAME is the value that you expect in the name field of the table. NAME is a value for the `username` field in the `users` table. The name fields of the other tables are `role_name`, `permission_name`, and `resource-name`.

- **get-permission-ids** `(rbac permissions)`
  Returns a hash table where the keys consist of permission names and the values consist of permission IDs. If PERMISSIONS is NIL, the hash table contains all existing permissions and their IDs. Otherwise, if PERMISSIONS is not NIL, the hash table contains IDs for the permissions in PERMISSIONS only. If PERMISSIONS contains a permission that doesn't exist, this function signals an error.

- **get-role-ids** `(rbac roles)`
  Returns a hash table where the keys consist of role names and the values consist of role IDs. If ROLES is NIL, the hash table contains all existing roles and their IDs. Otherwise, if ROLES is not NIL, the hash table contains IDs for the roles in ROLES only. If ROLES contains a role that doesn't exist, this function signals an error.

- **get-value** `(rbac table field &rest search)`
  Retrieves the value from FIELD in TABLE where SEARCH points to a unique row. TABLE and FIELD are strings, and SEARCH is a series of field names and values that identify the row uniquely. TABLE, FIELD, and the field names in SEARCH must exist in the database. If no row is found, this function returns NIL.

- **list-permissions** `(rbac page page-size)`
  List permissions, returning PAGE-SIZE permissions starting on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-permissions-count** `(rbac)`
  Return the count of permissions in the database.

- **list-resource-roles** `(rbac resource page page-size)`
  List roles for a resource, returning PAGE-SIZE roles starting on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-resource-roles-count** `(rbac resource)`
  Return the count of roles for a resource.

- **list-resource-roles-regular** `(rbac resource page page-size)`
  List non-exclusive roles for a resource, returning PAGE-SIZE

- **list-resource-roles-regular-count** `(rbac resource)`
  Return the count of non-exclusive roles for a resource.

- **list-resource-users** `(rbac resource permission page page-size)`
  List the users have PERMISSION on RESOURCE, returning PAGE-SIZE rows from PAGE. If PERMISSION is nil, this function lists RESOURCE users with any permission. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-resource-users-count** `(rbac resource permission)`
  Return the count of users who have PERMISSION on RESOURCE.

- **list-resources** `(rbac page page-size)`
  List resources, returning PAGE-SIZE resources starting on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-resources-count** `(rbac)`
  Return the count of resources in the database.

- **list-role-permissions** `(rbac role page page-size)`
  List permissions for a role, returning PAGE-SIZE permissions starting on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-role-permissions-count** `(rbac role)`
  Return the count of permissions for a role.

- **list-role-users** `(rbac role page page-size)`
  List users for a role, returning PAGE-SIZE users starting on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-role-users-count** `(rbac role)`
  Return the count of users for a role.

- **list-roles** `(rbac page page-size)`
  List roles, returning PAGE-SIZE roles starting on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-roles-count** `(rbac)`
  Return the count of roles in the database.

- **list-roles-regular** `(rbac page page-size)`
  List non-exclusive roles, returning PAGE-SIZE roles starting

- **list-roles-regular-count** `(rbac)`
  Return the count of regular roles in the database.

- **list-rows** `(rbac select-fields tables where-clauses values order-by-fields page page-size)`
  Returns a list of rows, with each row represented as a plist.

- **list-users** `(rbac page page-size)`
  List users sorted by SORT-BY. Return PAGE-SIZE users starting from PAGE. SORT-BY is a list of fields, where each field string consists of the name of a field optionally followed by ASC or DESC. :PAGE is the page number, starting from 1, and PAGE-SIZE is an integer between 1 and 1000.

- **list-users-count** `(rbac)`
  Return the count of users in the database.

- **list-users-filtered** `(rbac sort-by descending filters page page-size)`
  List users sorted by SORT-BY and filtered by FILTERS. SORT-BY is a string consisting of the name of a field. DESCENDING is a boolean that indicates whether the sort is descending or not. FILTERS is a list of filters, where each filter is a list of three elements: field name, operator, and value. The supported operators are =, <>, <, >, <=, >=, like, ilike, not like, not ilike, is, is not. Return PAGE-SIZE users starting from PAGE. PAGE starts from 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-users-filtered-count** `(rbac filters)`
  Returns the count of users filtered by FILTERS. FILTERS is a list of filters, where each filter is a list of three elements: field name, operator, and value. The supported operators are =, <>, <, >, <=, >=, like, ilike, not like, not ilike, is, is not.

- **list-user-roles** `(rbac user page page-size)`
  List the roles for a given user, returning PAGE-SIZE roles starting on page PAGE. Page starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-user-roles-count** `(rbac user)`
  Return the count of roles for USER.

- **list-user-roles-regular** `(rbac user page page-size)`
  List the roles for USER excluding the user's exclusive role, the public role, and the logged-in role, returning PAGE-SIZE roles starting on page PAGE.

- **list-user-roles-regular-count** `(rbac user)`
  Return the count of roles for USER excluding the user's exclusive role, the public role, and the logged-in role.

- **list-user-resources** `(rbac user page page-size)`
  List the resources that USER has access to, returning PAGE-SIZE rows from PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000.

- **list-user-resources-count** `(rbac user)`
  Return the count of resources that USER has access to.

- **login** `(rbac username password actor)`
  If USERNAME exists and PASSWORD is correct, update last_login for USERNAME and return the user ID. Otherwise, return NIL.

- **remove-permission** `(rbac permission actor)`
  Remove (soft delete) PERMISSION from the database.

- **remove-resource** `(rbac resource actor)`
  Remove (soft delete) RESOURCE from the database.

- **remove-resource-role** `(rbac resource role actor)`
  Remove (soft delete) a role permission from a resource.

- **remove-role** `(rbac role actor)`
  Remove (soft delete) a role from the database.

- **remove-role-permission** `(rbac role permission actor)`
  Remove (soft delete) a permission from a role.

- **remove-role-user** `(rbac role user actor)`
  Remove (soft delete) a user from a role.

- **remove-user** `(rbac username actor)`
  Remove (soft delete) USERNAME from the database.

- **soft-delete** `(rbac delete-target-sql delete-refs-sql details delete-exclusive-role-sql)`
  Executes the given SQL statements in a transaction, to soft delete a row and references to that row, updating the audit table.

- **sql-for-list** `(rbac select-fields tables where-clauses values order-by-fields page page-size)`
  Generates an SQL statement that selects a list of records, each containing SELECT-FIELDS, from TABLES. SELECT-FIELDS is a list of field names to select. TABLES is a table name, or a string representing the tables to select from, including any join SQL syntax. WHERE-CLAUSES is a list of conditions, in SQL syntax, that must all be true for a record to be selected. ORDER-BY-FIELDS is a list of field names to order the results by, with each string in the list optionally followed by a space and either ASC or DESC, to indicate the sort order. PAGE is the page number, starting from 1, and PAGE-SIZE is the number of records to return per page. It must be an integer between 1 and 1000. The SQL statement consists of a list with an SQL string followed by values that are used to replace the placeholders in the string. The generated SQL includes a WHERE clause that excludes deleted records, i.e. records where the deleted_at field is not null.

- **to-hash-table** `(rbac row)`
  Convert a row into a hash table where the table keys correspond to the field names and the table values correspond to the field values.

- **to-hash-tables** `(rbac row)`
  Convert a list of rows representing the result of a database query from the :STR-ALISTS format into a list of hash tables where each hash table represents a row.

- **user-allowed** `(rbac username permission resource)`
  Determine if user with USER-ID has PERMISSION on RESOURCE.

- **user-has-role** `(rbac username &rest role)`
  Check if USERNAME has any of the specified ROLE(s).

- **valid-description-p** `(rbac description)`
  Validates new DESCRIPTION string.

- **valid-email-p** `(rbac email)`
  Validates new EMAIL string. The string must look like an email address, with a proper domain name, and it must have a length that doesn't exceed 128 characters.

- **valid-password-p** `(rbac password)`
  Validates new PASSWORD string. PASSWORD must have - at least password-length-min characters - at least one letter - at least one digit - at least one common punctuation character - at most password-length-max characters

- **valid-permission-p** `(rbac permission)`
  Validates new PERMISSION string. PMERISSION must: - start with a letter - consist of letters, digits, and hyphens - optionally have a colon that is not at the beginning or the end - contain at most permission-length-max characters

- **valid-resource-p** `(rbac resource)`
  Validates new RESOURCE string.

- **valid-role-p** `(rbac role)`
  Validates new ROLE string. ROLE must: - start with a letter - consist of letters, digits, and hyphens - have at most role-length-max characters - optionally have a colon that is not at the beginning or the end

- **valid-username-p** `(rbac username)`
  Validates new USERNANME string. USERNAME must: - Have at least 1 character - Have at most username-length-max characters - Start with a letter - Contain only ASCII characters for - letters (any case) - digits - underscores - dashes - periods - plus sign (+)

### Functions with Defaults

- **d-add-permission** `(rbac permission &key description actor)`
  Add a permission with defaults.

- **d-add-resource** `(rbac resource &key description roles actor)`
  Add a resource with defaults.

- **d-add-resource-role** `(rbac resource role &key actor)`
  Add a role to a resource with defaults.

- **d-add-role** `(rbac role &key description exclusive permissions actor)`
  Add a role with defaults.

- **d-add-role-permission** `(rbac role permission &key actor)`
  Add a permission to a role with defaults.

- **d-add-role-user** `(rbac role user &key actor)`
  Add a user to a role with defaults.

- **d-add-user** `(rbac username password &key email roles actor)`
  Add a user with defaults.

- **d-add-user-role** `(rbac user role &key actor)`
  Add a role to a user with defaults.

- **d-login** `(rbac username password &key actor)`
  Log in user.

- **d-remove-permission** `(rbac permission &key actor)`
  Remove permission with defaults.

- **d-remove-resource** `(rbac resource &key actor)`
  Remove resource with defaults.

- **d-remove-resource-role** `(rbac resource role &key actor)`
  Remove a role from a resource with defaults.

- **d-remove-role** `(rbac role &key actor)`
  Remove ROLE with defauls.

- **d-remove-role-permission** `(rbac role permission &key actor)`
  Remove a permission from a role with defaults.

- **d-remove-role-user** `(rbac role user &key actor)`
  Remove a user from a role with defaults.

- **d-remove-user** `(rbac username &key actor)`
  Remove a user with defaults.

- **d-remove-user-role** `(rbac user role &key actor)`
  Remove a role from a user with defaults.

### Simple List Functions

- **list-usernames** `(rbac &key page page-size)`
  List all usernames

- **list-user-resource-names** `(rbac user &key page page-size)`
  List resources for user

- **list-role-names** `(rbac &key page page-size)`
  List all roles

- **list-role-names-regular** `(rbac &key page page-size)`
  List all regular roles

- **list-permission-names** `(rbac &key page page-size)`
  List all permissions

- **list-resource-names** `(rbac &key page page-size)`
  List all resources

- **list-resource-usernames** `(rbac resource permission &key page page-size)`
  List usernames that have PERMISSION on RESOURCE.

- **list-role-usernames** `(rbac role &key page page-size)`
  List users for role

- **list-user-role-names** `(rbac user &key page page-size)`
  List roles for user

- **list-user-role-names-regular** `(rbac user &key page page-size)`
  List regular roles for user

- **list-role-permission-names** `(rbac role &key page page-size)`
  List permissions for role

- **list-resource-role-names** `(rbac resource &key page page-size)`
  List roles for resource

- **list-resource-role-names-regular** `(rbac resource &key page page-size)`
  List regular roles for resource

- **list-role-resource-names** `(rbac role &key page page-size)`
  List resources for role
