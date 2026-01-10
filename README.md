<a id="x-28RBAC-3A-40RBAC-MANUAL-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-MANUAL%20MGL-PAX:SECTION"></a>

# `RBAC` System Reference Manual

## Table of Contents

- [1 Examples][967f]
- [2 `RBAC-PG` Class][7b8a]
- [3 Functions][94ab]
- [4 Special Variables][7829]
- [5 Macros][d0c7]

###### \[in package RBAC\]
This is a simple Role-Based Access Control (`RBAC`) system implemented in Common Lisp. It provides an [`rbac-pg`][5ba5] class and functions for managing users, roles, permissions, and resources.

## Overview

This library provides functions and initial `SQL` for supporting Role-Based Access Control (`RBAC`).

The system provides users, roles, permissions, and resources. Users have roles. Roles have permissions. Resources also have roles. However, resources do not have users. To determine if user 'adam' has 'read' access to resource 'book', the user and the book must both have the same role and the role must have the 'read' permission.

A role can be exclusive, which means that it can be associated with only one user. Exclusive roles are managed by the system, so there's never any need to create or delete exclusive roles. However, you can manage the permission for an exclusive role. Whenever a user is created with the [`add-user`][e768] function, the library creates the user's exclusive role. The user's exclusive role is also removed when the user is removed. Thus, the exclusive role represents that user only. In this way, it's possible to give a specific user access to the resource. All users have a corresponding exclusive role, except for the `guest` user. You can obtaine the name of a user's exclusive role  with the [`exclusive-role-for`][ac36] function.

All new users are created with default roles: 'logged-in', 'public', and the exclusive role for that user. If a resource has the 'logged-in' role, then every logged-in user (that is, every user except for 'guest') has access to the resource. If a resource has the 'public' role, then all users, including the guest user (not logged in), have access to the resource. The 'public' and 'logged-in' roles have 'read' permission by default.

Unless you specify specific permissions when creating a new role, its permission defaults to 'create', 'read', 'update', and 'delete'. These are general, default permissions, but you can add any permission you like to the system.

All new resources are created with the default role 'admin'.

## Installation

### Roswell

You'll need to install some dependencies first:
`sh
ros install postmodern
ros install fiveam
ros install cl-csv
ros install trivial-utf-8
ros install ironclad
ros install swank
ros install macnod/dc-dlist/v1.0
ros install macnod/dc-ds/v0.5
ros install macnod/dc-time/v0.5
ros install macnod/p-log/v0.9
ros install macnod/dc-eclectic/v0.51
`

Then, you can install `rbac` like this:

`ros install macnod/rbac/vX.X`

where X.X is the release.

### GitHub

Clone the repo to a directory that Quicklisp or ASDF can see, such as ~/common-lisp. For example:

```sh
cd ~/common-lisp
git clone git@github.com:macnod/rbac.git
cd rbac
```

Then, install the macnod dependencies in a similar fashion. If use Quicklisp, then Quicklisp will take care of installing the other dependencies (non-macnod) when you do `(ql:quickload :rbac)`.

## Usage

One way to use the `RBAC` library is to create a project that includes the `RBAC` init.sql file. You might want to edit the init.sql file to change the database name, for example, or to add some tables.

Your project should start PostgreSQL, initialize the database with init.sql (if that hasn't already been done), and load the `RBAC` library.

Your project can then use the library via the `RBAC` API.

<a id="x-28RBAC-3A-40RBAC-EXAMPLES-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-EXAMPLES%20MGL-PAX:SECTION"></a>

## 1 Examples

Usage examples.

```lisp
(require :rbac)
(defpackage :rbac-example (:use :cl :rbac))
(in-package :rbac-example)

;; Connect to the databse
(defparameter *rbac* (make-instance 'rbac-pg
                       :host "127.0.0.1"
                       :port "5432"
                       :user-name "rbac"
                       :password "rbac-password"))

;; Initialize the database. This will create the base users,
;; roles, and permissions. The password would normally come
;; from an environment variable.
(initialize-database *rbac* "admin-password-1")

;; Add a bogus permission
(add-permission *rbac* "bogus-permission")

;; Add some roles. The first role has the "read" permission only.
(add-role *rbac* "role-a" :permissions '("read"))

;; role-b has the default permissions, "create", "read", "update",
;; and "delete".
(add-role *rbac* "role-b")

;; role-c has the default permissions plus the "bogus-permission".
(add-role *rbac* "role-c"
  :permissions (cons "bogus-permission" *default-permissions*))

;; role-d has only the "bogus" permission only.
(add-role *rbac* "role-d"
  :permissions '("bogus-permission"))

;; Add a user with roles "role-a" and "role-b"
(add-user *rbac* "user-1" "user-1@example.com" "password-01"
    :roles '("role-a" "role-b")

;; Add a resource that is accessible to the public
(add-resource *rbac* "test:resource-1"
    :roles '("public" "role-b"))

;; Should list 3 users: "admin", "guest", and the user we just
;; added, "user-1"
(list-user-names *rbac*)

;; Should list the default permissions
(list-permission-names *rbac*)

;; Lists the roles for user "user-1", including "role-a" and
;; "role-b", which we assigned, the user's exclusive role,
;; "user-1:exclusive", which the system assigned, and the
;; "logged-in" role, also assigned by the system.
(list-user-role-names *rbac* "user-1")

;; Lists the permissions that "user-1" has on resource
;; "test:resource-1", which should be all the permissions from
;; the roles that the user and the resource share, "public"
;; and "role-b". This amounts to all the default permissions.
(list-user-resource-permission-names *rbac* "user-1" "test:resource-1")

;; Returns T, because "read" is among the permissions that
;; the user has on the resource.
(user-allowed *rbac* "user-1" "read" "test:resource-1")
```


<a id="x-28RBAC-3A-40RBAC-PG-CLASS-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-PG-CLASS%20MGL-PAX:SECTION"></a>

## 2 `RBAC-PG` Class

[`RBAC-PG`][5ba5] Class and Accessors.

<a id="x-28RBAC-3ARBAC-PG-20CLASS-29"></a>
<a id="RBAC:RBAC-PG%20CLASS"></a>

- [class] **RBAC-PG** *RBAC*

    \[public\] `RBAC` database class for PostgreSQL.

<a id="x-28RBAC-3ADB-HOST-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-PG-29-29"></a>
<a id="RBAC:DB-HOST%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC-PG%29"></a>

- [accessor] **DB-HOST** *RBAC-PG (:DB-HOST = "postgres")*

    \[public\] Host name for connecting to the `RBAC` database.

<a id="x-28RBAC-3ADB-NAME-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-PG-29-29"></a>
<a id="RBAC:DB-NAME%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC-PG%29"></a>

- [accessor] **DB-NAME** *RBAC-PG (:DB-NAME = "rbac")*

    \[public\] Name of the `RBAC` database.

<a id="x-28RBAC-3ADB-PASSWORD-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-PG-29-29"></a>
<a id="RBAC:DB-PASSWORD%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC-PG%29"></a>

- [accessor] **DB-PASSWORD** *RBAC-PG (:DB-PASSWORD = "")*

    \[public\] Password for connecting to the `RBAC` database.

<a id="x-28RBAC-3ADB-PORT-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-PG-29-29"></a>
<a id="RBAC:DB-PORT%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC-PG%29"></a>

- [accessor] **DB-PORT** *RBAC-PG (:DB-PORT = 5432)*

    \[public\] Port number for connecting to the `RBAC` database.

<a id="x-28RBAC-3ADB-USER-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-PG-29-29"></a>
<a id="RBAC:DB-USER%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC-PG%29"></a>

- [accessor] **DB-USER** *RBAC-PG (:DB-USER = "cl-user")*

    \[public\] User name for connecting to the `RBAC` database.

<a id="x-28RBAC-3AEMAIL-LENGTH-MAX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:EMAIL-LENGTH-MAX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **EMAIL-LENGTH-MAX** *RBAC (:EMAIL-LENGTH-MAX = 128)*

    \[public\] Maximum length of an email address.

<a id="x-28RBAC-3AEMAIL-REGEX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:EMAIL-REGEX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **EMAIL-REGEX** *RBAC (:EMAIL-REGEX =
 "^\[a-zA-Z0-9\]\[-a-zA-Z0-9.\_%+\]+@(\[a-zA-Z0-9\]+)(\\\\.?\[-a-zA-Z0-9\])+\\\\.\[a-zA-Z\]{2,}$|^no-email$")*

    \[public\] Regex for validation of email address strings.

<a id="x-28RBAC-3APASSWORD-LENGTH-MAX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:PASSWORD-LENGTH-MAX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **PASSWORD-LENGTH-MAX** *RBAC (:PASSWORD-LENGTH-MAX = 64)*

    \[public\] Maximum length of password string.

<a id="x-28RBAC-3APASSWORD-LENGTH-MIN-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:PASSWORD-LENGTH-MIN%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **PASSWORD-LENGTH-MIN** *RBAC (:PASSWORD-LENGTH-MIN = 6)*

    \[public\] Minimum length of password string.

<a id="x-28RBAC-3APASSWORD-REGEXES-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:PASSWORD-REGEXES%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **PASSWORD-REGEXES** *RBAC (:PASSWORD-REGEXES =
 (LIST "^\[\\\\x00-\\\\x7f\]+$" "\[a-zA-Z\]" "\[-!@#$%^\&\*()+={}\[\]|:;\<>,.?/~\`\]" "\[0-9\]"))*

    \[public\] List of regular expressions that a valid password must match.
    Every regex in the list must match.

<a id="x-28RBAC-3APERMISSION-LENGTH-MAX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:PERMISSION-LENGTH-MAX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **PERMISSION-LENGTH-MAX** *RBAC (:PERMISSION-LENGTH-MAX = 64)*

    \[public\] Maximum length of permission name string.

<a id="x-28RBAC-3APERMISSION-REGEX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:PERMISSION-REGEX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **PERMISSION-REGEX** *RBAC (:PERMISSION-REGEX = "^\[a-z\](\[-a-z0-9\_.+\]\*\[a-z0-9\])\*(:\[a-z\]+)?$")*

    \[public\] Regex for validating permission name strings.

<a id="x-28RBAC-3ARESOURCE-LENGTH-MAX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:RESOURCE-LENGTH-MAX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **RESOURCE-LENGTH-MAX** *RBAC (:RESOURCE-LENGTH-MAX = 512)*

    \[public\] Maximum length of resource name string.

<a id="x-28RBAC-3ARESOURCE-REGEX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:RESOURCE-REGEX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **RESOURCE-REGEX** *RBAC (:RESOURCE-REGEX = "^\[a-zA-Z\]\[-a-zA-Z0-9\]\*:?\[a-zA-Z0-9\]\[-a-zA-Z0-9\]\*$")*

    \[public\] Defaults to an absolute directory path string that ends with /

<a id="x-28RBAC-3AROLE-LENGTH-MAX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:ROLE-LENGTH-MAX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **ROLE-LENGTH-MAX** *RBAC (:ROLE-LENGTH-MAX = 64)*

    \[public\] Maximum length of role name string.

<a id="x-28RBAC-3AROLE-REGEX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:ROLE-REGEX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **ROLE-REGEX** *RBAC (:ROLE-REGEX = "^\[a-z\](\[-a-z0-9\_.+\]\*\[a-z0-9\])\*(:\[a-z\]+)?$")*

    \[public\] Regex for validating role name strings.

<a id="x-28RBAC-3AUSER-NAME-LENGTH-MAX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:USER-NAME-LENGTH-MAX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **USER-NAME-LENGTH-MAX** *RBAC (:USER-NAME-LENGTH-MAX = 64)*

    \[public\] Maximum length of user name string.

<a id="x-28RBAC-3AUSER-NAME-REGEX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:USER-NAME-REGEX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **USER-NAME-REGEX** *RBAC (:USER-NAME-REGEX = "^\[a-zA-Z\]\[-a-zA-Z0-9\_.+\]\*$")*

    \[public\] Regex for validating user name strings.

<a id="x-28RBAC-3A-40RBAC-FUNCTIONS-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-FUNCTIONS%20MGL-PAX:SECTION"></a>

## 3 Functions

Accessors and methods for manipulating `RBAC` objects.

<a id="x-28RBAC-3AADD-PERMISSION-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ADD-PERMISSION%20GENERIC-FUNCTION"></a>

- [generic-function] **ADD-PERMISSION** *RBAC PERMISSION &KEY DESCRIPTION*

    \[public\] Add a new permission and returns the ID of the
    new entry.  `DESCRIPTION` is optional and auto-generated if not provided.

<a id="x-28RBAC-3AADD-RESOURCE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ADD-RESOURCE%20GENERIC-FUNCTION"></a>

- [generic-function] **ADD-RESOURCE** *RBAC RESOURCE &KEY DESCRIPTION ROLES*

    \[public\] Add a new resource and returns the ID of the
    new entry. The resource is automatically linked to the roles in
    *default-resource-roles* plus any additional `ROLES` provided. `DESCRIPTION` is
    optional and auto-generated if not provided.

<a id="x-28RBAC-3AADD-RESOURCE-ROLE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ADD-RESOURCE-ROLE%20GENERIC-FUNCTION"></a>

- [generic-function] **ADD-RESOURCE-ROLE** *RBAC RESOURCE ROLE*

    \[public\] Add an existing role to an existing resource.
    Returns the ID of the new resource\_roles row.

<a id="x-28RBAC-3AADD-ROLE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ADD-ROLE%20GENERIC-FUNCTION"></a>

- [generic-function] **ADD-ROLE** *RBAC ROLE &KEY DESCRIPTION PERMISSIONS*

    \[public\] Add a new `ROLE`. Description is optional and
    auto-generated if not provided. If the role name ends with ':exclusive', the
    role is marked as exclusive, so the `EXCLUSIVE` parameter is optional. `PERMISSIONS`
    is a list of permission names to add to the role, defaulting to
    [`*DEFAULT-PERMISSIONS*`][c729].  All `PERMISSIONS` must already exist. Returns the new
    role's ID.

<a id="x-28RBAC-3AADD-ROLE-PERMISSION-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ADD-ROLE-PERMISSION%20GENERIC-FUNCTION"></a>

- [generic-function] **ADD-ROLE-PERMISSION** *RBAC ROLE PERMISSION*

    \[public\] Add an existing permission to an existing role.
    Returns the ID of the new role\_permissions row.

<a id="x-28RBAC-3AADD-ROLE-USER-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ADD-ROLE-USER%20GENERIC-FUNCTION"></a>

- [generic-function] **ADD-ROLE-USER** *RBAC ROLE USER*

    \[public\] Add an existing user to an existing role.
    Returns the ID of the new role\_users row.

<a id="x-28RBAC-3AADD-USER-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ADD-USER%20GENERIC-FUNCTION"></a>

- [generic-function] **ADD-USER** *RBAC USER-NAME EMAIL PASSWORD &KEY ROLES*

    \[public\] Add a new user. This creates an exclusive role,
    which is for this user only, and adds the user to the public and logged-in roles
    (given by *default-user-roles*). Returns the new user's ID.

<a id="x-28RBAC-3AADD-USER-ROLE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ADD-USER-ROLE%20GENERIC-FUNCTION"></a>

- [generic-function] **ADD-USER-ROLE** *RBAC USER ROLE*

    \[public\] Add an existing role to an existing user.
    Returns the ID of the new role\_users row.

<a id="x-28RBAC-3AEXCLUSIVE-ROLE-FOR-20FUNCTION-29"></a>
<a id="RBAC:EXCLUSIVE-ROLE-FOR%20FUNCTION"></a>

- [function] **EXCLUSIVE-ROLE-FOR** *USER-NAME*

    \[public\] Returns the exclusive role for `USER-NAME`.

<a id="x-28RBAC-3AGET-ID-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:GET-ID%20GENERIC-FUNCTION"></a>

- [generic-function] **GET-ID** *RBAC TABLE NAME*

    \[public\] Returns the ID associated with `NAME` in `TABLE`.

<a id="x-28RBAC-3AGET-VALUE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:GET-VALUE%20GENERIC-FUNCTION"></a>

- [generic-function] **GET-VALUE** *RBAC TABLE FIELD &REST SEARCH*

    \[public\] Retrieves the value from `FIELD` in `TABLE` where
    `SEARCH` points to a unique row. `TABLE` and `FIELD` are strings, and `SEARCH` is a
    series of field names and values that identify the row uniquely. `TABLE`, `FIELD`,
    and the field names in `SEARCH` must exist in the database. If no row is found,
    this function returns `NIL`.

<a id="x-28RBAC-3AID-EXISTS-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ID-EXISTS-P%20GENERIC-FUNCTION"></a>

- [generic-function] **ID-EXISTS-P** *RBAC TABLE ID*

    \[public\] Returns `T` when `ID` exists in `TABLE`.

<a id="x-28RBAC-3AINITIALIZE-DATABASE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:INITIALIZE-DATABASE%20GENERIC-FUNCTION"></a>

- [generic-function] **INITIALIZE-DATABASE** *RBAC ADMIN-PASSWORD*

    \[public\] Idempotent function that checks if the database,
    given by `RBAC`, has been initialized. If not, then this function initializes the
    database, which involves creating some base permissions, roles, and users. The
    base permissions are 'create', 'read', 'update', and 'delete'. The base roles
    are 'admin', 'admin:exclusive', 'logged-in', and 'public'. All of the roles have
    all the base permissions, except for the 'public' and 'logged-in' roles, which
    have the 'read' permission only. The base users are 'guest' and 'admin'. The
    'guest' user is assigned the 'public' role and the 'admin' user is assigned all
    of the roles and created with the password `ADMIN-PASSWORD`. The 'guest' user
    doesn't need a password, so the bogus value 'guest-password-1' is used. The
    database is considered initialized the users table contains records, in which
    case this function does nothing.

<a id="x-28RBAC-3ALIST-PERMISSION-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-PERMISSION-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-PERMISSION-NAMES** *RBAC &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List of permission names (all permissions by default). Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "permission\_name").

<a id="x-28RBAC-3ALIST-PERMISSIONS-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-PERMISSIONS%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-PERMISSIONS** *RBAC &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about permissions (all permissions by default). Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "permission\_name").

<a id="x-28RBAC-3ALIST-RESOURCE-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-RESOURCE-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-RESOURCE-NAMES** *RBAC &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List of resource names (all resources by default). Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "resource\_name").

<a id="x-28RBAC-3ALIST-RESOURCE-ROLE-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-RESOURCE-ROLE-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-RESOURCE-ROLE-NAMES** *RBAC RESOURCE &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List names of roles associated with `RESOURCE`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "role\_name").

<a id="x-28RBAC-3ALIST-RESOURCE-ROLES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-RESOURCE-ROLES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-RESOURCE-ROLES** *RBAC RESOURCE &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about roles associated with `RESOURCE`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "role\_name").

<a id="x-28RBAC-3ALIST-RESOURCE-USER-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-RESOURCE-USER-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-RESOURCE-USER-NAMES** *RBAC RESOURCE PERMISSION &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List user names of resources where the user has `PERMISSION` on the resource. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "u.user\_name").

<a id="x-28RBAC-3ALIST-RESOURCE-USERS-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-RESOURCE-USERS%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-RESOURCE-USERS** *RBAC RESOURCE PERMISSION &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about resource users where the user has `PERMISSION` on the resource. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "u.user\_name").

<a id="x-28RBAC-3ALIST-RESOURCES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-RESOURCES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-RESOURCES** *RBAC &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about resources (all resources by default). Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "resource\_name").

<a id="x-28RBAC-3ALIST-ROLE-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-ROLE-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-ROLE-NAMES** *RBAC &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List of role names (all roles by default). Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "role\_name").

<a id="x-28RBAC-3ALIST-ROLE-PERMISSION-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-ROLE-PERMISSION-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-ROLE-PERMISSION-NAMES** *RBAC ROLE &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List names of permissions associated with `ROLE`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "permission\_name").

<a id="x-28RBAC-3ALIST-ROLE-PERMISSIONS-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-ROLE-PERMISSIONS%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-ROLE-PERMISSIONS** *RBAC ROLE &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about permissions associated with `ROLE`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "permission\_name").

<a id="x-28RBAC-3ALIST-ROLE-RESOURCE-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-ROLE-RESOURCE-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-ROLE-RESOURCE-NAMES** *RBAC ROLE &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List names of resources associated with `ROLE`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "resource\_name").

<a id="x-28RBAC-3ALIST-ROLE-RESOURCES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-ROLE-RESOURCES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-ROLE-RESOURCES** *RBAC ROLE &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about resources associated with `ROLE`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "resource\_name").

<a id="x-28RBAC-3ALIST-ROLE-USER-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-ROLE-USER-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-ROLE-USER-NAMES** *RBAC ROLE &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List names of users associated with `ROLE`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "user\_name").

<a id="x-28RBAC-3ALIST-ROLE-USERS-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-ROLE-USERS%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-ROLE-USERS** *RBAC ROLE &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about users associated with `ROLE`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "user\_name").

<a id="x-28RBAC-3ALIST-ROLES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-ROLES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-ROLES** *RBAC &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about roles (all roles by default). Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "role\_name").

<a id="x-28RBAC-3ALIST-USER-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-USER-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-USER-NAMES** *RBAC &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List of user names (all users by default). Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "user\_name").

<a id="x-28RBAC-3ALIST-USER-RESOURCE-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-USER-RESOURCE-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-USER-RESOURCE-NAMES** *RBAC USER PERMISSION &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List resource names of users where the user has `PERMISSION` on the resource. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "s.resource\_name").

<a id="x-28RBAC-3ALIST-USER-RESOURCE-PERMISSION-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-USER-RESOURCE-PERMISSION-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-USER-RESOURCE-PERMISSION-NAMES** *RBAC USER-NAME RESOURCE-NAME &KEY PAGE PAGE-SIZE*

    \[public\] List the names of the permissions that `USER-NAME`
    has on `RESOURCE-NAME`. Supports pagination via `PAGE` and `PAGE-SIZE`. `PAGE` defaults
    to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]

<a id="x-28RBAC-3ALIST-USER-RESOURCES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-USER-RESOURCES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-USER-RESOURCES** *RBAC USER PERMISSION &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about user resources where the user has `PERMISSION` on the resource. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "s.resource\_name").

<a id="x-28RBAC-3ALIST-USER-ROLE-NAMES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-USER-ROLE-NAMES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-USER-ROLE-NAMES** *RBAC USER &KEY PAGE PAGE-SIZE FILTERS ORDER-BY*

    \[public\] List names of roles associated with `USER`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "role\_name").

<a id="x-28RBAC-3ALIST-USER-ROLES-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-USER-ROLES%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-USER-ROLES** *RBAC USER &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about roles associated with `USER`. Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "role\_name").

<a id="x-28RBAC-3ALIST-USERS-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LIST-USERS%20GENERIC-FUNCTION"></a>

- [generic-function] **LIST-USERS** *RBAC &KEY PAGE PAGE-SIZE FIELDS FILTERS ORDER-BY*

    \[public\] List information about users (all users by default). Pagination is supported via the `PAGE` and `PAGE-SIZE` parameters. `PAGE` defaults to 1 and `PAGE-SIZE` defaults to [`*DEFAULT-PAGE-SIZE*`][df57]. The `FIELDS` parameter, a list of strings, can be used to limit which fields are included in the result. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "user\_name").

<a id="x-28RBAC-3ALOGIN-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:LOGIN%20GENERIC-FUNCTION"></a>

- [generic-function] **LOGIN** *RBAC USER-NAME PASSWORD*

    \[public\] If `USER-NAME` exists and `PASSWORD` is correct,
    update last\_login for `USER-NAME` and return the user ID. Otherwise, return `NIL`.

<a id="x-28RBAC-3APASSWORD-HASH-20FUNCTION-29"></a>
<a id="RBAC:PASSWORD-HASH%20FUNCTION"></a>

- [function] **PASSWORD-HASH** *USER-NAME PASSWORD*

    \[public\] Returns the hash of `PASSWORD`, using `USER-NAME` as the salt. This
    is how `RBAC` stores the password in the database.

<a id="x-28RBAC-3APASSWORD-HASH-20FUNCTION-29"></a>
<a id="RBAC:PASSWORD-HASH%20FUNCTION"></a>

- [function] **PASSWORD-HASH** *USER-NAME PASSWORD*

    \[public\] Returns the hash of `PASSWORD`, using `USER-NAME` as the salt. This
    is how `RBAC` stores the password in the database.

<a id="x-28RBAC-3APERMISSION-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:PERMISSION-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **PERMISSION-COUNT** *RBAC &KEY FILTERS*

    \[public\] Count the number of permissions (all permissions by default). The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3ARBAC-QUERY-20FUNCTION-29"></a>
<a id="RBAC:RBAC-QUERY%20FUNCTION"></a>

- [function] **RBAC-QUERY** *SQL-TEMPLATE-AND-PARAMETERS &OPTIONAL (RESULT-TYPE :PLISTS)*

    \[public\] Converts `SQL-TEMPLATE-AND-PARAMETERS` into a query that returns a
    list of rows, and executes that query. `SQL-TEMPLATE-AND-PARAMETERS` is a list
    where the first element is an `SQL` string (optionally with placeholders) and the
    rest of the elements are values that are used to replace the placeholders in the
    `SQL` string. This function needs to be called inside of a with-rbac block. Each
    row in the result is a plist, where the keys represent the field names.

<a id="x-28RBAC-3ARBAC-QUERY-SINGLE-20FUNCTION-29"></a>
<a id="RBAC:RBAC-QUERY-SINGLE%20FUNCTION"></a>

- [function] **RBAC-QUERY-SINGLE** *SQL-TEMPLATE-AND-PARAMETERS*

    \[public\] Converts `SQL-TEMPLATE-AND-PARAMETERS` into a query that returns a
    single value, and executes that query. `SQL-TEMPLATE-AND-PARAMETERS` is a list
    where the first element is an `SQL` string (optionally with placeholders) and the
    rest of the elements are the values that are used to replace the placeholders in
    the `SQL` string. This function needs to be called inside a with-rbac block.

<a id="x-28RBAC-3AREMOVE-PERMISSION-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:REMOVE-PERMISSION%20GENERIC-FUNCTION"></a>

- [generic-function] **REMOVE-PERMISSION** *RBAC PERMISSION*

    \[public\] Remove `PERMISSION` from the database. Returns the
    ID of the removed permission.

<a id="x-28RBAC-3AREMOVE-RESOURCE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:REMOVE-RESOURCE%20GENERIC-FUNCTION"></a>

- [generic-function] **REMOVE-RESOURCE** *RBAC RESOURCE*

    \[public\] Remove `RESOURCE` from the database. Returns the
    ID of the removed resource.

<a id="x-28RBAC-3AREMOVE-RESOURCE-ROLE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:REMOVE-RESOURCE-ROLE%20GENERIC-FUNCTION"></a>

- [generic-function] **REMOVE-RESOURCE-ROLE** *RBAC RESOURCE ROLE*

    \[public\] Remove a role from a resource. Returns the ID of
    the removed resource role.

<a id="x-28RBAC-3AREMOVE-ROLE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:REMOVE-ROLE%20GENERIC-FUNCTION"></a>

- [generic-function] **REMOVE-ROLE** *RBAC ROLE*

    \[public\] Remove a role from the database. Returns the ID
    of the removed role.

<a id="x-28RBAC-3AREMOVE-ROLE-PERMISSION-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:REMOVE-ROLE-PERMISSION%20GENERIC-FUNCTION"></a>

- [generic-function] **REMOVE-ROLE-PERMISSION** *RBAC ROLE PERMISSION*

    \[public\] Remove a permission from a role. Returns the ID
    of the removed role-permission.

<a id="x-28RBAC-3AREMOVE-ROLE-USER-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:REMOVE-ROLE-USER%20GENERIC-FUNCTION"></a>

- [generic-function] **REMOVE-ROLE-USER** *RBAC ROLE USER*

    \[public\] Remove a user from a role. Returns the ID of the
    removed role user.

<a id="x-28RBAC-3AREMOVE-USER-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:REMOVE-USER%20GENERIC-FUNCTION"></a>

- [generic-function] **REMOVE-USER** *RBAC USER-NAME*

    \[public\] Remove `USER-NAME` from the database.

<a id="x-28RBAC-3AREMOVE-USER-ROLE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:REMOVE-USER-ROLE%20GENERIC-FUNCTION"></a>

- [generic-function] **REMOVE-USER-ROLE** *RBAC USER ROLE*

    \[public\] Remove a role from a user. Returns the ID of the removed
    user role.

<a id="x-28RBAC-3ARESOURCE-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:RESOURCE-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **RESOURCE-COUNT** *RBAC &KEY FILTERS*

    \[public\] Count the number of resources (all resources by default). The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3ARESOURCE-ROLE-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:RESOURCE-ROLE-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **RESOURCE-ROLE-COUNT** *RBAC RESOURCE &KEY FILTERS*

    \[public\] Count the number of roles associated with `RESOURCE`. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be one of =, \<>, \<, >, \<=, >=, is, is not, like, ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3ARESOURCE-USER-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:RESOURCE-USER-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **RESOURCE-USER-COUNT** *RBAC RESOURCE PERMISSION &KEY FILTERS*

    \[public\] Count the number of resource users where the user has `PERMISSION` on the resource. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be one of =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "u.user\_name").

<a id="x-28RBAC-3AROLE-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ROLE-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **ROLE-COUNT** *RBAC &KEY FILTERS*

    \[public\] Count the number of roles (all roles by default). The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3AROLE-PERMISSION-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ROLE-PERMISSION-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **ROLE-PERMISSION-COUNT** *RBAC ROLE &KEY FILTERS*

    \[public\] Count the number of permissions associated with `ROLE`. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be one of =, \<>, \<, >, \<=, >=, is, is not, like, ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3AROLE-RESOURCE-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ROLE-RESOURCE-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **ROLE-RESOURCE-COUNT** *RBAC ROLE &KEY FILTERS*

    \[public\] Count the number of resources associated with `ROLE`. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be one of =, \<>, \<, >, \<=, >=, is, is not, like, ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3AROLE-USER-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ROLE-USER-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **ROLE-USER-COUNT** *RBAC ROLE &KEY FILTERS*

    \[public\] Count the number of users associated with `ROLE`. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be one of =, \<>, \<, >, \<=, >=, is, is not, like, ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3AUSER-ALLOWED-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:USER-ALLOWED%20GENERIC-FUNCTION"></a>

- [generic-function] **USER-ALLOWED** *RBAC USER-NAME PERMISSION RESOURCE*

    \[public\] Returns `T` if `USER-NAME` has `PERMISSION` on
    `RESOURCE`, `NIL` otherwise. Note that this permission may exist via more than one
    role.

<a id="x-28RBAC-3AUSER-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:USER-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **USER-COUNT** *RBAC &KEY FILTERS*

    \[public\] Count the number of users (all users by default). The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3AUSER-HAS-ROLE-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:USER-HAS-ROLE%20GENERIC-FUNCTION"></a>

- [generic-function] **USER-HAS-ROLE** *RBAC USER-NAME &REST ROLE*

    \[public\] Returns `T` if `USER-NAME` has any of the specified
    `ROLE`(s).

<a id="x-28RBAC-3AUSER-RESOURCE-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:USER-RESOURCE-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **USER-RESOURCE-COUNT** *RBAC USER PERMISSION &KEY FILTERS*

    \[public\] Count the number of user resources where the user has `PERMISSION` on the resource. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be one of =, \<>, \<, >, \<=, >=, is, is not, like, or ilike. Value is a string, number, :null, :true, or :false. The `ORDER-BY` parameter is a list of strings that represent field names and are used to order the results. It defaults to (list "s.resource\_name").

<a id="x-28RBAC-3AUSER-ROLE-COUNT-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:USER-ROLE-COUNT%20GENERIC-FUNCTION"></a>

- [generic-function] **USER-ROLE-COUNT** *RBAC USER &KEY FILTERS*

    \[public\] Count the number of roles associated with `USER`. The `FILTERS` parameter can be used to filter the results. It consists of a list of filters, where each filter is a list of three elements: field name, operator, and value. Operator, a string, can be one of =, \<>, \<, >, \<=, >=, is, is not, like, ilike. Value is a string, number, :null, :true, or :false.

<a id="x-28RBAC-3AVALID-DESCRIPTION-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:VALID-DESCRIPTION-P%20GENERIC-FUNCTION"></a>

- [generic-function] **VALID-DESCRIPTION-P** *RBAC DESCRIPTION*

    \[public\] Validates new `DESCRIPTION` string.

<a id="x-28RBAC-3AVALID-EMAIL-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:VALID-EMAIL-P%20GENERIC-FUNCTION"></a>

- [generic-function] **VALID-EMAIL-P** *RBAC EMAIL*

    \[public\] Validates new `EMAIL` string. The string must
    look like an email address, with a proper domain name, and it must have a length
    that doesn't exceed 128 characters.

<a id="x-28RBAC-3AVALID-PASSWORD-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:VALID-PASSWORD-P%20GENERIC-FUNCTION"></a>

- [generic-function] **VALID-PASSWORD-P** *RBAC PASSWORD*

    \[public\] Validates new `PASSWORD` string.
    `PASSWORD` must have
    - at least password-length-min characters
    - at least one letter
    - at least one digit
    - at least one common punctuation character
    - at most password-length-max characters

<a id="x-28RBAC-3AVALID-PERMISSION-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:VALID-PERMISSION-P%20GENERIC-FUNCTION"></a>

- [generic-function] **VALID-PERMISSION-P** *RBAC PERMISSION*

    \[public\] Validates new `PERMISSION` string.
    PMERISSION must:
    - start with a letter
    - consist of letters, digits, and hyphens
    - optionally have a colon that is not at the beginning or the end
    - contain at most permission-length-max characters

<a id="x-28RBAC-3AVALID-RESOURCE-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:VALID-RESOURCE-P%20GENERIC-FUNCTION"></a>

- [generic-function] **VALID-RESOURCE-P** *RBAC RESOURCE*

    \[public\] Validates new `RESOURCE` string.

<a id="x-28RBAC-3AVALID-ROLE-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:VALID-ROLE-P%20GENERIC-FUNCTION"></a>

- [generic-function] **VALID-ROLE-P** *RBAC ROLE*

    \[public\] Validates new `ROLE` string.
    `ROLE` must:
    - start with a letter
    - consist of letters, digits, and hyphens
    - have at most role-length-max characters
    - optionally have a colon that is not at the beginning or the end

<a id="x-28RBAC-3AVALID-USER-NAME-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:VALID-USER-NAME-P%20GENERIC-FUNCTION"></a>

- [generic-function] **VALID-USER-NAME-P** *RBAC USER-NAME*

    \[public\] Validates new USERNANME string.
    `USER-NAME` must:
    - Have at least 1 character
    - Have at most user-name-length-max characters
    - Start with a letter
    - Contain only ASCII characters for
      - letters (any case)
      - digits
      - underscores
      - dashes
      - periods
      - plus sign (+)

<a id="x-28RBAC-3A-40RBAC-VARIABLES-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-VARIABLES%20MGL-PAX:SECTION"></a>

## 4 Special Variables

Exported special variables.

<a id="x-28RBAC-3A-2AADMIN-2A-20VARIABLE-29"></a>
<a id="RBAC:*ADMIN*%20VARIABLE"></a>

- [variable] **\*ADMIN\*** *"admin"*

    \[public\] Administrator user name.

<a id="x-28RBAC-3A-2AGUEST-2A-20VARIABLE-29"></a>
<a id="RBAC:*GUEST*%20VARIABLE"></a>

- [variable] **\*GUEST\*** *"guest"*

    \[public\] Guest user name.

<a id="x-28RBAC-3A-2ADEFAULT-PAGE-SIZE-2A-20VARIABLE-29"></a>
<a id="RBAC:*DEFAULT-PAGE-SIZE*%20VARIABLE"></a>

- [variable] **\*DEFAULT-PAGE-SIZE\*** *1000*

    \[public\] Default page size. Used in functions that accept a :page-size
    parameter when the parameter is not specified.

<a id="x-28RBAC-3A-2ADEFAULT-PERMISSIONS-2A-20VARIABLE-29"></a>
<a id="RBAC:*DEFAULT-PERMISSIONS*%20VARIABLE"></a>

- [variable] **\*DEFAULT-PERMISSIONS\*** *("create" "delete" "read" "update")*

    \[public\] Default permissions for a new role when no value is provided for
    the :roles parameter

<a id="x-28RBAC-3A-2ADEFAULT-RESOURCE-ROLES-2A-20VARIABLE-29"></a>
<a id="RBAC:*DEFAULT-RESOURCE-ROLES*%20VARIABLE"></a>

- [variable] **\*DEFAULT-RESOURCE-ROLES\*** *("admin")*

    \[public\] A list of roles to be used when a resource is created without
    specifying a value for the :roles parameter.

<a id="x-28RBAC-3A-2ADEFAULT-USER-ROLES-2A-20VARIABLE-29"></a>
<a id="RBAC:*DEFAULT-USER-ROLES*%20VARIABLE"></a>

- [variable] **\*DEFAULT-USER-ROLES\*** *("logged-in" "public")*

    \[public\] A list of roles to be used when a user is first created. These
    roles are appended to whatever the caller specifies for the :roles parameter.

<a id="x-28RBAC-3A-40RBAC-MACROS-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-MACROS%20MGL-PAX:SECTION"></a>

## 5 Macros

Exported macros.

<a id="x-28RBAC-3AWITH-RBAC-20MGL-PAX-3AMACRO-29"></a>
<a id="RBAC:WITH-RBAC%20MGL-PAX:MACRO"></a>

- [macro] **WITH-RBAC** *(RBAC) &BODY BODY*

    \[public\] Opens a connection (pooled) to the rbac database to execute
    `BODY`. There's no global connection, so this macro must be used wherever a
    connection is needed. The connection is closed after `BODY` is executed.

  [5ba5]: #RBAC:RBAC-PG%20CLASS "RBAC:RBAC-PG CLASS"
  [7829]: #RBAC:@RBAC-VARIABLES%20MGL-PAX:SECTION "Special Variables"
  [7b8a]: #RBAC:@RBAC-PG-CLASS%20MGL-PAX:SECTION "`RBAC-PG` Class"
  [94ab]: #RBAC:@RBAC-FUNCTIONS%20MGL-PAX:SECTION "Functions"
  [967f]: #RBAC:@RBAC-EXAMPLES%20MGL-PAX:SECTION "Examples"
  [ac36]: #RBAC:EXCLUSIVE-ROLE-FOR%20FUNCTION "RBAC:EXCLUSIVE-ROLE-FOR FUNCTION"
  [c729]: #RBAC:*DEFAULT-PERMISSIONS*%20VARIABLE "RBAC:*DEFAULT-PERMISSIONS* VARIABLE"
  [d0c7]: #RBAC:@RBAC-MACROS%20MGL-PAX:SECTION "Macros"
  [df57]: #RBAC:*DEFAULT-PAGE-SIZE*%20VARIABLE "RBAC:*DEFAULT-PAGE-SIZE* VARIABLE"
  [e768]: #RBAC:ADD-USER%20GENERIC-FUNCTION "RBAC:ADD-USER GENERIC-FUNCTION"
