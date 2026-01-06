<a id="x-28RBAC-3A-40RBAC-MANUAL-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-MANUAL%20MGL-PAX:SECTION"></a>

# `RBAC` System Reference Manual

## Table of Contents

- [1 Classes][bd0a]
- [2 Accessors and Methods][943e]
- [3 Functions][94ab]
- [4 Examples][967f]

###### \[in package RBAC\]
This is a simple Role-Based Access Control ([`RBAC`][898b]) system implemented in Common Lisp. It provides an [`rbac-pg`][5ba5] class, together with accessors, methods, and functions for managing users, roles, permissions, and resources.

## Overview

This library provides functions and initial `SQL` for supporting Role-Based Access Control.

The system provides users, roles, permissions, and resources. Users have roles. Roles have permissions. Resources also have roles. However, resources do not have users. To determine if user 'adam' has 'read' access to resource 'book', the user and the book must both have the same role and the role must have the 'read' permission.

A role can be exclusive, which means that it can be associated with only one user. Whenever a user is created, with the d-add-user or add-user function, the library creates the user's exclusive role. The user's exclusive role is also removed when the user is removed. Thus, the exclusive role represents that single user only, and represents only that user when associated with a resource. In this way, it's possible to give a specific user access to the resource.

All new users are created with default roles: 'logged-in', 'public', and the exclusive role for that user. If a resource has the 'logged-in' role, then every logged-in user has access to the resource. If a resource has the 'public' role, then all users, including the guest user (not logged in), have access to the resource. The 'public' and 'logged-in' roles have 'read' permission.

Unless you specify specific permissions when creating a new role, it's permission default to 'create', 'read', 'updated', and 'delete'. These are general, default permissions, but you can add any permission you like to the system.

All new resources are created with the default roles 'system'. The 'system' role should never be assigned to a user.

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
`ros install macnod/rbac/v0.2`

### GitHub

Clone the repo to a directory that Quicklisp or ASDF can see, such as ~/common-lisp. For example:

```sh
cd ~/common-lisp
git clone git@github.com:macnod/rbac.git
cd rbac
```

Then, install the dependencies in a similar fashion.

### Quicklisp

Clone the repo to a directory that Quicklisp or ASDF can see, such as ~/common-lisp. For example:

```sh
cd ~/common-lisp
git clone git@github.com:macnod/rbac.git
cd rbac
```

Then, Quicklisp will take care of installing any additional dependencies.

## Usage

See the API reference below for details.

<a id="x-28RBAC-3A-40RBAC-CLASSES-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-CLASSES%20MGL-PAX:SECTION"></a>

## 1 Classes

Core classes for the [`RBAC`][898b] system.

<a id="x-28RBAC-3ARBAC-20CLASS-29"></a>
<a id="RBAC:RBAC%20CLASS"></a>

- [class] **RBAC**

    Abstract base class for user database.

<a id="x-28RBAC-3ARBAC-PG-20CLASS-29"></a>
<a id="RBAC:RBAC-PG%20CLASS"></a>

- [class] **RBAC-PG** *[RBAC][898b]*

    [`RBAC`][898b] database class for PostgreSQL.

<a id="x-28RBAC-3A-40RBAC-ACCESSORS-AND-METHODS-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-ACCESSORS-AND-METHODS%20MGL-PAX:SECTION"></a>

## 2 Accessors and Methods

Accessors and methods for manipulating [`RBAC`][898b] objects.

<a id="x-28RBAC-3ARESOURCE-REGEX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:RESOURCE-REGEX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **RESOURCE-REGEX** *RBAC (:RESOURCE-REGEX = "^\[a-zA-Z\]\[-a-zA-Z0-9\]\*:?\[a-zA-Z0-9\]\[-a-zA-Z0-9\]\*$")*

    Defaults to an absolute directory path string that ends with a /

<a id="x-28RBAC-3ARESOURCE-LENGTH-MAX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:RESOURCE-LENGTH-MAX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **RESOURCE-LENGTH-MAX** *RBAC (:RESOURCE-LENGTH-MAX = 512)*

    Maximum length of resource name string.

<a id="x-28RBAC-3AUSER-NAME-LENGTH-MAX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:USER-NAME-LENGTH-MAX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **USER-NAME-LENGTH-MAX** *RBAC (:USER-NAME-LENGTH-MAX = 64)*

    Maximum length of user name string.

<a id="x-28RBAC-3AUSER-NAME-REGEX-20-28MGL-PAX-3AACCESSOR-20RBAC-3ARBAC-29-29"></a>
<a id="RBAC:USER-NAME-REGEX%20%28MGL-PAX:ACCESSOR%20RBAC:RBAC%29"></a>

- [accessor] **USER-NAME-REGEX** *RBAC (:USER-NAME-REGEX = "^\[a-zA-Z\]\[-a-zA-Z0-9\_.+\]\*$")*

    Regex for validating user name strings.

<a id="x-28RBAC-3AID-EXISTS-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:ID-EXISTS-P%20GENERIC-FUNCTION"></a>

- [generic-function] **ID-EXISTS-P** *RBAC TABLE ID*

    Returns `T` when `ID` exists in `TABLE`.

<a id="x-28RBAC-3AVALID-USER-NAME-P-20GENERIC-FUNCTION-29"></a>
<a id="RBAC:VALID-USER-NAME-P%20GENERIC-FUNCTION"></a>

- [generic-function] **VALID-USER-NAME-P** *RBAC USER-NAME*

    Validates new USERNANME string.
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

<a id="x-28RBAC-3A-40RBAC-FUNCTIONS-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-FUNCTIONS%20MGL-PAX:SECTION"></a>

## 3 Functions

Exported support functions.

<a id="x-28RBAC-3AUSQL-20FUNCTION-29"></a>
<a id="RBAC:USQL%20FUNCTION"></a>

- [function] **USQL** *SQL*

    Converts `SQL` into a one-line string, removing extra spaces and newlines.
    This does not work correctly if `SQL` contains quoted field names or values that
    include multiple consecutive whitespace characters.

<a id="x-28RBAC-3APLURAL-20FUNCTION-29"></a>
<a id="RBAC:PLURAL%20FUNCTION"></a>

- [function] **PLURAL** *STRING*

    Adds 's' to `STRING`, unless `STRING` already ends with 's'.

<a id="x-28RBAC-3APASSWORD-HASH-20FUNCTION-29"></a>
<a id="RBAC:PASSWORD-HASH%20FUNCTION"></a>

- [function] **PASSWORD-HASH** *USER-NAME PASSWORD*

    Returns the hash of `PASSWORD`, using `USER-NAME` as the salt. This is how [`RBAC`][898b]
    stores the password in the database.

<a id="x-28RBAC-3A-40RBAC-EXAMPLES-20MGL-PAX-3ASECTION-29"></a>
<a id="RBAC:@RBAC-EXAMPLES%20MGL-PAX:SECTION"></a>

## 4 Examples

Usage examples.

```lisp
(add-permission *rbac* "bogus-permission")
(add-role *rbac* "role-a" :permissions '("read"))
(add-role *rbac* "role-b")
(add-role *rbac* "role-c"
  :permissions (cons "bogus-permission" *default-permissions*))
(add-role *rbac* "role-d"
  :permissions '("bogus-permission"))
(add-user *rbac* "user-1" "user-1@example.com" "password-01" :roles roles)
(add-resource *rbac* "test:resource-1" :roles "public")
(list-user-names *rbac*)
(list-permission-names *rbac*)
(list-user-role-names *rbac* "user-1")
(list-user-resource-permission-names *rbac* "user-1" "test:resource-1")
(user-allowed *rbac* "user-1" "read" "test:resource-1")
```


  [5ba5]: #RBAC:RBAC-PG%20CLASS "RBAC:RBAC-PG CLASS"
  [898b]: #RBAC:RBAC%20CLASS "RBAC:RBAC CLASS"
  [943e]: #RBAC:@RBAC-ACCESSORS-AND-METHODS%20MGL-PAX:SECTION "Accessors and Methods"
  [94ab]: #RBAC:@RBAC-FUNCTIONS%20MGL-PAX:SECTION "Functions"
  [967f]: #RBAC:@RBAC-EXAMPLES%20MGL-PAX:SECTION "Examples"
  [bd0a]: #RBAC:@RBAC-CLASSES%20MGL-PAX:SECTION "Classes"
