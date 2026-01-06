(in-package :rbac)

(defsection @rbac-manual
  (:title "RBAC System Reference Manual")
  "This is a simple Role-Based Access Control (RBAC) system implemented in Common Lisp. It provides an `rbac-pg` class, together with accessors, methods, and functions for managing users, roles, permissions, and resources.

## Overview
This library provides functions and initial SQL for supporting Role-Based Access Control.

The system provides users, roles, permissions, and resources. Users have roles. Roles have permissions. Resources also have roles. However, resources do not have users. To determine if user 'adam' has 'read' access to resource 'book', the user and the book must both have the same role and the role must have the 'read' permission.

A role can be exclusive, which means that it can be associated with only one user. Whenever a user is created, with the d-add-user or add-user function, the library creates the user's exclusive role. The user's exclusive role is also removed when the user is removed. Thus, the exclusive role represents that single user only, and represents only that user when associated with a resource. In this way, it's possible to give a specific user access to the resource.

All new users are created with default roles: 'logged-in', 'public', and the exclusive role for that user. If a resource has the 'logged-in' role, then every logged-in user has access to the resource. If a resource has the 'public' role, then all users, including the guest user (not logged in), have access to the resource. The 'public' and 'logged-in' roles have 'read' permission.

Unless you specify specific permissions when creating a new role, it's permission default to 'create', 'read', 'updated', and 'delete'. These are general, default permissions, but you can add any permission you like to the system.

All new resources are created with the default roles 'system'. The 'system' role should never be assigned to a user.

## Installation
### Roswell

You'll need to install some dependencies first:
```sh
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
```

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
See the API reference below for details."

  (@rbac-classes section)
  (@rbac-accessors-and-methods section)
  (@rbac-functions section)
  ;; (@rbac-macros section)
  (@rbac-examples section))

(defsection @rbac-classes
  (:title "Classes")
  "Core classes for the RBAC system."
  (rbac class)
  (rbac-pg class))

(defsection @rbac-accessors-and-methods
  (:title "Accessors and Methods")
  "Accessors and methods for manipulating RBAC objects."
  (resource-regex (accessor rbac))
  (resource-length-max (accessor rbac))
  (user-name-length-max (accessor rbac))
  (user-name-regex (accessor rbac))
  (id-exists-p function)
  (valid-user-name-p function))

(defsection @rbac-functions
  (:title "Functions")
  "Exported support functions."
  (usql function)
  (plural function)
  (password-hash function))

(defsection @rbac-macros
  (:title "Macros")
  "Exported macros."
  (with-rbac macro)
  (rbac-query-single macro))

(defsection @rbac-examples
  (:title "Examples")
  "Usage examples.

```lisp
(add-permission *rbac* \"bogus-permission\")
(add-role *rbac* \"role-a\" :permissions '(\"read\"))
(add-role *rbac* \"role-b\")
(add-role *rbac* \"role-c\"
  :permissions (cons \"bogus-permission\" *default-permissions*))
(add-role *rbac* \"role-d\"
  :permissions '(\"bogus-permission\"))
(add-user *rbac* \"user-1\" \"user-1@example.com\" \"password-01\" :roles roles)
(add-resource *rbac* \"test:resource-1\" :roles \"public\")
(list-user-names *rbac*)
(list-permission-names *rbac*)
(list-user-role-names *rbac* \"user-1\")
(list-user-resource-permission-names *rbac* \"user-1\" \"test:resource-1\")
(user-allowed *rbac* \"user-1\" \"read\" \"test:resource-1\")
```
")

(defun generate-readme ()
  (with-open-file (stream "README.md"
                    :direction :output :if-exists :supersede)
    (document @rbac-manual :format :markdown :stream stream)))
