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
