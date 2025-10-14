;; Change 2

(in-package :cl-user)

(require :prove)
(require :cl-ppcre)
(require :dc-eclectic)
(require :dc-ds)
(require :postmodern)

(defparameter *host* nil)
(defparameter *port* nil)

(defun directory-exists-p (directory)
  "Check if the directory exists."
  (let ((path (probe-file directory)))
    (and path (uiop:directory-pathname-p path))))

(if (directory-exists-p "/rbac")
  (progn
    (pushnew (truename "/rbac/") asdf:*central-registry* :test #'equal)
    (setf 
      *host* "pgtest"
      *port* 5432))
  (progn
    (pushnew (truename ".") asdf:*central-registry* :test #'equal)
    (setf
      *host* "127.0.0.1"
      *port* 5433)))

(asdf:load-system :rbac)

(defpackage :test-database
  (:use :cl :prove)
  (:local-nicknames
    (:a :rbac)
    (:re :cl-ppcre)
    (:u :dc-eclectic)
    (:ds :dc-ds)
    (:db :postmodern)))
(in-package :test-database)

(setf prove:*enable-colors* t)
(u:open-log "/logs/rbac.log" :severity-threshold :debug :append nil)

(defparameter *rbac* (make-instance 'a:rbac-pg
                       :host cl-user::*host*
                       :port cl-user::*port*
                       :password "cl-user-password"))
(defparameter *admin-id* nil)
(defparameter *admin-email* "no-email")
(defparameter *system-id* (a:get-id *rbac* "users" "system"))
(defparameter *create-id* (a:get-id *rbac* "permissions" "create"))
(defparameter *delete-id* (a:get-id *rbac* "permissions" "delete"))
(defparameter *read-id* (a:get-id *rbac* "permissions" "read"))
(defparameter *admin-role-id* (a:get-id *rbac* "roles" "admin"))
(defparameter *editor-role-id* (a:get-id *rbac* "roles" "editor"))
(defparameter *roles* (list "admin" "admin:exclusive" "editor" "guest"
                        "logged-in" "system" "system:exclusive"))
(defparameter *permissions* (list "create" "delete" "read" "update"))
(defparameter *uuid-regex* "^[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$")

(defun bogus-email-address (user)
  "Return a fake email address for the user"
  (format nil "~a@invalid-domain.com" user))

(plan 34)

(subtest "next-placeholder"
  (is (a:sql-next-placeholder "select ... where c = $1") 2
    "select ... where c = $1 => 2")
  (is (a:sql-next-placeholder "select ... where c = $1 and d = $2") 3
    "select ... where c = $1 and d = $2 => 3")
  (is (a:sql-next-placeholder "select ... where c = $2 and d = $1") 3
    "select ... where c = $2 and d = $1 => 3")
  (is (a:sql-next-placeholder "select ... where c = 1 and d = 2") 1
    "select ... where c = 1 and d = 2 => 1")
  (is (a:sql-next-placeholder "$5") 6
    "$5 => 6")
  (is (a:sql-next-placeholder "") 1
    "(empty string) => 1")
  (is (a:sql-next-placeholder nil) 1
    "NIL => 1"))

(subtest "with-rbac"
  (a:with-rbac (*rbac*)
    (db:query "delete from users where username like 'test-user-%'")
    (db:query "delete from permissions
               where permission_name like 'test-permission%'")
    (db:query "delete from roles
               where role_name = 'test-role'
                 or role_name like 'test-user-%:exclusive'")
    (db:query "delete from resources
               where resource_name like 'test-resource%'")
    (is (db:query "select count(*) from users" :single) 1
      "with-rbac with simple query")))

(subtest "some-database-entries"
  ;; Add admin role
  (ok (setf *admin-role-id* (a:d-add-role *rbac* "admin")) "Add admin role")
  (ok (member "admin" (a:list-role-names *rbac*) :test 'equal)
    "New admin role exists")

  ;; Add editor role
  (like (setf *editor-role-id* 
          (a:d-add-role *rbac* "editor" :permissions '("read" "update")))
    *uuid-regex*
    "Add new editor role.")

  ;; Add admin user
  (like 
    (setf *admin-id* 
      (a:d-add-user *rbac* "admin" "weasel-1234" :roles '("admin")))
    *uuid-regex*
    "Add admin user with new admin role")

  ;; Check that admin user has new admin role
  (ok (member "admin" (a:list-user-role-names *rbac* "admin") :test 'equal)
    "User admin has role admin"))

(subtest "check"
  (let* (errors
          (x (a:check errors "x" "x failed")))
    (ok (null (a::report-errors errors))
      "no error for condition 'x'")
    (let ((y (a:check errors (equal x "y") "y failed."))
           (z (a:check errors (equal x "z") "z failed.")))
      (ok (null y) "y remains null for (equal x 'y')")
      (ok (null z) "z remains null for (equal x 'z')")
      (is-error (a::report-errors errors) 'simple-error
        "check (equal x 'y') and (equal x 'z') failed")
      (handler-case (a::report-errors errors)
        (error (e)
          (is (format nil "~a" e) "Errors: y failed. z failed."))
        (t (e)
          (fail (format nil "Unexpected error condition: ~a" e)))))))

(subtest "rbac-query-single"
  (a:with-rbac (*rbac*)
    (is (a:rbac-query-single (list "select count(*) from users")) 2
      "User count (no parameters)")
    (like (a:rbac-query-single
            (list "select id from users where username = $1" "admin"))
      *uuid-regex*
      "User ID (username parameter)")
    (like (a:rbac-query-single
          (list "select id from users where username = $1 and email = $2"
            "admin"
            *admin-email*))
      *uuid-regex*
      "User ID (username and email parameters")))

(subtest "rbac-query"
  (a:with-rbac (*rbac*)
    (is (a:rbac-query
          (list "select username from users order by username"))
      '((:username "admin") (:username "system"))
      "Usernames (no parameters)")
    (is (a:rbac-query
          (list "select username from users
                 where length(username) = $1
                 order by username"
            5))
      '((:username "admin"))
      "Usernames (1 parameter)")))

(subtest "usql"
  (is (a:usql "select
                 t1.field1,
                 t2.field2,
                 t3.field3
               from
                 table1 t1
                   join table2 t2 on t1.table2_id = t2.id
                   join table3 t3 on t1.table3_id = t3.id
               where
                 t1 = 4
                 and t2 = 2
               order by t1
               offset 10
               limit 20")
    (format nil "~{~a~^ ~}"
      (list
        "select t1.field1, t2.field2, t3.field3"
        "from table1 t1"
        "join table2 t2 on t1.table2_id = t2.id"
        "join table3 t3 on t1.table3_id = t3.id"
        "where t1 = 4 and t2 = 2"
        "order by t1 offset 10 limit 20"))
    "usql test 1"))

(subtest "classes"
  (let ((rbac (make-instance 'a:rbac))
         (rbac-pg (make-instance 'a:rbac-pg :password "password")))
    (is (type-of rbac) 'a:rbac "Base class instance has type 'rbac")
    (is (type-of rbac-pg) 'a:rbac-pg
      "Postgres rbac class instance has type 'rbac-pg")
    (is (a:username rbac-pg) "cl-user" "rbac-pg username is correct")
    (is (a:password rbac-pg) "password" "rbac-pg password is correct")
    (is (a:host rbac-pg) "postgres" "rbac-pg host is correct")
    (is (a:port rbac-pg) 5432 "rbac-pg port is correct")))

(subtest "to-hash-table"
  (is (ds:human
        (a:to-hash-table *rbac*
          '(("first" . "Jane") ("last" . "Doe") ("age" . 50))))
    (ds:human
      (ds:ds `(:map "first" "Jane" "last" "Doe" "age" 50)))
    "3-field str-alist converts to hash table")
  (is (ds:human (a:to-hash-table *rbac* nil))
    (ds:human (make-hash-table))
    "Empty result returns an empty hash table"))

(subtest "to-hash-tables"
  (is (ds:human
        (a:to-hash-tables *rbac*
          (a:with-rbac (*rbac*)
            (db:query "select permission_name, id
                       from permissions
                       order by permission_name
                       limit 2"
              :str-alists))))
    (ds:human (ds:ds `(:list
                        (:map "permission_name" "create"
                          "id" ,*create-id*)
                        (:map "permission_name" "delete"
                          "id" ,*delete-id*))))
    "to-hash-tables converts :str-alists result into a hash table"))

(subtest "sql-for-list"
  (is (a:sql-for-list
        *rbac*
        (list "a.fielda" "b.fieldb" "c.fieldc")
        "tablea a
           join tableb b on a.tableb_id b.id
           join tablec c on a.tablec_id c.id"
        (list "a.fielda = $1" "a.fieldb = $2")
        (list "one" "two")
        nil
        1
        10)
    (list
      (format nil "~{~a~^ ~}"
        (list
          "select a.fielda, b.fieldb, c.fieldc"
          "from tablea a join tableb b on a.tableb_id b.id"
          "join tablec c on a.tablec_id c.id"
          "where a.deleted_at is null"
          "and a.fielda = $1 and a.fieldb = $2"
          "offset 0 limit 10"))
      "one" "two")
    "Joined tables, values, no order-by-fields")
  (is (a:sql-for-list
        *rbac*
        (list "fielda" "fieldb" "fieldc")
        "tablea"
        (list "fielda = $1" "fieldb = $2")
        (list "one" "two")
        nil
        1
        10)
    (list
      (format nil "~{~a~^ ~}"
        (list
          "select fielda, fieldb, fieldc from tablea"
          "where deleted_at is null"
          "and fielda = $1 and fieldb = $2"
          "offset 0 limit 10"))
      "one" "two")
    "Single table, values, no order-by-fields")
  (is (a:sql-for-list
        *rbac*
        (list "fielda" "fieldb" "fieldc")
        "tablea"
        (list "fielda = $1" "fieldb = $2")
        (list "one" "two")
        (list "fielda" "fieldb desc")
        1
        10)
    (list
      (format nil "~{~a~^ ~}"
        (list
          "select fielda, fieldb, fieldc from tablea"
          "where deleted_at is null"
          "and fielda = $1 and fieldb = $2"
          "order by fielda, fieldb desc"
          "offset 0 limit 10"))
      "one" "two")
    "Single table, values, order-by-fields"))

(subtest "list-rows"
  (is (a:list-rows
        *rbac*
        (list "username" "id")
        "users"
        nil
        nil
        (list "username")
        1
        1)
    (list (list :username "admin" :id *admin-id*))
    "list-rows with single table, no where clause, no values, 1 row")
  (is (a:list-rows
        *rbac*
        (list "r.role_name" "p.permission_name")
        "users u
           join role_users ru on ru.user_id = u.id
           join roles r on ru.role_id = r.id
           join role_permissions rp on rp.role_id = r.id
           join permissions p on rp.permission_id = p.id"
        (list "u.username = $1")
        (list "admin")
        (list "r.role_name" "p.permission_name")
        1
        10)
    '((:ROLE-NAME "admin" :PERMISSION-NAME "create")
       (:ROLE-NAME "admin" :PERMISSION-NAME "delete")
       (:ROLE-NAME "admin" :PERMISSION-NAME "read")
       (:ROLE-NAME "admin" :PERMISSION-NAME "update")
       (:ROLE-NAME "admin:exclusive" :PERMISSION-NAME "create")
       (:ROLE-NAME "admin:exclusive" :PERMISSION-NAME "delete")
       (:ROLE-NAME "admin:exclusive" :PERMISSION-NAME "read")
       (:ROLE-NAME "admin:exclusive" :PERMISSION-NAME "update"))
    "List-rows with 4 table joins, a where clause, and a value"))

(subtest "upsert-link-sql"
  (is (a::upsert-link-sql "roles" "permissions")
    (a::usql 
      (format nil "~{~a~^ ~}"
        (list
          "insert into role_permissions (role_id, permission_id, updated_by)"
          "values ($1, $2, $3)"
          "on conflict (role_id, permission_id)"
          "do"
          "  update set"
          "    updated_by = $3,"
          "    updated_at = now(),"
          "    deleted_at = null"
          "returning id")))
    "upsert-link-sql works as expected"))

(subtest "username validation"
  (loop
    with valid-usernames = (list
                             "macnod"
                             "macnod1"
                             "m1234d"
                             "m12345"
                             (make-string (a:username-length-max *rbac*)
                               :initial-element #\a))
    for username in valid-usernames
    for message = (if (= (length username) (a:username-length-max *rbac*))
                    (format nil "a username with ~d characters is valid"
                      (a:username-length-max *rbac*))
                    (format nil "~s is valid" username))
    do (ok (a:valid-username-p *rbac* username) message))
  (loop
    with invalid-usernames = (list
                               "1macnod"
                               "12345"
                               ""
                               "mac┼nod"
                               (make-string 
                                 (1+ (a:username-length-max *rbac*))
                                 :initial-element #\a))
    for username in invalid-usernames
    for message = (if (> (length username) (a:username-length-max *rbac*))
                    (format nil 
                      "a username longer than ~d characters is not valid"
                      (a:username-length-max *rbac*))
                    (format nil "~s is not valid" username))
    do (ok (not (a:valid-username-p *rbac* username)) message)))

(subtest "password validation"
  (loop
    with valid-passwords = (list
                             "1!abcd"
                             "123-5a"
                             "pass1!"
                             "@@@@9z"
                             "h1vxTwuq!x"
                             "--~0Tc"
                             "-wUi^DT6VMe&u.f9D}hC[<*=^v1oOz&Q-:LU'SgPlc9(xSorY~&ul2&[z`E(|b}P")
    for password in valid-passwords
    for message = (format nil "~s is valid" password)
    do (ok (a:valid-password-p *rbac* password) message))
  (loop
    with invalid-passwords = (list
                               "password"
                               "123456"
                               ""
                               "z1y2!"
                               "abc123"
                               "123!@#"
                               ")(*xyz"
                               (format nil "~a~a"
                                 "heav3^-" 
                                 (make-string (- (a:password-length-max *rbac*) 6)
                                   :initial-element #\z)))
    for password in invalid-passwords
    for message = (if (> (length password) (a:password-length-max *rbac*))
                    (format nil "a password longer than ~d characters is not valid"
                      (a:password-length-max *rbac*))
                    (format nil "~s is not valid" password))
    do (ok (not (a:valid-password-p *rbac* password)) message)))

(subtest "email validation"
  (loop
    with valid-emails = (list
                          "abc@example.com"
                          "abc_def@one-two.com"
                          "abc.def@example-x.com"
                          "no-email"
                          (format nil "~a@domain.com"
                            (make-string 
                              (- (a:email-length-max *rbac*) 11)
                              :initial-element #\e)))
    for email in valid-emails
    for message = (if (= (length email) (a:email-length-max *rbac*))
                    "a proper email address can have length of up to 128 characters"
                    (format nil "~s is valid" email))
    do (ok (a:valid-email-p *rbac* email) message))
  (loop
    with invalid-emails = (list
                            "hello@one"
                            "@macnod"
                            "user"
                            ""
                            (format nil "~a@domain.com"
                              (make-string 
                                (- (a:email-length-max *rbac*) 10)
                                :initial-element #\f)))
    for email in invalid-emails
    for message = (if (> (length email) (a:email-length-max *rbac*))
                    (format nil 
                      "an email address longer than ~d characters is not valid"
                      (a:email-length-max *rbac*))
                    (format nil "~s is not valid" email))
    do (ok (not (a:valid-email-p *rbac* email)) message)))

(subtest "role validation"
  (loop
    with valid-roles = (list
                         "a1"
                         "a1b2"
                         "a.b"
                         "a.b.c"
                         "a-b-c"
                         "a.b_c"
                         "a1:bc"
                         "a-b-c:def"
                         "a+b"
                         "a.123"
                         "bac+def"
                         "a:b"
                         "a:bcde"
                         "abcd:e"
                         (make-string (a:role-length-max *rbac*) 
                           :initial-element #\a))
    for role in valid-roles
    for message = (if (= (length role) (a:role-length-max *rbac*))
                    (format nil "a valid role can have up to ~a characters"
                      (a:role-length-max *rbac*))
                    (format nil "~s is a valid role" role))
    do (ok (a:valid-role-p *rbac* role) message))
  (loop
    with invalid-roles = (list
                           "1"
                           "123"
                           "1abc"
                           "123a"
                           "1:a"
                           "a1:b2"
                           "abc:DEF"
                           "abc:d12"
                           "abc:"
                           ":abc"
                           "abc:def.ghi"
                           "abc:def-ghi"
                           "abc:def+ghi"
                           "_abc"
                           ".def"
                           "ABC"
                           "Abc"
                           "aBc"
                           ""
                           (make-string (1+ (a:role-length-max *rbac*))
                             :initial-element #\a))
    for role in invalid-roles
    for message = (if (> (length role) (a:role-length-max *rbac*))
                    (format nil "a role longer than ~a characters is not valid"
                      (a:role-length-max *rbac*))
                    (format nil "~s is not a valid role" role))
    do (ok (not (a:valid-role-p *rbac* role)) message)))

(subtest "permission validation"
  (loop
    with valid-permissions = (list
                               "create"
                               "read"
                               "update"
                               "delete"
                               "x:create"
                               "xyz:create"
                               "a.b"
                               "a.b.c"
                               "a1.b2.c3-x"
                               "create:system"
                               "create-2:x"
                               (make-string 
                                 (a:permission-length-max *rbac*)
                                 :initial-element #\a))
    for permission in valid-permissions
    for message = (if (= (length permission) (a:permission-length-max *rbac*))
                    (format nil 
                      "a valid permission can have up to ~d characters"
                      (a:permission-length-max *rbac*))
                    (format nil "~s is valid" permission))
    do (ok (a:valid-permission-p *rbac* permission) message))
  (loop
    with invalid-permissions = (list
                                 "1create"
                                 ":create"
                                 "_create"
                                 ".create"
                                 "create:"
                                 "create_"
                                 "Create"
                                 "read:1"
                                 "read:A"
                                 ""
                                 (make-string 
                                   (1+ (a:permission-length-max *rbac*))
                                   :initial-element #\a))
    for permission in invalid-permissions
    for message = (if (> (length permission) (a:permission-length-max *rbac*))
                    (format nil 
                      "a permission longer than ~d characters is not valid"
                      (a:permission-length-max *rbac*))
                    (format nil "~s is not valid" permission))
    do (ok (not (a:valid-permission-p *rbac* permission)) message)))

(subtest "resource validation"
  (loop
    with valid-resources = (list
                             "/"
                             "/abc/"
                             "/abc/defg/"
                             "/abcd/e fgh/i/"
                             "/a/b/c/d/e/f/g/hijkl/"
                             "/a_b/c-d/ef/"
                             (format nil "/~a/" 
                               (make-string (- (a:resource-length-max *rbac*) 2)
                                 :initial-element #\a)))
    for resource in valid-resources
    for message = (if (= (length resource) (a:resource-length-max *rbac*))
                    (format nil "a valid resource can have up to ~d characters"
                      (a:resource-length-max *rbac*))
                    (format nil "~s is a valid resource" resource))
    do (ok (a:valid-resource-p *rbac* resource) message))
  (loop
    with invalid-resources = (list
                               ""
                               "//"
                               "/a/b/c"
                               "/a/b/c//"
                               "/abc//def/"
                               "/abc?one*5/"
                               "/abc/def/file.txt"
                               (make-string 
                                 (1+ (a:resource-length-max *rbac*))
                                 :initial-element #\a))
    for resource in invalid-resources
    for message = (if (> (length resource) (a:resource-length-max *rbac*))
                    (format nil 
                      "a resource longer than ~d characters is not valid"
                      (a:resource-length-max *rbac*))
                    (format nil "~s is not a valid resource" resource))
    do (ok (not (a:valid-resource-p *rbac* resource)) message)))

(subtest "make search clause"
  (is (a::make-search-clause
        *rbac*
        "select id from users"
        (list "username" "system" "email" "no-email"))
    (list
      (format nil "~{~a~^ ~}"
        (list
          "select id from users"
          "where deleted_at is null"
          "and username = $1 and email = $2"))
      "system"
      "no-email")
    "single table, 2 search terms")
  (is (a::make-search-clause
        *rbac*
        "select r.role from users u
           join role_users ru on u.id = ru.user_id
           join roles r on ru.role_id = r.id"
        (list "u.username" "system"))
    (list
      (format nil "~{~a~^ ~}"
        (list
          "select r.role from users u"
          "join role_users ru on u.id = ru.user_id"
          "join roles r on ru.role_id = r.id"
          "where u.deleted_at is null"
          "and u.username = $1"))
      "system")
    "multiple joins, 1 search term")
  (is (a::make-search-clause
        *rbac*
        "update users set email = $1"
        (list "username" "system")
        "no-email")
    (list
      (format nil "~{~a~^ ~}"
        (list
          "update users set email = $1"
          "where deleted_at is null"
          "and username = $2"))
      "no-email"
      "system")
    "update query with where clause, 1 search term, and 1 first value"))

(subtest "soft-delete support"
  (is (a::soft-delete-sql *rbac* "users" `("user_id" ,*admin-id*) *system-id*)
    (list
      (format nil "~{~a~^ ~}"
        (list
          "update users"
          "set deleted_at = now(), updated_by = $1"
          "where deleted_at is null and user_id = $2"))
      *system-id* *admin-id*)
    "soft-delete-sql")
  (is (a::referencing-soft-delete-sql 
        *rbac* "user_roles" "users" *admin-id* *system-id*)
    (list
      (format nil "~{~a~^ ~}"
        (list
          "update user_roles"
          "set deleted_at = now(), updated_by = $1"
          "where deleted_at is null and user_id = $2"))
      *system-id* *admin-id*)
    "referencing-soft-delete-sql")
  (is (a::referencing-tables *rbac* "users")
    (list "role_users")
    "referencing-tables")
  (is (a::delete-refs-sql
        *rbac*
        "users"
        `("id" ,*admin-id*)
        *system-id*)
    (loop
      with referencing-tables = (list "role_users")
      and user-id = *admin-id*
      and actor-id = *system-id*
      for table in referencing-tables
      collect
      (list
        (format nil "~{~a~^ ~}"
          (list
            "update"
            table
            "set deleted_at = now(), updated_by = $1"
            "where deleted_at is null and user_id = $2"))
        actor-id
        user-id))
    "delete-refs-sql"))

(subtest "get-value"
  (is (a:get-id *rbac* "users" "admin")
    *admin-id*
    "get user ID by username")
  (is (a:get-value *rbac* "users" "id"
        "username" "admin" "email" *admin-email*)
    *admin-id*
    "get user ID by username and email")
  (is (a:get-value *rbac* "permissions" "permission_name" "id" *delete-id*)
    "delete"
    "get permission name by ID")
  (let ((datetime (u:timestamp-string
                    :universal-time
                    (a:get-value *rbac* "roles" "created_at"
                      "role_name" "system")))
         (regex "^20[0-9]{2}-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]$"))
    (ok (re:scan regex datetime) "get created_at timestamp for a role")))

(subtest "get ids"
  (is (ds:human (a:get-role-ids *rbac* (list "admin" "editor")))
    (ds:human (ds:ds `(:map
                        "admin" ,*admin-role-id*
                        "editor" ,*editor-role-id*)))
    "get-role-ids with specific roles")
  (is (length *roles*) (hash-table-count (a:get-role-ids *rbac* nil))
    "correct number of existing roles")
  (ok (loop for role being the hash-keys in (a:get-role-ids *rbac* nil)
        using (hash-value role-id)
        always (and (member role *roles* :test 'equal)
                 (re:scan *uuid-regex* role-id)))
    "get-role-ids with no roles returns all roles")
  (is (ds:human (a::get-permission-ids *rbac* (list "create" "read")))
    (ds:human (ds:ds `(:map "create" ,*create-id* "read" ,*read-id*)))
    "get-permission-ids with specific permissions")
  (is (hash-table-count (a::get-permission-ids *rbac* nil))
    (length *permissions*)
    "correct number of existing permissions")
  (ok (loop for permission being the hash-keys in
        (a::get-permission-ids *rbac* nil)
        using (hash-value permission-id)
        always (and (member permission *permissions* :test 'equal)
                 (re:scan *uuid-regex* permission-id)))
    "get-permission-ids with no permissions")
  (is-error (a:get-role-ids *rbac* (list "non-existing-role"))
    'simple-error
    "get-role-ids with non-existing role")
  (is-error (a:get-permission-ids *rbac* (list "p1" "p2"))
    'simple-error
    "get-permission-ids with multiple non-existing permissions"))

(subtest "add user"
  (let ((a::*allow-test-user-insert* t)
         (roles (list "admin" "editor"))
         (actor "system"))
    (loop
      with all-applicable-roles = (append roles a::*default-roles*)
      for a from 1 to 3
      for username = (format nil "test-user-~d" a)
      for email = (bogus-email-address username)
      for password = (format nil "~a-password" username)
      for log = (diag (format nil "Adding user ~a with email ~a"
                        username email))
      for user-id = (a:add-user *rbac* username email password roles actor)
      do
      (is (a:get-id *rbac* "users" username)
        user-id
        (format nil "User ID for ~a is correct" username))
      (is (a:get-value *rbac* "users" "email" "username" username)
        email
        (format nil "Email for ~a is correct" username))
      (is (a:get-value *rbac* "users" "username" "id" user-id)
        username
        (format nil "Username for user ID ~a is correct" user-id))
      (is (a:get-value *rbac* "users" "password_hash" "id" user-id)
        (a:password-hash username password)
        (format nil "Password for user ~a is correct" username))
      (let ((new-roles (a:with-rbac (*rbac*)
                         (db:query "select role_name
                                  from roles r
                                    join role_users ru on r.id = ru.role_id
                                    where ru.user_id = $1"
                           user-id :column))))
        (ok (every (lambda (role)
                     (member role new-roles :test #'string=))
              all-applicable-roles)
          (format nil "User ~a has roles ~{~a~^, ~}"
            username (append roles a::*default-roles*)))))
    (is-error (a:add-user *rbac* "test-user-1" 
                (bogus-email-address "test-user-4")
                "test-user-4-password" roles actor)
      'simple-error
      "Username must be unique")
    (ok (not (a:get-value *rbac* "users" "id"
               "email" (bogus-email-address "test-user-4")))
      "Duplicate username addition does not create a user")
    (ok (a:add-user *rbac* "test-user-5" (bogus-email-address "test-user-1")
          "test-user-5-password" roles actor)
      "Multple users can have the same email address")
    (is (a:with-rbac (*rbac*)
          (db:query "select count(*) from users where email = $1"
            (bogus-email-address "test-user-1") :single))
      2
      "2 users with the same email address exist")))

(subtest "remove user"
  (let* ((sql-user "select id, username, email
                    from users
                    where username = $1")
          (sql-user-roles "select ru.id
                           from role_users ru
                             join users u on ru.user_id = u.id
                             join roles r on ru.role_id = r.id
                           where u.username = $1")
          (username "test-user-5")
          (user (a:with-rbac (*rbac*)
                  (db:query sql-user username :plist)))
          (role-user-ids (a:with-rbac (*rbac*)
                           (db:query sql-user-roles username :column)))
          (user-roles (a:list-user-role-names *rbac* username)))
    (ok user (format nil "user ~a exists" username))
    (ok role-user-ids (format nil "user ~a has roles: ~{~a~^, ~}" username user-roles))

    (a:remove-user *rbac* username "system")
    (ok (not (a::get-id *rbac* "users" username))
      (format nil "user ~a no longer exists" username))
    (ok (notany
          (lambda (role-user-id)
            (a::get-value *rbac* "role_users" "id" "id" role-user-id))
          role-user-ids)
          (format nil "roles for user ~a no longer exist" username))))

(subtest "list users"
  (let ((two-users-by-name (a:list-users *rbac* 1 2))
         (two-users-by-name-2 (a:list-users *rbac* 2 2))
         (all-users (a:list-users *rbac* 1 10))
         (all-users-2 (a:list-users *rbac* 2 10)))
    (is (length two-users-by-name) 2 "two-users-by-name page params work")
    (is (length two-users-by-name-2) 2 "two-users-by-name-2 page params work")
    (is (length all-users) 5 "all-users page params work")
    (ok (null all-users-2) "all-users-2 page 2 is empty")
    (is (mapcar (lambda (u) (getf u :username)) two-users-by-name)
      (list "admin" "system")
      "two-users-by-name sorting works")
    (is (mapcar (lambda (u) (getf u :username)) two-users-by-name-2)
      (mapcar
        (lambda (u) (getf u :username))
        (a:with-rbac (*rbac*)
          (db:query "select username, id from users
                     where deleted_at is null
                     order by username
                     offset 2
                     limit 2"
            :plists)))
      "two-users-by-name-2 sorting and paging works")
    (is (mapcar (lambda (u) (getf u :username)) all-users)
      (mapcar
        (lambda (u) (getf u :username))
        (a:with-rbac (*rbac*)
          (db:query "select username, id from users
                     where deleted_at is null
                     order by username
                     limit 10"
            :plists)))
      "all-users sorting works")))

(subtest "permissions"
  (let* ((permissions-a (mapcar (lambda (p) (getf p :permission-name))
                          (a:list-permissions *rbac* 1 10)))
          (permissions-sql "select permission_name 
                            from permissions
                            where deleted_at is null
                            order by permission_name")
          (permissions-b (a:with-rbac (*rbac*)
                           (db:query permissions-sql :column)))
          (new-permission "test-permission"))
    ;; Check the baseline state of permissions
    (is permissions-a permissions-b 
      "list-permissions returns correct list")
    (ok (not (member new-permission permissions-a :test 'equal))
      (format nil "permissions do not include '~a'" new-permission))
    ;; Add a new permission and check the updated list
    (let ((new-id (a:add-permission *rbac* new-permission "test permission"
                    "system"))
           (permissions-c (mapcar (lambda (p) (getf p :permission-name))
                            (a:list-permissions *rbac* 1 10)))
           (permissions-d (a:with-rbac (*rbac*)
                            (db:query permissions-sql :column))))
      (is permissions-c permissions-d 
        "list-permissions value includes new permission")
      (isnt permissions-a permissions-c
        "the list of permissions has changed")
      (is (1+ (length permissions-b)) (length permissions-c)
        "there is one more permission")
      (ok (member new-permission permissions-c :test 'equal)
        (format nil "permissions now include '~a'" new-permission))
      (is (a:with-rbac (*rbac*)
            (db:query "select u.username
                       from users u
                         join permissions p on p.updated_by = u.id
                       where p.permission_name = $1"
              new-permission
              :single))
        "system"
        "user system has the new permission")
      ;; Soft delete the new permission and check the updated list
      (diag (format nil "Removing permission '~a'" new-permission))
      (a:remove-permission *rbac* new-permission "system")
      (isnt (a:with-rbac (*rbac*) 
              (db:query "select deleted_at from permissions
                         where permission_name = $1" 
                new-permission
                :single))
        :null
        (format nil "permission '~a' is soft-deleted" new-permission))
      (ok (not (member new-permission
                 (mapcar (lambda (p) (getf p :permission-name))
                   (a:list-permissions *rbac* 1 10))))
        (format nil "permissions no longer include '~a'" new-permission))
      ;; Add the soft-deleted parmission back
      (is new-id
        (a:add-permission *rbac* new-permission new-permission "admin")
        "add a permission that was previously soft-deleted")
      (is (mapcar (lambda (p) (getf p :permission-name))
            (a:list-permissions *rbac* 1 10))
        permissions-c
        "list-permissions value includes the re-added permission")
      (is (a:with-rbac (*rbac*)
            (db:query "select u.username
                       from users u
                         join permissions p on p.updated_by = u.id
                       where p.permission_name = $1"
              new-permission
              :single))
        "admin"
        "user admin has the re-added permission"))))

(subtest "roles"
  (let* ((roles-a (mapcar (lambda (r) (getf r :role-name))
                    (a:list-roles *rbac* 1 100)))
          (roles-sql "select role_name 
                      from roles
                      where deleted_at is null
                      order by role_name")
          (role-permissions-sql "select p.permission_name
                                 from permissions p
                                   join role_permissions rp on rp.permission_id = p.id
                                   join roles r on rp.role_id = r.id
                                 where
                                   p.deleted_at is null
                                   and rp.deleted_at is null
                                   and r.deleted_at is null
                                   and r.role_name = $1
                                 order by p.permission_name")
          (roles-b (a:with-rbac (*rbac*)
                       (db:query roles-sql :column)))
          (new-role "test-role")
          (new-role-permissions '("read" "update"))
          (actor "system"))
    ;; Check the baseline state of roles
    (is roles-a roles-b "list-roles returns correct list")
    (ok (not (member new-role roles-a :test 'equal))
      (format nil "roles do not include '~a'" new-role))
    ;; Add a new role and check the updated list
    (let ((new-id (a:add-role *rbac* new-role new-role
                    nil new-role-permissions actor))
           (roles-c (mapcar (lambda (r) (getf r :role-name))
                            (a:list-roles *rbac* 1 100)))
           (roles-d (a:with-rbac (*rbac*)
                        (db:query roles-sql :column))))
      (is roles-c roles-d "list-roles value includes a new role")
      (isnt roles-a roles-c "the list of roles has changed")
      (is (1+ (length roles-b)) (length roles-c) "there is one more role")
      (ok (member new-role roles-c :test 'equal)
        (format nil "roles now include '~a'" new-role))
      (is (a:with-rbac (*rbac*)
            (db:query role-permissions-sql new-role :column))
        new-role-permissions
        "new role has correct permissions, by sql")
      (is (mapcar (lambda (p) (getf p :permission-name))
                    (a:list-role-permissions *rbac* new-role 1 10))
        new-role-permissions
        "new role has correct permissions, by list-role-permissions")
      ;; Soft delete the new role and check the updated list
      (diag (format nil "Removing role '~a'" new-role))
      (a:remove-role *rbac* new-role actor)
      (isnt (a:with-rbac (*rbac*) 
              (db:query "select deleted_at from roles
                         where role_name = $1" 
                new-role
                :single))
        :null
        (format nil "role '~a' is soft-deleted" new-role))
      (ok (not (member new-role
                  (mapcar (lambda (r) (getf r :role-name))
                    (a:list-roles *rbac* 1 100))
                 :test 'equal))
        (format nil "roles no longer include '~a'" new-role))
      ;; Add back the soft-deleted role
      (diag "Adding back removed role (un-soft-deleting role)")
      (is new-id
        (a:add-role *rbac* new-role new-role nil new-role-permissions actor)
        "add back the role that was just soft-deleted")
      (is (mapcar (lambda (r) (getf r :role-name))
            (a:list-roles *rbac* 1 100))
        (a:with-rbac (*rbac*) (db:query roles-sql :column))
        "list-roles and equivalent sql match after reinstating role")
      (ok (member new-role 
            (mapcar (lambda (r) (getf r :role-name))
              (a:list-roles *rbac* 1 100))
            :test 'equal)
        (format nil "role ~a exists and has been un-soft-deleted" new-role)))))

(subtest "role users"
  (let* ((user-1 "test-user-1")
          (user-2 "test-user-2")
          (user-3 "test-user-3")
          (role "test-role")
          (role-users (mapcar
                        (lambda (u) (getf u :username))
                        (a:list-role-users *rbac* role 1 100)))
          (role-users-sql "select u.username
                           from users u
                             join role_users ru on ru.user_id = u.id
                             join roles r on ru.role_id = r.id
                           where
                             u.deleted_at is null
                             and ru.deleted_at is null
                             and r.deleted_at is null
                             and r.role_name = $1
                           order by
                             u.username")
          (actor "system"))
    ;; Check the baseline state of the role
    (ok (not (member user-1 role-users :test 'equal))
      (format nil "~a is not among the users of role ~a, via list-role-users"
        user-1 role))
    (ok (not (member
               user-1
               (a:with-rbac (*rbac*)
                 (db:query role-users-sql role :column))))
      (format nil "~a is not among the users of role ~a, via sql"
        user-1 role))
    (ok (not (member user-2 role-users :test 'equal))
      (format nil "~a is not among the users of role ~a"
        user-2 role))
    ;; Add users to the role
    (diag (format nil "Adding users to role ~a" role))
    (let ((ru-id-1 (a:add-role-user *rbac* role user-1 actor))
           (ru-id-2 (a:add-role-user *rbac* role user-2 actor))
           (ru-id-3 (a:add-role-user *rbac* role user-3 actor)))
      (push user-1 role-users)
      (push user-2 role-users)
      ;; Let's see if we got some good ids for the new role-user rows
      (ok ru-id-1 (format nil "~a/~a -> ~a" role user-1 ru-id-1))
      (ok ru-id-2 (format nil "~a/~a -> ~a" role user-2 ru-id-2))
      (ok ru-id-3 (format nil "~a/~a -> ~a" role user-3 ru-id-3))
      ;; Check that role users include the new users now
      (ok (member
            user-1
            (mapcar
              (lambda (u) (getf u :username))
              (a:list-role-users *rbac* role 1 100))
            :test 'equal)
        (format nil "role ~a users now includes ~a" role user-1))
      (ok (member
            user-2
            (mapcar
              (lambda (u) (getf u :username))
              (a:list-role-users *rbac* role 1 100))
            :test 'equal)
        (format nil "role ~a users now include ~a"
          role user-2))
      (ok (member
            user-3
            (mapcar
              (lambda (u) (getf u :username))
              (a:list-role-users *rbac* role 1 100))
            :test 'equal)
        (format nil "role ~a users now include ~a"
          role user-3))
      ;; Check that the actor is being recorded correctly
      (is (a:with-rbac (*rbac*)
            (db:query "select u.username
                       from users u join role_users ru on ru.updated_by = u.id
                       where ru.id = $1"
              ru-id-3
              :single))
        actor
        "updated_by correct after adding new role user")
      ;; Remove (soft-delete) a user from the role
      (diag "Removing a role user")
      (a:remove-role-user *rbac* role user-3 actor)
      (let ((deleted-at (a:with-rbac (*rbac*)
                          (db:query "select deleted_at from role_users
                                     where id = $1"
                            ru-id-3
                            :single))))
        (isnt deleted-at :null
          (format nil "role_users row for ~a has non-null deleted_at value ~a"
            user-3 deleted-at)))
      (ok (not (member
                 user-3
                 (mapcar 
                   (lambda (ru) (getf ru :username))
                   (a:list-role-users *rbac* role 1 10))))
        (format nil "user ~a no longer part of role ~a"
          user-3 role))
      ;; Reinstate (un-soft-delete) the user's role
      (diag "Reinstante soft-deleted role user")
      (is ru-id-3 (a:add-role-user *rbac* role user-3 "admin")
        "add-role-user with soft-deleted row returns original role-user id")
      (is (a:with-rbac (*rbac*) 
            (db:query "select u.username
                       from users u join role_users ru on ru.updated_by = u.id
                       where ru.id = $1"
              ru-id-3
              :single))
        "admin"
        "updated_by correct after reinstating soft-deleted role user"))))

(subtest "role permissions"
  (let* ((actor "system")
          (actor-id (a:get-id *rbac* "users" actor))
          (new-permissions (mapcar 
                            (lambda (n) 
                              (let ((permission (format nil 
                                                  "test-permission-~d" n)))
                                (a:add-permission
                                  *rbac*
                                  permission
                                  permission
                                  actor)
                                permission))
                            (u:range 1 3)))
          (role "test-role")
          (get-role-permissions (lambda ()
                                  (mapcar
                                    (lambda (u) (getf u :permission-name))
                                    (a:list-role-permissions *rbac* role 1 99))))
          (role-permissions-sql "select p.permission_name
                                 from permissions p
                                   join role_permissions rp
                                     on rp.permission_id = p.id
                                   join roles r on rp.role_id = r.id
                                 where
                                   p.deleted_at is null
                                   and rp.deleted_at is null
                                   and r.deleted_at is null
                                   and r.role_name = $1
                                 order by p.permission_name")
          (get-rp-deleted-at (lambda (id)
                               (a:with-rbac (*rbac*)
                                 (db:query
                                   "select deleted_at
                                    from role_permissions
                                    where id = $1"
                                   id
                                   :single))))
          (get-rp-updated-by (lambda (id)
                               (a:with-rbac (*rbac*)
                                 (db:query
                                   "select updated_by
                                    from role_permissions
                                    where id = $1"
                                   id
                                   :single)))))
    ;; Check baseline state of the role
    (is (funcall get-role-permissions) 
      (a:with-rbac (*rbac*) (db:query role-permissions-sql role :column))
      "get-role-permissions equivalent to sql")
    (loop 
      with role-permissions = (funcall get-role-permissions)
      for permission in new-permissions
      for permission-id = (a:get-id *rbac* "permissions" permission)
      do
      ;; The new permissions exist
      (ok permission-id (format nil "permission ~a exists" permission))
      ;; But, they're not part of the role "test-role"
      (ok (not (member permission role-permissions :test 'equal))
        (format nil "role ~a does not include ~a"
          role permission)))
    ;; Add permissions to the role
    (let ((role-permission-ids (loop 
                                 for permission in new-permissions
                                 for id = (a:add-role-permission *rbac* 
                                            role permission actor)
                                 do (ok id (format nil "Added ~a -> ~a" 
                                             role permission))
                                 collect id)))
      ;; Ensure that role permissions include new permissions now
      (loop
        with role-permissions = (funcall get-role-permissions)
        for permission in new-permissions do
        (ok (member permission role-permissions :test 'equal)
          (format nil "role ~a permissions now include ~a" role permission)))
      ;; Role permissions row should have deleted_at set to null
      (is (funcall get-rp-deleted-at (car role-permission-ids))
        :null
        (format nil "deleted_at is null for ~a -> ~a"
          role (car new-permissions)))
      (is (funcall get-rp-updated-by (car role-permission-ids)) actor-id
        (format nil "role permission last updated by ~a" actor))
      ;; Soft-delete permission-1, using a different actor
      (a:remove-role-permission *rbac* role (car new-permissions) "admin")
      ;; Role permissions should no longer include permission-1
      (ok (not (member (car new-permissions) 
                 (funcall get-role-permissions) 
                 :test 'equal))
        (format nil "role ~a no longer includes permission ~a" 
          role (car new-permissions)))
      ;; role-permissions row should have a deleted_at time that is less
      ;; than 2 seconds in the past
      (ok (<
            (- (get-universal-time)
              (funcall get-rp-deleted-at (car role-permission-ids)))
            2)
        (format nil "role-permissions row has a good value for deleted_at"))
      ;; role-permissions row was last updated by admin
      (is (funcall get-rp-updated-by (car role-permission-ids))
        (a:get-id *rbac* "users" "admin")
        (format nil "role permission ~a, ~a was last updated by admin" 
          role (car new-permissions)))
      ;; Reinstante soft-deleted role permission
      (is (a:add-role-permission *rbac* role (car new-permissions) actor)
        (car role-permission-ids)
        (format nil "reinstanted soft-deleted role permission ~a -> ~a"
          role (car new-permissions)))
      ;; role-permissions row should once again have a non-null deleted_at value
      (is (funcall get-rp-deleted-at (car role-permission-ids))
        :null
        (format nil "deleted_at is null for ~a -> ~a"
          role (car new-permissions))))))

(defun get-resources (&optional part)
  (let ((resources (a:list-resources *rbac* 1 1000)))
    (if part
      (mapcar (lambda (l) (getf l part)) resources)
      resources)))

(defun get-resource-value (resource-name key)
  (getf
    (a:with-rbac (*rbac*)
      (db:query
        "select * from resources where resource_name = $1"
        resource-name
        :plist))
    key))

(defun get-resources-with-sql ()
  (a:with-rbac (*rbac*)
    (db:query 
      "select resource_name from resources
       where deleted_at is null
       order by resource_name"
      :column)))

(subtest "resources"
  (let* ((new-resources (mapcar (lambda (n) (format nil "/test-resource-~d/" n))
                          (u:range 1 3)))
          (existing-resources (list 
                                "/admin/"
                                "/public/" 
                                "/user/"))
          (roles (list "viewer" "test-role"))
          (actor "system")
          (actor-id (a:get-id *rbac* "users" actor)))
    ;; Insert the viewer role and the so-called existing resources, so that we
    ;; can pretend they existed all along
    (like (a:d-add-role *rbac* "viewer" :permissions '("read")) *uuid-regex*
      "added viewer role")
    (loop for resource in existing-resources
      for resource-id = (a:d-add-resource *rbac* resource :roles roles)
      do (like resource-id *uuid-regex* 
           (format nil "added resource ~a (~a)" resource resource-id)))
    ;; Check baseline
    (is (get-resources :resource-name) (get-resources-with-sql)
      "get-resources matches sql query result")
    (is (get-resources :resource-name) existing-resources
      "expected existing resources")
    (is (sort (u:distinct-values (get-resources :updated-by)) #'string<)
      (list actor-id)
      "All existing resources updated by system")
    (ok (loop for new-resource in new-resources
          never (member new-resource existing-resources :test 'equal))
      "None of the new resources exist yet")
    (ok (loop 
          with existing-resource-roles = 
          (ds:ds 
            '(:map
               "/admin/" (:list "test-role" "viewer")
               "/public/" (:list "test-role" "viewer")
               "/user/" (:list "test-role" "viewer")))
          for resource in existing-resources
          for resource-roles = (mapcar
                                 (lambda (rr) (getf rr :role-name))
                                 (a:list-resource-roles *rbac* resource 1 100))
          do (u:log-it :debug "~a roles: ~{~a~^, ~}" resource resource-roles)
          always (equal resource-roles (gethash resource existing-resource-roles)))
      "All resources have expected roles")
    ;; Add some resources
    (diag "Adding new resources")
    (let ((new-resource-ids (loop
                              for resource in new-resources
                              collect (a:add-resource *rbac* 
                                        resource resource roles actor))))
      ;; Check that new resource exist now
      (is (get-resources :resource-name)
        (sort (append existing-resources new-resources) #'string<)
        "New resources in database")
      ;; All resources, including the new ones, updated by system
      (is (sort (u:distinct-values (get-resources :updated-by)) #'string<)
        (list actor-id))
      ;; Soft-delete test-resource-1
      (diag "Soft-deleting test-resource-1")
      (a:remove-resource *rbac* (car new-resources) actor)
      ;; Resource is no longer listed
      (ok (not (member (car new-resources)
                 (get-resources :resource-name) 
                 :test 'equal))
        (format nil "Resource ~a no longer listed" (car new-resources)))
      ;; Check deleted_at on soft-deleted resource
      (ok (< (- (get-universal-time)
               (get-resource-value (car new-resources) :deleted-at))
            2)
        "soft-deleted resource has correct deleted_at timestamp")
      ;; Check that appropriate resource_roles rows have been soft-deleted
      ;; Reinstante soft-deleted resource test-resource-1
      (is (a:add-resource *rbac* 
            (car new-resources) 
            (car new-resources)
            (cons "editor" roles)
            actor)
        (car new-resource-ids)
        "correctly reinstated soft-deleted resource"))))

(defun get-resource-roles (resource)
  (mapcar (lambda (r) (getf r :role-name))
    (a:list-resource-roles *rbac* resource 1 100)))

(subtest "resource roles"
  (let* ((resource "/test-resource-1/")
          (old-resource-roles (list "editor" "test-role" "viewer"))
          (actor "system")
          (new-resource-roles (list 
                                "test-user-1:exclusive"
                                "test-user-2:exclusive")))
    ;; Check baseline
    (is (get-resource-roles resource)
      old-resource-roles
      (format nil "resource ~a has roles ~{~a~^, ~}" 
        resource old-resource-roles))
    ;; Add some new roles to the resource
    (let ((resource-role-ids (loop for role in new-resource-roles collect
                               (a:add-resource-role *rbac*
                                 resource role actor))))
      (let ((roles-expected (sort
                              (append old-resource-roles new-resource-roles)
                              #'string<))
             (roles-actual (get-resource-roles resource)))
        (is roles-actual roles-expected "new roles were added to resource"))
      ;; Soft-delete one of the new roles
      (is (a:remove-resource-role *rbac* 
            resource (car new-resource-roles) actor)
        (car resource-role-ids)
        (format nil "soft-deleting resource role returns its ID: ~a"
          (car new-resource-roles)))
      (ok (not (member (car new-resource-roles)
                 (get-resource-roles resource)
                 :test 'equal))
        (format nil "resource no longer has role ~a"
          (car new-resource-roles)))
      ;; Reinstate resource role
      (is (a:add-resource-role *rbac* resource (car new-resource-roles) actor)
        (car resource-role-ids)
        (format nil "role ~a reinstated to resource ~a"
          (car new-resource-roles) resource))
      (ok (member (car new-resource-roles)
            (get-resource-roles resource)
            :test 'equal)
        (format nil "resource ~a has role ~a" resource
          (car new-resource-roles))))))

(subtest "user allowed"
  (let* ((resource "/test-resource-3/")
          (main-user "macnod")
          (main-permission "read")
          (main-role "test-role")
          (exclusive-role "macnod:exclusive")
          (actor "system"))
    ;; Add the main user
    (like (a:d-add-user *rbac* main-user "password-1234") *uuid-regex*
      (format nil "add user ~a" main-user))
    ;; 1. User doesn't have read access to resource
    (ok (not (a:user-allowed *rbac* main-user main-permission resource))
      (format nil "1. user ~a does not have ~a access to resource ~a"
        main-user main-permission resource))
    ;; 2. Give user read access to resource via main-role
    (ok (a:add-role-user *rbac* main-role main-user actor)
      (format nil "2. add role ~a to user ~a" main-role main-user))
    ;; 3. User has read access to resource
    (ok (a:user-allowed *rbac* main-user main-permission resource)
      (format nil "3. user ~a has ~a access to resource ~a"
        main-user main-permission resource))
    ;; 4. Remove user's read access to resource by removing user from main-role
    (ok (a:remove-role-user *rbac* main-role main-user actor)
      (format nil "4. remove role ~a from user ~a" main-role main-user))
    ;; 5. User does not have read access to resource
    (ok (not (a:user-allowed *rbac* main-user main-permission resource))
      (format nil "5. user ~a does not have ~a access to resource ~a"
        main-user main-permission resource))
    ;; 6. Restore soft-deleted user's main-role
    (ok (a:add-role-user *rbac* main-role main-user actor)
      (format nil "6. restore soft-deleted role ~a for user ~a" 
        main-role main-user))
    ;; 7. User has read access to resource
    (ok (a:user-allowed *rbac* main-user main-permission resource)
      (format nil "7. user ~a has ~a access to resource ~a"
        main-user main-permission resource))
    ;; 8. Remove user from role again
    (ok (a:remove-role-user *rbac* main-role main-user actor)
      (format nil "8. remove role ~a from user ~a" main-role main-user))
    ;; 9. User does not have read access to resource
    (ok (not (a:user-allowed *rbac* main-user main-permission resource))
      (format nil "9. user ~a does not have ~a access to resource ~a"
        main-user main-permission resource))
    ;; 10. Give user access to the resource by adding the user's exclusive role
    ;;     to the resource
    (ok (a:add-resource-role *rbac* resource exclusive-role actor)
      (format nil "10. add user ~a's exclusive role to resource ~a"
        main-user resource))
    ;; 11. User has read access to the resource
    (ok (a:user-allowed *rbac* main-user main-permission resource)
      (format nil "11. user ~a has ~a access to ~a via user's exclusive role."
        main-user main-permission resource))
    ;; 12. Remove user's access by removing read permission from user's
    ;;     exclusive role
    (ok (a:remove-role-permission *rbac* exclusive-role main-permission actor)
      (format nil "12. remove ~a permission from exclusive role ~a."
        main-permission exclusive-role))
    ;; 13. User does not have read access to resource
    (ok (not (a:user-allowed *rbac* main-user main-permission resource))
      (format nil "13. user ~a does not have ~a access to resource ~a"
        main-user main-permission resource))))

(subtest "add user, add role, add resource, add role to user & resource"
  (ok (a:d-add-role *rbac* "re-role") "Create role re-role")
  (ok (a:d-add-user *rbac* "re-user" "password-1234") "Add user re-user")
  (ok (a:d-add-resource *rbac* "/re-dir/") "Add resource /re-dir/")
  (ok (not (a:user-allowed *rbac* "re-user" "create" "/re-dir/"))
    "User re-user forbidden create access to /re-dir/ (1)")
  (ok (a:d-add-user-role *rbac* "re-user" "re-role")
    "Add role re-role to user re-user (1)")
  (ok (not (a:user-allowed *rbac* "re-user" "create" "/re-dir/"))
    "User re-user forbiden create access to /re-dir/ (2)")
  (ok (a:d-add-resource-role *rbac* "/re-dir/" "re-role")
    "Add role re-role to resource /re-dir/")
  (ok (a:user-allowed *rbac* "re-user" "create" "/re-dir/")
    "User re-user has create access to /re-dir/ (1)")
  (ok (a:d-remove-user-role *rbac* "re-user" "re-role")
    "Remove role re-role from user re-user")
  (ok (not (a:user-allowed *rbac* "re-user" "create" "/re-dir/"))
    "User re-user forbiden create access to /re-dir/ (3)")
  (ok (a:d-add-user-role *rbac* "re-user" "re-role")
    "Add role re-role to user re-user (2)")
  (ok (a:user-allowed *rbac* "re-user" "create" "/re-dir/")
    "User re-user has create access to /re-dir/ (2)")
  (ok (a:d-remove-role-permission *rbac* "re-role" "create")
    "Remove create permission from role re-role")
  (ok (not (member "create" (a:list-role-permission-names *rbac* "re-role")
             :test 'equal))
    "Role re-role no longer has create permission")
  (ok (not (a:user-allowed *rbac* "re-user" "create" "/re-dir/"))
    "User re-user forbiden create access to /re-dir/ (4)")
  (ok (a:d-add-role-permission *rbac* "re-role" "create")
    "Add create permission to role re-role")
  (ok (member "create" (a:list-role-permission-names *rbac* "re-role")
        :test 'equal)
    "Role re-role has create permission once again")
  (ok (a:user-allowed *rbac* "re-user" "create" "/re-dir/")
    "User re-user has create access to /re-dir/ (2)")
  (ok (a:list-role-permission-names *rbac* "re-role")
    "Role re-role has permissions"))

(u:close-log)
(if (finalize)
  (uiop:quit 0)
  (uiop:quit 1))
