(require :asdf)
(require :fiveam)
(require :cl-ppcre)
(require :postmodern)
(require :uiop)
(require :swank)
(require :dc-ds)
(require :dc-time)
(require :dc-eclectic)

(push (uiop:getcwd) asdf:*central-registry*)
(ql:register-local-projects)
(asdf:load-system :rbac)

(defpackage :rbac-test
  (:use :cl :fiveam :rbac :p-log)
  (:local-nicknames
    (:re :cl-ppcre)
    (:db :postmodern)
    (:ds :dc-ds)
    (:u :dc-eclectic)))

(in-package :rbac-test)

;; Environment variables
(defparameter *db-host* (u:getenv "DB_HOST" :required t))
(defparameter *db-port* (u:getenv "DB_PORT" :required t :type :integer))
(defparameter *db-user* (u:getenv "DB_USER" :required t))
(defparameter *db-password* (u:getenv "DB_PASSWORD" :required t))
(defparameter *log-file* (u:getenv "LOG_FILE"))
(defparameter *run-tests* (u:getenv "RUN_TESTS" :type :boolean))
(defparameter *swank-port* (u:getenv "SWANK_PORT" :type :integer))

;; Database connection
(defparameter *rbac* (make-instance 'rbac-pg
                       :host *db-host*
                       :port *db-port*
                       :user-name *db-user*
                       :password *db-password*))

;; Test support
(defparameter uuid-regex "^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$")

(when *log-file*
  (make-log-stream "tests" *log-file* :append nil))

(defun clear-database ()
  (with-rbac (*rbac*)
    (loop for user in (u:exclude (list-user-names *rbac*) "system")
      do (remove-user *rbac* user))
    (loop for permission in (u:exclude (list-permission-names *rbac*)
                              '("create" "read" "update" "delete"))
      do (remove-permission *rbac* permission))
    (loop for role in (u:exclude (list-role-names *rbac*)
                         '("system" "system:exclusive" "logged-in" "public"))
      do (remove-role *rbac* role))
    (loop for resource in (list-resource-names *rbac*)
      do (remove-resource *rbac* resource))
    (clear-cache *rbac*)
    t))

(defun is-uuid (s)
  (when (re:scan uuid-regex s) t))

(def-suite rbac-suite :description "FiveAM tests for the rbac package")

(in-suite rbac-suite)

(test current-directory
  (is-true
    (member "rbac-tests.lisp"
      (mapcar (lambda (d) (u:filename-only (namestring d)))
        (directory (u:join-paths (uiop:getcwd) "tests" "/*.*")))
      :test 'equal)
    "Expected ~%~{~a~%~} to contain the file tests/rbac-tests.lisp"
    (directory (parse-namestring (u:join-paths (uiop:getcwd) "tests" "**")))
    (uiop:getcwd)))

(test with-rbac
  (with-rbac (*rbac*)
    (is (= 1 (db:query "select count(*) from users where user_name = $1"
               "system" :single)))))

(test basic-operations
  (clear-database)

  ;; Add a permission
  (is-true (is-uuid (add-permission *rbac* "bogus")))

  ;; Add a couple of roles
  (is-true (is-uuid (add-role *rbac* "role-a" :permissions '("read"))))
  (is-true (is-uuid (add-role *rbac* "role-b")))
  (is-true (is-uuid (add-role *rbac* "role-c"
                      :permissions (cons "bogus" *default-permissions*))))

  ;; Add a few users
  (loop
    with role-lists = '(("role-a") ("role-b") ("role-a" "role-b")
                         ("role-a" "role-c"))
    for a from 1 to 8
    for user = (format nil "user-~2,'0d" a)
    for email = (format nil "~a@sinistercode.com" user)
    for password = (format nil "password-~2,'0d" a)
    for roles = (nth (mod a 4) role-lists)
    do (is-true (is-uuid (add-user *rbac* user email password :roles roles))))

  ;; Add a user without roles
  (is-true
    (is-uuid
      (add-user *rbac* "user-09" "user-09@sinistercode.com" "password-09")))

  ;; Add some resources
  (loop with roles = '("public" "logged-in" "system" "role-a" "role-b" "role-c")
    for role in roles
    for a = 1 then (1+ a)
    for resource = (format nil "test:resource-~2,'0d" a)
    do (is-true (is-uuid (add-resource *rbac* resource :roles (list role)))))

  ;; Add a resource without roles
  (is-true (is-uuid (add-resource *rbac* "test:resource-noroles")))

  ;; Add a second resource with the "role-a" role
  (is-true (is-uuid (add-resource *rbac* "test:resource-04a"
                      :roles (list "role-a"))))

  ;; Let's see if everything got added correctly

  ;; Check users, roles, permissions, and resources
  (is (equal (sort (cons "bogus" *default-permissions*) #'string<)
        (list-permission-names *rbac*)))
  (is (equal (u:safe-sort '("role-a" "role-b" "role-c"
                             "system" "logged-in" "public"))
        (u:exclude-regex (list-role-names *rbac*) ":exclusive$")))
  (is (equal (loop for a from 1 to 9
               collect (format nil "user-~2,'0d" a))
        (u:exclude (list-user-names *rbac*) "system")))
  (is (equal '("test:resource-01" "test:resource-02"
                 "test:resource-03" "test:resource-04"
                 "test:resource-04a" "test:resource-05"
                 "test:resource-06" "test:resource-noroles")
        (list-resource-names *rbac*)))
  (is (equal (list-user-permission-names *rbac* "user-01")
        '("read"))))

;; (test some-database-entries-test
;;   ;; Add admin role
;;   (is-true (setf *admin-role-id* (d-add-role *rbac* "admin"))
;;     "Add admin role")
;;   (is-true (member "admin" (list-role-names *rbac*) :test 'equal)
;;     "new admin role exists")

;;   ;; Add editor role
;;   (is (re:scan *uuid-regex* (setf *editor-role-id*
;;                               (d-add-role *rbac* "editor" :permissions '("read" "update"))))
;;     "add new editor role.")

;;   ;; Add admin user
;;   (is (re:scan *uuid-regex*
;;         (setf *admin-id*
;;           (d-add-user *rbac* "admin" "weasel-1234" :roles '("admin"))))
;;     "add admin user with new admin role")

;;   ;; Check that admin user has new admin role
;;   (is-true (member "admin" (list-user-role-names *rbac* "admin") :test 'equal)
;;     "user admin has role admin")

;;   ;; Add a user that will be immediately soft-deleted
;;   (let* ((id-1 (d-add-user *rbac* "soft-user" "password-1"))
;;           (id-2 (get-id *rbac* "users" "soft-user")))
;;     (is (equal id-1 id-2) "d-add-user and get-id return same user id")
;;     ;; Soft-delete the user
;;     (d-remove-user *rbac* "soft-user")

;;     ;; Ensure get-id doesn't return the soft-deleted user's ID
;;     (is-false (get-id *rbac* "users" "soft-user")
;;       "get-id returns nil for soft-deleted user")))

;; (test check-test
;;   (let* (errors
;;           (x (check errors "x" "x failed")))
;;     (is-true (null (report-errors errors))
;;       "no error for condition 'x'")
;;     (let ((y (check errors (equal x "y") "y failed."))
;;            (z (check errors (equal x "z") "z failed.")))
;;       (is-true (null y) "y remains null for (equal x 'y')")
;;       (is-true (null z) "z remains null for (equal x 'z')")
;;       (signals simple-error (report-errors errors)))
;;     (handler-case (report-errors errors)
;;       (error (e)
;;         (is (equal (format nil "~a" e) "Errors: y failed. z failed.")
;;           "error reported correctly"))
;;       (t (e)
;;         (fail (format nil "unexpected error condition: ~a" e))))))

;; (test rbac-query-single-test
;;   (with-rbac (*rbac*)
;;     (is (= (rbac-query-single
;;              (list "select count(*) from users where deleted_at is null"))
;;           2)
;;       "user count (no parameters)")
;;     (is (re:scan *uuid-regex* (rbac-query-single
;;                                 (list "select id from users where username = $1" "admin")))
;;       "user id (username parameter)")
;;     (is (re:scan *uuid-regex* (rbac-query-single
;;                                 (list "select id from users where username = $1 and email = $2"
;;                                   "admin"
;;                                   *admin-email*)))
;;       "user id (username and email parameters)")))

;; (test rbac-query-test
;;   (with-rbac (*rbac*)
;;     (is (equal (rbac-query
;;                  (list "select username from users
;;                  where deleted_at is null order by username"))
;;           '((:username "admin") (:username "system")))
;;       "usernames (no parameters)")
;;     (is (equal (rbac-query
;;                  (list "select username from users
;;                  where length(username) = $1
;;                  order by username"
;;                    5))
;;           '((:username "admin")))
;;       "usernames (1 parameter)")))

;; (test usql-test
;;   (is (equal (usql "select
;;                  t1.field1,
;;                  t2.field2,
;;                  t3.field3
;;                from
;;                  table1 t1
;;                    join table2 t2 on t1.table2_id = t2.id
;;                    join table3 t3 on t1.table3_id = t3.id
;;                where
;;                  t1 = 4
;;                  and t2 = 2
;;                order by t1
;;                offset 10
;;                limit 20")
;;         (format nil "~{~a~^ ~}"
;;           (list
;;             "select t1.field1, t2.field2, t3.field3"
;;             "from table1 t1"
;;             "join table2 t2 on t1.table2_id = t2.id"
;;             "join table3 t3 on t1.table3_id = t3.id"
;;             "where t1 = 4 and t2 = 2"
;;             "order by t1 offset 10 limit 20")))
;;     "usql test 1"))

;; (test classes-test
;;   (let ((rbac (make-instance 'rbac))
;;          (rbac-pg (make-instance 'rbac-pg :password "password")))
;;     (is (eq (type-of rbac) 'rbac) "base class instance has type 'rbac")
;;     (is (eq (type-of rbac-pg) 'rbac-pg)
;;       "postgres rbac class instance has type 'rbac-pg")
;;     (is (equal (username rbac-pg) "cl-user") "rbac-pg username is correct")
;;     (is (equal (password rbac-pg) "password") "rbac-pg password is correct")
;;     (is (equal (host rbac-pg) "postgres") "rbac-pg host is correct")
;;     (is (= (port rbac-pg) 5432) "rbac-pg port is correct")))

;; (test to-hash-table-test
;;   (is (equalp (ds:human
;;                 (to-hash-table *rbac*
;;                   '(("first" . "Jane") ("last" . "Doe") ("age" . 50))))
;;         (ds:human
;;           (ds:ds `(:map "first" "Jane" "last" "Doe" "age" 50))))
;;     "3-field str-alist converts to hash table")
;;   (is (equalp (ds:human (to-hash-table *rbac* nil))
;;         (ds:human (make-hash-table)))
;;     "empty result returns an empty hash table"))

;; (test to-hash-tables-test
;;   (is (equalp (ds:human
;;                 (to-hash-tables *rbac*
;;                   (with-rbac (*rbac*)
;;                     (db:query "select permission_name, id
;;                        from permissions
;;                        order by permission_name
;;                        limit 2"
;;                       :str-alists))))
;;         (ds:human (ds:ds `(:list
;;                             (:map "permission_name" "create"
;;                               "id" ,*create-id*)
;;                             (:map "permission_name" "delete"
;;                               "id" ,*delete-id*)))))
;;     "to-hash-tables converts :str-alists result into a hash table"))

;; (test sql-for-list-test
;;   (is (equal (sql-for-list
;;                *rbac*
;;                (list "a.username" "b.role_name" "c.permission_name")
;;                "users a
;;            join roles b on whatever
;;            join permissions c on whatever"
;;                (list "a.id = $1" "b.id = $2")
;;                (list "one" "two")
;;                nil
;;                1
;;                10)
;;         (list
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "select a.username, b.role_name, c.permission_name"
;;               "from users a join roles b on whatever"
;;               "join permissions c on whatever"
;;               "where a.deleted_at is null"
;;               "and a.id = $1 and b.id = $2"
;;               "offset 0 limit 10"))
;;           "one" "two"))
;;     "joined tables, values, no order-by-fields")
;;   (is (equal (sql-for-list
;;                *rbac*
;;                (list "username" "role_name" "permission_name")
;;                "users"
;;                (list "id = $1" "id = $2")
;;                (list "one" "two")
;;                nil
;;                1
;;                10)
;;         (list
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "select username, role_name, permission_name from users"
;;               "where deleted_at is null"
;;               "and id = $1 and id = $2"
;;               "offset 0 limit 10"))
;;           "one" "two"))
;;     "single table, values, no order-by-fields")
;;   (is (equal (sql-for-list
;;                *rbac*
;;                (list "id" "username" "password_hash")
;;                "users"
;;                (list "id = $1" "username = $2")
;;                (list "one" "two")
;;                (list "username" "id desc")
;;                1
;;                10)
;;         (list
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "select id, username, password_hash from users"
;;               "where deleted_at is null"
;;               "and id = $1 and username = $2"
;;               "order by username, id desc"
;;               "offset 0 limit 10"))
;;           "one" "two"))
;;     "single table, values, order-by-fields"))

;; (test list-rows-test
;;   (is (equal (list-rows
;;                *rbac*
;;                (list "username" "id")
;;                "users"
;;                nil
;;                nil
;;                (list "username")
;;                1
;;                1)
;;         (list (list :username "admin" :id *admin-id*)))
;;     "list-rows with single table, no where clause, no values, 1 row")
;;   (is (equal (list-rows
;;                *rbac*
;;                (list "r.role_name" "p.permission_name")
;;                "users u
;;            join role_users ru on ru.user_id = u.id
;;            join roles r on ru.role_id = r.id
;;            join role_permissions rp on rp.role_id = r.id
;;            join permissions p on rp.permission_id = p.id"
;;                (list "u.username = $1")
;;                (list "admin")
;;                (list "r.role_name" "p.permission_name")
;;                1
;;                10)
;;         '((:ROLE-NAME "admin" :PERMISSION-NAME "create")
;;            (:ROLE-NAME "admin" :PERMISSION-NAME "delete")
;;            (:ROLE-NAME "admin" :PERMISSION-NAME "read")
;;            (:ROLE-NAME "admin" :PERMISSION-NAME "update")
;;            (:ROLE-NAME "admin:exclusive" :PERMISSION-NAME "create")
;;            (:ROLE-NAME "admin:exclusive" :PERMISSION-NAME "delete")
;;            (:ROLE-NAME "admin:exclusive" :PERMISSION-NAME "read")
;;            (:ROLE-NAME "admin:exclusive" :PERMISSION-NAME "update")))
;;     "list-rows with 4 table joins, a where clause, and a value"))

;; (test upsert-link-sql-test
;;   (is (equal (rbac::upsert-link-sql "roles" "permissions")
;;         (rbac::usql
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "insert into role_permissions (role_id, permission_id, updated_by)"
;;               "values ($1, $2, $3)"
;;               "on conflict (role_id, permission_id)"
;;               "do"
;;               "  update set"
;;               "    updated_by = $3,"
;;               "    updated_at = now(),"
;;               "    deleted_at = null"
;;               "returning id"))))
;;     "upsert-link-sql works as expected"))

;; (test username-validation-test
;;   (loop
;;     with valid-usernames = (list
;;                              "macnod"
;;                              "macnod1"
;;                              "m1234d"
;;                              "m12345"
;;                              (make-string (username-length-max *rbac*)
;;                                :initial-element #\a))
;;     for username in valid-usernames
;;     for message = (if (= (length username) (username-length-max *rbac*))
;;                     (format nil "a username with ~d characters is valid"
;;                       (username-length-max *rbac*))
;;                     (format nil "username ~s is valid" username))
;;     do (is-true (valid-username-p *rbac* username) message))
;;   (loop
;;     with invalid-usernames = (list
;;                                "1macnod"
;;                                "12345"
;;                                ""
;;                                "mac┼nod"
;;                                (make-string
;;                                  (1+ (username-length-max *rbac*))
;;                                  :initial-element #\a))
;;     for username in invalid-usernames
;;     for message = (if (> (length username) (username-length-max *rbac*))
;;                     (format nil
;;                       "a username longer than ~d characters is not valid"
;;                       (username-length-max *rbac*))
;;                     (format nil "~s is not valid" username))
;;     do (is-false (valid-username-p *rbac* username) message)))

;; (test password-validation-test
;;   (loop
;;     with valid-passwords = (list
;;                              "1!abcd"
;;                              "123-5a"
;;                              "pass1!"
;;                              "@@@@9z"
;;                              "h1vxTwuq!x"
;;                              "--~0Tc"
;;                              "-wUi^DT6VMe&u.f9D}hC[<*=^v1oOz&Q-:LU'SgPlc9(xSorY~&ul2&[z`E(|b}P")
;;     for password in valid-passwords
;;     for message = (format nil "password ~s is valid" password)
;;     do (is-true (valid-password-p *rbac* password) message))
;;   (loop
;;     with invalid-passwords = (list
;;                                "password"
;;                                "123456"
;;                                ""
;;                                "z1y2!"
;;                                "abc123"
;;                                "123!@#"
;;                                ")(*xyz"
;;                                (format nil "~a~a"
;;                                  "heav3^-"
;;                                  (make-string (- (password-length-max *rbac*) 6)
;;                                    :initial-element #\z)))
;;     for password in invalid-passwords
;;     for message = (if (> (length password) (password-length-max *rbac*))
;;                     (format nil "a password longer than ~d characters is not valid"
;;                       (password-length-max *rbac*))
;;                     (format nil "~s is not valid" password))
;;     do (is-false (valid-password-p *rbac* password) message)))

;; (test email-validation-test
;;   (loop
;;     with valid-emails = (list
;;                           "abc@example.com"
;;                           "abc_def@one-two.com"
;;                           "abc.def@example-x.com"
;;                           "no-email"
;;                           (format nil "~a@domain.com"
;;                             (make-string
;;                               (- (email-length-max *rbac*) 11)
;;                               :initial-element #\e)))
;;     for email in valid-emails
;;     for message = (if (= (length email) (email-length-max *rbac*))
;;                     "a proper email address can have length of up to 128 characters"
;;                     (format nil "email ~s is valid" email))
;;     do (is-true (valid-email-p *rbac* email) message))
;;   (loop
;;     with invalid-emails = (list
;;                             "hello@one"
;;                             "@macnod"
;;                             "user"
;;                             ""
;;                             (format nil "~a@domain.com"
;;                               (make-string
;;                                 (- (email-length-max *rbac*) 10)
;;                                 :initial-element #\f)))
;;     for email in invalid-emails
;;     for message = (if (> (length email) (email-length-max *rbac*))
;;                     (format nil
;;                       "an email address longer than ~d characters is not valid"
;;                       (email-length-max *rbac*))
;;                     (format nil "~s is not valid" email))
;;     do (is-false (valid-email-p *rbac* email) message)))

;; (test role-validation-test
;;   (loop
;;     with valid-roles = (list
;;                          "a1"
;;                          "a1b2"
;;                          "a.b"
;;                          "a.b.c"
;;                          "a-b-c"
;;                          "a.b_c"
;;                          "a1:bc"
;;                          "a-b-c:def"
;;                          "a+b"
;;                          "a.123"
;;                          "bac+def"
;;                          "a:b"
;;                          "a:bcde"
;;                          "abcd:e"
;;                          (make-string (role-length-max *rbac*)
;;                            :initial-element #\a))
;;     for role in valid-roles
;;     for message = (if (= (length role) (role-length-max *rbac*))
;;                     (format nil "a valid role can have up to ~a characters"
;;                       (role-length-max *rbac*))
;;                     (format nil "~s is a valid role" role))
;;     do (is-true (valid-role-p *rbac* role) message))
;;   (loop
;;     with invalid-roles = (list
;;                            "1"
;;                            "123"
;;                            "1abc"
;;                            "123a"
;;                            "1:a"
;;                            "a1:b2"
;;                            "abc:DEF"
;;                            "abc:d12"
;;                            "abc:"
;;                            ":abc"
;;                            "abc:def.ghi"
;;                            "abc:def-ghi"
;;                            "abc:def+ghi"
;;                            "_abc"
;;                            ".def"
;;                            "ABC"
;;                            "Abc"
;;                            "aBc"
;;                            ""
;;                            (make-string (1+ (role-length-max *rbac*))
;;                              :initial-element #\a))
;;     for role in invalid-roles
;;     for message = (if (> (length role) (role-length-max *rbac*))
;;                     (format nil "a role longer than ~a characters is not valid"
;;                       (role-length-max *rbac*))
;;                     (format nil "~s is not a valid role" role))
;;     do (is-false (valid-role-p *rbac* role) message)))

;; (test permission-validation-test
;;   (loop
;;     with valid-permissions = (list
;;                                "create"
;;                                "read"
;;                                "update"
;;                                "delete"
;;                                "x:create"
;;                                "xyz:create"
;;                                "a.b"
;;                                "a.b.c"
;;                                "a1.b2.c3-x"
;;                                "create:system"
;;                                "create-2:x"
;;                                (make-string
;;                                  (permission-length-max *rbac*)
;;                                  :initial-element #\a))
;;     for permission in valid-permissions
;;     for message = (if (= (length permission) (permission-length-max *rbac*))
;;                     (format nil
;;                       "a valid permission can have up to ~d characters"
;;                       (permission-length-max *rbac*))
;;                     (format nil "permission ~s is valid" permission))
;;     do (is-true (valid-permission-p *rbac* permission) message))
;;   (loop
;;     with invalid-permissions = (list
;;                                  "1create"
;;                                  ":create"
;;                                  "_create"
;;                                  ".create"
;;                                  "create:"
;;                                  "create_"
;;                                  "Create"
;;                                  "read:1"
;;                                  "read:A"
;;                                  ""
;;                                  (make-string
;;                                    (1+ (permission-length-max *rbac*))
;;                                    :initial-element #\a))
;;     for permission in invalid-permissions
;;     for message = (if (> (length permission) (permission-length-max *rbac*))
;;                     (format nil
;;                       "a permission longer than ~d characters is not valid"
;;                       (permission-length-max *rbac*))
;;                     (format nil "~s is not valid" permission))
;;     do (is-false (valid-permission-p *rbac* permission) message)))

;; (test resource-validation-test
;;   (loop
;;     with valid-resources = (list
;;                              "/"
;;                              "/abc/"
;;                              "/abc/defg/"
;;                              "/abcd/e fgh/i/"
;;                              "/a/b/c/d/e/f/g/hijkl/"
;;                              "/a_b/c-d/ef/"
;;                              (format nil "/~a/"
;;                                (make-string (- (resource-length-max *rbac*) 2)
;;                                  :initial-element #\a)))
;;     for resource in valid-resources
;;     for message = (if (= (length resource) (resource-length-max *rbac*))
;;                     (format nil "a valid resource can have up to ~d characters"
;;                       (resource-length-max *rbac*))
;;                     (format nil "~s is a valid resource" resource))
;;     do (is-true (valid-resource-p *rbac* resource) message))
;;   (loop
;;     with invalid-resources = (list
;;                                ""
;;                                "//"
;;                                "/a/b/c"
;;                                "/a/b/c//"
;;                                "/abc//def/"
;;                                "/abc?one*5/"
;;                                "/abc/def/file.txt"
;;                                (make-string
;;                                  (1+ (resource-length-max *rbac*))
;;                                  :initial-element #\a))
;;     for resource in invalid-resources
;;     for message = (if (> (length resource) (resource-length-max *rbac*))
;;                     (format nil
;;                       "a resource longer than ~d characters is not valid"
;;                       (resource-length-max *rbac*))
;;                     (format nil "~s is not a valid resource" resource))
;;     do (is-false (valid-resource-p *rbac* resource) message)))

;; (test make-search-clause-test
;;   (is (equal (rbac::make-search-clause
;;                *rbac*
;;                "select id from users"
;;                (list "username" "system" "email" "no-email"))
;;         (list
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "select id from users"
;;               "where deleted_at is null"
;;               "and username = $1 and email = $2"))
;;           "system"
;;           "no-email"))
;;     "single table, 2 search terms")
;;   (is (equal (rbac::make-search-clause
;;                *rbac*
;;                "select r.role from users u
;;            join role_users ru on u.id = ru.user_id
;;            join roles r on ru.role_id = r.id"
;;                (list "u.username" "system"))
;;         (list
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "select r.role from users u"
;;               "join role_users ru on u.id = ru.user_id"
;;               "join roles r on ru.role_id = r.id"
;;               "where u.deleted_at is null"
;;               "and u.username = $1"))
;;           "system"))
;;     "multiple joins, 1 search term")
;;   (is (equal (rbac::make-search-clause
;;                *rbac*
;;                "update users set email = $1"
;;                (list "username" "system")
;;                "no-email")
;;         (list
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "update users set email = $1"
;;               "where deleted_at is null"
;;               "and username = $2"))
;;           "no-email"
;;           "system"))
;;     "update query with where clause, 1 search term, and 1 first value"))

;; (test soft-delete-support-test
;;   (is (equal (rbac::soft-delete-sql *rbac* "users" `("user_id" ,*admin-id*) *system-id*)
;;         (list
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "update users"
;;               "set deleted_at = now(), updated_by = $1"
;;               "where deleted_at is null and user_id = $2"))
;;           *system-id* *admin-id*))
;;     "soft-delete-sql")
;;   (is (equal (rbac::referencing-soft-delete-sql
;;                *rbac* "user_roles" "users" *admin-id* *system-id*)
;;         (list
;;           (format nil "~{~a~^ ~}"
;;             (list
;;               "update user_roles"
;;               "set deleted_at = now(), updated_by = $1"
;;               "where deleted_at is null and user_id = $2"))
;;           *system-id* *admin-id*))
;;     "referencing-soft-delete-sql")
;;   (is (equal (rbac::referencing-tables *rbac* "users")
;;         (list "role_users"))
;;     "referencing-tables")
;;   (is (equal (rbac::delete-refs-sql
;;                *rbac*
;;                "users"
;;                `("id" ,*admin-id*)
;;                *system-id*)
;;         (loop
;;           with referencing-tables = (list "role_users")
;;           and user-id = *admin-id*
;;           and actor-id = *system-id*
;;           for table in referencing-tables
;;           collect
;;           (list
;;             (format nil "~{~a~^ ~}"
;;               (list
;;                 "update"
;;                 table
;;                 "set deleted_at = now(), updated_by = $1"
;;                 "where deleted_at is null and user_id = $2"))
;;             actor-id
;;             user-id)))
;;     "delete-refs-sql"))

;; (test get-value-test
;;   (is (equal (get-id *rbac* "users" "admin")
;;         *admin-id*)
;;     "get user ID by username")
;;   (is (equal (get-value *rbac* "users" "id"
;;                "username" "admin" "email" *admin-email*)
;;         *admin-id*)
;;     "get user ID by username and email")
;;   (is (equal (get-value *rbac* "permissions" "permission_name" "id" *delete-id*)
;;         "delete")
;;     "get permission name by ID")
;;   (let ((datetime (dc-time:timestamp-string
;;                     :universal-time
;;                     (get-value *rbac* "roles" "created_at"
;;                       "role_name" "system")))
;;          (regex "^20[0-9]{2}-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]$"))
;;     (is-true (re:scan regex datetime) "get created_at timestamp for a role")))

;; (test get-ids-test
;;   (is (equalp (ds:human (get-role-ids *rbac* (list "admin" "editor")))
;;         (ds:human (ds:ds `(:map
;;                             "admin" ,*admin-role-id*
;;                             "editor" ,*editor-role-id*))))
;;     "get-role-ids with specific roles")
;;   (is (= (length *roles*) (hash-table-count (get-role-ids *rbac* nil)))
;;     "correct number of existing roles")
;;   (is-true (loop for role being the hash-keys in (get-role-ids *rbac* nil)
;;              using (hash-value role-id)
;;              always (and (member role *roles* :test 'equal)
;;                       (re:scan *uuid-regex* role-id)))
;;     "get-role-ids with no roles returns all roles")
;;   (is (equalp (ds:human (rbac::get-permission-ids *rbac* (list "create" "read")))
;;         (ds:human (ds:ds `(:map "create" ,*create-id* "read" ,*read-id*))))
;;     "get-permission-ids with specific permissions")
;;   (is (= (hash-table-count (rbac::get-permission-ids *rbac* nil))
;;         (length *permissions*))
;;     "correct number of existing permissions")
;;   (is-true (loop for permission being the hash-keys in
;;              (rbac::get-permission-ids *rbac* nil)
;;              using (hash-value permission-id)
;;              always (and (member permission *permissions* :test 'equal)
;;                       (re:scan *uuid-regex* permission-id)))
;;     "get-permission-ids with no permissions")
;;   (signals simple-error (get-role-ids *rbac* (list "non-existing-role"))
;;     "get-role-ids with non-existing role")
;;   (signals simple-error (get-permission-ids *rbac* (list "p1" "p2"))
;;     "get-permission-ids with multiple non-existing permissions"))

;; (test add-user-test
;;   (let ((rbac::*allow-test-user-insert* t)
;;          (roles (list "admin" "editor"))
;;          (actor "system"))
;;     (loop
;;       with all-applicable-roles = (append roles rbac::*default-user-roles*)
;;       for a from 1 to 3
;;       for username = (format nil "test-user-~d" a)
;;       for email = (bogus-email-address username)
;;       for password = (format nil "~a-password" username)
;;       for user-id = (add-user *rbac* username email password roles actor)
;;       do
;;       (is (equal (get-id *rbac* "users" username)
;;             user-id)
;;         (format nil "user id for ~a is correct" username))
;;       (is (equal (get-value *rbac* "users" "email" "username" username)
;;             email)
;;         (format nil "email for ~a is correct" username))
;;       (is (equal (get-value *rbac* "users" "username" "id" user-id)
;;             username)
;;         (format nil "username for user id ~a is correct" user-id))
;;       (is (equal (get-value *rbac* "users" "password_hash" "id" user-id)
;;             (password-hash username password))
;;         (format nil "password for user ~a is correct" username))
;;       (let ((new-roles (with-rbac (*rbac*)
;;                          (db:query "select role_name
;;                                   from roles r
;;                                     join role_users ru on r.id = ru.role_id
;;                                     where ru.user_id = $1"
;;                            user-id :column))))
;;         (is-true (every (lambda (role)
;;                           (member role new-roles :test #'string=))
;;                    all-applicable-roles)
;;           (format nil "user ~a has roles ~{~a~^, ~}"
;;             username (append roles rbac::*default-user-roles*)))))
;;     (let ((reference-role-count (list-roles-count *rbac*))
;;            (reference-user-count (list-users-count *rbac*)))
;;       (signals simple-error (add-user *rbac* "test-user-1"
;;                               (bogus-email-address "test-user-4")
;;                               "test-user-4-password" roles actor)
;;         "username must be unique")
;;       (is (= (list-users-count *rbac*) reference-user-count)
;;         "user count unchanged after duplicate username addition")
;;       (is (= (list-roles-count *rbac*) reference-role-count)
;;         "role count unchanged after duplicate username addition"))
;;     (is-false (get-value *rbac* "users" "id"
;;                 "email" (bogus-email-address "test-user-4"))
;;       "duplicate username addition does not create a user")
;;     (is-true (add-user *rbac* "test-user-5" (bogus-email-address "test-user-1")
;;                "test-user-5-password" roles actor)
;;       "Multple users can have the same email address")
;;     (is (= (with-rbac (*rbac*)
;;              (db:query "select count(*) from users where email = $1"
;;                (bogus-email-address "test-user-1") :single))
;;           2)
;;       "2 users with the same email address exist")))

;; (test remove-user-test
;;   (let* ((sql-user "select id, username, email
;;                     from users
;;                     where username = $1")
;;           (sql-user-roles "select ru.id
;;                            from role_users ru
;;                              join users u on ru.user_id = u.id
;;                              join roles r on ru.role_id = r.id
;;                            where u.username = $1")
;;           (username "test-user-5")
;;           (user (with-rbac (*rbac*)
;;                   (db:query sql-user username :plist)))
;;           (role-user-ids (with-rbac (*rbac*)
;;                            (db:query sql-user-roles username :column)))
;;           (user-roles (list-user-role-names *rbac* username)))
;;     (is-true user (format nil "user ~a exists" username))
;;     (is-true role-user-ids (format nil "user ~a has roles: ~{~a~^, ~}" username user-roles))

;;     (remove-user *rbac* username "system")
;;     (is-false (rbac::get-id *rbac* "users" username)
;;       (format nil "user ~a no longer exists" username))
;;     (is-true (loop for id in role-user-ids
;;                never (rbac::get-value *rbac* "role_users" "id" "id" id))
;;       (format nil "roles for user ~a no longer exist" username))))

;; (test list-users-test
;;   (let ((two-users-by-name (list-users *rbac* 1 2))
;;          (two-users-by-name-2 (list-users *rbac* 2 2))
;;          (all-users (list-users *rbac* 1 10))
;;          (all-users-2 (list-users *rbac* 2 10)))
;;     (is (= (length two-users-by-name) 2) "two-users-by-name page params work")
;;     (is (= (length two-users-by-name-2) 2) "two-users-by-name-2 page params work")
;;     (is (= (length all-users) 5) "all-users page params work")
;;     (is-true (null all-users-2) "all-users-2 page 2 is empty")
;;     (is (equal (mapcar (lambda (u) (getf u :username)) two-users-by-name)
;;           (list "admin" "system"))
;;       "two-users-by-name sorting works")
;;     (is (equal (mapcar (lambda (u) (getf u :username)) two-users-by-name-2)
;;           (mapcar
;;             (lambda (u) (getf u :username))
;;             (with-rbac (*rbac*)
;;               (db:query "select username, id from users
;;                      where deleted_at is null
;;                      order by username
;;                      offset 2
;;                      limit 2"
;;                 :plists))))
;;       "two-users-by-name-2 sorting and paging works")
;;     (is (equal (mapcar (lambda (u) (getf u :username)) all-users)
;;           (mapcar
;;             (lambda (u) (getf u :username))
;;             (with-rbac (*rbac*)
;;               (db:query "select username, id from users
;;                      where deleted_at is null
;;                      order by username
;;                      limit 10"
;;                 :plists))))
;;       "all-users sorting works")))

;; (test permissions-test
;;   (let* ((permissions-a (mapcar (lambda (p) (getf p :permission-name))
;;                           (list-permissions *rbac* 1 10)))
;;           (permissions-sql "select permission_name
;;                             from permissions
;;                             where deleted_at is null
;;                             order by permission_name")
;;           (permissions-b (with-rbac (*rbac*)
;;                            (db:query permissions-sql :column)))
;;           (new-permission "test-permission"))
;;     ;; Check the baseline state of permissions
;;     (is (equal permissions-a permissions-b)
;;       "list-permissions returns correct list")
;;     (is-false (member new-permission permissions-a :test 'equal)
;;       (format nil "permissions do not include '~a'" new-permission))
;;     ;; Add a new permission and check the updated list
;;     (let ((new-id (add-permission *rbac* new-permission "test permission"
;;                     "system"))
;;            (permissions-c (mapcar (lambda (p) (getf p :permission-name))
;;                             (list-permissions *rbac* 1 10)))
;;            (permissions-d (with-rbac (*rbac*)
;;                             (db:query permissions-sql :column))))
;;       (is (equal permissions-c permissions-d)
;;         "list-permissions value includes new permission")
;;       (is-false (equal permissions-a permissions-c)
;;         "the list of permissions has changed")
;;       (is (= (1+ (length permissions-b)) (length permissions-c))
;;         "there is one more permission")
;;       (is-true (member new-permission permissions-c :test 'equal)
;;         (format nil "permissions now include '~a'" new-permission))
;;       (is (equal (with-rbac (*rbac*)
;;                    (db:query "select u.username
;;                        from users u
;;                          join permissions p on p.updated_by = u.id
;;                        where p.permission_name = $1"
;;                      new-permission
;;                      :single))
;;             "system")
;;         "user system has the new permission")
;;       ;; Soft delete the new permission and check the updated list
;;       (remove-permission *rbac* new-permission "system")
;;       (is-false (equal (with-rbac (*rbac*)
;;                          (db:query "select deleted_at from permissions
;;                          where permission_name = $1"
;;                            new-permission
;;                            :single))
;;                   :null)
;;         (format nil "permission '~a' is soft-deleted" new-permission))
;;       (is-false (member new-permission
;;                   (mapcar (lambda (p) (getf p :permission-name))
;;                     (list-permissions *rbac* 1 10)))
;;         (format nil "permissions no longer include '~a'" new-permission))
;;       ;; Add the soft-deleted permission back
;;       (is (equal new-id
;;             (add-permission *rbac* new-permission new-permission "admin"))
;;         "add a permission that was previously soft-deleted")
;;       (is (equal (mapcar (lambda (p) (getf p :permission-name))
;;                    (list-permissions *rbac* 1 10))
;;             permissions-c)
;;         "list-permissions value includes the re-added permission")
;;       (is (equal (with-rbac (*rbac*)
;;                    (db:query "select u.username
;;                        from users u
;;                          join permissions p on p.updated_by = u.id
;;                        where p.permission_name = $1"
;;                      new-permission
;;                      :single))
;;             "admin")
;;         "user admin has the re-added permission"))))

;; (test roles-test
;;   (let* ((roles-a (mapcar (lambda (r) (getf r :role-name))
;;                     (list-roles *rbac* 1 100)))
;;           (roles-sql "select role_name
;;                       from roles
;;                       where deleted_at is null
;;                       order by role_name")
;;           (role-permissions-sql "select p.permission_name
;;                                  from permissions p
;;                                    join role_permissions rp on rp.permission_id = p.id
;;                                    join roles r on rp.role_id = r.id
;;                                  where
;;                                    p.deleted_at is null
;;                                    and rp.deleted_at is null
;;                                    and r.deleted_at is null
;;                                    and r.role_name = $1
;;                                  order by p.permission_name")
;;           (roles-b (with-rbac (*rbac*)
;;                      (db:query roles-sql :column)))
;;           (new-role "test-role")
;;           (new-role-permissions '("read" "update"))
;;           (actor "system"))
;;     ;; Check the baseline state of roles
;;     (is (equal roles-a roles-b) "list-roles returns correct list")
;;     (is-false (member new-role roles-a :test 'equal)
;;       (format nil "roles do not include '~a'" new-role))
;;     ;; Add a new role and check the updated list
;;     (let ((new-id (add-role *rbac* new-role new-role
;;                     nil new-role-permissions actor))
;;            (roles-c (mapcar (lambda (r) (getf r :role-name))
;;                       (list-roles *rbac* 1 100)))
;;            (roles-d (with-rbac (*rbac*)
;;                       (db:query roles-sql :column))))
;;       (is (equal roles-c roles-d) "list-roles value includes a new role")
;;       (is-false (equal roles-a roles-c) "the list of roles has changed")
;;       (is (= (1+ (length roles-b)) (length roles-c)) "there is one more role")
;;       (is-true (member new-role roles-c :test 'equal)
;;         (format nil "roles now include '~a'" new-role))
;;       (is (equal (with-rbac (*rbac*)
;;                    (db:query role-permissions-sql new-role :column))
;;             new-role-permissions)
;;         "new role has correct permissions, by sql")
;;       (is (equal (mapcar (lambda (p) (getf p :permission-name))
;;                    (list-role-permissions *rbac* new-role 1 10))
;;             new-role-permissions)
;;         "new role has correct permissions, by list-role-permissions")
;;       ;; Soft delete the new role and check the updated list
;;       (remove-role *rbac* new-role actor)
;;       (is-false (equal (with-rbac (*rbac*)
;;                          (db:query "select deleted_at from roles
;;                          where role_name = $1"
;;                            new-role
;;                            :single))
;;                   :null)
;;         (format nil "role '~a' is soft-deleted" new-role))
;;       (is-false (member new-role
;;                   (mapcar (lambda (r) (getf r :role-name))
;;                     (list-roles *rbac* 1 100))
;;                   :test 'equal)
;;         (format nil "roles no longer include '~a'" new-role))
;;       ;; Add back the soft-deleted role
;;       (is (equal new-id
;;             (add-role *rbac* new-role new-role nil new-role-permissions actor))
;;         "add back the role that was just soft-deleted")
;;       (is (equal (mapcar (lambda (r) (getf r :role-name))
;;                    (list-roles *rbac* 1 100))
;;             (with-rbac (*rbac*) (db:query roles-sql :column)))
;;         "list-roles and equivalent sql match after reinstating role")
;;       (is-true (member new-role
;;                  (mapcar (lambda (r) (getf r :role-name))
;;                    (list-roles *rbac* 1 100))
;;                  :test 'equal)
;;         (format nil "role ~a exists and has been un-soft-deleted" new-role)))))

;; (test role-users-test
;;   (let* ((user-1 "test-user-1")
;;           (user-2 "test-user-2")
;;           (user-3 "test-user-3")
;;           (role "test-role")
;;           (role-users (mapcar
;;                         (lambda (u) (getf u :username))
;;                         (list-role-users *rbac* role 1 100)))
;;           (role-users-sql "select u.username
;;                            from users u
;;                              join role_users ru on ru.user_id = u.id
;;                              join roles r on ru.role_id = r.id
;;                            where
;;                              u.deleted_at is null
;;                              and ru.deleted_at is null
;;                              and r.deleted_at is null
;;                              and r.role_name = $1
;;                            order by
;;                              u.username")
;;           (actor "system"))
;;     ;; Check the baseline state of the role
;;     (is-false (member user-1 role-users :test 'equal)
;;       (format nil "~a is not among the users of role ~a, via list-role-users"
;;         user-1 role))
;;     (is-false (member
;;                 user-1
;;                 (with-rbac (*rbac*)
;;                   (db:query role-users-sql role :column)))
;;       (format nil "~a is not among the users of role ~a, via sql"
;;         user-1 role))
;;     (is-false (member user-2 role-users :test 'equal)
;;       (format nil "~a is not among the users of role ~a"
;;         user-2 role))
;;     ;; Add users to the role
;;     (let ((ru-id-1 (add-role-user *rbac* role user-1 actor))
;;            (ru-id-2 (add-role-user *rbac* role user-2 actor))
;;            (ru-id-3 (add-role-user *rbac* role user-3 actor)))
;;       ;; Let's see if we got some good ids for the new role-user rows
;;       (is-true ru-id-1 (format nil "~a/~a -> ~a" role user-1 ru-id-1))
;;       (is-true ru-id-2 (format nil "~a/~a -> ~a" role user-2 ru-id-2))
;;       (is-true ru-id-3 (format nil "~a/~a -> ~a" role user-3 ru-id-3))
;;       ;; Check that role users include the new users now
;;       (is-true (member
;;                  user-1
;;                  (mapcar
;;                    (lambda (u) (getf u :username))
;;                    (list-role-users *rbac* role 1 100))
;;                  :test 'equal)
;;         (format nil "role ~a users now includes ~a" role user-1))
;;       (is-true (member
;;                  user-2
;;                  (mapcar
;;                    (lambda (u) (getf u :username))
;;                    (list-role-users *rbac* role 1 100))
;;                  :test 'equal)
;;         (format nil "role ~a users now include ~a"
;;           role user-2))
;;       (is-true (member
;;                  user-3
;;                  (mapcar
;;                    (lambda (u) (getf u :username))
;;                    (list-role-users *rbac* role 1 100))
;;                  :test 'equal)
;;         (format nil "role ~a users now include ~a"
;;           role user-3))
;;       ;; Check that the actor is being recorded correctly
;;       (is (equal (with-rbac (*rbac*)
;;                    (db:query "select u.username
;;                        from users u join role_users ru on ru.updated_by = u.id
;;                        where ru.id = $1"
;;                      ru-id-3
;;                      :single))
;;             actor)
;;         "updated_by correct after adding new role user")
;;       ;; Remove (soft-delete) a user from the role
;;       (remove-role-user *rbac* role user-3 actor)
;;       (let ((deleted-at (with-rbac (*rbac*)
;;                           (db:query "select deleted_at from role_users
;;                                      where id = $1"
;;                             ru-id-3
;;                             :single))))
;;         (is-false (equal deleted-at :null)
;;           (format nil "role_users row for ~a has non-null deleted_at value ~a"
;;             user-3 deleted-at)))
;;       (is-false (member
;;                   user-3
;;                   (mapcar
;;                     (lambda (ru) (getf ru :username))
;;                     (list-role-users *rbac* role 1 10)))
;;         (format nil "user ~a no longer part of role ~a"
;;           user-3 role))
;;       ;; Reinstate (un-soft-delete) the user's role
;;       (is (equal ru-id-3 (add-role-user *rbac* role user-3 "admin"))
;;         "add-role-user with soft-deleted row returns original role-user id")
;;       (is (equal (with-rbac (*rbac*)
;;                    (db:query "select u.username
;;                        from users u join role_users ru on ru.updated_by = u.id
;;                        where ru.id = $1"
;;                      ru-id-3
;;                      :single))
;;             "admin")
;;         "updated_by correct after reinstating soft-deleted role user"))))

;; (test role-permissions-test
;;   (let* ((actor "system")
;;           (actor-id (get-id *rbac* "users" actor))
;;           (new-permissions (mapcar
;;                              (lambda (n)
;;                                (let ((permission (format nil
;;                                                    "test-permission-~d" n)))
;;                                  (add-permission
;;                                    *rbac*
;;                                    permission
;;                                    permission
;;                                    actor)
;;                                  permission))
;;                              (u:range 1 3)))
;;           (role "test-role")
;;           (get-role-permissions (lambda ()
;;                                   (mapcar
;;                                     (lambda (u) (getf u :permission-name))
;;                                     (list-role-permissions *rbac* role 1 99))))
;;           (role-permissions-sql "select p.permission_name
;;                                  from permissions p
;;                                    join role_permissions rp
;;                                      on rp.permission_id = p.id
;;                                    join roles r on rp.role_id = r.id
;;                                  where
;;                                    p.deleted_at is null
;;                                    and rp.deleted_at is null
;;                                    and r.deleted_at is null
;;                                    and r.role_name = $1
;;                                  order by p.permission_name")
;;           (get-rp-deleted-at (lambda (id)
;;                                (with-rbac (*rbac*)
;;                                  (db:query
;;                                    "select deleted_at
;;                                     from role_permissions
;;                                     where id = $1"
;;                                    id
;;                                    :single))))
;;           (get-rp-updated-by (lambda (id)
;;                                (with-rbac (*rbac*)
;;                                  (db:query
;;                                    "select updated_by
;;                                     from role_permissions
;;                                     where id = $1"
;;                                    id
;;                                    :single)))))
;;     ;; Check baseline state of the role
;;     (is (equal (funcall get-role-permissions)
;;           (with-rbac (*rbac*) (db:query role-permissions-sql role :column)))
;;       "get-role-permissions equivalent to sql")
;;     (loop
;;       with role-permissions = (funcall get-role-permissions)
;;       for permission in new-permissions
;;       for permission-id = (get-id *rbac* "permissions" permission)
;;       do
;;       ;; The new permissions exist
;;       (is-true permission-id (format nil "permission ~a exists" permission))
;;       ;; But, they're not part of the role "test-role"
;;       (is-false (member permission role-permissions :test 'equal)
;;         (format nil "role ~a does not include ~a"
;;           role permission)))
;;     ;; Add permissions to the role
;;     (let ((role-permission-ids (loop
;;                                  for permission in new-permissions
;;                                  for id = (add-role-permission *rbac*
;;                                             role permission actor)
;;                                  do (is-true id (format nil "Added ~a -> ~a"
;;                                                   role permission))
;;                                  collect id)))
;;       ;; Ensure that role permissions include new permissions now
;;       (loop
;;         with role-permissions = (funcall get-role-permissions)
;;         for permission in new-permissions do
;;         (is-true (member permission role-permissions :test 'equal)
;;           (format nil "role ~a permissions now include ~a" role permission)))
;;       ;; Role permissions row should have deleted_at set to null
;;       (is (equal (funcall get-rp-deleted-at (car role-permission-ids))
;;             :null)
;;         (format nil "deleted_at is null for ~a -> ~a"
;;           role (car new-permissions)))
;;       (is (equal (funcall get-rp-updated-by (car role-permission-ids)) actor-id)
;;         (format nil "role permission last updated by ~a" actor))
;;       ;; Soft-delete permission-1, using a different actor
;;       (remove-role-permission *rbac* role (car new-permissions) "admin")
;;       ;; Role permissions should no longer include permission-1
;;       (is-false (member (car new-permissions)
;;                   (funcall get-role-permissions)
;;                   :test 'equal)
;;         (format nil "role ~a no longer includes permission ~a"
;;           role (car new-permissions)))
;;       ;; role-permissions row should have a deleted_at time that is less
;;       ;; than 2 seconds in the past
;;       (is-true (<
;;                  (- (get-universal-time)
;;                    (funcall get-rp-deleted-at (car role-permission-ids)))
;;                  10)
;;         (format nil "role-permissions row has a good value for deleted_at"))
;;       ;; role-permissions row was last updated by admin
;;       (is (equal (funcall get-rp-updated-by (car role-permission-ids))
;;             (get-id *rbac* "users" "admin"))
;;         (format nil "role permission ~a, ~a was last updated by admin"
;;           role (car new-permissions)))
;;       ;; Reinstante soft-deleted role permission
;;       (is (equal (add-role-permission *rbac* role (car new-permissions) actor)
;;             (car role-permission-ids))
;;         (format nil "reinstanted soft-deleted role permission ~a -> ~a"
;;           role (car new-permissions)))
;;       ;; role-permissions row should once again have a non-null deleted_at value
;;       (is (equal (funcall get-rp-deleted-at (car role-permission-ids))
;;             :null)
;;         (format nil "deleted_at is null for ~a -> ~a"
;;           role (car new-permissions))))))

;; (test resources-test
;;   (let* ((new-resources (mapcar (lambda (n) (format nil "/test-resource-~d/" n))
;;                           (u:range 1 3)))
;;           (existing-resources (list
;;                                 "/admin/"
;;                                 "/public/"
;;                                 "/user/"))
;;           (roles (list "viewer" "test-role"))
;;           (actor "system")
;;           (actor-id (get-id *rbac* "users" actor)))
;;     ;; Insert the viewer role and the so-called existing resources, so that we
;;     ;; can pretend they existed all along
;;     (is (re:scan *uuid-regex* (d-add-role *rbac* "viewer" :permissions '("read")))
;;       "added viewer role")
;;     (loop for resource in existing-resources
;;       for resource-id = (d-add-resource *rbac* resource :roles roles)
;;       do (is (re:scan *uuid-regex* resource-id)
;;            (format nil "add resource ~a (~a)" resource resource-id)))
;;     ;; Check baseline
;;     (is (equal (get-resources :resource-name) (get-resources-with-sql))
;;       "get-resources matches sql query result")
;;     (is (equal (get-resources :resource-name) existing-resources)
;;       "expected existing resources")
;;     (is (equal (sort (u:distinct-values (get-resources :updated-by)) #'string<)
;;           (list actor-id))
;;       "All existing resources updated by system")
;;     (is-true (loop for new-resource in new-resources
;;                never (member new-resource existing-resources :test 'equal))
;;       "none of the new resources exist yet")
;;     ;; Check that existing resources have expected roles
;;     (is-true (list-includes-all-p
;;                (list-resource-role-names *rbac* "/admin/")
;;                '("test-role" "viewer"))
;;       "resource /admin/ has expected roles")
;;     (is-true (list-includes-all-p
;;                (list-resource-role-names *rbac* "/public/")
;;                '("test-role" "viewer"))
;;       "resource /public/ has expected roles")
;;     (is-true (list-includes-all-p
;;                (list-resource-role-names *rbac* "/user/")
;;                '("test-role" "viewer"))
;;       "resource /user/ has expected roles")
;;     ;; Add some resources
;;     (let ((new-resource-ids (loop
;;                               for resource in new-resources
;;                               collect (add-resource *rbac*
;;                                         resource resource roles actor))))
;;       ;; Check that new resource exist now
;;       (is (equal (get-resources :resource-name)
;;             (sort (append existing-resources new-resources) #'string<))
;;         "new resources in database")
;;       ;; All resources, including the new ones, updated by system
;;       (is (equal (sort (u:distinct-values (get-resources :updated-by)) #'string<)
;;             (list actor-id))
;;         "all resources updated by user system")
;;       ;; Soft-delete test-resource-1
;;       (remove-resource *rbac* (car new-resources) actor)
;;       ;; Resource is no longer listed
;;       (is-false (member (car new-resources)
;;                   (get-resources :resource-name)
;;                   :test 'equal)
;;         (format nil "resource ~a no longer listed" (car new-resources)))
;;       ;; Check deleted_at on soft-deleted resource
;;       (is-true (< (- (get-universal-time)
;;                     (get-resource-value (car new-resources) :deleted-at))
;;                  10)
;;         "soft-deleted resource has correct deleted_at timestamp")
;;       ;; Reinstante soft-deleted resource test-resource-1
;;       (is (equal (add-resource *rbac*
;;                    (car new-resources)
;;                    (car new-resources)
;;                    (cons "editor" roles)
;;                    actor)
;;             (car new-resource-ids))
;;         "correctly reinstated soft-deleted resource"))))

;; (test resource-roles-test
;;   (let* ((resource "/test-resource-1/")
;;           (old-resource-roles (list "editor" "test-role" "viewer"))
;;           (actor "system")
;;           (new-rr1 "test-user-1:exclusive")
;;           (new-rr2 "test-user-2:exclusive"))
;;     ;; Check baseline
;;     (is (equal (exclude (list-resource-role-names *rbac* resource) *system-roles*)
;;           old-resource-roles)
;;       (format nil "resource ~a has roles ~{~a~^, ~}"
;;         resource old-resource-roles))
;;     ;; Add some new roles to the resource
;;     (let* ((new-rr1-id (progn
;;                          (add-resource-role *rbac* resource new-rr2 actor)
;;                          (add-resource-role *rbac* resource new-rr1 actor)))
;;             (roles-expected (sort
;;                               (append
;;                                 *system-roles*
;;                                 old-resource-roles
;;                                 (list new-rr1 new-rr2))
;;                               #'string<))
;;             (roles-actual (list-resource-role-names
;;                             *rbac* resource :page-size 100)))
;;       (is (equal roles-actual roles-expected) "new roles were added to resource")
;;       ;; Soft-delete one of the new roles
;;       (is (equal (remove-resource-role *rbac* resource new-rr1 actor) new-rr1-id)
;;         "soft-deleting resource role returns deleted ID")
;;       (is-false (member new-rr1
;;                   (list-resource-role-names *rbac* resource :page-size 100)
;;                   :test 'equal)
;;         (format nil "resource no longer has role ~a" new-rr1))
;;       ;; Reinstate resource role
;;       (is (equal (add-resource-role *rbac* resource new-rr1 actor)
;;             new-rr1-id)
;;         (format nil "role ~a reinstated to resource ~a" new-rr1 resource))
;;       (is-true (member new-rr1
;;                  (list-resource-role-names *rbac* resource :page-size 100)
;;                  :test 'equal)
;;         (format nil "resource ~a has role ~a" resource
;;           new-rr1)))))

;; (test user-allowed-test
;;   (let* ((resource "/test-resource-3/")
;;           (main-user "macnod")
;;           (main-permission "read")
;;           (main-role "test-role")
;;           (exclusive-role "macnod:exclusive")
;;           (actor "system"))
;;     ;; Add the main user
;;     (is (re:scan *uuid-regex* (d-add-user *rbac* main-user "password-1234"))
;;       (format nil "add user ~a" main-user))
;;     ;; 1. User doesn't have read access to resource
;;     (is-false (user-allowed *rbac* main-user main-permission resource)
;;       (format nil "1. user ~a does not have ~a access to resource ~a"
;;         main-user main-permission resource))
;;     ;; 2. Give user read access to resource via main-role
;;     (is-true (add-role-user *rbac* main-role main-user actor)
;;       (format nil "2. add role ~a to user ~a" main-role main-user))
;;     ;; 3. User has read access to resource
;;     (is-true (user-allowed *rbac* main-user main-permission resource)
;;       (format nil "3. user ~a has ~a access to resource ~a"
;;         main-user main-permission resource))
;;     ;; 4. Remove user's read access to resource by removing user from main-role
;;     (is-true (remove-role-user *rbac* main-role main-user actor)
;;       (format nil "4. remove role ~a from user ~a" main-role main-user))
;;     ;; 5. User does not have read access to resource
;;     (is-false (user-allowed *rbac* main-user main-permission resource)
;;       (format nil "5. user ~a does not have ~a access to resource ~a"
;;         main-user main-permission resource))
;;     ;; 6. Restore soft-deleted user's main-role
;;     (is-true (add-role-user *rbac* main-role main-user actor)
;;       (format nil "6. restore soft-deleted role ~a for user ~a"
;;         main-role main-user))
;;     ;; 7. User has read access to resource
;;     (is-true (user-allowed *rbac* main-user main-permission resource)
;;       (format nil "7. user ~a has ~a access to resource ~a"
;;         main-user main-permission resource))
;;     ;; 8. Remove user from role again
;;     (is-true (remove-role-user *rbac* main-role main-user actor)
;;       (format nil "8. remove role ~a from user ~a" main-role main-user))
;;     ;; 9. User does not have read access to resource
;;     (is-false (user-allowed *rbac* main-user main-permission resource)
;;       (format nil "9. user ~a does not have ~a access to resource ~a"
;;         main-user main-permission resource))
;;     ;; 10. Give user access to the resource by adding the user's exclusive role
;;     ;;     to the resource
;;     (is-true (add-resource-role *rbac* resource exclusive-role actor)
;;       (format nil "10. add user ~a's exclusive role to resource ~a"
;;         main-user resource))
;;     ;; 11. User has read access to the resource
;;     (is-true (user-allowed *rbac* main-user main-permission resource)
;;       (format nil "11. user ~a has ~a access to ~a via user's exclusive role."
;;         main-user main-permission resource))
;;     ;; 12. Remove user's access by removing read permission from user's
;;     ;;     exclusive role
;;     (is-true (remove-role-permission *rbac* exclusive-role main-permission actor)
;;       (format nil "12. remove ~a permission from exclusive role ~a."
;;         main-permission exclusive-role))
;;     ;; 13. User does not have read access to resource
;;     (is-false (user-allowed *rbac* main-user main-permission resource)
;;       (format nil "13. user ~a does not have ~a access to resource ~a"
;;         main-user main-permission resource))))

;; (test add-user-add-role-add-resource-test
;;   (is-true (d-add-role *rbac* "re-role") "Create role re-role")
;;   (is-true (d-add-user *rbac* "re-user" "password-1234") "Add user re-user")
;;   (is-true (d-add-resource *rbac* "/re-dir/") "Add resource /re-dir/")
;;   (is-false (user-allowed *rbac* "re-user" "create" "/re-dir/")
;;     "user re-user forbidden create access to /re-dir/ (1)")
;;   (is-true (d-add-user-role *rbac* "re-user" "re-role")
;;     "add role re-role to user re-user (1)")
;;   (is-false (user-allowed *rbac* "re-user" "create" "/re-dir/")
;;     "user re-user forbiden create access to /re-dir/ (2)")
;;   (is-true (d-add-resource-role *rbac* "/re-dir/" "re-role")
;;     "add role re-role to resource /re-dir/")
;;   (is-true (user-allowed *rbac* "re-user" "create" "/re-dir/")
;;     "user re-user has create access to /re-dir/ (1)")
;;   (is-true (d-remove-user-role *rbac* "re-user" "re-role")
;;     "remove role re-role from user re-user")
;;   (is-false (user-allowed *rbac* "re-user" "create" "/re-dir/")
;;     "user re-user forbiden create access to /re-dir/ (3)")
;;   (is-true (d-add-user-role *rbac* "re-user" "re-role")
;;     "add role re-role to user re-user (2)")
;;   (is-true (user-allowed *rbac* "re-user" "create" "/re-dir/")
;;     "user re-user has create access to /re-dir/ (2)")
;;   (is-true (d-remove-role-permission *rbac* "re-role" "create")
;;     "remove create permission from role re-role")
;;   (is-false (member "create" (list-role-permission-names *rbac* "re-role")
;;               :test 'equal)
;;     "role re-role no longer has create permission")
;;   (is-false (user-allowed *rbac* "re-user" "create" "/re-dir/")
;;     "user re-user forbiden create access to /re-dir/ (4)")
;;   (is-true (d-add-role-permission *rbac* "re-role" "create")
;;     "add create permission to role re-role")
;;   (is-true (member "create" (list-role-permission-names *rbac* "re-role")
;;              :test 'equal)
;;     "role re-role has create permission once again")
;;   (is-true (user-allowed *rbac* "re-user" "create" "/re-dir/")
;;     "user re-user has create access to /re-dir/ (2)")
;;   (is-true (list-role-permission-names *rbac* "re-role")
;;     "role re-role has permissions"))

;; (test add-user-login-test
;;   (is-true (d-add-user *rbac* "user-1" "password-1") "add user-1")
;;   (is (equal (get-value *rbac* "users" "last_login" "username" "user-1")
;;         :null)
;;     "last_login null before user login")
;;   (is (re:scan *uuid-regex*
;;         (with-rbac (*rbac*) (d-login *rbac* "user-1" "password-1")))
;;     "first login successful")
;;   (with-rbac (*rbac*)
;;     (let ((login-1 (db:query "select last_login from users where username = $1"
;;                      "user-1" :single))
;;            (now (db:query "select now()" :single)))
;;       (is-true (<= login-1 now) "last_login properly set after user login")
;;       (is (re:scan *uuid-regex*
;;             (d-login *rbac* "user-1" "password-1"))
;;         "second login successful")
;;       (is-true (<=
;;                  (db:query "select last_login from users where username = $1"
;;                    "user-1" :single)
;;                  (db:query "select now()" :single))
;;         "second login happened in the past")
;;       (is-true (<=
;;                  login-1
;;                  (db:query "select last_login from users where username = $1"
;;                    "user-1" :single))
;;         "second login happened after first login"))))

;; (test list-user-resources-test
;;   (is-true (d-add-role *rbac* "role-ur") "add role role-ur")
;;   (is-true (d-add-user *rbac* "user-ur" "password-1" :roles '("role-ur"))
;;     "add user user-ur with role role-ur")
;;   (is (equal (list-user-role-names *rbac* "user-ur")
;;         (sort (copy-seq '("public" "logged-in" "role-ur" "user-ur:exclusive"))
;;           #'string<))
;;     "user-ur has expected roles")
;;   (is-true (d-add-resource *rbac* "/resource-2-1/" :roles '("role-ur"))
;;     "add /resource-2-1/ with role-ur")
;;   (is-true (d-add-resource *rbac* "/resource-2-2/" :roles '("role-ur"))
;;     "add /resource-2-2/ with role-ur")
;;   (is (equal (exclude (list-resource-role-names *rbac* "/resource-2-1/")
;;                *system-roles*)
;;         '("role-ur"))
;;     "resource /resource-2-1/ has single role role-ur")
;;   (is (equal (exclude (list-resource-role-names *rbac* "/resource-2-2/")
;;                *system-roles*)
;;         '("role-ur"))
;;     "resource /resource-2-2/ has single role role-ur")
;;   (let ((user-resources (list "/resource-2-1/" "/resource-2-2/")))
;;     (is (equal (list-user-resource-names *rbac* "user-ur" "read") user-resources)
;;       (format nil "user resources with read: ~{~a~^, ~}" user-resources))))

;; (test list-resource-users-test
;;   (let ((users (mapcar
;;                  (lambda (n) (format nil "user-read-~2,'0d" n))
;;                  (u:range 1 10)))
;;          (role-read "role-read")
;;          (role-create "role-create")
;;          (role-update "role-update")
;;          (resource "/ro-444/"))
;;     ;; Create the roles
;;     (is-true (d-add-role *rbac* role-read :permissions '("read"))
;;       (format nil "add role ~a" role-read))
;;     (is-true (d-add-role *rbac* role-create :permissions '("create"))
;;       (format nil "add role ~a" role-create))
;;     (is-true (d-add-role *rbac* role-update :permissions '("update"))
;;       (format nil "add role ~a" role-update))
;;     (is-true (d-add-permission *rbac* "bogus-permission") "add bogus-permission")
;;     (is-true (d-add-role *rbac* "bogus-role" :permissions '("bogus-permission"))
;;       "add bogus-role with bogus-permission")
;;     ;; First, create user user-read-01 with both role-read and role-create
;;     (is-true (d-add-user *rbac* (car users) (car users)
;;                :roles (list role-read role-create))
;;       (format nil "add user ~a" (car users)))
;;     ;; Add the resource
;;     (is-true (d-add-resource *rbac* resource :roles '("bogus-role"))
;;       (format nil "add resource ~a with bogus-role" resource))
;;     ;; Remove admin role from the new resource
;;     (is-true (d-remove-resource-role *rbac* resource "admin")
;;       (format nil "remove role admin from resource ~a" resource))
;;     ;; The resourse should have no users at all
;;     (is (equal (list-resource-usernames *rbac* resource "read")
;;           (list "system"))
;;       (format nil "resource ~a has no users" resource))
;;     ;; Initially, the user should not have read access to the resource
;;     (is-false (user-allowed *rbac* (car users) "read" resource)
;;       (format nil "user ~a does not have read access to resource ~a"
;;         (car users) resource))
;;     ;; Add role-create to the resource
;;     (is-true (d-add-resource-role *rbac* resource role-create)
;;       (format nil "add role ~a to resource ~a" role-create resource))
;;     ;; The user should still not have read access to the resource
;;     (is-false (user-allowed *rbac* (car users) "read" resource)
;;       (format nil "user ~a does not have 'read' permission on resource ~a"
;;         (car users) resource))
;;     ;; Now add role-read to the resource
;;     (is-true (d-add-resource-role *rbac* resource role-read)
;;       (format nil "add role ~a to resource ~a" role-read resource))
;;     ;; The user should now have read access to the resource
;;     (is-true (user-allowed *rbac* (car users) "read" resource)
;;       (format nil "user ~a has 'read' permission on resource ~a"
;;         (car users) resource))
;;     ;; The list of users with read access should include only this user
;;     ;; and the system users
;;     (is (equal (list-resource-usernames *rbac* resource "read")
;;           (sort (list (car users) "system") #'string<))
;;       (format nil "list-resource-users ~a ~a ~a"
;;         resource "read" (car users)))
;;     ;; Add the rest of the users with read access
;;     (loop for user in (cdr users)
;;       do (is-true (d-add-user *rbac* user user :roles (list role-read))
;;            (format nil "add user ~a with role ~a" user role-read)))
;;     ;; Add a new user with only update access
;;     (is-true (d-add-user *rbac* "user-write-01" "user-write-01"
;;                :roles (list role-update))
;;       (format nil "add user-write-01 with role ~a" role-update))
;;     ;; Add role-update to the resource
;;     (is-true (d-add-resource-role *rbac* resource role-update)
;;       (format nil "add role '~a' to resource '~a'" role-update resource))
;;     ;; This should include only users that have read access. The last user
;;     ;; we added should not be included.
;;     (let ((users-read (exclude
;;                         (list-resource-usernames *rbac* resource "read")
;;                         *system-users*))
;;            (users-create (exclude
;;                            (list-resource-usernames *rbac* resource "create")
;;                            *system-users*))
;;            (users-create-1 (exclude
;;                              (mapcar
;;                                (lambda (user)
;;                                  (getf user :username))
;;                                (list-resource-users *rbac* resource "create"
;;                                  1 20))
;;                              *system-users*)))
;;       (is (equal users-read users)
;;         (format nil "~d users have read access to resource ~a"
;;           (length users-read) resource))
;;       (is (equal users-create (list "user-read-01"))
;;         (format nil "create access to resource ~a: ~{~a~^, ~}"
;;           resource users-create))
;;       (is (equal users-create-1 (list "user-read-01"))
;;         (format nil "create access to resource ~a (usernames): ~{~a~^, ~}"
;;           resource users-create-1)))))

;; (test list-users-filtered-test
;;   (is (equal (mapcar
;;                (lambda (plist) (getf plist :username))
;;                (list-users-filtered
;;                  *rbac* "username" nil '(("username" "like" "user-read-%")) 1 1000))
;;         (mapcar (lambda (u) (format nil "user-read-~2,'0d" u)) (u:range 1 10)))
;;     "list-users-filtered like user-read-%")
;;   (is-false (member
;;               "user-read-1"
;;               (list-users-filtered
;;                 *rbac* "username" nil '(("username" "not like" "user-read-%"))
;;                 1 1000))
;;     "list-users-filtered not like user-read-% does not include user-read-1"))

;; (test counts-test
;;   (is (= (list-users-count *rbac*) 20) "list-users-count")
;;   (is (= (list-users-filtered-count *rbac* '(("email" "=" "no-email"))) 17)
;;     "list-users-filtered-count")
;;   (is (= (list-permissions-count *rbac*) 9) "list-permissions-count")
;;   (is (= (list-roles-count *rbac*) 33) "list-roles-count")
;;   (is (= (list-roles-regular-count *rbac*) 10) "list-roles-regular-count")
;;   (is (= (list-role-permissions-count *rbac* "role-read") 1)
;;     "list-role-permissions-count")
;;   (is (= (list-role-users-count *rbac* "role-read") 10)
;;     "list-role-users-count")
;;   (is (= (list-user-roles-count *rbac* "user-read-01") 5)
;;     "list-user-roles-count")
;;   (is (= (list-user-roles-regular-count *rbac* "user-read-01") 2)
;;     "list-user-roles-regular-count"))

;; (test regular-roles-test
;;   (is (equal (list-user-role-names-regular *rbac* "user-read-01" :page-size 100)
;;         (remove-if
;;           (lambda (r) (re:scan "^(public|logged-in|.+:exclusive)$" r))
;;           (list-user-role-names *rbac* "user-read-01" :page-size 100)))
;;     "Regular roles exclude public, logged-in, and exclusive role"))

;; (test regular-resource-roles-test
;;   (is-true (d-add-role *rbac* "rrr-1") "add role rrr-1")
;;   (is-true (d-add-role *rbac* "rrr-2") "add-role rrr-2")
;;   (is-true (d-add-role *rbac* "rrr-3") "add-role rrr-3")
;;   (is-true (d-add-user *rbac* "rrr-user" "password-rrr-1"
;;              :roles '("rrr-1" "rrr-2" "rrr-3"))
;;     "create a user for the exclusive role")
;;   (is-true (d-add-resource *rbac* "/rrr-test/" :roles '("rrr-1" "rrr-2" "rrr-3"))
;;     "add resource /rrr-test/")
;;   (is (equal (list-resource-role-names *rbac* "/rrr-test/")
;;         (sort
;;           (u:distinct-values
;;             (append
;;               (list-resource-role-names-regular *rbac* "/rrr-test/")
;;               *system-roles*))
;;           #'string<))
;;     "at this point, all resource roles are regular roles (plus system roles)")
;;   (is (equal (list-resource-role-names *rbac* "/rrr-test/")
;;         (sort (append '("rrr-1" "rrr-2" "rrr-3") *system-roles*) #'string<))
;;     "resource has expected roles")
;;   (is-true (d-add-resource-role *rbac* "/rrr-test/" "rrr-user:exclusive"))
;;   (is (equal (list-resource-role-names *rbac* "/rrr-test/")
;;         (sort
;;           (u:distinct-values
;;             (append
;;               (list "rrr-user:exclusive")
;;               *system-roles*
;;               (list-resource-role-names-regular *rbac* "/rrr-test/")))
;;           #'string<))
;;     "after adding exclusive role, list-resource-role-names includes it"))

;; (test user-has-role-test
;;   (is-true (d-add-role *rbac* "uhr-role-1") "add role uhr-role-1")
;;   (is-true (d-add-role *rbac* "uhr-role-2") "add role uhr-role-2")
;;   (is-true (d-add-role *rbac* "uhr-role-3") "add role uhr-role-3")
;;   (is-true (d-add-role *rbac* "uhr-role-4") "add role uhr-role-4")
;;   (is-true (d-add-user *rbac* "uhr-user-1" "uhr-user-1-password")
;;     "add user uhr-user-1")
;;   (is-true (d-add-user *rbac* "uhr-user-2" "uhr-user-2-password")
;;     "add user uhr-user-2")
;;   (is-true (d-add-user-role *rbac* "uhr-user-1" "uhr-role-1")
;;     "add role uhr-role-1 to user uhr-user-1")
;;   (is-true (d-add-user-role *rbac* "uhr-user-1" "uhr-role-2")
;;     "add role uhr-role-2 to user uhr-user-1")
;;   (is-true (d-add-user-role *rbac* "uhr-user-1" "uhr-role-3")
;;     "add role uhr-role-3 to user uhr-user-1")
;;   (is-true (d-add-user-role *rbac* "uhr-user-2" "uhr-role-3")
;;     "add role uhr-role-3 to user uhr-user-2")
;;   (is-true (d-add-user-role *rbac* "uhr-user-2" "uhr-role-4")
;;     "add role uhr-role-4 to user uhr-user-2")
;;   (is-true (user-has-role *rbac* "uhr-user-1" "uhr-role-1")
;;     "user uhr-user-1 has role uhr-role-1")
;;   (is-true (user-has-role *rbac* "uhr-user-1" "uhr-role-2" "uhr-role-3")
;;     "user uhr-user-1 has at least one of uhr-role-2 and uhr-role-3")
;;   (is-true (user-has-role *rbac* "uhr-user-1" "uhr-role-3" "uhr-role-4")
;;     "user uhr-user-1 has at least one of uhr-role-3 and uhr-role-4")
;;   (is-false (user-has-role *rbac* "uhr-user-1" "uhr-role-4")
;;     "user uhr-user-1 does not have role uhr-role-4")
;;   (is-true (user-has-role *rbac* "uhr-user-2" "uhr-role-3" "uhr-role-4")
;;     "user uhr-user-2 has at least one of uhr-role-3 and uhr-role-4")
;;   (is-false (user-has-role *rbac* "uhr-user-2" "uhr-role-1" "uhr-role-2")
;;     "user uhr-user-2 does not have access to uhr-role-1 or uhr-role-2"))

;;; Run tests
(if *run-tests*
  (let ((test-results (run-all-tests)))
    (close-log-stream "tests")
    (unless test-results
      (sb-ext:quit :unix-status 1)))
  (progn
    (pinfo :in "rbac-tests"
      :status "Starting Swank server for interactive debugging"
      :port *swank-port*)
    (defparameter *swank-server* (swank:create-server
                                   :interface "0.0.0.0"
                                   :port *swank-port*
                                   :style :spawn
                                   :dont-close t))
    (pinfo :in "rbac-tests" :status "Swank server started" :port *swank-port*)))
