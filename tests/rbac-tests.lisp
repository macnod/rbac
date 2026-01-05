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
(defparameter *rbac-repl* (u:getenv "RBAC_REPL" :type :boolean :default nil))
(defparameter *swank-port* (u:getenv "SWANK_PORT" :type :integer))

;; Database connection
(defparameter *rbac* (make-instance 'rbac-pg
                       :host *db-host*
                       :port *db-port*
                       :user-name *db-user*
                       :password *db-password*))

;; Test support
(defparameter uuid-regex "^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$")

(setf *default-page-size* 1000)

(when *log-file*
  (make-log-stream "tests" *log-file* :append nil))

(defun clear-database ()
  (loop for user in (u:exclude (list-user-names *rbac*) "system")
    do (remove-user *rbac* user))
  (loop for permission in (u:exclude (list-permission-names *rbac*)
                            *default-permissions*)
    do (remove-permission *rbac* permission))
  (loop for role in (u:exclude (list-role-names *rbac*)
                      '("system" "system:exclusive" "logged-in" "public"))
    do (remove-role *rbac* role))
  (loop for resource in (list-resource-names *rbac*)
    do (remove-resource *rbac* resource))
  t)

(defun is-uuid (s)
  (when (re:scan uuid-regex s) t))

(defun ascii-all ()
  (concatenate 'string
    (u:ascii-alpha-num)
    "[-!@#$%^&*()\+={}[\]|:;<>,.?/~`]"))

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
  (is-true (is-uuid (add-permission *rbac* "bogus-permission")))
  ;; Add a couple of roles
  (is-true (is-uuid (add-role *rbac* "role-a" :permissions '("read"))))
  (is-true (is-uuid (add-role *rbac* "role-b")))
  (is-true (is-uuid (add-role *rbac* "role-c"
                      :permissions (cons "bogus-permission"
                                     *default-permissions*))))
  (is-true (is-uuid (add-role *rbac* "role-d"
                      :permissions '("bogus-permission"))))
  ;; Add a few users
  (loop
    with user-roles = (ds:ds '(:map
                                "user-01" (:list "role-a")
                                "user-02" (:list "role-b")
                                "user-03" (:list "role-a" "role-b")
                                "user-04" (:list "role-c")
                                "user-05" (:list "role-a" "role-c")
                                "user-06" (:list "role-d")))
    for user in (u:hash-keys user-roles)
    for email = (format nil "~a@sinistercode.com" user)
    for password = (format nil "~a-password" user)
    for roles = (gethash user user-roles)
    do (is-true (is-uuid (add-user *rbac* user email password :roles roles))))
  ;; Add a user without roles
  (is-true (is-uuid (add-user *rbac* "user-07" "user-09@sinistercode.com"
                      "user-06-password")))
  ;; Add some resources
  (loop
    with resource-roles = (ds:ds
                            '(:map
                               "test:resource-01" (:list "public")
                               "test:resource-02" (:list "logged-in")
                               "test:resource-03" (:list "system")
                               "test:resource-04" (:list "role-a")
                               "test:resource-05" (:list "role-a")
                               "test:resource-06" (:list "role-c")
                               "test:resource-07" (:list "role-a" "role-b"
                                                    "role-c")
                               "test:resource-08" (:list "role-d")))
    for resource in (u:hash-keys resource-roles)
    for roles = (gethash resource resource-roles)
    do (is-true (is-uuid (add-resource *rbac* resource :roles roles))))
  ;; Add a resource without roles
  (is-true (is-uuid (add-resource *rbac* "test:resource-09")))
  ;; Let's see if everything got added correctly
  ;; Check users, roles, permissions, and resources
  (is (equal (sort (cons "bogus-permission" *default-permissions*) #'string<)
        (list-permission-names *rbac*)))
  (is (equal (u:safe-sort '("role-a" "role-b" "role-c" "role-d"
                             "system" "logged-in" "public"))
        (u:exclude-regex (list-role-names *rbac*) ":exclusive$")))
  (is (equal (loop for a from 1 to 7
               collect (format nil "user-~2,'0d" a))
        (u:exclude (list-user-names *rbac*) "system")))
  (is (equal '("test:resource-01" "test:resource-02"
                "test:resource-03" "test:resource-04"
                "test:resource-05" "test:resource-06"
                "test:resource-07" "test:resource-08"
                "test:resource-09")
        (list-resource-names *rbac*)))
  (is (equal '("read")
        (list-user-resource-permission-names *rbac*
          "user-01" "test:resource-01")))
  (is (equal '("read")
        (list-user-resource-permission-names *rbac*
          "user-01" "test:resource-04")))
  (is (equal *default-permissions*
        (list-user-resource-permission-names *rbac*
          "user-03" "test:resource-07")))
  (is (equal (cons "bogus-permission" *default-permissions*)
        (list-user-resource-permission-names *rbac*
          "user-04" "test:resource-06")))
  (is (equal '("bogus-permission")
        (list-user-resource-permission-names *rbac*
          "user-06" "test:resource-08"))))

(test default-roles
  (clear-database)
  (let ((resource "test:resource")
         (role "custom-role")
         (user "some-user"))
    ;; Add a resource with no roles
    (is-true (is-uuid (add-resource *rbac* resource)))
    ;; Add a custom role
    (is-true (is-uuid (add-role *rbac* role :permissions '("read"))))
    ;; Add a user with the custom role
    (is-true (is-uuid (add-user *rbac* user "no-email" "password-01"
                        :roles (list role))))
    ;; User should have default user roles plus the custom role
    (is (equal (u:safe-sort (cons role *default-user-roles*))
          (list-user-role-names *rbac* user)))
    ;; Resource should have default resource roles
    (is (equal *default-resource-roles*
          (list-resource-role-names *rbac* resource)))
    ;; User should not have any permissions on the resource
    (loop for permission in *default-permissions*
      do (is-false (user-allowed *rbac* user permission resource)))
    (is-false (list-user-resource-permission-names *rbac*
                user resource))
    ;; Add the "logged-in" and custom roles to the resource
    (add-resource-role *rbac* resource "logged-in")
    (add-resource-role *rbac* resource role)
    ;; Now the user should have read permission on the resource
    (is-true (user-allowed *rbac* user "read" resource))
    (is (equal '("read") (list-user-resource-permission-names
                           *rbac* user resource)))
    ;; The default user roles don't have any other permission
    (is-false (user-allowed *rbac* user "create" resource))
    ;; Remove the "logged-in" role from the resource
    (remove-resource-role *rbac* resource "logged-in")
    ;; User should still have read permission on the resource, via the custom
    ;; role
    (is-true (user-allowed *rbac* user "read" resource))
    ;; Remove the custom role from the resource
    (remove-resource-role *rbac* resource role)
    ;; Now the user should not have that read permission anymore
    (is-false (user-allowed *rbac* user "read" resource))
    ;; In fact, the user should have no permissions at all on the resource
    (is-false (list-user-resource-permission-names *rbac* user resource))))

(test permissions-via-multiple-roles
  (clear-database)
  (add-role *rbac* "role-1" :permissions '("read"))
  (add-role *rbac* "role-2" :permissions '("create"))
  (add-role *rbac* "role-3" :permissions '("update"))
  (add-user *rbac* "multi-role-user" "multi@sinistercode.com" "password-01"
    :roles '("role-1" "role-2" "role-3"))
  (add-resource *rbac* "multi-role-resource"
    :roles '("role-1" "role-2" "role-3"))
  (is (equal (u:safe-sort '("create" "read" "update"))
        (list-user-resource-permission-names *rbac*
          "multi-role-user" "multi-role-resource")))
  (is-true (user-allowed *rbac*
             "multi-role-user" "read" "multi-role-resource"))
  (remove-resource-role *rbac* "multi-role-resource" "role-1")
  (remove-resource-role *rbac* "multi-role-resource" "role-2")
  (is-false (user-allowed *rbac*
              "multi-role-user" "read" "multi-role-resource"))
  (is-false (user-allowed *rbac*
              "multi-role-user" "create" "multi-role-resource"))
  (is-true (user-allowed *rbac*
              "multi-role-user" "update" "multi-role-resource"))
  (is (equal '("update")
        (list-user-resource-permission-names *rbac*
          "multi-role-user" "multi-role-resource"))))

(test with-rbac
  (clear-database)
  (with-rbac (*rbac*)
    (is (= 1 (db:query "select count(*) from users where user_name = $1"
               "system" :single)))
    (is (= 1 (rbac-query-single
               '("select count(*) from users where user_name = $1"
                  "system"))))
    (is (= 1 (rbac-query
               '("select count(*) from users where user_name = $1"
                  "system")
               :single)))
    (is (equal '("system")
          (rbac-query
            '("select user_name from users where user_name = $1"
               "system")
            :column)))
    (is (equal '((:user-name "system" :email "no-email"))
          (rbac-query
            '("select user_name, email from users where user_name = $1"
               "system")
            :plists)))))

(test utils
  (is (equal "select a from b where c = e and d = f"
        (usql "select a
               from b
               where c = e
                 and d = f")))
  (is (equal "cats" (plural "cat")))
  (is (equal "cats" (plural "cats")))
  (is (equal "user_id" (rbac::external-reference-field "users")))
  (is (equal "ba5943b4e73f11457efbb7ae7639462f"
        (password-hash "user-01" "password")))
  (is (equal "user-01:exclusive"
        (exclusive-role-for "user-01")))
  (is (equal "Role 'admin'" (rbac::make-description "role" "admin")))
  (is (equal "role_name" (rbac::field-no-prefix "r.role_name")))
  (is (equal (cons 1 "$1") (rbac::render-placeholder 1 1)))
  (is (equal (cons 1 "$2") (rbac::render-placeholder "two" 2)))
  (is (equal (cons 0 "null") (rbac::render-placeholder nil 3)))
  (is (equal (cons 0 "null") (rbac::render-placeholder :null 4)))
  (is (equal (cons 0 "false") (rbac::render-placeholder :false 5)))
  (is (equal (cons 0 "true") (rbac::render-placeholder :true 6)))
  (is (equal 'ALPHA-BRAVO (rbac::name-to-identifier "alpha_bravo" "~a")))
  (is (equal "user" (rbac::singular "users")))
  (is (equal "role_name" (rbac::table-name-field "roles"))))

(test user-name-validation
  (signals error (valid-user-name-p *rbac* nil))
  (signals error (valid-user-name-p *rbac* 1))
  (is-false (valid-user-name-p *rbac* ""))
  (is-false (valid-user-name-p *rbac* "1"))
  (is-false (valid-user-name-p *rbac* "1a"))
  (is-false (valid-user-name-p *rbac* "-"))
  (is-false (valid-user-name-p *rbac* "-a"))
  (is-false (valid-user-name-p *rbac* "user!"))
  (is-false (valid-user-name-p *rbac* "!user"))
  (is-false (valid-user-name-p *rbac* "!"))
  (is-false (valid-user-name-p *rbac* (u:random-string 65 (u:ascii-alpha))))
  (is-true (valid-user-name-p *rbac* (u:random-string 64 (u:ascii-alpha))))
  (is-true (valid-user-name-p *rbac* "a1"))
  (is-true (valid-user-name-p *rbac* "a-"))
  (is-true (valid-user-name-p *rbac* "a_"))
  (is-true (valid-user-name-p *rbac* "ABC-def+123")))

(test password-validation
  (signals error (valid-password-p *rbac* nil))
  (signals error (valid-password-p *rbac* 1))
  (is-false (valid-password-p *rbac* ""))
  (is-false (valid-password-p *rbac* "12345"))
  (is-false (valid-password-p *rbac* "123456"))
  (is-false (valid-password-p *rbac* "password"))
  (is-false (valid-password-p *rbac* "password1"))
  (is-false (valid-password-p *rbac* "password⋮"))
  (is-true (valid-password-p *rbac* "password-01"))
  (is-true (valid-password-p *rbac* "1-password"))
  (is-false (valid-password-p *rbac* "pass1"))
  (is-true (valid-password-p *rbac* "pass-1"))
  (is-true (valid-password-p *rbac* "/complex_Pass0rd!"))
  (is-true (valid-password-p *rbac* (u:random-string 64 (ascii-all))))
  (is-false (valid-password-p *rbac* (u:random-string 65 (ascii-all)))))

(test email-validation
  (signals error (valid-email-p *rbac* nil))
  (signals error (valid-email-p *rbac* 1))
  (is-false (valid-email-p *rbac* ""))
  (is-false (valid-email-p *rbac* "plainaddress"))
  (is-false (valid-email-p *rbac* "@no-local-part.com"))
  (is-false (valid-email-p *rbac* "Outlook Contact <"))
  (is-false (valid-email-p *rbac* "example.com"))
  (is-false (valid-email-p *rbac* "user@"))
  (is-false (valid-email-p *rbac* "user@.com"))
  (is-false (valid-email-p *rbac* "user@com"))
  (is-false (valid-email-p *rbac* "user@site..com"))
  (is-false (valid-email-p *rbac* "abc@def@site.com"))
  (is-false (valid-email-p *rbac*
              (format nil "~a@site.com" (u:random-string 120 (u:ascii-alpha)))))
  (is-true (valid-email-p *rbac* "user@site.com"))
  (is-true (valid-email-p *rbac*
             (format nil "~a@site.com" (u:random-string 119 (u:ascii-alpha)))))
  (is-true (valid-email-p *rbac* "no-email")))

(test role-validation
  (signals error (valid-role-p *rbac* nil))
  (signals error (valid-role-p *rbac* 1))
  (is-false (valid-role-p *rbac* ""))
  (is-false (valid-role-p *rbac* "1role"))
  (is-false (valid-role-p *rbac* "-role"))
  (is-false (valid-role-p *rbac* "role!"))
  (is-false (valid-role-p *rbac* "!role"))
  (is-false (valid-role-p *rbac* "!"))
  (is-false (valid-role-p *rbac* (u:random-string 65 (u:ascii-alpha-lower))))
  (is-true (valid-role-p *rbac* (u:random-string 64 (u:ascii-alpha-lower))))
  (is-true (valid-role-p *rbac* "role-01"))
  (is-false (valid-role-p *rbac* "ROLE_02"))
  (is-true (valid-role-p *rbac* "role_02"))
  (is-false (valid-role-p *rbac* "Role+03"))
  (is-true (valid-role-p *rbac* "role+03"))
  (is-true (valid-role-p *rbac* "admin"))
  (is-true (valid-role-p *rbac* "logged-in"))
  (is-true (valid-role-p *rbac* "public")))

(test resource-validation
  (signals error (valid-resource-p *rbac* nil))
  (signals error (valid-resource-p *rbac* 1))
  (is-false (valid-resource-p *rbac* ""))
  (is-false (valid-resource-p *rbac* "resource!"))
  (is-false (valid-resource-p *rbac* "-resource"))
  (is-false (valid-resource-p *rbac* "resource:-one"))
  (is-true (valid-resource-p *rbac* "resource-"))
  (is-true (valid-resource-p *rbac* "resource:one"))
  (is-true (valid-resource-p *rbac* "resource:one-"))
  (is-true (valid-resource-p *rbac* "resource:one-two-12"))
  (is-false (valid-resource-p *rbac* ":resource"))
  (is-true (valid-resource-p *rbac* "a:one-1"))
  (is-true (valid-resource-p *rbac* "a:1-one"))
  (is-false (valid-resource-p *rbac* "1-a:one"))
  (is-true (valid-resource-p *rbac* "a-1:one"))
  (is-true (valid-resource-p *rbac*
             (format nil "x~a:x~a"
               (u:random-string 6 (u:ascii-alpha-num))
               (u:random-string (- (rbac::resource-length-max *rbac*) 9)
                 (u:ascii-alpha-num)))))
  (is-false (valid-resource-p *rbac*
              (format nil "x~a:x~a"
                (u:random-string 6 (u:ascii-alpha-num))
                (u:random-string (- (rbac::resource-length-max *rbac*) 8)
                  (u:ascii-alpha-num))))))

(test description-validation
  (signals error (valid-description-p *rbac* nil))
  (signals error (valid-description-p *rbac* 1))
  (is-false (valid-description-p *rbac* ""))
  (is-false (valid-description-p *rbac* (u:random-string 257 (ascii-all))))
  (is-true (valid-description-p *rbac* (u:random-string 256 (ascii-all)))))

(test link-user-roles
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (add-user *rbac* "user-1" "no-email" "password-01")
  (add-user *rbac* "user-2" "no-email" "password-02")
  (is-false (u:exclude (list-user-role-names *rbac* "user-1")
              *default-user-roles*))
  (is-false (u:exclude (list-user-role-names *rbac* "user-2")
              *default-user-roles*))
  (is-true (is-uuid (rbac::link *rbac* "users" "roles" "user-1" "role-1")))
  (rbac::link *rbac* "users" "roles" "user-1" "role-2")
  (is (equal '("role-1" "role-2")
        (u:exclude (list-user-role-names *rbac* "user-1")
          *default-user-roles*)))
  (is-false (u:exclude (list-user-role-names *rbac* "user-2")
              *default-user-roles*)))

(test link-resource-roles
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (add-resource *rbac* "resource-1")
  (add-resource *rbac* "resource-2")
  (is-false (u:exclude (list-resource-role-names *rbac* "resource-1")
              *default-resource-roles*))
  (is-false (u:exclude (list-resource-role-names *rbac* "resource-2")
              *default-resource-roles*))
  (rbac::link *rbac* "resources" "roles" "resource-1" "role-1")
  (rbac::link *rbac* "resources" "roles" "resource-1" "role-2")
  (is (equal '("role-1" "role-2")
        (u:exclude (list-resource-role-names *rbac* "resource-1")
          *default-resource-roles*)))
  (is-false (u:exclude (list-resource-role-names *rbac* "resource-2")
              *default-resource-roles*)))

(test link-role-permissions
  (clear-database)
  (add-permission *rbac* "permission-1")
  (add-permission *rbac* "permission-2")
  (add-role *rbac* "role-1")
  (is-false (u:exclude (list-role-permission-names *rbac* "role-1")
              *default-permissions*))
  (rbac::link *rbac* "roles" "permissions" "role-1" "permission-1")
  (rbac::link *rbac* "roles" "permissions" "role-1" "permission-2")
  (is (equal '("permission-1" "permission-2")
        (u:exclude (list-role-permission-names *rbac* "role-1")
          *default-permissions*))))

(test link-user-resources
  (clear-database)
  (add-user *rbac* "user-1" "no-email" "password-01")
  (add-resource *rbac* "resource-1")
  (add-role *rbac* "role-1")
  (is-false (list-user-resource-permission-names *rbac* "user-1" "resource-1"))
  (is-false (user-allowed *rbac* "user-1" "read" "resource-1"))
  (rbac::link *rbac* "users" "roles" "user-1" "role-1")
  (rbac::link *rbac* "resources" "roles" "resource-1" "role-1")
  (is-true (list-user-resource-permission-names *rbac* "user-1" "resource-1")
    *default-permissions*)
  (is-true (user-allowed *rbac* "user-1" "read" "resource-1")))

(test unlink-user-roles
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (add-user *rbac* "user-1" "no-email" "password-01"
    :roles '("role-1" "role-2"))
  (is (equal '("role-1" "role-2")
        (u:exclude (list-user-role-names *rbac* "user-1")
          *default-user-roles*)))
  (rbac::unlink *rbac* "users" "roles" "user-1" "role-1")
  (is (equal '("role-2")
        (u:exclude (list-user-role-names *rbac* "user-1")
          *default-user-roles*)))
  (rbac::unlink *rbac* "users" "roles" "user-1" "role-2")
  (is-false (u:exclude (list-user-role-names *rbac* "user-1")
              *default-user-roles*)))

(test get-value
  (clear-database)
  (let ((user-id (add-user *rbac* "user-1" "no-email" "password-01"))
         (role-id (add-role *rbac* "role-1" :description "test role"))
         (resource-id (add-resource *rbac* "resource-1"
                        :description "test resource"))
         (permission-id (add-permission *rbac* "permission-1"
                          :description "test permission"))
         (user-role-id (rbac::link *rbac* "users" "roles" "user-1" "role-1")))
    (is (equal user-id
          (get-value *rbac* "users" "id" "user_name" "user-1")))
    (is (equal "user-1"
          (get-value *rbac* "users" "user_name" "id" user-id)))
    (is (equal "no-email"
          (get-value *rbac* "users" "email" "id" user-id)))
    (is (equal role-id
          (get-value *rbac* "roles" "id" "role_name" "role-1")))
    (is (equal "role-1"
          (get-value *rbac* "roles" "role_name" "id" role-id)))
    (is (equal "test role"
          (get-value *rbac* "roles" "role_description" "id" role-id)))
    (is (equal resource-id
          (get-value *rbac* "resources" "id" "resource_name" "resource-1")))
    (is (equal "resource-1"
          (get-value *rbac* "resources" "resource_name" "id" resource-id)))
    (is (equal "test resource"
          (get-value *rbac* "resources" "resource_description"
            "id" resource-id)))
    (is (equal permission-id
          (get-value *rbac* "permissions" "id" "permission_name"
            "permission-1")))
    (is (equal "permission-1"
          (get-value *rbac* "permissions" "permission_name" "id" permission-id)))
    (is (equal "test permission"
          (get-value *rbac* "permissions" "permission_description"
            "id" permission-id)))
    (is (equal user-role-id
          (get-value *rbac* "role_users" "id"
            "user_id" user-id "role_id" role-id)))))

(test validate-login-params
  (is-false (rbac::validate-login-params *rbac* "amy" "password"))
  (is-true (rbac::validate-login-params *rbac* "amy" "password-01"))
  (is-false (rbac::validate-login-params *rbac* "1-bob" "password-02")))

(test exclusive-role
  (clear-database)
  (let ((user-id (add-user *rbac* "user-1" "no-email" "password-01"))
         (role-id (get-id *rbac* "roles" (exclusive-role-for "user-1"))))
  (is-true (member (exclusive-role-for "user-1")
             (list-role-names *rbac*) :test #'equal))
  (is-uuid (get-value *rbac* "role_users" "id"
             "role_id" role-id "user_id" user-id))))

(test get-id
  (clear-database)
  (let ((user-id (add-user *rbac* "user-1" "no-email" "password-01"))
         (role-id (add-role *rbac* "role-1"))
         (resource-id (add-resource *rbac* "resource-1"))
         (permission-id (add-permission *rbac* "permission-1")))
    (is (equal user-id (get-id *rbac* "users" "user-1")))
    (is (equal role-id (get-id *rbac* "roles" "role-1")))
    (is (equal resource-id (get-id *rbac* "resources" "resource-1")))
    (is (equal permission-id (get-id *rbac* "permissions" "permission-1")))
    (signals error (get-id *rbac* "resource_roles" "resource-1"))))

(test compute-link-table-name
  (is (equal "role_users"
        (rbac::compute-link-table-name *rbac* "users" "roles")))
  (is (equal "role_users"
        (rbac::compute-link-table-name *rbac* "roles" "users")))
  (is (equal "resource_roles"
        (rbac::compute-link-table-name *rbac* "roles" "resources")))
  (is (equal "role_permissions"
        (rbac::compute-link-table-name *rbac* "roles" "permissions")))
  (signals error (rbac::compute-link-table-name *rbac* "users" "resources")))

(test user-has-role
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (add-role *rbac* "role-3")
  (add-user *rbac* "user-1" "no-email" "password-01" :roles '("role-1"))
  (add-user *rbac* "user-2" "no-email" "password-02" :roles '("role-2" "role-3"))
  (is-true (user-has-role *rbac* "user-1" "role-1"))
  (is-true (user-has-role *rbac* "user-1" "role-3" "role-2" "role-1"))
  (is-true (user-has-role *rbac* "user-2" "role-1" "role-2" "role-3"))
  (is-false (user-has-role *rbac* "user-1" "role-2" "role-3"))
  (is-false (user-has-role *rbac* "user-1" "role-3"))
  (is-false (user-has-role *rbac* "user-2" "role-1")))

(test remove-user
  (clear-database)
  (is-false (member "user-1" (list-user-names *rbac*) :test #'equal))
  (add-user *rbac* "user-1" "no-email" "password-01")
  (is-true (member "user-1" (list-user-names *rbac*) :test #'equal))
  (remove-user *rbac* "user-1")
  (is-false (member "user-1" (list-user-names *rbac*) :test #'equal)))

(test remove-role
  (clear-database)
  (is-false (member "role-1" (list-role-names *rbac*) :test #'equal))
  (is-false (member "role-2" (list-role-names *rbac*) :test #'equal))
  (let ((role-1-id (add-role *rbac* "role-1"))
         (role-2-id (add-role *rbac* "role-2"))
         (user-id (add-user *rbac* "user-1" "no-email" "password-01"
                    :roles '("role-1" "role-2"))))
    (u:has (list-role-names *rbac*) '("role-1" "role-2"))
    (is-true (u:has (list-user-role-names *rbac* "user-1")
               '("role-1" "role-2")))
    (is-true (get-value *rbac* "role_users" "id"
               "role_id" role-1-id "user_id" user-id))
    (is-true (get-value *rbac* "role_users" "id"
               "role_id" role-2-id "user_id" user-id))
    (remove-role *rbac* "role-1")
    (is-false (u:has (list-role-names *rbac*) "role-1"))
    (is-false (u:has (list-user-role-names *rbac* "user-1") "role-1"))
    (is-true (u:has (list-user-role-names *rbac* "user-1") "role-2"))
    (is-false (get-value *rbac* "role_users" "id"
                "role_id" role-1-id "user_id" user-id))
    (is-true (u:has (list-user-names *rbac*) "user-1"))))

(test remove-resource
  (clear-database)
  (is-false (u:has (list-resource-names *rbac*) "resource-1"))
  (let ((role-id (add-role *rbac* "role-1"))
         (resource-id (add-resource *rbac* "resource-1" :roles '("role-1"))))
    (add-resource *rbac* "resource-2")
    (is-true (u:has (list-resource-names *rbac*) "resource-1"))
    (is-true (u:has (list-resource-role-names *rbac* "resource-1") "role-1"))
    (is-true (get-value *rbac* "resource_roles" "id"
               "resource_id" resource-id "role_id" role-id))
    (remove-resource *rbac* "resource-1")
    (is-false (u:has (list-resource-names *rbac*) "resource-1"))
    (is-false (u:has (list-resource-role-names *rbac* "resource-1") "role-1"))
    (is-false (get-value *rbac* "resource_roles" "id"
                "resource_id" resource-id "role_id" role-id))
    (is-true (u:has (list-resource-names *rbac*) "resource-2"))))

(test remove-permission
  (clear-database)
  (is-false (u:has (list-permission-names *rbac*) "permission-1"))
  (let ((permission-id (add-permission *rbac* "permission-1"))
         (role-id (progn (add-permission *rbac* "permission-2")
                    (add-role *rbac* "role-1"
                      :permissions '("permission-1" "permission-2")))))
    (is-true (u:has (list-permission-names *rbac*) "permission-1"))
    (is-true (u:has (list-role-permission-names *rbac* "role-1")
               '("permission-1" "permission-2")))
    (is-true (get-value *rbac* "role_permissions" "id"
                "role_id" role-id "permission_id" permission-id))
    (remove-permission *rbac* "permission-1")
    (is-false (u:has (list-permission-names *rbac*) "permission-1"))
    (is-false (u:has (list-role-permission-names *rbac* "role-1")
                "permission-1"))
    (is-false (get-value *rbac* "role_permissions" "id"
                "role_id" role-id "permission_id" permission-id))
    (is-true (u:has (list-permission-names *rbac*) "permission-2"))
    (is-true (u:has (list-role-permission-names *rbac* "role-1")
               "permission-2"))))

(test manage-role-permissions
  (clear-database)
  (add-permission *rbac* "permission-1")
  (add-permission *rbac* "permission-2")
  (add-role *rbac* "role-1")
  (is-false (u:has (list-role-permission-names *rbac* "role-1")
              '("permission-1" "permission-2")))
  (add-role-permission *rbac* "role-1" "permission-1")
  (add-role-permission *rbac* "role-1" "permission-2")
  (is-true (u:has (list-role-permission-names *rbac* "role-1")
             '("permission-1" "permission-2")))
  (remove-role-permission *rbac* "role-1" "permission-1")
  (is-false (u:has (list-role-permission-names *rbac* "role-1") "permission-1"))
  (is-true (u:has (list-role-permission-names *rbac* "role-1") "permission-2")))

(test manage-role-users
  (clear-database)
  (add-role *rbac* "role-1")
  (add-user *rbac* "user-1" "no-email" "password-01")
  (add-user *rbac* "user-2" "no-email" "password-02")
  (is-false (u:has (list-user-role-names *rbac* "user-1") "role-1"))
  (is-false (u:has (list-user-role-names *rbac* "user-2") "role-1"))
  (add-role-user *rbac* "role-1" "user-1")
  (add-role-user *rbac* "role-1" "user-2")
  (is-true (u:has (list-user-role-names *rbac* "user-1") "role-1"))
  (is-true (u:has (list-user-role-names *rbac* "user-2") "role-1"))
  (remove-role-user *rbac* "role-1" "user-1")
  (is-false (u:has (list-user-role-names *rbac* "user-1") "role-1"))
  (is-true (u:has (list-user-role-names *rbac* "user-2") "role-1")))

(test manage-user-roles
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (add-user *rbac* "user-1" "no-email" "password-01")
  (is-false (u:has (list-user-role-names *rbac* "user-1")
              '("role-1" "role-2")))
  (add-user-role *rbac* "user-1" "role-1")
  (add-user-role *rbac* "user-1" "role-2")
  (is-true (u:has (list-user-role-names *rbac* "user-1")
             '("role-1" "role-2")))
  (remove-user-role *rbac* "user-1" "role-1")
  (is-false (u:has (list-user-role-names *rbac* "user-1") "role-1"))
  (is-true (u:has (list-user-role-names *rbac* "user-1") "role-2")))

(test manage-resource-roles
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (add-resource *rbac* "resource-1")
  (is-false (u:has (list-resource-role-names *rbac* "resource-1")
              '("role-1" "role-2")))
  (add-resource-role *rbac* "resource-1" "role-1")
  (add-resource-role *rbac* "resource-1" "role-2")
  (is-true (u:has (list-resource-role-names *rbac* "resource-1")
             '("role-1" "role-2")))
  (remove-resource-role *rbac* "resource-1" "role-1")
  (is-false (u:has (list-resource-role-names *rbac* "resource-1") "role-1"))
  (is-true (u:has (list-resource-role-names *rbac* "resource-1") "role-2")))

(test list-users
  (clear-database)
  (add-user *rbac* "user-1" "no-email" "password-01")
  (add-user *rbac* "user-2" "no-email" "password-02")
  (let ((users (list-users *rbac*)))
    (is (= 3 (length users)))
    (is (equal '("system" "user-1" "user-2")
          (mapcar (lambda (user) (getf user :user-name)) users)))
    (is-true (every (lambda (u) (is-uuid (getf u :id))) users))
    (is-true (every (lambda (u) (integerp (getf u :created-at))) users))
    (is-true (every (lambda (u) (integerp (getf u :updated-at))) users))
    (is-true (every (lambda (u) (equal (getf u :email) "no-email")) users))
    (is-true (every (lambda (u) (equal (getf u :last-login) :null)) users))
    (is-true (every (lambda (u)
                      (re:scan "^[a-f0-9]{32}$" (getf u :password-hash)))
               users)))
  (is (equal '("system" "user-1" "user-2") (list-user-names *rbac*)))
  (is (= 3 (user-count *rbac*))))

(test list-roles
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (let ((all-roles (list-role-names *rbac*))
         (roles (list-roles *rbac*)))
    (is (= 6 (length roles)))
    (is (equal all-roles (mapcar (lambda (r) (getf r :role-name)) roles)))
    (is-true (every (lambda (r) (is-uuid (getf r :id))) roles))
    (is-true (every (lambda (r) (integerp (getf r :created-at))) roles))
    (is-true (every (lambda (r) (integerp (getf r :updated-at))) roles))
    (is-true (every (lambda (r)
                      (let ((desc (getf r :role-description)))
                        (and (stringp desc)
                          (<= (length desc) 256)
                          (> (length desc) 0))))
               roles))
    (is-true (every (lambda (r)
                      (if (re:scan ":exclusive$" (getf r :role-name))
                        (getf r :exclusive)
                        (not (getf r :exclusive))))
               roles))
    (is (= (length all-roles) (role-count *rbac*)))))

(test list-permissions
  (clear-database)
  (add-permission *rbac* "permission-1")
  (add-permission *rbac* "permission-2")
  (let ((all-permissions (list-permission-names *rbac*))
         (permissions (list-permissions *rbac*)))
    (is (= 6 (length permissions)))
    (is (equal all-permissions
          (mapcar (lambda (p) (getf p :permission-name)) permissions)))
    (is-true (every (lambda (p) (is-uuid (getf p :id))) permissions))
    (is-true (every (lambda (p) (integerp (getf p :created-at))) permissions))
    (is-true (every (lambda (p) (integerp (getf p :updated-at))) permissions))
    (is-true (every (lambda (p)
                      (let ((desc (getf p :permission-description)))
                        (and (stringp desc)
                          (<= (length desc) 256)
                          (> (length desc) 0))))
               permissions))
    (is (= (length all-permissions) (permission-count *rbac*)))))

(test list-resources
  (clear-database)
  (add-resource *rbac* "resource-1")
  (add-resource *rbac* "resource-2")
  (let ((all-resources (list-resource-names *rbac*))
         (resources (list-resources *rbac*)))
    (is (= 2 (length resources)))
    (is (equal all-resources
          (mapcar (lambda (r) (getf r :resource-name)) resources)))
    (is-true (every (lambda (r) (is-uuid (getf r :id))) resources))
    (is-true (every (lambda (r) (integerp (getf r :created-at))) resources))
    (is-true (every (lambda (r) (integerp (getf r :updated-at))) resources))
    (is-true (every (lambda (r)
                      (let ((desc (getf r :resource-description)))
                        (and (stringp desc)
                          (<= (length desc) 256)
                          (> (length desc) 0))))
               resources))
    (is (= (length all-resources) (resource-count *rbac*)))))

(test list-user-roles
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (add-user *rbac* "user-1" "no-email" "password-01"
    :roles '("role-1" "role-2"))
  (let ((user-role-names (list-user-role-names *rbac* "user-1"))
         (user-roles (list-user-roles *rbac* "user-1")))
    (is (= 4 (length user-roles)))
    (is (equal user-role-names
          (mapcar (lambda (r) (getf r :role-name)) user-roles)))
    (is-true (every (lambda (r) (is-uuid (getf r :role-user-id))) user-roles))
    (is-true (every (lambda (r) (integerp (getf r :role-user-created-at))) user-roles))
    (is-true (every (lambda (r) (integerp (getf r :role-user-updated-at))) user-roles))
    (is-true (every (lambda (r) (is-uuid (getf r :user-id))) user-roles))
    (is-true (every (lambda (r) (integerp (getf r :user-created-at))) user-roles))
    (is-true (every (lambda (r) (integerp (getf r :user-updated-at))) user-roles))
    (is-true (every (lambda (r) (equal (getf r :user-last-login) :null)) user-roles))
    (is-true (every (lambda (r) (equal (getf r :user-email) "no-email")) user-roles))
    (is-true (every (lambda (r) (is-uuid (getf r :role-id))) user-roles))
    (is-true (every (lambda (r) (integerp (getf r :role-created-at))) user-roles))
    (is-true (every (lambda (r) (integerp (getf r :role-updated-at))) user-roles))
    (is-true (every (lambda (r)
                      (let ((desc (getf r :role-description)))
                        (and (stringp desc)
                          (<= (length desc) 256)
                          (> (length desc) 0))))
               user-roles))
    (is-true (every (lambda (r)
                      (if (re:scan ":exclusive$" (getf r :role-name))
                        (getf r :role-exclusive)
                        (not (getf r :role-exclusive))))
               user-roles))
    (is (= (length user-role-names) (user-role-count *rbac* "user-1")))))

(test list-role-permissions
  (clear-database)
  (add-permission *rbac* "permission-1")
  (add-permission *rbac* "permission-2")
  (add-role *rbac* "role-1" :permissions '("permission-1" "permission-2"))
  (let ((role-permission-names (list-role-permission-names *rbac* "role-1"))
         (role-permissions (list-role-permissions *rbac* "role-1")))
    (is (= 2 (length role-permissions)))
    (is (equal role-permission-names
          (mapcar (lambda (p) (getf p :permission-name)) role-permissions)))
    (is-true (every (lambda (p) (is-uuid (getf p :role-permission-id)))
               role-permissions))
    (is-true (every (lambda (p) (integerp (getf p :role-permission-created-at)))
               role-permissions))
    (is-true (every (lambda (p) (integerp (getf p :role-permission-updated-at)))
               role-permissions))
    (is-true (every (lambda (p) (is-uuid (getf p :role-id))) role-permissions))
    (is-true (every (lambda (p) (integerp (getf p :role-created-at)))
               role-permissions))
    (is-true (every (lambda (p) (integerp (getf p :role-updated-at)))
               role-permissions))
    (is (equal (length role-permission-names)
          (role-permission-count *rbac* "role-1")))))

(test list-role-users
  (clear-database)
  (add-role *rbac* "role-1")
  (add-user *rbac* "user-1" "no-email" "password-01" :roles '("role-1"))
  (add-user *rbac* "user-2" "no-email" "password-02" :roles '("role-1"))
  (let ((role-user-names (list-role-user-names *rbac* "role-1"))
         (role-users (list-role-users *rbac* "role-1")))
    (is (= 2 (length role-users)))
    (is (equal role-user-names
          (mapcar (lambda (u) (getf u :user-name)) role-users)))
    (is-true (every (lambda (u) (is-uuid (getf u :role-user-id))) role-users))
    (is-true (every (lambda (u) (integerp (getf u :role-user-created-at))) role-users))
    (is-true (every (lambda (u) (integerp (getf u :role-user-updated-at))) role-users))
    (is-true (every (lambda (u) (is-uuid (getf u :user-id))) role-users))
    (is-true (every (lambda (u) (integerp (getf u :user-created-at))) role-users))
    (is-true (every (lambda (u) (integerp (getf u :user-updated-at))) role-users))
    (is-true (every (lambda (u) (equal (getf u :user-last-login) :null)) role-users))
    (is-true (every (lambda (u) (equal (getf u :user-email) "no-email")) role-users))
    (is (= (length role-user-names)
          (role-user-count *rbac* "role-1")))))

(test list-role-resources
  (clear-database)
  (add-role *rbac* "role-1")
  (add-resource *rbac* "resource-1" :roles '("role-1"))
  (add-resource *rbac* "resource-2" :roles '("role-1"))
  (let ((role-resource-names (list-role-resource-names *rbac* "role-1"))
         (role-resources (list-role-resources *rbac* "role-1")))
    (is (= 2 (length role-resources)))
    (is (equal role-resource-names
          (mapcar (lambda (r) (getf r :resource-name)) role-resources)))
    (is-true (every (lambda (r) (is-uuid (getf r :resource-role-id)))
               role-resources))
    (is-true (every (lambda (r) (integerp (getf r :resource-role-created-at)))
               role-resources))
    (is-true (every (lambda (r) (integerp (getf r :resource-role-updated-at)))
               role-resources))
    (is-true (every (lambda (r) (is-uuid (getf r :role-id))) role-resources))
    (is-true (every (lambda (r) (integerp (getf r :role-created-at)))
               role-resources))
    (is-true (every (lambda (r) (integerp (getf r :role-updated-at)))
               role-resources))
    (is (= (length role-resource-names)
          (role-resource-count *rbac* "role-1")))))

(test list-resource-roles
  (clear-database)
  (add-role *rbac* "role-1")
  (add-role *rbac* "role-2")
  (add-resource *rbac* "resource-1" :roles '("role-1" "role-2"))
  (let ((resource-role-names (list-resource-role-names *rbac* "resource-1"))
         (resource-roles (list-resource-roles *rbac* "resource-1")))
    (is (= 3 (length resource-roles)))
    (is (equal resource-role-names
          (mapcar (lambda (r) (getf r :role-name)) resource-roles)))
    (is-true (every (lambda (r) (is-uuid (getf r :resource-role-id)))
               resource-roles))
    (is-true (every (lambda (r) (integerp (getf r :resource-role-created-at)))
               resource-roles))
    (is-true (every (lambda (r) (integerp (getf r :resource-role-updated-at)))
               resource-roles))
    (is-true (every (lambda (r) (is-uuid (getf r :role-id))) resource-roles))
    (is-true (every (lambda (r) (integerp (getf r :role-created-at)))
               resource-roles))
    (is-true (every (lambda (r) (integerp (getf r :role-updated-at)))
               resource-roles))
    (is (= (length resource-role-names)
          (resource-role-count *rbac* "resource-1")))))

(test list-user-resources
  (clear-database)
  (add-role *rbac* "role-1")
  (add-user *rbac* "user-1" "no-email" "password-01" :roles '("role-1"))
  (add-resource *rbac* "resource-1" :roles '("role-1"))
  (add-resource *rbac* "resource-2" :roles '("role-1"))
  (let ((user-resource-names (list-user-resource-names *rbac* "user-1" "read"))
         (user-resources (list-user-resources *rbac* "user-1" "read")))
    (is (= 2 (length user-resources)))
    (is (equal user-resource-names
          (mapcar (lambda (r) (getf r :resource-name)) user-resources)))
    (is (= (length user-resource-names)
          (user-resource-count *rbac* "user-1" "read")))))

(test list-resource-users
  (clear-database)
  (add-role *rbac* "role-1")
  (add-resource *rbac* "resource-1" :roles '("role-1"))
  (add-user *rbac* "user-1" "no-email" "password-01" :roles '("role-1"))
  (add-user *rbac* "user-2" "no-email" "password-02" :roles '("role-1"))
  (let ((resource-user-names (list-resource-user-names *rbac* "resource-1" "read"))
         (resource-users (list-resource-users *rbac* "resource-1" "read")))
    (is (= 3 (length resource-users)))
    (is (equal resource-user-names
          (mapcar (lambda (u) (getf u :user-name)) resource-users)))
    (is (= (length resource-user-names)
          (resource-user-count *rbac* "resource-1" "read")))))

(test list-user-resource-permission-names
  (clear-database)
  (add-role *rbac* "role-1" :permissions '("create" "read"))
  (add-role *rbac* "role-2" :permissions '("delete"))
  (add-user *rbac* "user-1" "no-email" "password-01" :roles '("role-1" "role-2"))
  (add-resource *rbac* "resource-1" :roles '("role-1"))
  (is (equal '("create" "read")
        (list-user-resource-permission-names *rbac* "user-1" "resource-1")))
  (add-resource-role *rbac* "resource-1" "role-2")
  (is (equal '("create" "delete" "read")
        (list-user-resource-permission-names *rbac* "user-1" "resource-1"))))

;;; Run tests
(if *run-tests*
  (let ((test-results (run-all-tests)))
    (close-log-stream "tests")
    (unless test-results
      (sb-ext:quit :unix-status 1)))
  (if *rbac-repl*
    (progn
      (pinfo :in "rbac-tests"
        :status "Starting Swank server for interactive debugging"
        :port *swank-port*)
      (defparameter *swank-server* (swank:create-server
                                     :interface "0.0.0.0"
                                     :port *swank-port*
                                     :style :spawn
                                     :dont-close t))
      (pinfo :in "rbac-tests" :status "Swank server started" :port *swank-port*))
    (format t "Compiled and loaded.~%")))
