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
