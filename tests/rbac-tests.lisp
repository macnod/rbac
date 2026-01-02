(require :asdf)
(require :fiveam)
(require :cl-ppcre)
(require :postmodern)
(require :uiop)
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
  (is-true (is-uuid (add-permission *rbac* "bogus-permission")))

  ;; Add a couple of roles
  (is-true (is-uuid (add-role *rbac* "role-a" :permissions '("read"))))
  (is-true (is-uuid (add-role *rbac* "role-b")))
  (is-true (is-uuid (add-role *rbac* "role-c"
                      :permissions (cons "bogus-permission"
                                     *default-permissions*))))

  ;; Add a few users
  (loop
    with user-roles = (ds:ds '(:map
                                "user-01" (:list "role-a")
                                "user-02" (:list "role-b")
                                "user-03" (:list "role-a" "role-b")
                                "user-04" (:list "role-c")
                                "user-05" (:list "role-a" "role-c")))
    for user in (u:hash-keys user-roles)
    for email = (format nil "~a@sinistercode.com" user)
    for password = (format nil "~a-password" user)
    for roles = (gethash user user-roles)
    do (is-true (is-uuid (add-user *rbac* user email password :roles roles))))

  ;; Add a user without roles
  (is-true (is-uuid (add-user *rbac* "user-06" "user-09@sinistercode.com"
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
                                                    "role-c")))
    for resource in (u:hash-keys resource-roles)
    for roles = (gethash resource resource-roles)
    do (is-true (is-uuid (add-resource *rbac* resource :roles roles))))

  ;; Add a resource without roles
  (is-true (is-uuid (add-resource *rbac* "test:resource-08")))

  ;; Let's see if everything got added correctly

  ;; Check users, roles, permissions, and resources
  (is (equal (sort (cons "bogus-permission" *default-permissions*) #'string<)
        (list-permission-names *rbac*)))
  (is (equal (u:safe-sort '("role-a" "role-b" "role-c"
                             "system" "logged-in" "public"))
        (u:exclude-regex (list-role-names *rbac*) ":exclusive$")))
  (is (equal (loop for a from 1 to 6
               collect (format nil "user-~2,'0d" a))
        (u:exclude (list-user-names *rbac*) "system")))
  (is (equal '("test:resource-01" "test:resource-02"
                "test:resource-03" "test:resource-04"
                "test:resource-05" "test:resource-06"
                "test:resource-07" "test:resource-08")
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
          "user-04" "test:resource-06"))))

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
