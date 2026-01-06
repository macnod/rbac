(push (uiop:getcwd) asdf:*central-registry*)
(ql:register-local-projects)
(asdf:load-system :rbac)

(in-package :rbac)

(require :swank)

(defparameter *db-host* (u:getenv "DB_HOST" :required t))
(defparameter *db-port* (u:getenv "DB_PORT" :required t :type :integer))
(defparameter *db-user* (u:getenv "DB_USER" :required t))
(defparameter *db-password* (u:getenv "DB_PASSWORD" :required t))
(defparameter *swank-port* (u:getenv "SWANK_PORT" :required t :type :integer))
(defparameter *log-file* (u:getenv "LOG_FILE"))

;; Database connection
(defparameter *rbac* (make-instance 'rbac-pg
                       :host *db-host*
                       :port *db-port*
                       :user-name *db-user*
                       :password *db-password*))

(l:make-log-stream "repl" *log-file* :append nil)

;; Add some roles
(add-role *rbac* "role-a" :permissions '("read"))
(add-role *rbac* "role-b")

;; Add some users
(loop for a from 1 to 6
  for user = (format nil "user-~2,'0d" a)
  for email = (format nil "~a@sinistercode.com" user)
  for password = (format nil "~a-password" user)
  for roles = (nth (mod a 3) '(("role-a") ("role-b") ("role-a" "role-b")))
  do (add-user *rbac* user email password :roles roles))

;; Add some resources
(loop for a from 1 to 10
  for resource = (format nil "test:resource-~2,'0d" a)
  for roles = (nth (mod a 3) '(("role-a") ("role-b") ("role-a" "role-b")))
  do (add-resource *rbac* resource :roles roles))

(defparameter *swank-server*
  (swank:create-server
    :interface "0.0.0.0"
    :port *swank-port*
    :style :spawn
    :dont-close t))
