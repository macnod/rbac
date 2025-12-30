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

(defparameter *swank-server*
  (swank:create-server
    :interface "0.0.0.0"
    :port *swank-port*
    :style :spawn
    :dont-close t))
