(in-package :rbac)

;;
;; Constants
;;
(defparameter *default-permissions* (list "create" "read" "update" "delete")
  "Default permissions for a new role.")

;; SQL to find tables that reference a table with a foreign key. We use this
;; so that we can soft delete a row in a table, and then soft delete all the
;; rows in other tables that reference the row in the first table. This is
;; akin to a cascading delete, but we don't actually delete the rows.
(defparameter *referencing-tables-sql*
  "SELECT DISTINCT tc.table_name
   FROM
       information_schema.table_constraints tc
       JOIN information_schema.referential_constraints rc
           ON tc.constraint_name = rc.constraint_name
           AND tc.table_schema = rc.constraint_schema
       JOIN information_schema.constraint_table_usage ctu
           ON rc.constraint_name = ctu.constraint_name
           AND rc.constraint_schema = ctu.table_schema
       JOIN information_schema.key_column_usage kcu
           ON tc.constraint_name = kcu.constraint_name
           AND tc.table_schema = kcu.table_schema
           AND tc.table_name = kcu.table_name
   WHERE
       tc.constraint_type = 'FOREIGN KEY'
       AND ctu.table_name = $1
   ORDER BY tc.table_name"
  "Internal. SQL query to find all tables that reference a table with a foreign
key.")

(defparameter *table-aliases*
  (ds:ds '(:map
            "users" "u"
            "roles" "r"
            "permissions" "p"
            "resources" "s"
            "role_permissions" "rp"
            "role_users" "ru"
            "resource_roles" "sr"))
  "Internal. Mapping from table names to table aliases.")

;; These roles are assigned to new users
(defparameter *default-user-roles* (list "public" "logged-in") "Internal.")
(defparameter *default-resource-roles* (list "system") "Internal.")

(defparameter *default-page-size* 20 "Default page size")
(defparameter *max-page-size* 1000 "Maximum page size")

;; Caches
(defparameter *table-fields* nil "Internal. Cache of table field names.")

;;
;; Macros
;;

(defmacro with-rbac ((rbac) &body body)
  "Opens a connection (pooled) to the rbac database to execute BODY. There's
no global connection, so this macro must be used wherever a connection is
needed. The connection is closed after BODY is executed."
  `(db:with-connection (list (dbname ,rbac)
                         (user-name ,rbac)
                         (password ,rbac)
                         (host ,rbac)
                         :port (port ,rbac)
                         :pooled-p t)
     ,@body))

(defmacro check (errors condition &rest error-message-args)
  "Internal. Evaluates CONDITION. If the return value of CONDITION is NIL, this
function pushes an error message onto ERROS. The error message is created by
using the format function with the arguments in ERROR-MESSAGE-ARGS. This
function returns the result of evaluating CONDITION, so that it can be used as
part of setting a variable, for example."
  `(let (result)
     (unless (setf result ,condition)
       (push (format nil ,@error-message-args) ,errors))
     result))

;;
;; Global functions
;;
(defun report-errors (function-name errors &optional (fail-on-error t))
  "Internal. If ERRORS is not NIL, this function signals an error with a message
that consists the strings in ERRORS, separated by spaces."
  (when errors
    (l:perror :in function-name :errors errors)
    (when fail-on-error
      (error (format nil "Error~p: ~{~a~^ ~}"
               (length errors) (reverse errors))))))

(defun rbac-query-single (sql-template-and-parameters)
  "Converts SQL-TEMPLATE-AND-PARAMETERS into a query that returns a single
value, and executes that query. SQL-TEMPLATE-AND-PARAMETERS is a list where the
first element is an SQL string (optionally with placeholders) and the rest of
the elements are the values that are used to replace the placeholders in the SQL
string. This function needs to be called inside a with-rbac block."
  (eval (cons 'db:query (append sql-template-and-parameters (list :single)))))

(defun rbac-query (sql-template-and-parameters &optional (result-type :plists))
  "Converts SQL-TEMPLATE-AND-PARAMETERS into a query that returns a list of
rows, and executes that query. SQL-TEMPLATE-AND-PARAMETERS is a list where the
first element is an SQL string (optionally with placeholders) and the rest of
the elements are values that are used to replace the placeholders in the SQL
string. This function needs to be called inside of a with-rbac block. Each
row in the result is a plist, where the keys represent the field names."
  (eval (cons 'db:query (append
                          sql-template-and-parameters
                          (list result-type)))))

(defun usql (sql)
  "Converts SQL into a one-line string, removing extra spaces and newlines.
This does not work correctly if SQL contains quoted field names or values that
include multiple consecutive whitespace characters."
  (u:trim (re:regex-replace-all "\\s+" sql " ")))

(defun plural (string)
  "Adds 's' to STRING, unless STRING already ends with 's'."
  (if (re:scan "s$" string)
    string
    (format nil "~as" string)))

(defun external-reference-field (external-table)
  "Internal. Creates a field name that references the id field in
EXTERNAL-TABLE."
  (format nil "~a_id" (singular external-table)))

(defun password-hash (user-name password)
  "Returns the hash of PASSWORD, using USER-NAME as the salt. This is how RBAC
stores the password in the database."
  (u:hash-string password :salt user-name :size 32))

(defun exclusive-role-for (user-name)
  "Returns the exclusive role for USER-NAME."
  (format nil "~a:exclusive" user-name))

(defun make-description (name value)
  "Internal. Create a description string for NAME with VALUE. The database has a
description field in several tables, and sometimes the description is optional
when creating a new row. When a description is not provided, this function can
be used to create a default description."
  (format nil "~@(~a~) '~a'" name value))

;;
;; Class definitions
;;

(defclass rbac ()
  ((resource-regex :accessor resource-regex
     :initarg :resource-regex
     :type string
     :initform "^[a-zA-Z][-a-zA-Z0-9]*:?[a-zA-Z0-9][-a-zA-Z0-9]*$"
     :documentation
     "Defaults to an absolute directory path string that ends with a /")
    (resource-length-max :accessor resource-length-max
      :initarg :resource-length-max
      :type integer
      :initform  512
      :documentation "Maximum length of resource name string.")
    (user-name-length-max :accessor user-name-length-max
      :initarg :user-name-length-max
      :type integer
      :initform 64
      :documentation "Maximum length of user name string.")
    (user-name-regex :accessor user-name-regex
      :initarg :user-name-regex
      :type string
      :initform "^[a-zA-Z][-a-zA-Z0-9_.+]*$"
      :documentation "Regex for validating user name strings.")
    (password-length-min :accessor password-length-min
      :initarg :password-length-min
      :type integer
      :initform 6
      :documentation "Minimum length of password string.")
    (password-length-max :accessor password-length-max
      :initarg :password-length-max
      :type integer
      :initform 64
      :documentation "Maximum length of password string.")
    (password-regexes :accessor password-regexes
      :initarg :password-regexes
      :type list
      :initform (list
                  ;; These must all be true
                  "^[\\x00-\\x7f]+$"
                  "[a-zA-Z]"
                  "[-!@#$%^&*()\+={}[\]|:;<>,.?/~`]"
                  "[0-9]")
      :documentation "List of regular expressions that a valid password must
      match. Every regex in the list must match.")
    (email-length-max :accessor email-length-max
      :initarg :email-length-max
      :type integer
      :initform 128)
    (email-regex :accessor email-regex
      :initarg :email-regex
      :type string
      :initform "^[-a-zA-Z0-9._%+]+@[-a-zA-Z0-9.]+\\.[a-zA-Z]{2,}$|^no-email$"
      :documentation "Regex for validation of email address strings.")
    (role-length-max :accessor role-length-max
      :initarg :role-length-max
      :type integer
      :initform 64
      :documentation "Maximum length of role name string.")
    (role-regex :accessor role-regex
      :initarg :role-regex
      :type string
      :initform "^[a-z]([-a-z0-9_.+]*[a-z0-9])*(:[a-z]+)?$"
      :documentation "Regex for validating role name strings.")
    (permission-length-max :accessor permission-length-max
      :initarg :permission-length-max
      :type integer
      :initform 64
      :documentation "Maximum length of permission name string.")
    (permission-regex :accessor permission-regex
      :initarg :permission-regex
      :type string
      :initform "^[a-z]([-a-z0-9_.+]*[a-z0-9])*(:[a-z]+)?$"
      :documentation "Regex for validating permission name strings."))
  (:documentation "Abstract base class for user database."))

(defclass rbac-pg (rbac)
  ((dbname :accessor dbname :initarg :dbname :initform "rbac" :type string
     :documentation "Name of the RBAC database.")
    (user-name :accessor user-name :initarg :user-name :initform "cl-user"
      :type string
      :documentation "User name for connecting to the RBAC database.")
    (password :accessor password :initarg :password :initform "" :type string
      :documentation "Password for connecting to the RBAC database.")
    (host :accessor host :initarg :host :initform "postgres" :type string
      :documentation "Host name for connecting to the RBAC database.")
    (port :accessor port :initarg :port :initform 5432 :type integer
      :documentation "Port number for connecting to the RBAC database.")
    (cache-size :reader cache-size
      :initarg :cache-size
      :type integer
      :initform 10000
      :documentation "Maximum number of entries in the RBAC cache before LRU
eviction occurs.")
    ;; The cache is an lru-cache instance that maps from a key to a value. The
    ;; key is derived from query parameters, and the value is the query result.
    ;; This cache is intended to reduce the number database querires for
    ;; frequently requested data.
    (cache :accessor cache
      :documentation "Internal. LRU cache for RBAC queries.")
    ;; The anti-cache is an lru-cache instance that maps from a record ID to a
    ;; cache key. This is used to evict cache entries when a record is updated
    ;; or deleted.
    (anti-cache :accessor anti-cache
      :documentation "Internal LRU anti-cache for RBAC queries."))
  (:documentation "RBAC database class for PostgreSQL."))

(defmethod initialize-instance :after ((rbac rbac-pg) &key)
  "Internal. Initialize the lru cache for RBAC."
  (setf (cache rbac)
    (make-instance 'c:lru-cache :max-size (cache-size rbac)))
  (setf (anti-cache rbac)
    (make-instance 'c:lru-cache :max-size (cache-size rbac))))

(defgeneric clear-cache (rbac)
  (:method ((rbac rbac-pg))
    (setf (cache rbac)
      (make-instance 'c:lru-cache :max-size (cache-size rbac)))
    (setf (anti-cache rbac)
      (make-instance 'c:lru-cache :max-size (cache-size rbac))))
  (:documentation "Clears the RBAC cache."))

(defgeneric id-exists-p (rbac table id)
  (:method ((rbac rbac-pg) (table string) (id string))
    (when (get-value rbac table "id" "id" id) t))
  (:documentation "Returns T when ID exists in TABLE."))

(defgeneric delete-by-id (rbac table id)
  (:method ((rbac rbac-pg) (table string) (id string))
    (let ((sql (format nil "delete from ~a where id = $1" table))
           (key (c:cache-get id (anti-cache rbac)))
           (database-updated nil)
           (cache-updated nil)
           (anti-cache-updated nil))
      (when (id-exists-p rbac table id)
        (with-rbac (rbac)
          (multiple-value-bind (value rows-affected)
            (db:query sql id)
            (declare (ignore value))
            (setf database-updated (not (zerop rows-affected)))))
        (when key
          (setf
            cache-updated (c:cache-remove key (cache rbac))
            anti-cache-updated (c:cache-remove id (anti-cache rbac)))))
      (l:pdebug :in "delete-by-id"
        :status (if database-updated "deleted" "not found")
        :table table :id id
        :cache-updated cache-updated
        :anti-cache-updated anti-cache-updated)
      (values id database-updated)))
  (:documentation "Internal. Deletes ID row from TABLE. Raises an error if ID
is not present in TABLE. Returns the ID of the deleted row."))

(defgeneric table-fields (rbac &optional cache)
  (:method ((rbac rbac-pg) &optional (cache t))
    (if (and *table-fields* cache)
      *table-fields*
      (with-rbac (rbac)
        (loop
          with sql = "select table_name
                    from information_schema.tables
                    where table_schema = 'public'
                      and table_type = 'BASE TABLE'
                    order by table_name"
          with table-fields = (make-hash-table :test 'equal)
          for table in (db:query sql :column)
          for fields = (db:query
                         "select column_name from information_schema.columns
                        where table_schema = 'public'
                          and table_name = $1"
                         table
                         :column)
          do (setf (gethash table table-fields) fields)
          finally (return (setf *table-fields* table-fields))))))
  (:documentation "Internal. Returns a hash table where the keys are table names
and the values are lists of field names for each table."))

(defgeneric aliased-fields (rbac table)
  (:method ((rbac rbac-pg) (table string))
    (loop with fields = (gethash table (table-fields rbac))
      and alias = (gethash table *table-aliases*)
      and distinct = (list
                       (table-name-field table)
                       (format nil "~a_description" (singular table)))
      and excepted = (list "password_hash")
      for field in fields
      for aliased = (not (member field distinct :test 'equal))
      unless (member field excepted :test 'equal)
      collect (if aliased
                (format nil "~a.~a as ~a_~a" alias field (singular table) field)
                (format nil "~a.~a" alias field))))
  (:documentation "Internal. Returns a list of fields from TABLE, with each
field prefixed with the table alias, and, except for distinct fields, prefixed
with the table name."))

(defgeneric table-join-2 (rbac table-1 table-2 &key fields for-count)
  (:method ((rbac rbac-pg) (table-1 string) (table-2 string) &key
             fields for-count)
    (let* ((link-table (compute-link-table-name rbac table-1 table-2))
            (alias-link (gethash link-table *table-aliases*))
            (alias-1 (gethash table-1 *table-aliases*))
            (alias-2 (gethash table-2 *table-aliases*))
            (link-id-1 (format nil "~a.~a_id" alias-link (singular table-1)))
            (link-id-2 (format nil "~a.~a_id" alias-link (singular table-2)))
            (id-1 (format nil "~a.id" alias-1))
            (id-2 (format nil "~a.id" alias-2))
            (foreign-key-p (lambda (l)
                            (re:scan (format nil "^~a\\.(~a|~a)_id as"
                                       alias-link
                                       (singular table-1)
                                       (singular table-2))
                              l)))
            (link-table-fields (aliased-fields rbac link-table))
            (fields (or fields
                      (append
                        ;; Excluding foreign key fields from link table because
                        ;; the same info is available from the joined tables.
                        (remove-if foreign-key-p link-table-fields)
                        (aliased-fields rbac table-1)
                        (aliased-fields rbac table-2))))
            (field-selector (if for-count
                              " count(*)"
                              (format nil "~%~{  ~a~^,~%~}" fields))))
      (format nil
        "select~a
from ~a ~a
  join ~a ~a on ~a = ~a
  join ~a ~a on ~a = ~a"
        field-selector
        link-table alias-link
        table-1 alias-1 link-id-1 id-1
        table-2 alias-2 link-id-2 id-2)))
  (:documentation "Internal. Returns SQL with a select and join clauses for
TABLE-1 and TABLE-2 joined through their link table. The name of the link table
is computeed. If FIELDS is provided, those fields are selected. Otherwise, all
fields from TABLE-1 and TABLE-2 are selected, excluding foreign key fields. The
tables and fields are aliased appropriately. If FOR-COUNT is true, the select
clause returns count(*) instead of the fields."))

(defgeneric user-resources-join (rbac join-type &key fields for-count)
  (:method ((rbac rbac-pg) (join-type symbol) &key fields for-count)
    (let* ((all-fields (or fields
                         (append
                           fields
                           (aliased-fields rbac "users")
                           (aliased-fields rbac "roles")
                           (aliased-fields rbac "permissions")
                           (aliased-fields rbac "resources"))))
            (sql (case join-type
                   (:user-resources
                     (let ((select-fields
                             (cons "s.resource_name"
                               (remove-if
                                 (lambda (f) (string= f "s.resource_name"))
                                 all-fields))))
                       (format nil
                         "select ~a
                          from resources s
                            join resource_roles sr on s.id = sr.resource_id
                            join roles r on sr.role_id = r.id
                            join role_users ru on r.id = ru.role_id
                            join users u on ru.user_id = u.id
                            join role_permissions rp on rp.role_id = r.id
                            join permissions p on rp.permission_id = p.id"
                         (if for-count
                           "count(distinct s.resource_name)"
                           (format nil "~{~a~^, ~}" select-fields)))))
                   (:resource-users
                     (let ((select-fields
                             (cons "u.user_name"
                               (remove-if
                                 (lambda (f) (string= f "u.user_name"))
                                 all-fields))))
                       (format nil
                         "select ~a
                          from users u
                            join role_users ru on u.id = ru.user_id
                            join roles r on ru.role_id = r.id
                            join role_permissions rp on r.id = rp.role_id
                            join permissions p on rp.permission_id = p.id
                            join resource_roles sr on r.id = sr.role_id
                            join resources s on sr.resource_id = s.id"
                         (if for-count
                           "count(distinct u.user_name)"
                           (format nil "~{~a~^, ~}" select-fields)))))
                   (t (error "Invalid join-type '~a'." join-type)))))
      (l:pdebug :in "user-resources-join" :join-type join-type
        :fields fields :all-fields all-fields :for-count for-count :sql sql)
      sql))
  (:documentation "Internal. Returns SQL with select and join clauses for the
tables users, roles, permissions, resources, and the associated link tables. The
tables and fields are aliased properly. JOIN-TYPE can be :user-resources or
:resource-users. If FOR-COUNT is true, the select clause has count(*) instead
of the fields. The fields in the select clause always include either the
resource_name or the user_name field, depending on JOIN-TYPE. If FIELDS is
provided, those fields are also included in the select clause."))

(defgeneric table-exists-p (rbac table)
  (:method ((rbac rbac-pg) (table string))
    (when (gethash table (table-fields rbac)) t))
  (:documentation "Internal. Returns T if TABLE exists in the database."))

(defgeneric table-field-exists-p (rbac table field)
  (:method ((rbac rbac-pg) (table string) (field string))
    (when (and
            (table-exists-p rbac table)
            (member field
              (gethash table (table-fields rbac))
              :test 'equal))
      t))
  (:documentation "Internal. Returns T if FIELD exists in TABLE in the
database."))

(defgeneric field-exists-p (rbac field)
  (:method ((rbac rbac-pg) (field string))
    (let ((all-fields (loop for fields being the hash-values of
                        (table-fields rbac)
                        append fields)))
      (when (member field all-fields :test 'equal) t)))
  (:documentation "Internal. Returns T if FIELD exists in any RBAC table in the
database."))

(defun field-no-prefix (field)
  "Internal. In SQL query strings, fields are often prefixed with the table alias,
such as 'r.id' or 'rs.created_at'. This function removes the prefix and the dot,
so that it returns just the field name, such as 'id' or 'created_at'. If FIELD
doesn't have a prefix, it is returned unchanged."
  (if (re:scan "\\." field)
    (second (re:split "\\." field))
    field))

(defgeneric list-rows (rbac tables &key
                        fields filters order-by page page-size for-count
                        result-type)
  (:method ((rbac rbac-pg) (tables list) &key
             fields
             filters
             order-by
             (page 1)
             (page-size *default-page-size*)
             for-count
             (result-type :plists))
    (let ((query (make-query rbac tables
                   :fields fields
                   :filters filters
                   :order-by order-by
                   :page page
                   :page-size page-size
                   :for-count for-count)))
      (l:pdebug :in "list-rows"
        :tables tables
        :filters filters
        :order-by order-by
        :page page
        :page-size page-size
        :for-count for-count
        :result-type result-type
        :query query)
      (with-rbac (rbac)
          (rbac-query query result-type))))
  (:documentation "Internal. Returns results from TABLES that satisfy the
conditions in FILTERS. If RESULT-TYPE is :single, a single value is returned,
from a single row and column. If RESULT-TYPE is :column, a list of values is
returned, where each value corresponds to a field in a row. If RESULT-TYPE is
anything else (the default is :plists), a list of plists is returned, where each
plist represents a row, with the plist keys representing the field names and the
plist values representing the field values in that row. TABLES is a list of
table names that this function will join together automatically using computed
link table names. This list excludes the link table names. FILTERS is a list of
conditions that must all be true for a row to be included in the result. Each
condition in FILTERS consists of a field name, an operator, and a value. The
operator, a string, must be =, !=, <, <=, >, >=, like, ilike, in, or not in. The
value can be a string, a number, :null, :true, or :false. If ORDER-BY is
provided (a list of strings representing the field names), the result is ordered
by those fields. Pagination is supported using PAGE (1-based) and PAGE-SIZE.
PAGE defaults to 1. PAGE-SIZE defaults to *default-page-size*. FIELDS is a list
of field names to include in the result. If FIELDS is not provided, all fields
from all non-link tables are included in the result. If FOR-COUNT is true, the
result is a count of the rows that satisfy the conditions in FILTERS."))

(defgeneric count-rows (rbac tables &key filters)
  (:method ((rbac rbac-pg) (tables list) &key filters)
    (l:pdebug :in "count-rows" :tables tables :flters filters)
    (list-rows rbac tables :filters filters :for-count t :result-type :single))
  (:documentation "Internal. Returns the count of rows in TABLES that satisfy
the conditions in FILTER. TABLES is a list of table names that will be joined
together. This list excludes the link table names. FILTERS is a list of
conditions that must all be true for a row to be counted. Each condition in
FILTERS consists of a list containing a field name, an operator, and a value."))

(defgeneric valid-user-name-p (rbac user-name)
  (:method ((rbac rbac-pg) (user-name string))
    (when (and (<= (length user-name) (user-name-length-max rbac))
            (re:scan (user-name-regex rbac) user-name))
      t))
  (:documentation "Validates new USERNANME string.
  USER-NAME must:
  - Have at least 1 character
  - Have at most user-name-length-max characters
  - Start with a letter
  - Contain only ASCII characters for
    - letters (any case)
    - digits
    - underscores
    - dashes
    - periods
    - plus sign (+)"))

(defgeneric valid-password-p (rbac password)
  (:method ((rbac rbac-pg) (password string))
    (when (and password
            (>= (length password) (password-length-min rbac))
            (<= (length password) (password-length-max rbac))
            (every (lambda (r) (re:scan r password)) (password-regexes rbac)))
      t))
  (:documentation "Validates new PASSWORD string.
PASSWORD must have
- at least password-length-min characters
- at least one letter
- at least one digit
- at least one common punctuation character
- at most password-length-max characters"))

(defgeneric valid-email-p (rbac email)
  (:method ((rbac rbac-pg) (email string))
    (when (and (re:scan (email-regex rbac) email)
            (<= (length email) 128))
      t))
  (:documentation "Validates new EMAIL string. The string must look like an
email address, with a proper domain name, and it must have a length that
doesn't exceed 128 characters."))

(defgeneric valid-permission-p (rbac permission)
  (:method ((rbac rbac-pg) (permission string))
    (when (and (<= (length permission) (permission-length-max rbac))
            (re:scan (permission-regex rbac) permission))
      t))
  (:documentation "Validates new PERMISSION string.
PMERISSION must:
- start with a letter
- consist of letters, digits, and hyphens
- optionally have a colon that is not at the beginning or the end
- contain at most permission-length-max characters"))

(defgeneric valid-role-p (rbac role)
  (:method ((rbac rbac-pg) (role string))
    (when (and (<= (length role) (role-length-max rbac))
            (re:scan (role-regex rbac) role))
      t))
  (:documentation "Validates new ROLE string.
ROLE must:
- start with a letter
- consist of letters, digits, and hyphens
- have at most role-length-max characters
- optionally have a colon that is not at the beginning or the end"))

(defgeneric valid-resource-p (rbac resource)
  (:method ((rbac rbac-pg) (resource string))
    (when (and (<= (length resource) (resource-length-max rbac))
            (re:scan (resource-regex rbac) resource))
      t))
  (:documentation "Validates new RESOURCE string."))

(defgeneric valid-description-p (rbac description)
  (:method ((rbac rbac-pg) (description string))
    (when (and (not (zerop (length description)))
            (< (length description) 250))
      t))
  (:documentation "Validates new DESCRIPTION string."))

(defgeneric link (rbac table-1 table-2 name-1 name-2)
  (:method ((rbac rbac-pg)
             (table-1 string)
             (table-2 string)
             (name-1 string)
             (name-2 string))
    (let ((link-table-field-1 (format nil "~a_id" (singular table-1)))
           (link-table-field-2 (format nil "~a_id" (singular table-2)))
           (name-1-field (table-name-field table-1))
           (name-2-field (table-name-field table-2)))
      (l:pdebug :in "link"
        :table-1 table-1 :table-2 table-2
        :name-1 name-1 :name-2 name-2
        :link-table-field-1 link-table-field-1
        :link-table-field-2 link-table-field-2
        :name-1-field name-1-field
        :name-2-field name-2-field)
      (let* (errors
              (id-1 (check errors (get-id rbac table-1 name-1)
                      "~a ~a doesn't exist." (singular table-1) name-1))
              (id-2 (check errors (get-id rbac table-2 name-2)
                      "~a ~a doesn't exist." (singular table-2) name-2)))
        (report-errors "link" errors)
        (let* ((link-table (compute-link-table-name rbac table-1 table-2))
                (id-link (get-value rbac link-table "id"
                           link-table-field-1 id-1
                           link-table-field-2 id-2)))
          (if id-link
            (progn
              (l:pdebug :in "link" :message "Link already exists"
                :link-table link-table
                :link-table-field-1 link-table-field-1 :id-1 id-1
                :link-table-field-2 link-table-field-2 :id-2 id-2)
              id-link)
            (insert-link rbac table-1 table-2 id-1 id-2))))))
  (:documentation "Internal. Adds a link between NAME-1 in TABLE-1 and NAME-2 in
TABLE-2. Computes the link table name. Returns the ID of the new link row."))

(defgeneric unlink (rbac table-1 table-2 name-1 name-2)
  (:method ((rbac rbac-pg)
             (table-1 string)
             (table-2 string)
             (name-1 string)
             (name-2 string))
    (let* ((link-table (compute-link-table-name rbac table-1 table-2))
            (link-table-field-1 (format nil "~a_id" table-1))
            (link-table-field-2 (format nil "~a_id" table-2)))
      (let* (errors
              (id-1 (check errors (get-id rbac table-1 name-1)
                      "~a ~a doesn't exist." (singular table-1) name-1))
              (id-2 (check errors (get-id rbac table-2 name-2)
                      "~a ~a doesn't exist." (singular table-2) name-2)))
        (report-errors "unlink" errors)
        (let ((id-link (get-value rbac link-table "id"
                         link-table-field-1 id-1
                         link-table-field-2 id-2)))
          (if id-link
            (delete-by-id rbac link-table id-link)
            (progn
              (l:pdebug :in "unlink" :message "Link does not exist"
                :link-table link-table
                :table-1 table-1 :name-1 name-1
                :table-2 table-2 :name-2 name-2
                :link-table-field-1 link-table-field-1 :id-1 id-1
                :link-table-field-2 link-table-field-2 :id-2 id-2)
              nil))))))
  (:documentation "Internal. Removes the link between NAME-1 in TABLE-1 and
NAME-2 in TABLE-2. Computes the link table name. Returns the ID of the deleted
link row, or NIL if the link did not exist."))

(defun make-search-key (field search)
  "Internal. Helper for the GET-VALUE function. Given a FIELD and a SEARCH list
of alternating field names and values, this function computes a unique key
string that represents the search conditions for FIELD. This value is useful for
caching the result and avoiding a database call if the value has been recently
retrieved."
  (let ((parts (cons (u:safe-encode field)
                 (mapcar #'u:safe-encode search))))
    (format nil "~{~a~^;~}" parts)))

(defgeneric get-value (rbac table field &rest search)
  (:method ((rbac rbac-pg)
             (table string)
             (field string)
             &rest search)
    (multiple-value-bind (result found)
      (c:cache-get (make-search-key field search) (cache rbac))
      (if found
        (progn
          (let ((id (first result))
                 (value (second result)))
            (l:pdebug :in "get-value" :status "cache hit" :id id :value value)
            ;; Move this ID to the front of the anti-cache
            (c:cache-get id (anti-cache rbac))
            value))
        (progn
          (let* (errors)
            (check errors (table-exists-p rbac table)
              "Table '~a' does not exist." table)
            (check errors (table-field-exists-p rbac table field)
              "Field '~a' does not exist in table '~a'." field table)
            (loop for key in search by #'cddr
              do (check errors (table-field-exists-p rbac table key)
                   "Seach Field '~a' does not exist in table '~a'." key table))
            (check errors (and search (zerop (mod (length search) 2)))
              "Invalid search. ~a"
              "Must an even number of alternating field names and values.")
            (report-errors "get-value" errors))
          (let* ((tables (list table))
                  (fields (list "id" field))
                  (filters (loop for key in search by #'cddr
                             for value in (cdr search) by #'cddr
                             collect (list key "=" value)))
                  (result (list-rows rbac (list table)
                            :fields fields :filters filters
                            :result-type :row))
                  (id (when result (first result)))
                  (value (when result (second result)))
                  (key (when value (make-search-key field search))))
            (when key
              (c:cache-put key result (cache rbac))
              (c:cache-put id key (anti-cache rbac)))
            (l:pdebug :in "get-value" :status "cache miss"
              :tables tables :fields fields :filters filters
              :key key :value value)
            value)))))
  (:documentation "Retrieves the value from FIELD in TABLE where SEARCH points
to a unique row. TABLE and FIELD are strings, and SEARCH is a series of field
names and values that identify the row uniquely. TABLE, FIELD, and the field
names in SEARCH must exist in the database. If no row is found, this function
returns NIL."))

(defgeneric get-id (rbac table name)
  (:method ((rbac rbac-pg)
             (table string)
             (name string))
    (let ((name-field (table-name-field table)))
      (l:pdebug :in "get-id"
        :table table :name-field name-field :name name)
      (get-value rbac table "id" name-field name)))
  (:documentation "Returns the ID associated with NAME in TABLE."))

(defgeneric get-permission-ids (rbac permissions)
  (:method ((rbac rbac-pg) (permissions list))
    (loop
      with errors
      and permissions = (if permissions
                          permissions
                          (with-rbac (rbac)
                            (db:query
                              "select permission_name from permissions
                               order by permission_name"
                              :column)))
      and permission-ids = (make-hash-table :test 'equal)
      for permission in permissions
      do (setf (gethash permission permission-ids)
           (check errors (get-id rbac "permissions" permission)
             "Permission '~a' not found." permission))
      finally (return (progn
                        (report-errors "get-permission-ids" errors)
                        permission-ids))))
  (:documentation "Returns a hash table where the keys consist of permission
names and the values consist of permission IDs. If PERMISSIONS is NIL, the hash
table contains all existing permissions and their IDs. Otherwise, if PERMISSIONS
is not NIL, the hash table contains IDs for the permissions in PERMISSIONS only.
If PERMISSIONS contains a permission that doesn't exist, this function signals
an error."))

(defgeneric validate-login-params (rbac user-name password)
  (:method ((rbac rbac-pg)
             (user-name string)
             (password string))
    (let* ((errors nil))
      (check errors (valid-user-name-p rbac user-name)
        "Invalid user-name '~a'." user-name)
      (check errors (valid-password-p rbac password) "Invalid password.")
      (report-errors "validate-login-params" errors nil)
      t))
  (:documentation "Internal. Validates login parameters and signals an error if
there's a problem. Returns T upon success"))

(defun make-insert-name-query (table name &rest other-fields)
  "Internal. Generates an SQL insert statement with placeholders and values for
inserting a new row into TABLE with fields NAME and OTHER-FIELDS. Returns a list
where the first element is the SQL string and the remaaining elements are the
values to be used. The return value is suitable for passing to rbac-query or
rbac-query-single."
  (let* ((name-field (table-name-field table))
          (description-field (format nil "~a_description" (singular table)))
          (additional-fields (cond
                               ((equal table "users")
                                 (list "email" "password_hash"))
                               ((equal table "roles")
                                 (list description-field "exclusive"))
                               (t (list description-field))))
          (all-fields (cons name-field additional-fields))
          (values (cons name
                    (cond
                      ((equal table "users")
                        (list
                          ;; email
                          (car other-fields)
                          ;; password
                          (password-hash name (cadr other-fields))))
                      ((equal table "roles")
                        (list
                          ;; description
                          (car other-fields)
                          ;; exclusive
                          (cadr other-fields)))
                      (t (list
                           ;; description
                           (car other-fields))))))
          (value-placeholders (loop for a from 1 to (length all-fields)
                                collect (format nil "$~d" a))))
    (cons
      (format nil
        "insert into ~a (~{~a~^, ~}) values (~{~a~^, ~}) returning id"
        table all-fields value-placeholders)
      values)))

(defgeneric check-insert-name-params (rbac table name &key
                                       description email password exclusive)
  (:method ((rbac rbac-pg) (table string) (name string) &key
             description email password exclusive)
    (let (errors)
      (cond
        ((equal table "users")
          (check errors (and email password)
            "Missing required fields for users: email, password.")
          (check errors (valid-user-name-p rbac name)
            "Invalid user-name '~a'." name)
          (check errors (valid-email-p rbac email)
            "Invalid email '~a'." email)
          (check errors (valid-password-p rbac password)
            "Invalid password."))
        ((equal table "roles")
          (check errors (valid-role-p rbac name)
            "Invalid role name '~a'." name)
          (check errors (valid-description-p rbac description)
            "Invalid description '~a'." description)
          (check errors
            (or
              (and (not exclusive) (not (re:scan ":exclusive$" name)))
              (and exclusive (re:scan ":exclusive$" name)))
            "Bad name for ~a role. (role='~a'; exclusive=~a)"
            (if exclusive "an exclusive" "a non-exclusive") name exclusive))
        ((equal table "permissions")
          (check errors (valid-permission-p rbac name)
            "Invalid permission name '~a'." name))
        ((equal table "resources")
          (check errors (valid-resource-p rbac name)
            "Invalid resource name '~a'." name)))
      (report-errors "check-insert-name-params" errors)))
  (:documentation "Internal. Validates parameters for inserting NAME into TABLE.
Helper function for insert-name."))

(defgeneric insert-name (rbac table name &key
                          description email password exclusive)
  (:method ((rbac rbac-pg)
             (table string)
             (name string)
             &key (description (unless (equal table "users")
                                         (format nil "~a '~a'"
                                           (singular table) name)))
             email
             password
             exclusive)
    (let* (errors)
      (check errors (table-exists-p rbac table)
        "Table ~a does not exist." table)
      (check errors (not (get-id rbac table name))
        "~a '~a' already exists." (singular table) name)
      (report-errors "insert-name" errors))
      (check-insert-name-params rbac table name
        :description description
        :email email
        :password password
        :exclusive exclusive)
    (let* ((other-values (list description email password exclusive))
            (query-params (append (list table name) other-values)))
      (let ((query (apply #'make-insert-name-query query-params)))
        (l:pdebug :in "insert-name"
          :table table :name name
          :description description :email email :exclusive exclusive
          :query query)
        (with-rbac (rbac)
          (rbac-query-single query)))))
  (:documentation "Internal. Adds NAME to TABLE with DESCRIPTION. Raises an
error if NAME already exists in TABLE. The users and roles tables require
additional parameters which must be provided via the &KEY arguments. Returns the
ID of the new row."))

(defgeneric insert-user (rbac user-name email password)
  (:method ((rbac rbac-pg) (user-name string) (email string) (password string))
    (l:pdebug :in "insert-user" :user-name user-name :email email)
    (insert-name rbac "users" user-name :email email :password password))
  (:documentation "Internal. Inserts a new user into the users table without
validating any of the parameters. Returns the new user's ID. For internal use
only."))

(defgeneric insert-role (rbac role &key description exclusive)
  (:method ((rbac rbac-pg) (role string) &key
             (description (format nil "role '~a'" role))
             exclusive)
    (l:pdebug :in "insert-role" :status "inserting new role" :role role
      :exclusive exclusive)
    (insert-name rbac "roles" role :description description
      :exclusive exclusive))
  (:documentation "Internal. Inserts a new role into the roles table without
 validating any of the parameters. Returns the new role's ID. For internal use
only."))

(defgeneric set-exclusive-role (rbac user-name)
  (:method ((rbac rbac-pg) (user-name string))
    (l:pdebug :in "set-exclusive-role" :user-name user-name)
    (let ((errors nil)
           (role (exclusive-role-for user-name))
           (description (format nil "Exclusive role for user ~a." user-name)))
      (check errors (valid-user-name-p rbac user-name)
        "Invalid user-name '~a'" user-name)
      (check errors (not (get-id rbac "roles" role))
        "Exclusive role '~a' already exists." role)
      (report-errors "set-exclusive-role" errors)
      (insert-name rbac "roles" role :description description :exclusive t)))
  (:documentation "Internal. Add an exclusive role for USER, returning the ID
of the new role"))

(defgeneric insert-permission (rbac permission &key description)
  (:method ((rbac rbac-pg) (permission string) &key
             (description (format nil "permission '~a'" permission)))
    (l:pdebug :in "insert-permission" :permission permission)
    (insert-name rbac "permissions" permission :description description))
  (:documentation "Internal. Inserts a new permission into the permissions table
without validating any of the parameters. Returns the new permission's ID. For
internal use only."))

(defgeneric insert-resource (rbac resource &key description)
  (:method ((rbac rbac-pg) (resource string) &key
             (description (format nil "resource '~a'" resource)))
    (l:pdebug :in "insert-resource" :resource resource)
    (insert-name rbac "resources" resource :description description))
  (:documentation "Internal. Inserts a new resource into the resources table
without validating any of the parameters. Returns the new resource's ID. For
internal"))

(defgeneric compute-link-table-name (rbac &rest tables)
  (:method ((rbac rbac-pg) &rest tables)
    (if (= (length tables) 1)
      (singular (first tables))
      (let* ((t1 (first tables))
              (t2 (second tables))
              (option-1 (format nil "~a_~a" (singular t1) t2))
              (option-2 (format nil "~a_~a" (singular t2) t1)))
        (cond
          ((table-exists-p rbac option-1) option-1)
          ((table-exists-p rbac option-2) option-2)
          (t (error "No link table exists for ~a and ~a" t1 t2))))))
  (:documentation "Internal. Computes the name of the link table that links the
tables in TABLES. TABLES can contain 1 or 2 table names.  If TABLES contains 1
table name, the function returns the singluar of that table name. If TABLES
contains 2 table names, the function finds the and existing table that links the
2 tables, and returns its name. If no such link table exists, the function
signals an error."))

(defun link-table-p (rbac table)
  "Internal. Checks if TABLE is a link table."
  (let* ((parts (re:split "_" table)))
    (and
      (> (length parts) 1)
      (every (lambda (p)
               (or
                 (table-exists-p rbac p)
                 (table-exists-p rbac (plural p))))
        parts))))

(defgeneric insert-link-sql (rbac table-1 table-2)
  (:method ((rbac rbac-pg) (table-1 string) (table-2 string))
    (l:pdebug :in "insert-link-sql" :table-1 table-1 :table-2 table-2)
    (let* ((link-table (compute-link-table-name rbac table-1 table-2))
            (id-1-field (format nil "~a_id" (singular table-1)))
            (id-2-field (format nil "~a_id" (singular table-2))))
      (usql (format nil
              "insert into ~a (~a, ~a) values ($1, $2) returning id"
              link-table
              id-1-field id-2-field))))
  (:documentation "Internal. Creates SQL that upserts a row into a link table
that has fields that reference TABLE-1 and TABLE-2, creating a new link between
rows in TABLE-1 and TABLE-2.

Parameters:
  - TABLE-1 (string): The name of the first table.
  - TABLE-2 (string): The name of the second table.

Description:

This function makes the following assumptions:

  - The names of TABLE-1 and TABLE-2 can be plural and plurals always end in
    's' who's singular form is the plural name minus the 's'.

  - The link table already exists and has a name that conssists of the singular
    of TABLE-1, followed by an underscore, followed by TABLE-2 (plural or not),
    or vice-versa.

  - In the link table, the field, xref1, that references TABLE-1 has a name that
    consists of the singular of TABLE-1 followed by '_id'. The same is true for
    the field, xref2, that references TABLE-2.

  - The link table has a unique index on the pair of rows that reference
    TABLE-1 and TABLE-2, unique({xref1}_id, {xref2}_id).

  - All the tables have a primary key named 'id' of type UUID, and, in addition
    to the already mentioned foreign key references, the link table has the
    field 'updated_at'.

For example, if you call the function with 'roles' and 'permissions', the
function will make the following concrete assumptions:

  - The name of the link table, where a row will be upserted, is
    'role_permissions'.

  - The link table will contain the following fields:

    - role_id (uuid, references 'roles')

    - permission_id (uuid, references 'permissions')

    - updated_at (timestamp)

  - The link table will contain a unique index on (role_id, permission_id)
"))

(defgeneric insert-link (rbac table-1 table-2 id-1 id-2)
  (:method ((rbac rbac-pg)
             (table-1 string)
             (table-2 string)
             (id-1 string)
             (id-2 string))
    (l:pdebug :in "insert-link"
      :table-1 table-1 :table-2 table-2 :id-1 id-1 :id-2 id-2)
    (let* ((sql (insert-link-sql rbac table-1 table-2))
            (name-field-1 (table-name-field table-1))
            (name-field-2 (table-name-field table-2))
            (name-1 (get-value rbac table-1 name-field-1 "id" id-1))
            (name-2 (get-value rbac table-2 name-field-2 "id" id-2)))
      (l:pdebug :in "insert-link"
        :table-1 table-1 :name-1 name-1 :id-1 id-1
        :table-2 table-2 :name-2 name-2 :id-2 id-2
        :sql sql)
      (with-rbac (rbac)
        (rbac-query-single (list sql id-1 id-2 :single)))))
  (:documentation "Internal. Inserts a row into a link table that has fields that
reference TABLE-1 and TABLE-2, creating a new link between rows in TABLE-1 and
TABLE-2. The rows are given by ID-1 and ID-2. The name of the table that
references TABLE-1 and TABLE-2 is derived from the names of TABLE-1 and TABLE-2,
as described in the documentation for insert-link-sql."))

(defgeneric filters-valid-p (rbac filters)
  (:method ((rbac rbac-pg) (filters list))
    (let ((ops '("=" "<>" "<" ">" "<=" ">=" "is" "is not"
                  "like" "ilike" "not like" "not ilike")))
      (every
        (lambda (f)
          (and
            (listp f)
            (= (length f) 3)
            (member (second f) ops :test 'equal)
            (field-exists-p rbac (field-no-prefix (first f)))))
        filters)))
  (:documentation  "Internal. Checks that the operators in FILTERS are valid. A
FILTER is a list of three elements: field name, operator, and value."))

(defun render-placeholder (value index)
  "Internal. Given a string VALUE and an integer INDEX, this funtion returns a
cons where the car is the number of values to be added to the query parameters
(0 or 1) and the cdr is the placeholder string to be used in the SQL query.
When VALUE is :null, :true, or :false, no value needs to be added to the query
parameters, so the car of the returned cons is 0. When VALUE is any other value,
the car of the returned cons is 1, and the cdr is something like '$1', '$2'."
  (cond
    ((or (not value) (eql value :null)) (cons 0 "null"))
    ((eql value :false) (cons 0 "false"))
    ((eql value :true) (cons 0 "true"))
    (t (cons 1 (format nil "$~d" index)))))

(defgeneric make-query (rbac tables &key
                         fields filters order-by page page-size for-count)
  (:method ((rbac rbac-pg) (tables list) &key
             fields
             filters
             order-by
             (page 1)
             (page-size *default-page-size*)
             for-count)
    (let* (errors)
      (check errors (member (length tables) '(1 2 4))
        "Must provide 1, 2, or 4 tables.")
      (check errors (every (lambda (a) (table-exists-p rbac a)) tables)
        "One or more of these tables do not exist: ~{~a~^, ~}" tables)
      (check errors (filters-valid-p rbac filters)
        "One or more filters are invalid: ~{~a~^, ~}" filters)
      (check errors (and (integerp page) (>= page 1))
        "Page ~a must be an integer >= 1." page)
      (check errors (and (integerp page-size) (>= page-size 1))
        "Page-size ~a must be an integer >= 1." page-size)
      (check errors (member (length tables) '(1 2 4))
        "Only 1, 2, or 4 tables are supported.")
      (when (= (length tables) 4)
        (check errors
          (or (equal tables '("users" "roles" "permissions" "resources"))
            (equal tables '("resources" "roles" "permissions" "users")))
          "When specifying 4 tables, they must be either ~a, or ~a."
          "(users, roles, permissions, resources)"
          "(resources, roles, permissions, users)"))
      (report-errors "make-query" errors))
    (let* ((table-count (nth (1- (length tables)) '(:one :two :three :four)))
            (select (case table-count
                      (:one (format nil "select ~a from ~a"
                              (if for-count
                                "count(*)"
                                (if fields (format nil "~{~a~^, ~}" fields) "*"))
                              (first tables)))
                      (:two (table-join-2 rbac (first tables) (second tables)
                              :fields fields :for-count for-count))
                      (:four (user-resources-join
                               rbac
                               (if (equal (first tables) "users")
                                 :user-resources
                                 :resource-users)
                               :for-count for-count
                               :fields fields))
                      (otherwise (error "1, 2, or 4 tables are supported."))))
            (where (when filters
                     (loop
                       for (field operator value) in filters
                       for index = 1 then (+ index index-delta)
                       for (index-delta . placeholder) = (render-placeholder
                                                           value index)
                       collect (format nil "~a ~a ~a"
                                 field operator placeholder)
                       into where-clauses
                       unless (zerop index-delta)
                       collect value into values
                       finally
                       (return
                         (cons
                           (format nil "~%where ~{~a~^ and ~}" where-clauses)
                           values)))))
            (order (let* ((table (car (last tables)))
                           (alias (gethash table *table-aliases*))
                           (name-field (table-name-field table))
                           (aliased-field (if (eql table-count :one)
                                            name-field
                                            (format nil "~a.~a" alias name-field))))
                     (unless (or
                               for-count
                               (link-table-p rbac (car (last tables)))
                               (not (table-field-exists-p rbac table name-field)))
                       (or order-by
                           (format nil "~%order by ~a" aliased-field)))))
            (limit-offset (unless for-count
                            (format nil "~%limit ~d~%offset ~d"
                              page-size (* (1- page) page-size))))
            (sql (format nil "~{~a~^ ~}"
                   (remove-if-not #'identity
                     (list select (car where) order limit-offset))))
            (query (cons sql (cdr where))))
      (l:pdebug :in "make-query" :tables tables :table-count table-count
        :fields fields :filters filters :page page :page-size page-size
        :select select :where where :order order :limit-offset limit-offset
        :query query)
      query))
  (:documentation "Internal. Constructs an SQL query string with parameters.
Returns a list where the first element is the SQL string and the remaining
elements are the parameters to be used for the placeholders in the SQL
string. This functions computes the names of the link tables needed to join
TABLES together. FIELDS defaults to all fields. If FIELDS is provided, it should
be a list of strings (field names) to be included in the select clause. However,
when FOR-COUNT is T, the select clause consists of 'count(*)' FIELDS is ignored.
FILTERS is a list of filters to be applied in the where clause. Each filter is a
list of three elements: field name, operator, and value. Operator must be =, <>,
<, >, <=, >=, is, is not, like, ilike, not like, or not ilike. VALUE can be a
string, a number, :null, :true, or :false. ORDER-BY is a list of strings
representing the names of the fields to be used to order the results. Those
fields need not be listed in FIELDS. ORDER-BY defaults to the name field of the
last table in TABLES, but is ignored if FOR-COUNT is T or if the last table is
a link table. PAGE and PAGE-SIZE are used to paginate the results. PAGE defaults
to 1 and PAGE-SIZE defaults to *default-page-size*. If FOR-COUNT is T, the query
returns the count of rows that match the filters instead of the rows."))

(defgeneric user-allowed (rbac user-name permission resource)
  (:method ((rbac rbac-pg)
             (user-name string)
             (permission string)
             (resource string))
    "Returns a list of plists showing how the user USER-NAME has PERMISSION access to
RESOURCE. If the list is empty, the user does not have access."
    (l:pdebug :in "user-allowed"
      :status "checking if user has permission on resource"
      :user user-name
      :resource resource
      :permission permission)
    (with-rbac (rbac)
      (when
        (db:query
          "select
             rp.id,
             u.user_name,
             ru.id as role_user_id,
             r.role_name,
             p.permission_name,
             s.resource_name
           from
             users u
             join role_users ru on ru.user_id = u.id
             join roles r on ru.role_id = r.id
             join role_permissions rp on rp.role_id = r.id
             join permissions p on rp.permission_id = p.id
             join resource_roles sr on sr.role_id = r.id
             join resources s on sr.resource_id = s.id
           where
             u.user_name = $1
             and s.resource_name = $2
             and p.permission_name = $3
           order by
             u.user_name,
             r.role_name,
             p.permission_name,
             s.resource_name"
          user-name resource permission :plists)
        t)))
  (:documentation "Returns T if USER-NAME has PERMISSION on RESOURCE, NIL
otherwise. Note that this permission may exist via more than one role."))

(defgeneric user-has-role (rbac user-name &rest role)
  (:method ((rbac rbac-pg)
             (user-name string)
              &rest role)
    "Returns T if USER-NAME has any of ROLE, NIL otherwise."
    (l:pdebug :in "user-has-role" :user-name user-name :roles role)
    (with-rbac (rbac)
      (let* ((place-holders (loop for a from 1 to (length role)
                              collect (format nil "$~d" (1+ a))))
              (query (format nil
                       "select count(*) from
                         users u
                         join role_users ru on ru.user_id = u.id
                         join roles r on ru.role_id = r.id
                       where
                         u.user_name = $1
                         and r.role_name in (~{~a~^, ~})"
                       place-holders))
              (query-params (cons user-name role))
              (count (rbac-query-single (cons query query-params))))
        (> count 0))))
  (:documentation "Returns T if USER-NAME has any of the specified ROLE(s)."))

(defgeneric login (rbac user-name password)
  (:method ((rbac rbac-pg)
             (user-name string)
             (password string))
    (l:pdebug :in "login" :user-name user-name)
    (validate-login-params rbac user-name password)
    (let* ((hash (password-hash user-name password))
            (user-id (get-value rbac "users" "id"
                       "user_name" user-name
                       "password_hash" hash)))
      (if user-id
        (progn
          (l:pdebug :in "login" :status "success" :user user-name)
          (with-rbac (rbac)
            (db:query
              "update users set last_login = now() where id = $1"
              user-id))
          user-id)
        (progn
          (l:pdebug :in "login" :status "fail" :user user-name)
          nil))))
  (:documentation "If USER-NAME exists and PASSWORD is correct, update last_login
for USER-NAME and return the user ID. Otherwise, return NIL."))

;;
;; API
;;

;; Add and remove things

(defgeneric add-user (rbac user-name email password &key roles)
  (:method ((rbac rbac-pg)
             (user-name string)
             (email string)
             (password string)
             &key roles)
    (l:pdebug :in "add-user"
      :user-name user-name
      :email email
      :password password
      :roles roles
      :all-roles (append roles *default-user-roles*))
    (let* (errors
            (all-roles (append roles *default-user-roles*))
            (missing-roles (remove-if (lambda (r) (get-id rbac "roles" r))
                             all-roles)))
      (check errors (not missing-roles)
        "The following roles do not exist: ~{~a~^, ~}." missing-roles)
      (report-errors "add-user" errors)
      ;; Add the user
      (insert-user rbac user-name email password)
      ;; Create the user's exclusive role and add the user to it
      (set-exclusive-role rbac user-name)
      ;; Add the user to the rest of the roles
      (loop for role-name in all-roles
        do (link rbac "roles" "users" role-name user-name))
      (l:pdebug :in "add-user"
        :status "created user" :user-name user-name
        :user-id (get-id rbac "users" user-name)
        :roles all-roles)
      (get-id rbac "users" user-name)))
  (:documentation "Add a new user. This creates an exclusive role, which is
for this user only, and adds the user to the public and logged-in roles
(given by *default-user-roles*). Returns the new user's ID."))

(defgeneric remove-user (rbac user-name)
  (:method ((rbac rbac-pg)
             (user-name string))
    (let* (errors
            (user-id (check errors (get-id rbac "users" user-name)
                       "User '~a' not found." user-name))
            (role-id (get-id rbac "roles"
                       (exclusive-role-for user-name))))
      (report-errors "remove-user" errors)
      (delete-by-id rbac "users" user-id)
      ;; Remove the exclusive role associated with the user
      (delete-by-id rbac "roles" role-id)
      user-id))
  (:documentation "Remove USER-NAME from the database."))

(defgeneric add-role (rbac role &key description permissions)
  (:method ((rbac rbac-pg) (role string) &key
             (description (make-description "role" role))
             (permissions *default-permissions*))
    (l:pdebug :in "add-role" :role role :permissions permissions)
    (let (errors
           (missing-permissions
              (remove-if (lambda (p) (get-id rbac "permissions" p))
                permissions)))
      (check errors (not missing-permissions)
        "The following permissions do not exist: ~{~a~^, ~}."
        missing-permissions)
      (report-errors "add-role" errors))
    ;; Insert the role
    (insert-role rbac role :description description :exclusive exclusive)
    ;; Insert the role's permissions
    (loop for permission-name in permissions
      do (link rbac "roles" "permissions" role permission-name))
    (l:pdebug :in "add-role" :status "created role"
      :role role :role-id (get-id rbac "roles" role))
    (get-id rbac "roles" role))
  (:documentation "Add a new ROLE. Description is optional and auto-generated
if not provided. If the role name ends with ':exclusive', the role is marked
as exclusive, so the EXCLUSIVE parameter is optional. PERMISSIONS is a list
of permission names to add to the role, defaulting to *DEFAULT-PERMISSIONS*.
All PERMISSIONS must already exist. Returns the new role's ID."))

(defgeneric remove-role (rbac role)
  (:method ((rbac rbac-pg) (role string))
    (l:pdebug :in "remove-role" :role role)
    (let* (errors
            (role-id (check errors (get-id rbac "roles" role)
                       "Role '~a' doesn't exist." role)))
      (report-errors "remove-role" errors)
      (delete-by-id rbac "roles" role-id)
      role-id))
  (:documentation "Remove a role from the database. Returns the ID of the
removed role."))

(defgeneric add-resource (rbac resource &key description roles)
  (:method ((rbac rbac-pg) (resource string) &key
             (description (make-description "resource" resource))
             roles)
    (let (errors
           (missing-roles (remove-if
                             (lambda (r) (get-id rbac "roles" r))
                             roles)))
      (check errors (not missing-roles)
        "The following roles do not exist: ~{~a~^, ~}." missing-roles)
      (report-errors "add-resource" errors))
    (let ((all-roles (append *default-resource-roles* roles)))
      (insert-name rbac "resources" resource :description description)
      (loop for role in all-roles
        do (link rbac "resources" "roles" resource role))
      (l:pdebug :in "add-resource"
        :resource resource :description description
        :roles roles :all-roles all-roles)
      (get-id rbac "resources" resource)))
  (:documentation "Add a new resource and returns the ID of the new entry. The
resource is automatically linked to the roles in *default-resource-roles* plus
any additional ROLES provided. DESCRIPTION is optional and auto-generated if
not provided."))

(defgeneric remove-resource (rbac resource)
  (:method ((rbac rbac-pg) (resource string))
    (l:pdebug :in "remove-resource" :resource resource)
    (let* (errors
            (resource-id (check errors
                           (get-id rbac "resources" resource)
                           "Resource '~a' doesn't exist." resource)))
      (report-errors "remove-resource" errors)
      (delete-by-id rbac "resources" resource-id)))
  (:documentation "Remove RESOURCE from the database. Returns the ID of the
removed resource."))

(defgeneric add-permission (rbac permission &key description)
  (:method ((rbac rbac-pg) (permission string) &key
             (description (make-description "permission" permission)))
    (insert-name rbac "permissions" permission :description description))
  (:documentation "Add a new permission and returns the ID of the new entry.
DESCRIPTION is optional and auto-generated if not provided."))

(defgeneric remove-permission (rbac permission)
  (:method ((rbac rbac-pg) (permission string))
    (l:pdebug :in "remove-permission" :permission permission)
    (let* (errors
            (permission-id (check errors
                             (get-id rbac "permissions" permission)
                             "Unknown permission '~a'." permission)))
      (report-errors "remove-permission" errors)
      (delete-by-id rbac "permissions" permission-id)
      permission-id))
  (:documentation "Remove PERMISSION from the database. Returns the ID of the
removed permission."))

;; Link and unlink things

(defgeneric add-role-permission (rbac role permission)
  (:method ((rbac rbac-pg)
             (role string)
             (permission string))
    (l:pdebug :in "add-role-permission" :role role :permission permission)
    (link rbac "roles" "permissions" role permission))
  (:documentation "Add an existing permission to an existing role. Returns the
ID of the new role_permissions row."))

(defgeneric remove-role-permission (rbac role permission)
  (:method ((rbac rbac-pg)
             (role string)
             (permission string))
    (l:pdebug :in "remove-role-permission" :permission permission :role role)
    (unlink rbac "roles" "permissions" role permission))
  (:documentation "Remove a permission from a role. Returns the ID of the
removed role-permission."))

(defgeneric add-role-user (rbac role user)
  (:method ((rbac rbac-pg)
             (role string)
             (user string))
    (l:pdebug :in "add-role-user role" :role role :user user)
    (link rbac "roles" "users" role user))
  (:documentation "Add an existing user to an existing role. Returns the ID of
the new role_users row."))

(defgeneric add-user-role (rbac user role)
  (:method ((rbac rbac-pg)
             (user string)
             (role string))
    (l:pdebug :in "add-user-role" :user user :role role)
    (link rbac "roles" "users" role user))
  (:documentation "Add an existing role to an existing user. Returns the ID of
the new role_users row."))

(defgeneric remove-role-user (rbac role user)
  (:method ((rbac rbac-pg)
             (role string)
             (user string))
    (l:pdebug :in "remove-role-user" :role role :user user)
    (unlink rbac "roles" "users" role user))
  (:documentation "Remove a user from a role. Returns the ID of the removed
role user."))

(defgeneric remove-user-role (rbac user role)
  (:method ((rbac rbac-pg)
             (user string)
             (role string))
    (l:pdebug :in "remove-user-role" :user user :role role)
    (unlink rbac "roles" "users" role user))
  (:documentation "Remove a role from a user. Returns the ID of the removed
user role."))

(defgeneric add-resource-role (rbac resource role)
  (:method ((rbac rbac-pg)
             (resource string)
             (role string))
    (l:pdebug :in "add-resource-role" :resource resource :role role)
    (link rbac "resources" "roles" resource role))
  (:documentation "Add an existing role to an existing resource. Returns the ID
of the new resource_roles row."))

(defgeneric remove-resource-role (rbac resource role)
  (:method ((rbac rbac-pg)
             (resource string)
              (role string))
      (l:pdebug :in "remove-resource-role" :resource resource :role role)
      (unlink rbac "resources" "roles" resource role))
  (:documentation "Remove a role from a resource. Returns the ID of the removed
resource role."))

;; List function generators

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun name-to-identifier (name format)
    "Internal. Convert NAME to an identifier using FORMAT."
    (intern (format nil format (string-upcase (re:regex-replace "_" name "-")))))

  (defun singular (string)
    "Internal. If STRING ends with an 's', this function returns the string
without the 's'at the end."
    (re:regex-replace "s$" string ""))

  (defun table-name-field (table &optional as-keyword)
    "Internal. Returns the name field for TABLE. The name field is the singular
form of the table name, with '_name' appended."
    (format nil "~a~aname" (singular table) (if as-keyword "-" "_")))

  (defun make-documentation (format-string &rest values)
    "Internal. Creates documentation strings. FORMAT-STRING is a string with
placeholders like '~a'. VALUES is a list of values for the placeholders. This
function removes extra spaces."
    (let* ((doc-1 (apply #'format (append (list nil format-string) values)))
            (doc-2 (re:regex-replace-all "  +" doc-1 " "))
            (lines (remove-if (lambda (s) (zerop (length s)))
                     (re:split "\\n" doc-2)))
            (doc-3 (format nil "~{~a~^ ~}" (mapcar #'u:trim lines))))
      doc-3))

  (defparameter *table-aliases*   (ds:ds '(:map
                                            "users" "u"
                                            "roles" "r"
                                            "permissions" "p"
                                            "resources" "s"
                                            "role_permissions" "rp"
                                            "role_users" "ru"
                                            "resource_roles" "sr"))))

(defmacro define-list-functions (&rest tables)
  "Internal. This macro defines three list functions for the given tables: all,
names, and count. The functions are named according to the tables provided. For
example, if the table 'users' is provided as the only table, the functions are
named list-users, list-user-names, and user-count. IF the table 'permissions' is
provided, the functions are named list-permissions, list-permission-names, and
permission-count. The all function lists all the rows in the results, in plist
format. The names function returns a list of strings representing the values
from the last table's name field of each row in the results. The count function
returns the number of rows in the result.  Each function supports filtering, and
the all and names functions support pagination, filtering, ordering, and field
selection."
  (let* ((fname (if (= (length tables) 1)
                  (first tables)
                  (format nil "~a-~a"
                    (singular (first tables)) (second tables))))
          (f-all (name-to-identifier fname "LIST-~a"))
          (f-names (name-to-identifier (singular fname) "LIST-~a-NAMES"))
          (f-count (name-to-identifier (singular fname) "~a-COUNT"))
          (name-field (table-name-field (car (last tables))))
          (doc-row (make-documentation "List information about ~a (all ~a by
default). Pagination is supported via the PAGE and PAGE-SIZE parameters. PAGE
defaults to 1 and PAGE-SIZE defaults to *DEFAULT-PAGE-SIZE*. The FIELDS
parameter, a list of strings, can be used to limit which fields are included in
the result. The FILTERS parameter can be used to filter the results. It consists
of a list of filters, where each filter is a list of three elements: field name,
operator, and value. Operator, a string, can be =, <>, <, >, <=, >=, is, is not,
like, or ilike. Value is a string, number, :null, :true, or :false. The ORDER-BY
parameter is a list of strings that represent field names and are used to order
the results. It defaults to (list \"~a\")."
                     (first tables) (first tables) name-field))
          (doc-names (make-documentation "List of ~a names (all ~a by default).
Pagination is supported via the PAGE and PAGE-SIZE parameters. PAGE defaults to
1 and PAGE-SIZE defaults to *DEFAULT-PAGE-SIZE*. The FILTERS parameter can be
used to filter the results. It consists of a list of filters, where each filter
is a list of three elements: field name, operator, and value. Operator, a
string, can be =, <>, <, >, <=, >=, is, is not, like, or ilike. Value is a
string, number, :null, :true, or :false. The ORDER-BY parameter is a list of
strings that represent field names and are used to order the results. It
defaults to
(list \"~a\")."
                       (singular (first tables)) (first tables) name-field))
          (doc-count (make-documentation "Count the number of ~a (all ~a by
default). The FILTERS parameter can be used to filter the results. It consists
of a list of filters, where each filter is a list of three elements: field name,
operator, and value. Operator, a string, can be =, <>, <, >, <=, >=, is, is not,
like, or ilike. Value is a string, number, :null, :true, or :false."
                        (first tables) (first tables))))
    `(progn
       (defgeneric ,f-all (rbac &key page page-size fields filters order-by)
         (:method ((rbac rbac-pg) &key
                    (page 1)
                    (page-size *default-page-size*)
                    fields
                    filters
                    order-by)
           (list-rows rbac ',tables
             :page page :page-size page-size :fields fields
             :filters filters :order-by order-by))
         (:documentation ,doc-row))
       (defgeneric ,f-names (rbac &key page page-size filters order-by)
         (:method ((rbac rbac-pg) &key
                    (page 1)
                    (page-size *default-page-size*)
                    filters
                    order-by)
           (list-rows rbac ',tables
             :page page :page-size page-size
             :filters filters :order-by order-by
             :fields (list ,name-field) :result-type :column))
         (:documentation ,doc-names))
       (defgeneric ,f-count (rbac &key filters)
         (:method ((rbac rbac-pg) &key filters)
           (list-rows rbac ',tables
             :filters filters :result-type :single :for-count t))
         (:documentation ,doc-count)))))

(defmacro define-list-functions-1 (&rest tables)
  "Internal. See DEFINE-LIST-FUNCTIONS. This macro works exactly the same, except
that the functions generated take an additional parameter representing the object
for which you want a list. For example, if the tables 'users' and 'roles' are
provided, the functions generated are list-user-roles, list-user-role-names, and
user-role-count, and they accept a parameter USER representing the user for whom
you want to list roles."
  (let* ((fname (format nil "~a-~a"
                  (singular (first tables)) (second tables)))
          (f-all (name-to-identifier fname "LIST-~a"))
          (f-names (name-to-identifier (singular fname) "LIST-~a-NAMES"))
          (f-count (name-to-identifier (singular fname) "~a-COUNT"))
          (name-field (table-name-field (car (last tables))))
          (filter-field (table-name-field (car tables)))
          (param (name-to-identifier (singular (first tables)) "~a"))
          (doc-row (make-documentation "List information about ~a associated
with ~a. Pagination is supported via the PAGE and PAGE-SIZE parameters. PAGE
defaults to 1 and PAGE-SIZE defaults to *DEFAULT-PAGE-SIZE*. The FIELDS
parameter, a list of strings, can be used to limit which fields are included in
the result. The FILTERS parameter can be used to filter the results. It consists
of a list of filters, where each filter is a list of three elements: field name,
operator, and value. Operator, a string, can be =, <>, <, >, <=, >=, is, is not,
like, or ilike. Value is a string, number, :null, :true, or :false. The ORDER-BY
parameter is a list of strings that represent field names and are used to order
the results. It defaults to (list \"~a\")."
                     (second tables) param name-field))
          (doc-names (make-documentation "List names of ~a associated with ~a.
Pagination is supported via the PAGE and PAGE-SIZE parameters. PAGE defaults to
1 and PAGE-SIZE defaults to *DEFAULT-PAGE-SIZE*. The FILTERS parameter can be
used to filter the results. It consists of a list of filters, where each filter
is a list of three elements: field name, operator, and value. Operator, a
string, can be =, <>, <, >, <=, >=, is, is not, like, or ilike. Value is a
string, number, :null, :true, or :false. The ORDER-BY parameter is a list of
strings that represent field names and are used to order the results. It
defaults to
(list \"~a\")."
                       (second tables) param name-field))
          (doc-count (make-documentation "Count the number of ~a associated
with ~a. The FILTERS parameter can be used to filter the results. It consists of
a list of filters, where each filter is a list of three elements: field name,
operator, and value. Operator, a string, can be one of =, <>, <, >, <=, >=, is,
is not, like, ilike. Value is a string, number, :null, :true, or :false."
                        (second tables) param)))

    `(progn
       (defgeneric ,f-all (rbac ,param &key page page-size fields filters order-by)
         (:method ((rbac rbac-pg) (,param string) &key
                    (page 1)
                    (page-size *default-page-size*)
                    fields
                    filters
                    order-by)
           (list-rows rbac ',tables
             :page page :page-size page-size :fields fields
             :filters (cons (list ,filter-field "=" ,param) filters)
             :order-by order-by))
         (:documentation ,doc-row))
       (defgeneric ,f-names (rbac ,param &key page page-size filters order-by)
         (:method ((rbac rbac-pg) (,param string) &key
                    (page 1)
                    (page-size *default-page-size*)
                    filters
                    order-by)
           (list-rows rbac ',tables
             :page page :page-size page-size
             :filters (cons (list ,filter-field "=" ,param) filters)
             :fields (list ,name-field)
             :order-by order-by :result-type :column))
         (:documentation ,doc-names))
       (defgeneric ,f-count (rbac ,param &key filters)
         (:method ((rbac rbac-pg) (,param string) &key filters)
           (list-rows rbac ',tables
             :filters (cons (list ,filter-field "=" ,param) filters)
             :result-type :single :for-count t))
         (:documentation ,doc-count)))))

(defmacro define-list-functions-2 (&rest tables)
  "Internal. See DEFINE-LIST-FUNCTIONS and DEFINE-LIST-FUNCTIONS-1. This macro
works exactly the same as those, except that the generated functions take two
additional parameters representing the objects for which you want a list. For
example, if the tables 'users', 'roles', 'permissions', and 'resources' are
provided, the following functions are generated: list-user-resources,
list-user-resource-names, and user-resource-count, and they accept the
additional parameters USER and PERMISSION, such that resources are listed where
USER has PERMISSION on the resource. Currently, only the following table
combinations are supported: (users, roles, permissions, resources)
and (resources, roles, permissions, users)."
  (let* ((fname (if (string= (car tables) "users")
                  "user-resources"
                  "resource-users"))
          (f-all (name-to-identifier fname "LIST-~a"))
          (f-names (name-to-identifier (singular fname) "LIST-~a-NAMES"))
          (f-count (name-to-identifier (singular fname) "~a-COUNT"))
          (name-field (format nil "~a.~a"
                        (gethash (car (last tables)) *table-aliases*)
                        (table-name-field (car (last tables)))))
          (filter-field-1 (table-name-field (car tables)))
          (filter-field-2 (table-name-field (third tables)))
          (param (if (string= fname "user-resources")
                   (name-to-identifier "user" "~a")
                   (name-to-identifier "resource" "~a")))
          (doc-row (make-documentation "List information about ~a ~a where
the user has PERMISSION on the resource. Pagination is supported via the PAGE
and PAGE-SIZE parameters. PAGE defaults to 1 and PAGE-SIZE defaults to
*DEFAULT-PAGE-SIZE*. The FIELDS parameter, a list of strings, can be used to
limit which fields are included in the result. The FILTERS parameter can be used
to filter the results. It consists of a list of filters, where each filter is a
list of three elements: field name, operator, and value. Operator, a string, can
be =, <>, <, >, <=, >=, is, is not, like, or ilike. Value is a string, number,
:null, :true, or :false. The ORDER-BY parameter is a list of strings that
represent field names and are used to order the results. It defaults to (list
\"~a\")."
                     (singular (car tables)) (car (last tables)) name-field))
          (doc-names (make-documentation "List ~a names of ~a where the user
has PERMISSION on the resource. Pagination is supported via the PAGE and
PAGE-SIZE parameters. PAGE defaults to 1 and PAGE-SIZE defaults to
*DEFAULT-PAGE-SIZE*. The FILTERS parameter can be used to filter the results. It
consists of a list of filters, where each filter is a list of three elements:
field name, operator, and value. Operator, a string, can be =, <>, <, >, <=,
>=, is, is not, like, or ilike. Value is a string, number, :null, :true, or
:false. The ORDER-BY parameter is a list of strings that represent field names and
are used to order the results. It defaults to (list \"~a\")."
                       (singular (car (last tables))) (car tables) name-field))
          (doc-count (make-documentation "Count the number of ~a ~a where the
user has PERMISSION on the resource. The FILTERS parameter can be used to
filter the results. It consists of a list of filters, where each filter is a
list of three elements: field name, operator, and value. Operator, a string,
can be one of =, <>, <, >, <=, >=, is, is not, like, or ilike. Value is a
string, number, :null, :true, or :false. The ORDER-BY parameter is a list of
strings that represent field names and are used to order the results. It
defaults to (list \"~a\")."
                       (singular (car tables)) (car (last tables)) name-field)))
    `(progn
       (defgeneric ,f-all (rbac ,param permission &key
                            page page-size fields filters order-by)
         (:method ((rbac rbac-pg) (,param string) (permission string) &key
                    (page 1)
                    (page-size *default-page-size*)
                    fields
                    filters
                    order-by)
           (list-rows rbac ',tables
             :page page :page-size page-size :fields fields
             :filters (append
                        (list
                          (list ,filter-field-1 "=" ,param)
                          (list ,filter-field-2 "=" permission))
                        filters)
             :order-by order-by))
         (:documentation ,doc-row))
       (defgeneric ,f-names (rbac ,param permission &key
                              page page-size filters order-by)
         (:method ((rbac rbac-pg) (,param string) (permission string) &key
                    (page 1)
                    (page-size *default-page-size*)
                    filters
                    order-by)
           (u:distinct-values
             (list-rows rbac ',tables
               :page page :page-size page-size
               :filters (append
                          (list
                            (list ,filter-field-1 "=" ,param)
                            (list ,filter-field-2 "=" permission))
                          filters)
               :order-by order-by
               :fields (list ,name-field) :result-type :column)))
         (:documentation ,doc-names))
       (defgeneric ,f-count (rbac ,param permission &key filters)
         (:method ((rbac rbac-pg) (param string) (permission string) &key
                    filters)
           (list-rows rbac ',tables
             :filters (append
                        (list
                          (list ,filter-field-1 "=" ,param)
                          (list ,filter-field-2 "=" permission))
                        filters)
             :result-type :single :for-count t))
         (:documentation ,doc-count)))))

;;
;; List functions
;;

;; These require no parameters

;; Makes list-users, list-user-names, and user-count
(define-list-functions "users")

;; Makes list-roles, list-role-names, and role-count
(define-list-functions "roles")

;; Makes list-permissions, list-permission-names, and permission-count
(define-list-functions "permissions")

;; Makes list-resources, list-resource-names, and resource-count
(define-list-functions "resources")

;; These require 1 parameter

;; Makes list-user-roles, list-user-role-names, and user-role-count
(define-list-functions-1 "users" "roles")

;; Makes list-role-permissions, list-role-permission-names, and
;; role-permission-count
(define-list-functions-1 "roles" "permissions")

;; Makes list-role-users, list-role-user-names, role-user-count
(define-list-functions-1 "roles" "users")

;; Makes list-role-resources, list-role-resource-names, and
;; role-resource-count
(define-list-functions-1 "roles" "resources")

;; Make list-resource-roles, list-resource-role-names, and
;; resource-role-count
(define-list-functions-1 "resources" "roles")

;; These require 2 parameters

;; Makes lust-user-resources, list-user-resource-names, and user-resource-count
(define-list-functions-2 "users" "roles" "permissions" "resources")

;; Makes list-resource-users, list-resource-user-names, and resource-user-count
(define-list-functions-2 "resources" "roles" "permissions" "users")

(defgeneric list-user-resource-permission-names (rbac user-name resource-name &key
                                                  page page-size)
  (:method ((rbac rbac-pg) (user-name string) (resource-name string) &key
             (page 1) (page-size *default-page-size*))
    (let* ((sql (format nil
                  "select distinct p.permission_name
                   from users u
                     join role_users ru on ru.user_id = u.id
                     join roles r on ru.role_id = r.id
                     join resource_roles sr on sr.role_id = r.id
                     join resources s on sr.resource_id = s.id
                     join role_permissions rp on rp.role_id = r.id
                     join permissions p on rp.permission_id = p.id
                   where u.user_name = $1
                     and s.resource_name = $2
                   order by p.permission_name
                   limit ~a offset ~a"
                  (* page-size 1)
                  (* (1- page) page-size)))
            (params (list sql user-name resource-name)))
      (l:pdebug :in "list-user-permission-names"
        :user-name user-name :resource-name resource-name
        :page page :page-size page-size :sql sql)
      (with-rbac (rbac)
        (rbac-query params :column))))
  (:documentation "List the names of the permissions that USER-NAME has on
RESOURCE-NAME. Supports pagination via PAGE and PAGE-SIZE. PAGE defaults to 1
and PAGE-SIZE defaults to *DEFAULT-PAGE-SIZE*"))
