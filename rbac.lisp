(in-package :rbac)

;;
;; Constants
;;
(defparameter *default-permissions* (list "create" "read" "update" "delete"))
(defparameter *allow-test-user-insert* nil
  "If true, allows inserting a user with a user_name that starts with
'test-user-'.")

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
   ORDER BY tc.table_name")

(defparameter *table-aliases*
  (ds:ds '(:map
            "users" "u"
            "roles" "r"
            "permissions" "p"
            "resources" "s"
            "role_permissions" "rp"
            "role_users" "ru"
            "resource_roles" "sr")))

;; These roles are assigned to new users
(defparameter *default-user-roles* (list "public" "logged-in"))
(defparameter *default-resource-roles* (list "system"))

(defparameter *default-page-size* 20)
(defparameter *max-page-size* 1000)

;; Caches
(defparameter *table-fields* nil)

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
  "Evaluates CONDITION. If the return value of CONDITION is NIL, this function
pushes an error message onto ERROS. The error message is created by using
the format function with the arguments in ERROR-MESSAGE-ARGS. This function
returns the result of evaluating CONDITION, so that it can be used as part
of setting a variable, for example."
  `(let (result)
     (unless (setf result ,condition)
       (push (format nil ,@error-message-args) ,errors))
     result))

;;
;; Global functions
;;
(defun report-errors (function-name errors &optional (fail-on-error t))
  "If ERRORS is not NIL, this function signals an error with a message that
consists the strings in ERRORS, separated by spaces."
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

(defun sql-next-placeholder (sql)
  "Returns the biggest placeholder in SQL. This is useful when generating
SQL statements from base statements that already have placeholders, so that
additional placeholders can be added without conflicting with the existing
ones. If there are no placeholders in SQL, this function returns 1."
  (if (re:scan "\\$[0-9]+" sql)
    (1+ (apply
          #'max
          (mapcar
            (lambda (s) (parse-integer (subseq s 1)))
            (re:all-matches-as-strings "\\$([0-9]+)" sql))))
    1))

(defun main-table-alias (tables-sql)
  "Returns the alias for the main table in the SQL string TABLES-SQL, which
consists of the part of an SQL statement that specifies the tables and joins."
  (let* ((sql (usql tables-sql))
          (regex (cond
                   ((re:scan "^(?i)\\s*(select|delete)" sql)
                     "from\\s+(.+)(\\s+where)?")
                   ((re:scan "^(?i)\\s*update" sql)
                     "^(?i)(\\s*update\\s+)(.+?)(\\s+set)")
                   (t "(.+)(\\s+where)?"))))
    (if (re:scan regex sql)
      (multiple-value-bind (scan selected)
        (re:scan-to-strings regex sql)
        (if scan
          (let ((alias (second
                         (re:split
                           "\\s+"
                           (elt (remove-if (lambda (s) (equal s "")) selected) 0)))))
            (if (and alias (not (string= alias "")))
              (format nil "~a." alias)
              ""))
          "")))))

(defun plural (string)
  "Adds 's' to STRING"
  ;; TODO: improve
  (format nil "~as" string))

(defun external-reference-field (external-table)
  "Creates a field name that references the id field in EXTERNAL-TABLE."
  (format nil "~a_id" (singular external-table)))

(defun password-hash (user-name password)
  "Returns the hash of PASSWORD, using USER-NAME as the salt. This is how RBAC
stores the password in the database."
  (u:hash-string password :salt user-name :size 32))

(defun exclusive-role-for (user-name)
  (format nil "~a:exclusive" user-name))

(defun make-description (name value)
  "Create a description string for NAME with VALUE."
  (format nil "~@(~a~) '~a'" name value))

;;
;; Class definitions
;;

(defclass rbac ()
  ((resource-regex :accessor resource-regex
     :initarg :resource-regex
     :type string
     :initform "^/([-_.a-zA-Z0-9 ]+/)*$"
     :documentation
     "Defaults to an absolute directory path string that ends with a /")
    (resource-length-max :accessor resource-length-max
      :initarg :resource-length-max
      :type integer
      :initform  512)
    (user-name-length-max :accessor user-name-length-max
      :initarg :user-name-length-max
      :type integer
      :initform 64)
    (user-name-regex :accessor user-name-regex
      :initarg :user-name-regex
      :type string
      :initform "^[a-zA-Z][-a-zA-Z0-9_.+]*$")
    (password-length-min :accessor password-length-min
      :initarg :password-length-min
      :type integer
      :initform 6)
    (password-length-max :accessor password-length-max
      :initarg :password-length-max
      :type integer
      :initform 64)
    (password-regexes :accessor password-regexes
      :initarg :password-regexes
      :type list
      :initform (list
                  ;; These must all be true
                  "^[\\x00-\\x7f]+$"
                  "[a-zA-Z]"
                  "[-!@#$%^&*()\+={}[\]|:;<>,.?/~`]"
                  "[0-9]"))
    (email-length-max :accessor email-length-max
      :initarg :email-length-max
      :type integer
      :initform 128)
    (email-regex :accessor email-regex
      :initarg :email-regex
      :type string
      :initform "^[-a-zA-Z0-9._%+]+@[-a-zA-Z0-9.]+\\.[a-zA-Z]{2,}$|^no-email$")
    (role-length-max :accessor role-length-max
      :initarg :role-length-max
      :type integer
      :initform 64)
    (role-regex :accessor role-regex
      :initarg :role-regex
      :type string
      :initform "^[a-z]([-a-z0-9_.+]*[a-z0-9])*(:[a-z]+)?$")
    (permission-length-max :accessor permission-length-max
      :initarg :permission-length-max
      :type integer
      :initform 64)
    (permission-regex :accessor permission-regex
      :initarg :permission-regex
      :type string
      :initform "^[a-z]([-a-z0-9_.+]*[a-z0-9])*(:[a-z]+)?$"))
  (:documentation "Abstract base class for user database."))

(defclass rbac-pg (rbac)
  ((dbname :accessor dbname :initarg :dbname :initform "rbac")
    (user-name :accessor user-name :initarg :user-name :initform "cl-user")
    (password :accessor password :initarg :password :initform "")
    (host :accessor host :initarg :host :initform "postgres")
    (port :accessor port :initarg :port :initform 5432)
    (cache-size :reader cache-size
      :initarg :cache-size
      :type integer
      :initform 10000)
    (cache :accessor cache))
  (:documentation "RBAC database class for PostgreSQL."))

(defmethod initialize-instance :after ((rbac rbac-pg) &key)
  "Initialize the lru cache for RBAC."
  (setf (cache rbac) (make-instance 'c:lru-cache :max-size (cache-size rbac))))

(defgeneric clear-cache (rbac)
  (:method ((rbac rbac-pg))
    (setf (cache rbac)
      (make-instance 'c:lru-cache :max-size (cache-size rbac))))
  (:documentation "Clears the RBAC cache."))

(defgeneric id-exists-p (rbac table id)
  (:method ((rbac rbac-pg) (table string) (id string))
    (when (get-value rbac table "id" "id" id) t))
  (:documentation "Returns T when ID exists in TABLE."))

(defgeneric delete-by-id (rbac table id)
  (:method ((rbac rbac-pg) (table string) (id string))
    (let (errors
           (sql (format nil "delete from ~a where id = $1" table)))
      (check errors (get-value rbac table "id" "id" id)
        "ID '~a' not found in table '~a'." id table)
      (report-errors "delete-by-id" errors)
      (with-rbac (rbac)
        (db:query sql id)))
    id)
  (:documentation "Delete ID row from TABLE. Raises an error if ID is not
present in TABLE. Returns the ID of the deleted row."))

(defgeneric table-fields (rbac &optional cache)
  (:method ((rbac rbac) &optional (cache t))
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
  (:documentation "Returns a hash table where the keys are table names and the
values are lists of field names for each table."))

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
  (:documentation "Internal function that returns a list of fields from TABLE,
with each field prefixed with the table alias, and, except for distinct fields,
prefixed with the table name."))

(defgeneric table-join-2 (rbac table-1 table-2 &key fields for-count)
  (:method ((rbac rbac-pg) (table-1 string) (table-2 string) &key
             fields for-count)
    (let* ((link-table (compute-link-table-name (list table-1 table-2)))
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
        table-2 alias-2 link-id-2 id-2))))

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
      sql)))

(defgeneric table-exists-p (rbac table)
  (:method ((rbac rbac) (table string))
    (when (gethash table (table-fields rbac)) t))
  (:documentation "Returns T if TABLE exists in the database."))

(defgeneric table-field-exists-p (rbac table field)
  (:method ((rbac rbac) (table string) (field string))
    (when (and
            (table-exists-p rbac table)
            (member field
              (gethash table (table-fields rbac))
              :test 'equal))
      t))
  (:documentation "Returns T if FIELD exists in TABLE in the database."))

(defgeneric field-exists-p (rbac field)
  (:method ((rbac rbac) (field string))
    (let ((all-fields (loop for fields being the hash-values of
                        (table-fields rbac)
                        append fields)))
      (when (member field all-fields :test 'equal) t)))
  (:documentation "Returns T if FIELD exists in any table in the database."))

(defgeneric to-hash-table (rbac row)
  (:method ((rbac rbac) (row list))
    (loop
      with h = (make-hash-table :test 'equal)
      for (key . value) in row
      do (setf (gethash key h) value)
      finally (return h)))
  (:documentation "Convert a row into a hash table where the table keys
correspond to the field names and the table values correspond to the field
values."))

(defgeneric to-hash-tables (rbac row)
  (:method ((rbac rbac) (rows list))
    (loop for row in rows collect (to-hash-table rbac row)))
  (:documentation "Convert a list of rows representing the result of a
database query from the :STR-ALISTS format into a list of hash tables where each
hash table represents a row."))

(defgeneric name-id-index (rbac table)
  (:method ((rbac rbac) (table string))
    (let* (errors
            (name-field (table-name-field table))
            (index (make-hash-table :test 'equal))
            (sql (format nil "select ~a, id from ~a
                             order by ~a"
                   name-field table name-field)))
      (check errors (table-exists-p rbac table)
        "Table '~a' does not exist." table)
      (check errors (table-field-exists-p rbac table name-field)
        "Field '~a' does not exist in table '~a'." name-field table)
      (report-errors "name-id-index" errors)
      (with-rbac (rbac)
        (loop with result = (db:query sql)
          for (key value) in result
          do (setf (gethash key index) value)
          finally (return index)))))
  (:documentation "Returns a hash table where the keys consists of the names and
the values consist of the IDs from TABLE."))

(defun tables-from-join (join)
  "Given a string that represents the tables and joins part of an SQL statement,
this function returns a list of the table names involved in the join. This also
works if JOIN is just a single table name."
  (loop for table-ref in (re:split "join" join)
    for table = (first (re:split "\\s+" (u:trim table-ref)))
    collect table))

(defun field-no-prefix (field)
  "In SQL query strings, fields are often prefixed with the table alias, such as
'r.id' or 'rs.created_at'. This function removes the prefix and the dot, so that
it returns just the field name, such as 'id' or 'created_at'. If FIELD doesn't
have a prefix, it is returned unchanged."
  (if (re:scan "\\." field)
    (second (re:split "\\." field))
    field))

(defun fields-from-refs (select)
  "Given a list of field references that looks like this:
      (list
        \"rr.id as resource_role_id\"
        \"rr.created_at\"
        \"ro.role_description\")
This function returns a list of field names that looks like this:
      (list
        \"resource_role_id\"
        \"created_at\"
        \"role_description\""
  (loop for field-ref in select
    for field-with-prefix = (u:trim
                              (first
                                (remove-if
                                  (lambda (s) (string= s ""))
                                  (re:split
                                    "\\s+"
                                    (re:regex-replace-all
                                      "distinct|\(|\)" field-ref "")))))
    for field = (field-no-prefix field-with-prefix)
    unless (re:scan "^distinct" field) collect field))

(defgeneric sql-for-list (rbac
                           select-fields
                           tables
                           where
                           order-by-fields
                           page
                           page-size)
  (:method ((rbac rbac-pg)
             (select-fields list)
             (tables string)
             (where list)
             (order-by-fields list)
             (page integer)
             (page-size integer))
    "Generates an SQL statement that selects a list of records, according to the
documentation for the generic function. However, this function expects the main
table to be the first table in TABLES, and the main table must have an alias."
    (let* (errors
            (limit page-size)
            (offset (* (1- page) page-size))
            (order-by (if order-by-fields
                        (format nil "order by ~{~a~^, ~} " order-by-fields)
                        "")))
      (check errors (every
                      (lambda (table) (table-exists-p rbac table))
                      (tables-from-join tables))
        "One or more tables in TABLES do not exist: ~a." tables)
      (check errors (every
                      (lambda (field) (field-exists-p rbac field))
                      (fields-from-refs select-fields))
        "One or more fields in SELECT-FIELDS do not exist: ~a." select-fields)
      (check errors (and (> page-size 0)
                      (<= page-size *max-page-size*))
        "Page size must be between 1 and ~a, got ~a." *max-page-size* page-size)
      (check errors (> page 0) "Page must be greater than 0, got ~a." page)
      (report-errors "sql-for-list" errors)
      (let ((query (add-where-to-query
                     rbac
                     (format nil "select ~{~a~^, ~} from ~a"
                       select-fields tables)
                     where
                     (format nil "~aoffset ~d limit ~d"
                       order-by offset limit))))
        (l:pdebug :in "sql-for-list" :query query)
        query)))
  (:documentation "Internal helper function. Generates a query that selects a
list of records, each containing SELECT-FIELDS, from TABLES.  SELECT-FIELDS is a
list of field names to select. TABLES is a table name, or a string representing
the tables to select from, including any join SQL syntax.  WHERE is a list of
conditions where each condition consists of a field name, an operator, and a
value, with every condition having to be true for a record to be selected.
ORDER-BY-FIELDS is a list of field names to order the results by, with each
string in the list optionally followed by a space and either ASC or DESC, to
indicate the sort order. PAGE is the page number, starting from 1 and defaulting
to 1, and PAGE-SIZE is the number of records to return per page, defaulting to
*default-page-size*. The SQL statement consists of a list with an SQL string
followed by values that are used to replace the placeholders in the string. The
generated query consists of a list where the first element is an SQL string,
and the remaining elements are the values that are used to replace the
placeholders in the SQL string. The query is suitable for passing to the
rbac-query function."))

(defgeneric list-rows-old (rbac
                        select-fields
                        tables
                        where
                        order-by-fields
                        page
                        page-size)
  (:method ((rbac rbac-pg)
             (select-fields list)
             (tables string)
             (where list)
             (order-by-fields list)
             (page integer)
             (page-size integer))
    (let ((query (sql-for-list
                   rbac
                   select-fields
                   tables
                   where
                   order-by-fields
                   page
                   page-size)))
      (with-rbac (rbac)
        (rbac-query query))))
  (:documentation "Internal helper function. Returns a list of rows, with each
row represented as a plist."))

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
          (rbac-query query result-type)))))

;; (defgeneric list-rows (rbac tables &key where order-by fields page page-size)
;;   (:method ((rbac rbac-pg) (tables list) &key
;;              where
;;              fields
;;              (order-by (list (table-name-field (car (last tables)))))
;;              (page 1)
;;              (page-size *default-page-size*))
;;     (let* ((table-count (nth (length tables) '(:one :two :three)))
;;             (select (case table-count
;;                       (:one (format nil "select ~a from ~a"
;;                               (if fields (format nil "~{~a~^, ~}" fields) "*")))
;;                       (:two (table-join rbac (first tables) (second tables)
;;                               :fields fields))
;;                       (:tree (error "Not yet implemented"))))
;;             (quiery (add-where-to-query


             

(defgeneric count-rows (rbac tables &key where)
  (:method ((rbac rbac-pg) (tables string) &key where)
    (let* ((sql-before-where (format nil "select count(*) from ~a" tables))
            (query (add-where-to-query rbac sql-before-where where)))
      (l:pdebug :in "count-rows"
        :tables tables
        :query query)
      (with-rbac (rbac)
        (rbac-query-single query))))
  (:documentation "Returns the count of rows in TABLES that satisfy the
conditions in WHERE. TABLES is a table name, or a string representing the tables
to select from, including any join SQL syntax. WHERE is a list of conditions that must
all be true for a record to be selected. Each element of WHERE consists of a list
containing a field name, an operator, and a value."))

;; (defgeneric make-2-table-join (rbac table-1 table-1)


(defgeneric valid-user-name-p (rbac user-name)
  (:method ((rbac rbac) (user-name string))
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
  (:method ((rbac rbac) (password string))
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
  (:method ((rbac rbac) (email string))
    (when (and (re:scan (email-regex rbac) email)
            (<= (length email) 128))
      t))
  (:documentation "Validates new EMAIL string. The string must look like an
email address, with a proper domain name, and it must have a length that
doesn't exceed 128 characters."))

(defgeneric valid-permission-p (rbac permission)
  (:method ((rbac rbac) (permission string))
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
  (:method ((rbac rbac) (role string))
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
  (:method ((rbac rbac) (resource string))
    (when (and (<= (length resource) (resource-length-max rbac))
            (re:scan (resource-regex rbac) resource))
      t))
  (:documentation "Validates new RESOURCE string."))

(defgeneric valid-description-p (rbac description)
  (:method ((rbac rbac) (description string))
    (when (and (not (zerop (length description)))
            (< (length description) 250))
      t))
  (:documentation "Validates new DESCRIPTION string."))

(defgeneric make-search-clause (rbac sql-before-where search &rest first-values)
  (:method ((rbac rbac) sql-before-where (search list) &rest first-values)
    (loop
      initially (l:pdebug :in "make-search-clause"
                  :sql-before-where sql-before-where
                  :search search
                  :first-values first-values)
      with errors
      and nice-sql = (usql sql-before-where)
      with alias = (main-table-alias nice-sql)
      initially
      (check errors (and search (evenp (length search)))
        "Search conditions must be in pairs: field and value.")
      (report-errors "make-search-clause" errors)
      for key in search by #'cddr
      for value in (cdr search) by #'cddr
      for index = (sql-next-placeholder sql-before-where) then (1+ index)
      collect (format nil "~a = $~d" key index) into sql-clauses
      collect value into values
      finally
      (let ((result (append
                      (list
                        (usql (format nil "~a where ~{~a~^ and ~}~%"
                                nice-sql sql-clauses)))
                      first-values values)))
        (l:pdebug :in "make-search-clause" :result result)
        (return result))))
  (:documentation "Generates an SQL statement that selects rows.
SQL-BEFORE-WHERE is a string that contains the part of the SQL statement that
comes before the WHERE clause, such as 'select id, user_name from users', or
'update users set user_name = $1'. SEARCH is a list of alternating field names
and values, like '(\"user_name\" \"john\" \"email\" \"john@domain.com\")'. In
some cases, SQL-BEFORE-WHERE can contain placeholders, in which case you must
pass the values for those placeholders via FIRST-VALUES."))

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
        (let* ((link-table (compute-link-table-name (list table-1 table-2)))
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
  (:documentation "Adds a link between NAME-1 in TABLE-1 and NAME-2 in TABLE-2.
Returns the ID of the new link row."))

(defgeneric unlink (rbac table-1 table-2 name-1 name-2)
  (:method ((rbac rbac-pg)
             (table-1 string)
             (table-2 string)
             (name-1 string)
             (name-2 string))
    (let* ((link-table (compute-link-table-name (list table-1 table-2)))
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
  (:documentation "Removes the link between NAME-1 in TABLE-1 and NAME-2 in
TABLE-2. Returns the ID of the deleted link row, or NIL if the link did not
exist."))

(defun make-search-key (field search)
  "Internal helper function for the GET-VALUE function. Given a FIELD and a SEARCH
list of alternating field names and values, this function computes a unique key
string that represents the search conditions for FIELD. This value is useful for
checking the cache and avoiding a database call if the value has been recently
retrieved."
  (let ((parts (cons (u:safe-encode field)
                 (mapcar #'u:safe-encode search))))
    (format nil "~{~a~^;~}" parts)))

(defgeneric get-value (rbac table field &rest search)
  (:method ((rbac rbac-pg)
             (table string)
             (field string)
             &rest search)
    (l:pdebug :in "get-value"
      :table table :field field :search (format nil "~{~a=~a~^; ~}" search))
    (let* (errors
            (query-params (make-search-clause rbac
                            (format nil "select ~a from ~a"
                              field
                              table)
                            search)))
      (check errors (table-exists-p rbac table)
        "Table '~a' does not exist." table)
      (check errors (table-field-exists-p rbac table field)
        "Field '~a' does not exist in table '~a'." field table)
      (loop for key in search by #'cddr
        do (check errors (table-field-exists-p rbac table key)
             "Seach Field '~a' does not exist in table '~a'." key table))
      (check errors (and search query-params) "No search conditions provided.")
      (report-errors "get-value" errors)
      (l:pdebug :in "get-value" :query-params query-params)
      (multiple-value-bind (result found)
        (c:cache-get (make-search-key field search) (cache rbac))
        (if found
          (progn
            (l:pdebug :in "get-value" :status "cache hit")
            result)
          (progn
            (l:pdebug :in "get-value" :status "cache miss" :result result)
            (let ((result (with-rbac (rbac)
                            (rbac-query-single query-params))))
              (when result
                (c:cache-put
                  (make-search-key field search) result (cache rbac)))))))))
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

(defgeneric get-role-ids (rbac roles)
  (:method ((rbac rbac) (roles list))
    (loop
      with errors
      and roles = (if roles
                    roles
                    (with-rbac (rbac)
                      (db:query "select role_name from roles
                                 order by role_name"
                        :column)))
      and role-ids = (make-hash-table :test 'equal)
      for role in roles
      do (setf (gethash role role-ids)
           (check errors (get-id rbac "roles" role)
             "Role '~a' not found." role))
      finally (return (progn (report-errors "get-role-ids" errors) role-ids))))
  (:documentation "Returns a hash table where the keys consist of role names
and the values consist of role IDs. If ROLES is NIL, the hash table contains
all existing roles and their IDs. Otherwise, if ROLES is not NIL, the hash
table contains IDs for the roles in ROLES only. If ROLES contains a role
that doesn't exist, this function signals an error."))

(defgeneric get-permission-ids (rbac permissions)
  (:method ((rbac rbac) (permissions list))
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

(defgeneric validate-add-user-params (rbac user-name email password roles)
  (:method ((rbac rbac-pg)
             (user-name string)
             (email string)
             (password string)
             (roles list))
    (let* ((errors nil)
            (distinct-roles (u:distinct-elements roles))
            (role-ids (get-role-ids rbac distinct-roles)))
      (check errors (valid-user-name-p rbac user-name)
        "Invalid user-name '~a'." user-name)
      (check errors (valid-password-p rbac password) "Invalid password.")
      (check errors (valid-email-p rbac email)
        "Invalid email '~a'." email)
      (check errors (not (get-id rbac "users" user-name))
        "User-name '~a' is taken." user-name)
      (check errors (or *allow-test-user-insert*
                      (not (re:scan "^test-user-.*" user-name)))
        "User-names that start with 'test-user-' are not allowed.")
      (report-errors "validate-add-user-params" errors)
      role-ids))
  (:documentation "Validates add-user parameters and signals and error if
there's a problem. Returns ROLE-IDS (a hash table)."))

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
  (:documentation "Validates login parameters and signals an error if there's
a problem. Returns T upon success"))

(defgeneric validate-add-role-params (rbac
                                       role
                                       description
                                       exclusive
                                       permissions)
  (:method ((rbac rbac-pg)
             (role string)
             (description string)
             exclusive
             (permissions list))
    (let (errors
           (permission-ids (get-permission-ids rbac permissions)))
      (check errors (valid-role-p rbac role)
        "Invalid role name '~a'." role)
      (check errors (valid-description-p rbac description)
        "Invalid description '~a'." description)
      (check errors (not (get-id rbac "roles" role))
        "Role '~a' already exists." role)
      (if (re:scan ":exclusive$" role)
        (progn
          (check errors exclusive
            "Bad name for an exclusive role. (role='~a'; exclusive=~a)"
            role exclusive)
          (check errors (re:scan "^Exclusive role for user .+\\.$" description)
            "Bad description for an exclusive role: '~a'." description))
        (check errors (not exclusive)
          "Bad name for a non-exclusive role: '~a'" role))
      (report-errors "validate-add-role-params" errors)
      permission-ids))
  (:documentation "Validates add-role parameters and signals an error if
there's a problem. Returns a hash table with permission-name keys and
permission-ID values."))

(defun make-insert-name-query (table name &rest other-fields)
  "This is an internal function that generates an SQL insert statement with
placeholders and values for inserting a new row into TABLE with fields NAME and
OTHER-FIELDS. Returns a list where the first element is the SQL string and the
remaaining elements are the values to be used. The return value is suitable for
passing to rbac-query or rbac-query-single."
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
  (:documentation "Validates parameters for inserting NAME into TABLE. Internal
helper function for insert-name. Internal use only."))

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
  (:documentation "Adds NAME to TABLE with DESCRIPTION. Raises an error if NAME
already exists in TABLE. The users and roles tables require additional parameters
which must be provided via the &KEY arguments. Returns the ID of the new row."))

(defgeneric insert-user (rbac user-name email password)
  (:method ((rbac rbac-pg) (user-name string) (email string) (password string))
    (l:pdebug :in "insert-user" :user-name user-name :email email)
    (insert-name rbac "users" user-name :email email :password password))
  (:documentation "Inserts a new user into the users table without validating
any of the parameters. Returns the new user's ID. For internal use only."))

(defgeneric insert-role (rbac role &key description exclusive)
  (:method ((rbac rbac-pg) (role string) &key
             (description (format nil "role '~a'" role))
             exclusive)
    (l:pdebug :in "insert-role" :status "inserting new role" :role role
      :exclusive exclusive)
    (insert-name rbac "roles" role :description description :exclusive exclusive))
  (:documentation "Inserts a new role into the roles table without validating
any of the parameters. Returns the new role's ID. For internal use only."))

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
  (:documentation "Add an exclusive role for USER, returning the ID of the new
role"))

(defgeneric insert-permission (rbac permission &key description)
  (:method ((rbac rbac-pg) (permission string) &key
             (description (format nil "permission '~a'" permission)))
    (l:pdebug :in "insert-permission" :permission permission)
    (insert-name rbac "permissions" permission :description description))
  (:documentation "Inserts a new permission into the permissions table without
validating any of the parameters. Returns the new permission's ID. For internal
use only."))

(defgeneric insert-resource (rbac resource &key description)
  (:method ((rbac rbac-pg) (resource string) &key
             (description (format nil "resource '~a'" resource)))
    (l:pdebug :in "insert-resource" :resource resource)
    (insert-name rbac "resources" resource :description description))
  (:documentation "Inserts a new resource into the resources table without
validating any of the parameters. Returns the new resource's ID. For internal"))

(defun compute-link-table-name (tables)
  "Internal helper function that computes the name of the link table."
  (if (= (length tables) 1)
    (singular (first tables))
    (let* ((t1 (first tables))
            (t2 (second tables))
            (option-1 (format nil "~a_~a" (singular t1) t2))
           (option-2 (format nil "~a_~a" (singular t2) t1)))
      (cond
        ((table-exists-p *rbac* option-1) option-1)
        ((table-exists-p *rbac* option-2) option-2)
        (t (error "No link table exists for ~a and ~a" t1 t2))))))

(defgeneric insert-link-sql (table-1 table-2)
  (:method ((table-1 string) (table-2 string))
    (l:pdebug :in "insert-link-sql" :table-1 table-1 :table-2 table-2)
    (let* ((link-table (compute-link-table-name (list table-1 table-2)))
            (id-1-field (format nil "~a_id" (singular table-1)))
            (id-2-field (format nil "~a_id" (singular table-2))))
      (usql (format nil
              "insert into ~a (~a, ~a) values ($1, $2) returning id"
              link-table
              id-1-field id-2-field))))
  (:documentation "This is an internal helper function. It creates SQL that
upserts a row into a link table that has fields that reference TABLE-1 and
TABLE-2, creating a new link between rows in TABLE-1 and TABLE-2.

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
    (let* ((sql (insert-link-sql table-1 table-2))
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
  (:documentation "Internal helper function that inserts a row into a link table
that has fields that reference TABLE-1 and TABLE-2, creating a new link between
rows in TABLE-1 and TABLE-2. The rows are given by ID-1 and ID-2. The name of
the table that references TABLE-1 and TABLE-2 is derived from the names of
TABLE-1 and TABLE-2, as described in the documentation for insert-link-sql."))

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
  (:documentation  "Internal helper function. Check that the operators
in FILTERS are valid. A FILTER is a list of three elements: field name,
operator, and value."))

(defun render-placeholder (value index)
  (cond
    ((or (not value) (eql value :null)) "null")
    ((eql value :false) "false")
    ((eql value :true) "true")
    (t (format nil "$~d" index))))

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
          "When specifying 4 tables, they must be either ~a or ~a."
          "users, roles, permissions, resources"
          "resources, roles, permissions, users"))
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
                     (loop for (field operator value) in filters
                       for index = 1 then (1+ index)
                       for place = (render-placeholder value index)
                       collect (format nil "~a ~a ~a" field operator place)
                       into where-clauses
                       when (re:scan "^\\$[0-9]+$" place)
                       collect value into values
                       finally
                       (return
                         (cons
                           (format nil "~%where ~{~a~^ and ~}" where-clauses)
                           values)))))
            (order (unless for-count
                     (or order-by
                       (let* ((table (car (last tables)))
                               (alias (gethash table *table-aliases*))
                               (name-field (table-name-field table))
                               (field (if (eql table-count :one)
                                        name-field
                                        (format nil "~a.~a" alias name-field))))
                         (format nil "~%order by ~a" field)))))
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
      query)))

(defgeneric list-permissions (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (list-rows
      rbac
      (list "id" "permission_name" "permission_description" "created_at"
        "updated_at")
      "permissions"
      nil
      nil
      (list "permission_name")
      page
      page-size))
  (:documentation "List permissions, returning PAGE-SIZE permissions starting
on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-permissions-count (rbac)
  (:method ((rbac rbac-pg))
    (count-rows rbac "permissions" nil))
  (:documentation "Return the count of permissions in the database."))

(defgeneric list-roles (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (list-rows
      rbac
      (list "id" "role_name" "role_description" "exclusive" "created_at"
        "updated_at")
      "roles"
      nil
      nil
      (list "role_name")
      page
      page-size))
  (:documentation "List roles, returning PAGE-SIZE roles starting on page PAGE.
PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-roles-count (rbac)
  (:method ((rbac rbac-pg))
    (count-rows rbac "roles" nil nil))
  (:documentation "Return the count of roles in the database."))

(defgeneric list-roles-regular (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (list-rows
      rbac
      (list "id" "role_name" "role_description" "exclusive" "created_at"
        "updated_at")
      "roles"
      (list
        "exclusive = false"
        "role_name not like '%:exclusive'"
        "role_name not in ('public', 'logged-in', 'system')")
      nil
      (list "role_name")
      page
      page-size))
  (:documentation "List non-exclusive roles, returning PAGE-SIZE roles starting"))

(defgeneric list-roles-regular-count (rbac)
  (:method ((rbac rbac-pg))
    (count-rows
      rbac
      "roles"
      (list
        "exclusive = false"
        "role_name not like '%:exclusive'"
        "role_name not in ('public', 'logged-in', 'system')")
      nil))
  (:documentation "Return the count of regular roles in the database."))

(defgeneric list-role-permissions (rbac role page page-size)
  (:method ((rbac rbac-pg)
             (role string)
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-role-permissions"
      :role role :page page :page-size page-size)
    (list-rows
      rbac
      (list "rp.id as role_permission_id"
        "rp.created_at"
        "rp.updated_at"
        "p.id as permission_id"
        "p.permission_name"
        "p.permission_description")
      "role_permissions rp
       join roles r on rp.role_id = r.id
       join permissions p on rp.permission_id = p.id"
      (list "r.role_name = $1")
      (list role)
      (list "p.permission_name")
      page
      page-size))
  (:documentation "List permissions for a role, returning PAGE-SIZE permissions
starting on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and"))

(defgeneric list-role-permissions-count (rbac role)
  (:method ((rbac rbac-pg) (role string))
    (l:pdebug :in "list-role-permissions-count" :role role)
    (count-rows
      rbac
      "role_permissions rp
       join roles r on rp.role_id = r.id
       join permissions p on rp.permission_id = p.id"
      (list "r.role_name = $1")
      (list role)))
  (:documentation "Return the count of permissions for a role."))

(defgeneric list-role-users (rbac role page page-size)
  (:method ((rbac rbac-pg)
             (role string)
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-role-users" :role role :page page :page-size page-size)
    (list-rows
      rbac
      (list
        "ru.id as role_user_id"
        "ru.created_at"
        "ru.updated_at"
        "u.id as user_id"
        "u.user_name"
        "u.email")
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list "r.role_name = $1")
      (list role)
      (list "u.user_name")
      page
      page-size))
  (:documentation "List users for a role, returning PAGE-SIZE users starting
on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-role-users-count (rbac role)
  (:method ((rbac rbac-pg) (role string))
    (l:pdebug :in "list-role-users-count" :role role)
    (count-rows
      rbac
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list "r.role_name = $1")
      (list role)))
  (:documentation "Return the count of users for a role."))

(defgeneric list-user-roles (rbac user page page-size)
  (:method ((rbac rbac-pg)
             (user string)
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-user-roles" :user user :page page :page-size page-size)
    (list-rows
      rbac
      (list
        "ru.id as role_user_id"
        "ru.created_at"
        "ru.updated_at"
        "r.id as role_id"
        "r.role_name")
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list "u.user_name = $1")
      (list user)
      (list "r.role_name")
      page
      page-size))
  (:documentation "List the roles for a given user, returning PAGE-SIZE roles
starting on page PAGE. Page starts at 1. PAGE-SIZE is an integer between 1 and
1000."))

(defgeneric list-user-roles-count (rbac user)
  (:method ((rbac rbac-pg) (user string))
    (l:pdebug :in "list-user-roles-count" :user user)
    (count-rows
      rbac
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list "u.user_name = $1")
      (list user)))
  (:documentation "Return the count of roles for USER."))

(defgeneric list-user-roles-regular (rbac user page page-size)
  (:method ((rbac rbac-pg)
             (user string)
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-user-roles-regular" :user user)
    (list-rows
      rbac
      (list
        "ru.id as role_user_id"
        "ru.created_at"
        "ru.updated_at"
        "r.id as role_id"
        "r.role_name")
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list "u.user_name = $1"
        "r.exclusive = false"
        "r.role_name not like '%:exclusive'"
        "r.role_name not in ('public', 'logged-in', 'system')")
      (list user)
      (list "r.role_name")
      page
      page-size))
  (:documentation "List the roles for USER excluding the user's exclusive
role, the public role, and the logged-in role, returning PAGE-SIZE roles starting
on page PAGE."))

(defgeneric list-user-roles-regular-count (rbac user)
  (:method ((rbac rbac-pg) (user string))
    (l:pdebug :in "list-user-roles-regular-count" :user user)
    (count-rows
      rbac
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list
        "u.user_name = $1"
        "r.exclusive = false"
        "r.role_name not like '%:exclusive'"
        "r.role_name not in ('public', 'logged-in', 'system')")
      (list user)))
  (:documentation "Return the count of roles for USER excluding the user's
exclusive role, the public role, and the logged-in role."))

(defgeneric list-resources (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (list-rows
      rbac
      (list "id" "resource_name" "resource_description" "created_at"
        "updated_at")
      "resources"
      nil
      nil
      (list "resource_name")
      page
      page-size))
  (:documentation "List resources, returning PAGE-SIZE resources starting on
page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-resources-count (rbac)
  (:method ((rbac rbac-pg))
    (count-rows rbac "resources" nil nil))
  (:documentation "Return the count of resources in the database."))

(defgeneric list-user-resources (rbac user permission page page-size)
  (:method ((rbac rbac-pg)
             (user string)
             permission
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-user-resources"
      :user user :permission permission :page page :page-size page-size)
    (list-rows
      rbac
      (list
        "distinct s.id as resource_id"
        "s.resource_name"
        "s.resource_description")
      "resources s
         join resource_roles sr on s.id = sr.resource_id
         join roles r on sr.role_id = r.id
         join role_users ru on r.id = ru.role_id
         join users u on ru.user_id = u.id
         join role_permissions rp on rp.role_id = r.id
         join permissions p on rp.permission_id = p.id"
      (list
        "u.user_name = $1"
        (if permission "p.permission_name = $2" "1=1"))
      (remove-if-not #'identity (list user permission))
      (list "s.resource_name")
      page
      page-size))
  (:documentation "List the resources that USER has access to with PERMISSION, returning
PAGE-SIZE rows from PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-user-resources-count (rbac user permission)
  (:method ((rbac rbac-pg) (user string) permission)
    (l:pdebug :in "list-user-resources-count"
      :user user :permission permission)
    (count-rows
      rbac
      "resources s
         join resource_roles sr on s.id = sr.resource_id
         join roles r on sr.role_id = r.id
         join role_users ru on r.id = ru.role_id
         join users u on ru.user_id = u.id
         join role_permissions rp on rp.role_id = r.id
         join permissions p on rp.permission_id = p.id"
      (list
        "u.user_name = $1"
        (if permission "p.permission_name = $2" "1=1"))
      (remove-if-not #'identity (list user permission))))
  (:documentation "Return the count of resources that USER has access to with PERMISSION."))

(defgeneric list-resource-users
  (rbac resource permission page page-size)
  (:method ((rbac rbac-pg)
             (resource string)
             permission
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-resource-users"
      :resource resource
      :permission permission)
    (list-rows
      rbac
      (list
        "distinct u.id as user_id"
        "u.user_name")
      "users u
         join role_users ru on u.id = ru.user_id
         join roles r on ru.role_id = r.id
         join role_permissions rp on r.id = rp.role_id
         join permissions p on rp.permission_id = p.id
         join resource_roles sr on r.id = sr.role_id
         join resources s on sr.resource_id = s.id"
      (list
        "s.resource_name = $1"
        (if permission "p.permission_name = $2" "1=1"))
      (remove-if-not #'identity (list resource permission))
      (list "u.user_name")
      page
      page-size))
  (:documentation "List the users have PERMISSION on RESOURCE, returning PAGE-SIZE rows
from PAGE. If PERMISSION is nil, this function lists RESOURCE users with any
permission. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-resource-users-count (rbac resource permission)
  (:method ((rbac rbac-pg)
             (resource string)
             permission)
    (l:pdebug :in "list-resource-users-count"
      :resource resource
      :permission permission)
    (count-rows
      rbac
      "users u
         join role_users ru on u.id = ru.user_id
         join roles r on ru.role_id = r.id
         join role_permissions rp on r.id = rp.role_id
         join permissions p on rp.permission_id = p.id
         join resource_roles sr on r.id = sr.role_id
         join resources s on sr.resource_id = s.id"
      (list
        "s.resource_name = $1"
        (if permission "p.permission_name = $2" "1=1"))
      (remove-if-not #'identity (list resource permission))))
  (:documentation "Return the count of users who have PERMISSION on RESOURCE."))

(defgeneric list-resource-roles (rbac resource page page-size)
  (:method ((rbac rbac-pg)
             (resource string)
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-resource-roles"
      :resource resource :page page :page-size page-size)
    (list-rows
      rbac
      (list
        "rr.id as resource_role_id"
        "rr.created_at"
        "rr.updated_at"
        "ro.id as role_id"
        "ro.role_name"
        "ro.role_description")
      "resource_roles rr
       join resources re on rr.resource_id = re.id
       join roles ro on rr.role_id = ro.id"
      (list "re.resource_name = $1")
      (list resource)
      (list "ro.role_name")
      page
      page-size))
  (:documentation "List roles for a resource, returning PAGE-SIZE roles starting
on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-resource-roles-count (rbac resource)
  (:method ((rbac rbac-pg) (resource string))
    (l:pdebug :in "list-resource-roles-count" :resource resource)
    (count-rows
      rbac
      "resource_roles rr
       join resources re on rr.resource_id = re.id
       join roles r on rr.role_id = r.id"
      (list "re.resource_name = $1")
      (list resource)))
  (:documentation "Return the count of roles for a resource."))

(defgeneric list-resource-roles-regular (rbac resource page page-size)
  (:method ((rbac rbac-pg)
             (resource string)
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-resource-roles-regular"
      :resource resource :page page :page-size page-size)
    (list-rows
      rbac
      (list
        "rr.id as resource_role_id"
        "rr.created_at"
        "rr.updated_at"
        "ro.id as role_id"
        "ro.role_name"
        "ro.role_description")
      "resource_roles rr
       join resources re on rr.resource_id = re.id
       join roles ro on rr.role_id = ro.id"
      (list "re.resource_name = $1"
        "ro.exclusive = false"
        "ro.role_name not like '%:exclusive'"
        "ro.role_name not in ('public', 'logged-in', 'system')")
      (list resource)
      (list "ro.role_name")
      page
      page-size))
  (:documentation "List non-exclusive roles for a resource, returning PAGE-SIZE"))

(defgeneric list-resource-roles-regular-count (rbac resource)
  (:method ((rbac rbac-pg) (resource string))
    (l:pdebug :in "list-resource-roles-regular-count"
      :resource resource)
    (count-rows
      rbac
      "resource_roles rr
       join resources re on rr.resource_id = re.id
       join roles r on rr.role_id = r.id"
      (list
        "re.resource_name = $1"
        "r.exclusive = false"
        "r.role_name not like '%:exclusive'"
        "r.role_name not in ('public', 'logged-in', 'system')")
      (list resource)))
  (:documentation "Return the count of non-exclusive roles for a resource."))

(defgeneric list-role-resources (rbac role page page-size)
  (:method ((rbac rbac-pg)
             (role string)
             (page integer)
             (page-size integer))
    (l:pdebug :in "list-role-resources"
      :role role :page page :page-size page-size)
    (list-rows
      rbac
      (list
        "rr.id as resource_role_id"
        "rr.created_at"
        "rr.updated_at"
        "re.id as resource_id"
        "re.resource_name"
        "re.resource_description")
      "resource_roles rr
       join resources re on rr.resource_id = re.id
       join roles ro on rr.role_id = ro.id"
      (list "ro.role_name = $1")
      (list role)
      (list "ro.resource_name")
      page
      page-size))
  (:documentation "List resources associated with ROLE, returning PAGE-SIZE
resources on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and
1000."))

(defgeneric list-role-resources-count (rbac role)
  (:method ((rbac rbac-pg) (role string))
    (l:pdebug :in "list-role-resources-count" :role role)
    (count-rows
      rbac
      "resource_roles rr
       join resources re on rr.resource_id = re.id
       join roles r on rr.role_id = r.id"
      (list "r.role_name = $1")
      (list role)))
  (:documentation "Return the count of resources associated with ROLE."))

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
        user-name resource permission :plists)))
  (:documentation "Determine if user with USER-ID has PERMISSION on RESOURCE."))

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
  (:documentation "Check if USER-NAME has any of the specified ROLE(s)."))

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

(defgeneric d-remove-role (rbac role)
  (:documentation "Remove ROLE with defauls.")
  (:method ((rbac rbac-pg) (role string))
    (remove-role rbac role)))

(defgeneric d-remove-permission (rbac permission)
  (:documentation "Remove permission with defaults.")
  (:method ((rbac rbac-pg) (permission string))
    (remove-permission rbac permission)))

(defgeneric d-remove-resource (rbac resource)
  (:documentation "Remove resource with defaults.")
  (:method ((rbac rbac-pg) (resource string))
    (remove-resource rbac resource)))

(defgeneric d-add-resource-role (rbac resource role)
  (:documentation "Add a role to a resource with defaults.")
  (:method ((rbac rbac-pg) (resource string) (role string))
    (add-resource-role rbac resource role)))

(defgeneric d-remove-resource-role (rbac resource role)
  (:documentation "Remove a role from a resource with defaults.")
  (:method ((rbac rbac-pg) (resource string) (role string))
    (remove-resource-role rbac resource role)))

(defgeneric d-add-role-permission (rbac role permission)
  (:documentation "Add a permission to a role with defaults.")
  (:method ((rbac rbac-pg) (role string) (permission string))
    (add-role-permission rbac role permission)))

(defgeneric d-remove-role-permission (rbac role permission)
  (:documentation "Remove a permission from a role with defaults.")
  (:method ((rbac rbac-pg) (role string) (permission string))
    (remove-role-permission rbac role permission)))

(defgeneric d-add-role-user (rbac role user)
  (:documentation "Add a user to a role with defaults.")
  (:method ((rbac rbac-pg) (role string) (user string))
    (add-role-user rbac role user)))

(defgeneric d-add-user-role (rbac user role)
  (:documentation "Add a role to a user with defaults.")
  (:method ((rbac rbac-pg) (user string) (role string))
    (add-role-user rbac role user)))

(defgeneric d-remove-role-user (rbac role user)
  (:documentation "Remove a user from a role with defaults.")
  (:method ((rbac rbac-pg) (role string) (user string))
    (remove-role-user rbac role user)))

(defgeneric d-remove-user-role (rbac user role)
  (:documentation "Remove a role from a user with defaults.")
  (:method ((rbac rbac-pg) (user string) (role string))
    (remove-role-user rbac role user)))

(defgeneric d-add-user (rbac username password &key email roles)
  (:documentation "Add a user with defaults.")
  (:method ((rbac rbac-pg) (username string) (password string)
             &key (email "no-email") roles)
    (add-user rbac username email password roles)))

(defgeneric d-remove-user (rbac username)
  (:documentation "Remove a user with defaults.")
  (:method ((rbac rbac-pg) (username string))
    (remove-user rbac username)))

(defgeneric d-login (rbac username password)
  (:documentation "Log in user.")
  (:method ((rbac rbac-pg)
             (username string)
             (password string))
    (login rbac username password)))


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

(defgeneric add-role (rbac role &key description exclusive permissions)
  (:method ((rbac rbac-pg) (role string) &key
             (description (make-description "role" role))
             (exclusive (when (re:scan ":exclusive$" role) t))
             (permissions *default-permissions*))
    (l:pdebug :in "add-role"
      :role role :exclusive exclusive :permissions permissions)
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
  (:documentation "Add a new role. Description is optional and auto-generated
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

(defgeneric add-resource (rbac name &key description roles)
  (:method ((rbac rbac-pg) (resource string) &key
             (description (make-description "resource" resource))
             roles)
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
    "Convert NAME to an identifier using FORMAT."
    (intern (format nil format (string-upcase (re:regex-replace "_" name "-")))))

  (defun singular (string)
    "If STRING ends with an 's', this function returns the string without
the 's'at the end."
    (re:regex-replace "s$" string ""))

  (defun table-name-field (table &optional as-keyword)
    "Returns the name field for TABLE. The name field is the singular form of
the table name, with '_name' appended."
    (format nil "~a~aname" (singular table) (if as-keyword "-" "_"))))

(defmacro define-list-functions (&rest tables)
  (let* ((fname (if (= (length tables) 1)
                  (first tables)
                  (format nil "~a-~a"
                    (singular (first tables)) (second tables))))
          (f-all (name-to-identifier fname "LIST-~a"))
          (f-names (name-to-identifier (singular fname) "LIST-~a-NAMES"))
          (f-count (name-to-identifier (singular fname) "~a-COUNT"))
          (name-field (table-name-field (car (last tables)))))
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
             :filters filters :order-by order-by)))
       (defgeneric ,f-names (rbac &key page page-size filters order-by)
         (:method ((rbac rbac-pg) &key
                    (page 1)
                    (page-size *default-page-size*)
                    filters
                    order-by)
           (list-rows rbac ',tables
             :page page :page-size page-size
             :filters filters :order-by order-by
             :fields (list ,name-field) :result-type :column)))
       (defgeneric ,f-count (rbac &key filters)
          (:method ((rbac rbac-pg) &key filters)
            (list-rows rbac ',tables
              :filters filters :result-type :single :for-count t))))))

(defmacro define-list-functions-1 (&rest tables)
  (let* ((fname (if (= (length tables) 1)
                  (first tables)
                  (format nil "~a-~a"
                    (singular (first tables)) (second tables))))
          (f-all (name-to-identifier fname "LIST-~a"))
          (f-names (name-to-identifier (singular fname) "LIST-~a-NAMES"))
          (f-count (name-to-identifier (singular fname) "~a-COUNT"))
          (name-field (table-name-field (car (last tables))))
          (filter-field (table-name-field (car tables))))
    `(progn
       (defgeneric ,f-all (rbac subject &key page page-size fields filters order-by)
         (:method ((rbac rbac-pg) (subject string) &key
                    (page 1)
                    (page-size *default-page-size*)
                    fields
                    filters
                    order-by)
           (list-rows rbac ',tables
             :page page :page-size page-size :fields fields
             :filters (cons (list ,filter-field "=" subject) filters)
             :order-by order-by)))
       (defgeneric ,f-names (rbac subject &key page page-size filters order-by)
         (:method ((rbac rbac-pg) (subject string) &key
                    (page 1)
                    (page-size *default-page-size*)
                    filters
                    order-by)
           (list-rows rbac ',tables
             :page page :page-size page-size
             :filters (cons (list ,filter-field "=" subject) filters)
             :fields (list ,name-field)
             :order-by order-by :result-type :column)))
       (defgeneric ,f-count (rbac subject &key filters)
          (:method ((rbac rbac-pg) (subject string) &key filters)
            (list-rows rbac ',tables
              :filters (cons (list ,filter-field "=" subject) filters)
              :result-type :single :for-count t))))))

(defmacro define-list-functions-2 (&rest tables)
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
                   (name-to-identifier "resource" "~a"))))
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
             :order-by order-by)))
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
               :fields (list ,name-field) :result-type :column))))
       (defgeneric ,f-count (rbac ,param permission &key filters)
         (:method ((rbac rbac-pg) (param string) (permission string) &key
                    filters)
           (list-rows rbac ',tables
             :filters (append
                        (list
                          (list ,filter-field-1 "=" ,param)
                          (list ,filter-field-2 "=" permission))
                        filters)
             :result-type :single :for-count t))))))

;; List functions

;; These require no parameters
(define-list-functions "users")
(define-list-functions "roles")
(define-list-functions "permissions")
(define-list-functions "resources")

;; These require 1 parameter
(define-list-functions-1 "users" "roles")
(define-list-functions-1 "roles" "permissions")
(define-list-functions-1 "roles" "users")
(define-list-functions-1 "roles" "resources")
(define-list-functions-1 "resources" "roles")

;; These require 2 parameters
(define-list-functions-2 "users" "roles" "permissions" "resources")
(define-list-functions-2 "resources" "roles" "permissions" "users")
