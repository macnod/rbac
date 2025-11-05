(in-package :rbac)

;;
;; Constants
;;
(defparameter *default-permissions* (list "create" "read" "update" "delete"))
(defparameter *allow-test-user-insert* nil
  "If true, allows inserting a user with a username that starts with 'test-user-'.")

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
       AND kcu.column_name != 'updated_by'
   ORDER BY tc.table_name")

;; These roles are assigned to new users
(defparameter *default-roles* (list "guest" "logged-in"))

(defparameter *default-page-size* 20)

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
                         (username ,rbac)
                         (password ,rbac)
                         (host ,rbac)
                         :port (port ,rbac)
                         :pooled-p t)
     ,@body))

(defmacro check (errors condition &rest error-message-args)
  "Evaluates CONDITION. If the return value of CONDITION is NIL, this function
pushes an error message onto ERRORS. The error message is created by using
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
(defun report-errors (errors &optional (fail-on-error t))
  "If ERRORS is not NIL, this function signals an error with a message that
consists the strings in ERRORS, separated by spaces."
  (when errors
    (let ((error-message (format nil "Error~p: ~{~a~^ ~}" (length errors) (reverse errors))))
      (u:log-it :error error-message)
      (when fail-on-error
        (error error-message)))))

(defun rbac-query-single (sql-template-and-parameters)
  "Converts SQL-TEMPLATE-AND-PARAMETERS into a query that returns a single
value, and executes that query. SQL-TEMPLATE-AND-PARAMETERS is a list where the
first element is an SQL string (optionally with placeholders) and the rest of
the elements are the values that are used to replace the placeholders in the SQL
string. This function needs to be called inside a with-rbac block."
  (eval (cons 'db:query (append sql-template-and-parameters (list :single)))))

(defun rbac-query (sql-template-and-parameters)
  "Converts SQL-TEMPLATE-AND-PARAMETERS into a query that returns a list of
rows, and executes that query. SQL-TEMPLATE-AND-PARAMETERS is a list where the
first element is an SQL string (optionally with placeholders) and the rest of
the elements are values that are used to replace the placeholders in the SQL
string. This function needs to be called inside of a with-rbac block. Each
row in the result is a plist, where the keys represent the field names."
  (eval (cons 'db:query (append sql-template-and-parameters (list :plists)))))

(defun usql (sql)
  "Converts SQL into a one-line string, removing extra spaces and newlines."
  (re:regex-replace-all "^[ \\t\\n]+|[ \\t\\n]+$"
    (re:regex-replace-all "[ \\t\\n]+" sql " ") ""))

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

(defun singular (string)
  "If a STRING ends with an 's', this function returns the string without
the 's'at the end."
  (re:regex-replace "s$" string ""))

(defun external-reference-field (external-table)
  "Creates a field name that references the id field in EXTERNAL-TABLE."
  (format nil "~a_id" (singular external-table)))

(defun table-name-field (table)
  "Returns the name field for TABLE. If TABLE is 'users', the name field is
'username'. For all other tables, the name field is the singular form of the
table name, with '_name' appended."
  (if (equal table "users")
    "username"
    (format nil "~a_name" (singular table))))

(defun password-hash (username password)
  "Returns the hash of PASSWORD, using USERNAME as the salt. This is how RBAC
stores the password in the database."
  (u:hash-string password :salt username :size 32))

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
    (username-length-max :accessor username-length-max
      :initarg :username-length-max
      :type integer
      :initform 64)
    (username-regex :accessor username-regex
      :initarg :username-regex
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
  (:documentation "Abstract base class for user database. For auditing purposes, methods that
update the database require an actor parameter, which consists of a username
that exists in the users database."))

(defclass rbac-pg (rbac)
  ((dbname :accessor dbname :initarg :dbname :initform "rbac")
    (username :accessor username :initarg :username :initform "cl-user")
    (password :accessor password :initarg :password :initform "")
    (host :accessor host :initarg :host :initform "postgres")
    (port :accessor port :initarg :port :initform 5432))
  (:documentation "RBAC database class for PostgreSQL."))

;;
;; Generic functions
;;

(defgeneric table-fields (rbac &optional cache)
  (:method ((rbac rbac) &optional (cache t))
    (if (and *table-fields* cache)
      *table-fields*
      (with-rbac (rbac)
        (u:log-it-pairs :debug :details "table-fields from database")
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
    (u:log-it-pairs :debug :detail "name-id-index" :table table)
    (let* (errors
            (name-field (table-name-field table))
            (index (make-hash-table :test 'equal))
            (sql (format nil "select ~a, id from ~a
                             where deleted_at is null
                             order by ~a"
                   name-field table name-field)))
      (check errors (table-exists-p rbac table)
        "Table '~a' does not exist." table)
      (check errors (table-field-exists-p rbac table name-field)
        "Field '~a' does not exist in table '~a'." name-field table)
      (report-errors errors)
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
                           where-clauses
                           values
                           order-by-fields
                           page
                           page-size)
  (:method ((rbac rbac-pg)
             (select-fields list)
             (tables string)
             (where-clauses list)
             (values list)
             (order-by-fields list)
             (page integer)
             (page-size integer))
    "Generates an SQL statement that selects a list of records, according to the
documentation for the generic function. However, this function expects the main
table to be the first table in TABLES, and the main table must have an alias."
    (u:log-it :debug "sql-for-list")
    (let* (errors
            (limit page-size)
            (offset (* (1- page) page-size))
            (alias (main-table-alias tables))
            (order-by (if order-by-fields
                        (format nil "order by ~{~a~^, ~}~%" order-by-fields)
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
                      (<= page-size 1000))
        "Page size must be between 1 and 1000, got ~a." page-size)
      (check errors (> page 0) "Page must be greater than 0, got ~a." page)
      (report-errors errors)
      (push (format nil "~adeleted_at is null" alias) where-clauses)
      (let ((query (cons
                     (usql
                       (format nil "
        select
          ~{~a~^,~%          ~}
        from
          ~a
        where
          ~{~a~^~%          and ~}
        ~aoffset ~d
        limit ~d"
                         select-fields
                         tables
                         where-clauses
                         order-by
                         offset
                         limit))
                     values)))
        (u:log-it :debug "sql-for-list: ~a" query)
        query)))
  (:documentation "Generates an SQL statement that selects a list of records,
each containing SELECT-FIELDS, from TABLES. SELECT-FIELDS is a list of field
names to select. TABLES is a table name, or a string representing the tables to
select from, including any join SQL syntax. WHERE-CLAUSES is a list of
conditions, in SQL syntax, that must all be true for a record to be selected.
ORDER-BY-FIELDS is a list of field names to order the results by, with
each string in the list optionally followed by a space and either ASC or
DESC, to indicate the sort order. PAGE is the page number, starting from 1,
and PAGE-SIZE is the number of records to return per page. It must be an
integer between 1 and 1000. The SQL statement consists of a list with an
SQL string followed by values that are used to replace the placeholders in
the string. The generated SQL includes a WHERE clause that excludes deleted
records, i.e. records where the deleted_at field is not null."))

(defgeneric list-rows (rbac
                        select-fields
                        tables
                        where-clauses
                        values
                        order-by-fields
                        page
                        page-size)
  (:method ((rbac rbac-pg)
             (select-fields list)
             (tables string)
             (where-clauses list)
             (values list)
             (order-by-fields list)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-rows")
    (let ((params (sql-for-list
                    rbac
                    select-fields
                    tables
                    where-clauses
                    values
                    order-by-fields
                    page
                    page-size)))
      (with-rbac (rbac)
        (rbac-query params))))
  (:documentation "Returns a list of rows, with each row represented as a
plist."))

(defgeneric count-rows (rbac tables where-clauses values)
  (:method ((rbac rbac-pg)
             (tables string)
             (where-clauses list)
             (values list))
    (u:log-it-pairs :debug :detail "count-rows"
      :tables tables
      :where-clauses (format nil "~{~a~^ and ~}" where-clauses)
      :values (format nil "~{~a~^, ~}" values))
    (let* ((sql (format nil "
                   select count(*)
                   from ~a
                   where ~{~a~^ and ~}"
                  tables
                  where-clauses)))
      (with-rbac (rbac)
        (rbac-query-single (cons sql values)))))
  (:documentation "Returns the count of rows in TABLES that satisfy the
conditions in WHERE-CLAUSES. TABLES is a table name, or a string representing
the tables to select from, including any join SQL syntax. WHERE-CLAUSES is a
list of conditions, in SQL syntax, that must all be true for a record to be
selected."))

(defgeneric valid-username-p (rbac username)
  (:method ((rbac rbac) (username string))
    (when (and (<= (length username) (username-length-max rbac))
            (re:scan (username-regex rbac) username))
      t))
  (:documentation "Validates new USERNANME string.
  USERNAME must:
  - Have at least 1 character
  - Have at most username-length-max characters
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
      with errors
      and nice-sql = (usql sql-before-where)
      with alias = (main-table-alias nice-sql)
      initially
      (check errors (and search (evenp (length search)))
        "Search conditions must be in pairs: field and value.")
      (report-errors errors)
      for key in search by #'cddr
      for value in (cdr search) by #'cddr
      for index = (sql-next-placeholder sql-before-where) then (1+ index)
      collect (format nil "~a = $~d" key index) into sql-clauses
      collect value into values
      finally
      (let ((result (append
                      (list
                        (usql
                          (format nil
                            "~a where ~adeleted_at is null~%  and ~{~a~^~%  and ~}~%"
                            nice-sql alias sql-clauses)))
                      (append first-values values))))
        (u:log-it :debug "make-search-clause: ~a" result)
        (return result))))
  (:documentation "Generates an SQL statement that selects rows.
SQL-BEFORE-WHERE is a string that contains the part of the SQL statement that
comes before the WHERE clause, such as 'select id, username from users', or
'update users set username = $1'. SEARCH is a list of alternating field names
and values, like '(\"username\" \"john\" \"email\" \"john@domain.com\")'. In
some cases, SQL-BEFORE-WHERE can contain placeholders, in which case you must
pass the values for those placeholders via FIRST-VALUES."))

(defgeneric soft-delete-sql (rbac target-table target-row actor-id)
  (:method ((rbac rbac)
             (target-table string)
             (target-row list)
             (actor-id string))
    (u:log-it :debug "soft-delete-sql")
    (make-search-clause
      rbac
      (format nil
        "update ~a
         set
           deleted_at = now(),
           updated_by = $1"
        target-table)
      target-row
      actor-id))
  (:documentation "Generates a SQL statement that soft deletes a row from
TARGET-TABLE, where TARGET-ROW is a list of field names and values that
identify the row to b e deleted. The SQL statement consists of a list with
a an SQL string followed by values that are used to replace the placeholders"))

(defgeneric referencing-soft-delete-sql (rbac
                                          referencing-table
                                          target-table
                                          target-record-id
                                          actor-id)
  (:method ((rbac rbac)
             (referencing-table string)
             (target-table string)
             (target-record-id string)
             (actor-id string))
    (u:log-it :debug "referencing-soft-delete-sql")
    (make-search-clause
      rbac
      (format nil
        "update ~a
         set
           deleted_at = now(),
           updated_by = $1"
        referencing-table)
      (list
        (format nil "~a_id" (string-right-trim "s" target-table))
        target-record-id)
      actor-id))
  (:documentation "Generates a SQL statement that soft deletes rows from
REFERENCING-TABLE that reference TARGET-RECORD-ID in TARGET-TABLE."))

(defgeneric referencing-tables (rbac table)
  (:method ((rbac rbac) (table string))
    (u:log-it :debug "referencing-tables")
    (with-rbac (rbac)
      (db:query *referencing-tables-sql* table :column)))
  (:documentation "Returns a list of tables that reference TABLE with a foreign
key. TABLE is a string with the name of the table. The result is a list of
strings, where each string is the name of a table that references TABLE."))

(defgeneric delete-refs-sql (rbac table row actor-id)
  (:method ((rbac rbac) (table string) (row list) (actor-id string))
    (u:log-it :debug "delete-refs-sql")
    (let* ((ref-tables (referencing-tables rbac table))
            (row-id (apply #'get-value (append (list rbac table "id") row))))
      (loop for ref-table in ref-tables
        collect (referencing-soft-delete-sql
                  rbac
                  ref-table
                  table
                  row-id
                  actor-id))))
  (:documentation "Generates a list of SQL statements that soft delete rows
from all tables that reference ROW in TABLE. ROW is a list of field names and
values that identifies the referenced row, and TABLE is a string identifying the
table that contains ROW. For internal use only."))

(defgeneric soft-delete (rbac
                          delete-target-sql
                          delete-refs-sql
                          details
                          delete-exclusive-role-sql)
  (:method ((rbac rbac-pg)
             (delete-target-sql list)
             (delete-refs-sql list)
             (details hash-table)
             (delete-exclusive-role-sql list))
    (u:log-it :debug "soft-delete")
    (with-rbac (rbac)
      ;; Soft delete the user
      (rbac-query delete-target-sql)
      (u:log-it :debug "delete-target: ~a" delete-target-sql)
      ;; Soft delete all references to the target-record
      (loop for delete-ref in delete-refs-sql
        do
        (u:log-it :debug "delete-ref: ~a" delete-ref)
        (rbac-query delete-ref))
      ;; If the target is a user, then delete the user's exclusive role
      (when delete-exclusive-role-sql
        (rbac-query delete-exclusive-role-sql)
        (u:log-it :debug "deleted-exclusive-role: ~a" delete-exclusive-role-sql))
      ;; Audit the deletion
      (audit rbac details)))
  (:documentation "Executes the given SQL statements in a transaction, to soft
delete a row and references to that row, updating the audit table."))

(defgeneric get-value (rbac table field &rest search)
  (:method ((rbac rbac-pg)
             (table string)
             (field string)
             &rest search)
    (u:log-it-pairs :debug :detail "get-value"
      :table table :field field
      :search (format nil "~{~a=~a~^; ~}" search))
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
      (report-errors errors)
      (with-rbac (rbac)
        (rbac-query-single query-params))))
  (:documentation "Retrieves the value from FIELD in TABLE where SEARCH points
to a unique row. TABLE and FIELD are strings, and SEARCH is a series of field
names and values that identify the row uniquely. TABLE, FIELD, and the field
names in SEARCH must exist in the database. If no row is found, this function
returns NIL."))

(defgeneric get-id (rbac table name)
  (:method ((rbac rbac-pg)
             (table string)
             (name string))
    (u:log-it :debug "get-id")
    (let ((name-field (table-name-field table)))
      (u:log-it-pairs :debug :detail "get-id"
        :table table :name-field name-field :name name)
      (get-value rbac table "id" name-field name)))
  (:documentation "Returns the ID associated with NAME in TABLE."))

(defgeneric get-role-ids (rbac roles)
  (:method ((rbac rbac) (roles list))
    (loop
      initially (u:log-it :debug "get-role-ids")
      with errors
      and roles = (if roles
                    roles
                    (with-rbac (rbac)
                      (db:query "select role_name from roles
                                 where deleted_at is null
                                 order by role_name"
                        :column)))
      and role-ids = (make-hash-table :test 'equal)
      for role in roles
      do (setf (gethash role role-ids)
           (check errors (get-id rbac "roles" role)
             "Role '~a' not found." role))
      finally (return (progn (report-errors errors) role-ids))))
  (:documentation "Returns a hash table where the keys consist of role names
and the values consist of role IDs. If ROLES is NIL, the hash table contains
all existing roles and their IDs. Otherwise, if ROLES is not NIL, the hash
table contains IDs for the roles in ROLES only. If ROLES contains a role
that doesn't exist, this function signals an error."))

(defgeneric get-permission-ids (rbac permissions)
  (:method ((rbac rbac) (permissions list))
    (loop
      initially (u:log-it :debug "get-permission-ids")
      with errors
      and permissions = (if permissions
                          permissions
                          (with-rbac (rbac)
                            (db:query
                              "select permission_name from permissions
                               where deleted_at is null
                               order by permission_name"
                              :column)))
      and permission-ids = (make-hash-table :test 'equal)
      for permission in permissions
      do (setf (gethash permission permission-ids)
           (check errors (get-id rbac "permissions" permission)
             "Permission '~a' not found." permission))
      finally (return (progn (report-errors errors) permission-ids))))
  (:documentation "Returns a hash table where the keys consist of permission
names and the values consist of permission IDs. If PERMISSIONS is NIL, the hash
table contains all existing permissions and their IDs. Otherwise, if PERMISSIONS
is not NIL, the hash table contains IDs for the permissions in PERMISSIONS only.
If PERMISSIONS contains a permission that doesn't exist, this function signals
an error."))

(defgeneric validate-add-user-params (rbac username email password roles actor)
  (:method ((rbac rbac-pg)
             (username string)
             (email string)
             (password string)
             (roles list)
             (actor string))
    (u:log-it :debug "validate-add-user-params")
    (let* ((errors nil)
            (distinct-roles (u:distinct-elements roles))
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor with username '~a' not found" actor))
            (role-ids (get-role-ids rbac distinct-roles)))
      (check errors (valid-username-p rbac username)
        "Invalid username '~a'." username)
      (check errors (valid-password-p rbac password) "Invalid password.")
      (check errors (valid-email-p rbac email)
        "Invalid email '~a'." email)
      (check errors (not (get-id rbac "users" username))
        "Username '~a' is taken." username)
      (check errors (or *allow-test-user-insert*
                      (not (re:scan "^test-user-.*" username)))
        "Usernames that start with 'test-user-' are not allowed.")
      (report-errors errors)
      (values actor-id role-ids)))
  (:documentation "Validates add-user parameters and signals and error if
there's a problem. Returns ACTOR-ID (a string) and ROLE-IDS (a hash table)
as values."))

(defgeneric validate-login-params (rbac username password actor)
  (:method ((rbac rbac-pg)
             (username string)
             (password string)
             (actor string))
    (u:log-it :debug "validate-login-params")
    (let* ((errors nil)
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor with username '~a' not found" actor)))
      (check errors (valid-username-p rbac username)
        "Invalid username '~a'." username)
      (check errors (valid-password-p rbac password) "Invalid password.")
      (report-errors errors nil)
      actor-id))
  (:documentation "Validates login parameters and signals an error if there's
a problem. Returns ACTOR-ID (a string) as value."))

(defgeneric validate-add-permission-params (rbac permission description actor)
  (:method ((rbac rbac-pg)
             (permission string)
             (description string)
             (actor string))
    (u:log-it :debug "validate-add-permission-params")
    (let (errors actor-id)
      ;; Make sure the strings conform to standards
      (check errors (valid-permission-p rbac permission)
        "Invalid permission name '~a'." permission)
      (check errors (> (length description) 0)
        "Description is empty.")
      ;; Make sure that the actor exists
      (check errors (setf actor-id (get-id rbac "users" actor))
        "Actor '~a' doesn't exist." actor)
      ;; Make sure that the permission doesn't exist or that it exists with
      ;; the delete_at field set to a non-null value
      (check errors (not (get-id rbac "permissions" permission))
        "Permission '~a' already exists" permission)
      (report-errors errors)
      actor-id))
  (:documentation "Validates add-permission parameters and signals an error
if there's a problem."))

(defgeneric validate-add-role-params (rbac
                                       role
                                       description
                                       exclusive
                                       permissions
                                       actor)
  (:method ((rbac rbac-pg)
             (role string)
             (description string)
             exclusive
             (permissions list)
             (actor string))
    (u:log-it :debug "validate-add-role-params")
    (let (errors
           actor-id
           (permission-ids (get-permission-ids rbac permissions)))
      (check errors (valid-role-p rbac role)
        "Invalid role name '~a'." role)
      (check errors (valid-description-p rbac description)
        "Invalid description '~a'." description)
      (check errors (not (get-id rbac "roles" role))
        "Role '~a' already exists." role)
      (check errors (setf actor-id (get-id rbac "users" actor))
        "Actor '~a' doesn't exist." actor)
      (if (re:scan ":exclusive$" role)
        (progn
          (check errors exclusive
            "Bad name for an exclusive role: '~a'." role)
          (check errors (re:scan "^Exclusive role for user .+\\.$" description)
            "Bad description for an exclusive role: '~a'." description))
        (check errors (not exclusive)
          "Bad name for a non-exclusive role: '~a'" role))
      (report-errors errors)
      (values actor-id permission-ids)))
  (:documentation "Validates add-role parameters and signals an error if
there's a problem."))

(defgeneric insert-user (rbac username email password actor)
  (:method ((rbac rbac-pg)
             (username string)
             (email string)
             (password string)
             (actor-id string))
    (u:log-it :debug "insert-user username=~a email=~a actor-id=~a"
      username email actor-id)
    (db:query
      "insert into users (username, email, password_hash, updated_by)
     values ($1, $2, $3, $4)
     returning id"
      username
      email
      (password-hash username password)
      actor-id
      :single))
  (:documentation "Inserts a new user into the users table without validating
any of the parameters. Returns the new user's ID. For internal use only."))

(defgeneric insert-role (rbac name description exclusive actor-id)
  (:method ((rbac rbac-pg)
             (role string)
             (description string)
             exclusive
             (actor-id string))
    (if (db:query "select id from roles
                   where role_name = $1
                     and deleted_at is not null"
          role :single)
      (progn
        (u:log-it :debug "insert-role: Reinstating deleted role '~a'" role)
        (db:query
          "update roles set
             role_description = $1,
             updated_at = now(),
             deleted_at = null,
             updated_by = $2
           where role_name = $3
           returning id"
          description actor-id role :single))
      (progn
        (u:log-it :debug "insert-role: Inserting new role '~a'" role)
        (db:query
          "insert into roles (role_name, role_description, exclusive, updated_by)
             values ($1, $2, $3, $4)
             returning id"
          role description exclusive actor-id :single))))
  (:documentation "Inserts a new role into the roles table without validating
any of the parameters. If the role exists already, but has the deleted_at
field set to a non-null value, then the existing role is reinstanted by
setting deleted_at to null and updating the updated_at and updated_by fields.
Returns the new role's ID. For internal use only."))

(defgeneric insert-exclusive-role (rbac username actor-id)
  (:method ((rbac rbac-pg)
             (username string)
             (actor-id string))
    (loop
      initially (u:log-it :debug "insert-exclusive-role username=~a" username)
      with role = (format nil "~a:exclusive" username)
      with description = (format nil "Exclusive role for user ~a." username)
      with role-id = (insert-role rbac role description t actor-id)
      with user-id = (get-id rbac "users" username)
      with permission-ids = (get-permission-ids rbac *default-permissions*)
      for permission-name being the hash-keys of permission-ids
      using (hash-value permission-id)
      do (upsert-link rbac "roles" "permissions" role-id permission-id actor-id)
      finally
      (upsert-link rbac "roles" "users" role-id user-id actor-id)
      (return role)))
  (:documentation "Inserts an exclusive role for the user with USERNAME.
Every user has an exclusive role that is named {username}:exclusive, and
this function creates that role, assigns it to the user, and grants it the
default permissions. Returns the name of the exclusive role."))

(defgeneric insert-permission (rbac permission description actor-id)
  (:method ((rbac rbac-pg)
             (permission string)
             (description string)
             (actor-id string))
    (u:log-it :debug "insert-permission ~a" permission)
    (if (db:query "select id from permissions
                   where permission_name = $1
                     and deleted_at is not null"
          permission
          :single)
      (db:query
        "update permissions set
           permission_description = $1,
           updated_at = now(),
           deleted_at = null,
           updated_by = $2
         where permission_name = $3
         returning id"
        description
        actor-id
        permission
        :single)
      (db:query
        "insert into permissions
           (permission_name, permission_description, updated_by)
         values ($1, $2, $3)
         returning id"
        permission description actor-id :single)))
  (:documentation "Inserts a new permission into the permissions table without
validating any of the parameters. Returns the new permission's ID. For internal
use only."))

(defgeneric insert-resource (rbac resource description actor-id)
  (:method ((rbac rbac-pg)
             (resource string)
             (description string)
             (actor-id string))
    (u:log-it :debug "insert-resource ~a" resource)
    (if (db:query "select id from resources
                   where resource_name = $1
                     and deleted_at is not null"
          resource
          :single)
      (db:query
        "update resources set
           resource_description = $1,
           updated_by = $2,
           deleted_at = null,
           updated_at = now()
         where resource_name = $3
         returning id"
        description
        actor-id
        resource
        :single)
      (db:query
        "insert into resources (resource_name, resource_description, updated_by)
         values ($1, $2, $3)
         returning id"
        resource description actor-id :single)))
  (:documentation "Inserts a new resource into the resources table without
validating any of the parameters. Returns the new resource's ID. For internal"))

(defgeneric upsert-link-sql (table-1 table-2)
  (:method ((table-1 string) (table-2 string))
    (u:log-it :debug "upsert-link-sql ~a ~a" table-1 table-2)
    (let* ((link-table (format nil "~a_~a" (singular table-1) table-2))
            (id-1-field (format nil "~a_id" (singular table-1)))
            (id-2-field (format nil "~a_id" (singular table-2))))
      (usql (format nil
              "insert into ~a (~a, ~a, updated_by)
               values ($1, $2, $3)
               on conflict (~a, ~a)
               do
                 update set
                   updated_by = $3,
                   updated_at = now(),
                   deleted_at = null
               returning id"
              link-table
              id-1-field id-2-field
              id-1-field id-2-field))))
  (:documentation "Creates SQL that upserts a row into a link table that
has fields that reference TABLE-1 and TABLE-2, creating a new link between
rows in TABLE-1 and TABLE-2.

Parameters:
  - TABLE-1 (string): The name of the first table.
  - TABLE-2 (string): The name of the second table.

Description:

This function makes the following assumptions:

  - The names of TABLE-1 and TABLE-2 can be plural and plurals always end in
    's'.

  - The link table already exists and has a name consists of the singular of
    TABLE-1, followed by an underscore, followed by TABLE-2 (plural or not).

  - In the link table, the field, xref1, that references TABLE-1 has a name that
    consists of the singular of TABLE-1 followed by '_id'. The same is true for
    the field, xref2, that references TABLE-2.

  - The link table has a unique index on the pair of rows that reference
    TABLE-1 and TABLE-2, unique({xref1}_id, {xref2}_id).

  - All the tables have a primary key named 'id' of type UUID, and, in addition
    to the already mentioned foreign key references, the link table has the
    fields 'updated_by' (timestamp), 'updated_at' (uuid), and 'deleted_at'
    (uuid).

For example, if you call the function with 'roles' and 'permissions', the
function will make the following concrete assumptions:

  - The name of the link table, where a row will be upserted, is
    'role_permissions'.

  - The link table will contain the following fields:

    - role_id (uuid, references 'roles')

    - permission_id (uuid, references 'permissions')

    - updated_by (uuid, references 'users')

    - updated_at (timestamp)

    - deleted_at (timestamp)

  - The link table will contain a unique index on (role_id, permission_id)
"))

(defgeneric upsert-link (rbac table-1 table-2 id-1 id-2 actor-id)
  (:method ((rbac rbac-pg)
             (table-1 string)
             (table-2 string)
             (id-1 string)
             (id-2 string)
             (actor-id string))
    (u:log-it :debug "upsert-link ~a ~a ~a ~a"
      table-1 table-2 id-1 id-2)
    (let ((sql (upsert-link-sql table-1 table-2)))
      (u:log-it-lazy
        :debug
        (lambda ()
          (let ((name-1 (or (get-value rbac table-1 (table-name-field table-1)
                              "id" id-1)
                          "(not yet available)"))
                 (name-2 (or (get-value rbac table-2 (table-name-field table-2)
                               "id" id-2)
                           "(not yet available)")))
            (format nil "Upsert-link [~a:~a -> ~a:~a] SQL: ~a; (~a, ~a, ~a)"
              table-1 name-1 table-2 name-2 sql id-1 id-2 actor-id))))
      (db:query sql id-1 id-2 actor-id :single)))
  (:documentation "Upserts a row into a link table that has fields that
reference TABLE-1 and TABLE-2, creating a new link between rows in TABLE-1 and
TABLE-2. The rows are given by ID-1 and ID-2. The name of the table that
references TABLE-1 and TABLE-2 is derived from the names of TABLE-1 and TABLE-2,
as described in the documentation for upsert-link-sql."))

(defgeneric add-user (rbac username email password roles actor)
  (:method ((rbac rbac-pg)
             (username string)
             (email string)
             (password string)
             (roles list)
             (actor string))
    (u:log-it :debug "add-user '~a'" username)
    (let ((all-roles (append roles *default-roles*)))
      (multiple-value-bind (actor-id role-ids)
        (validate-add-user-params rbac username email password all-roles actor)
        (with-rbac (rbac)
          ;; Add the user
          (insert-user rbac username email password actor-id)
          ;; Create the user's exclusive role and add the user to it
          (insert-exclusive-role rbac username actor-id)
          ;; Add the user to the rest of the roles
          (loop
            with user-id = (get-id rbac "users" username)
            with details = (ds:ds `(:map
                                     :title "Created user"
                                     :username ,username
                                     :user_id ,user-id
                                     :email ,email
                                     :password ,(password-hash
                                                  username password)
                                     :actor ,actor
                                     :actor_id ,actor-id))
            for role-name being the hash-keys in role-ids
            using (hash-value role-id)
            do (upsert-link rbac "roles" "users" role-id user-id actor-id)
            finally
            (setf (gethash :roles details) role-ids)
            (audit rbac details)
            (return user-id))))))
  (:documentation "Add a new user. This creates an exclusive role, which is
for this user only, and adds the user to the guest and logged-in roles
(given by *default-roles*). Returns the new user's ID."))

(defgeneric remove-user (rbac username actor)
  (:method ((rbac rbac-pg)
             (username string)
             (actor string))
    (u:log-it :debug "remove-user '~a'" username)
    (let* (errors
            (user-id (check errors (get-id rbac "users" username)
                       "User '~a' not found." username))
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor '~a' not found." actor)))
      (if errors
        (u:log-it :debug "Errors: ~{~a~^, ~}~%" errors)
        (u:log-it :debug "No errors~%"))
      (report-errors errors)
      (u:log-it :debug "Reported errors~%")
      (let ((delete-user-sql (soft-delete-sql
                               rbac
                               "users"
                               (list "id" user-id)
                               actor-id))
             (delete-exclusive-role-sql (soft-delete-sql
                                          rbac
                                          "roles"
                                          (list "role_name"
                                            (format nil "~a:exclusive" username))
                                          actor-id))
             (delete-refs-sql (delete-refs-sql
                                rbac "users" (list "id" user-id) actor-id))
             (details (ds:ds `(:map
                                :title "Deleted user and references to user"
                                :username ,username
                                :user_id ,user-id
                                :actor ,actor
                                :actor_id ,actor-id))))
        (u:log-it :debug "About to soft delete~%")
        (u:log-it :debug "~{    ~a: ~a~%~}"
          (list
            "rbac" rbac
            "delete-user-sql" (format nil "~{~a~^; ~}" delete-user-sql)
            "delete-refs-sql" (format nil "~{~a~^; ~}" delete-refs-sql)
            "details" (ds:to-json details)
            "delete-exclusive-role-sql" (format nil "~{~a~^; ~}"
                                          delete-exclusive-role-sql)))
        (soft-delete
          rbac
          delete-user-sql
          delete-refs-sql
          details
          delete-exclusive-role-sql))))
  (:documentation "Remove (soft delete) USERNAME from the database."))

(defgeneric list-users (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-users")
    (list-rows
      rbac
      (list "id" "username" "email" "created_at" "updated_at" "last_login")
      "users"
      (list "deleted_at is null")
      nil
      '("username")
      page
      page-size))
  (:documentation "List users sorted by SORT-BY. Return PAGE-SIZE users starting
from PAGE. SORT-BY is a list of fields, where each field string consists of the
name of a field optionally followed by ASC or DESC. :PAGE is the page number,
starting from 1, and PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-users-count (rbac)
  (:method ((rbac rbac-pg))
    (u:log-it :debug "list-users-count")
    (count-rows rbac "users" (list "deleted_at is null") nil))
  (:documentation "Return the count of users in the database."))

(defgeneric list-users-filtered (rbac sort-by descending filters page page-size)
  (:method ((rbac rbac-pg)
             (sort-by string)
             descending
             (filters list)
             (page integer)
             (page-size integer))
    (u:log-it-pairs :debug :detail "list-users-sorted" :sort-by sort-by)
    (let (errors)
      (check errors (table-field-exists-p rbac "users" sort-by)
        "SORT-BY field '~a' does not exist in the users table." sort-by)
      (check errors (filter-structure-correct-p rbac filters)
        "Bad filter field for users table: ~a" filters)
      (check errors (filter-operators-valid-p filters)
        "Bad filter operator: ~{~a~^, ~}." (mapcar #'second filters))
      (report-errors errors))
    (loop
      for (field operator value) in filters
      collect (format nil "~a ~a $1" field operator) into where
      collect value into values
      finally (return
                (list-rows
                  rbac
                  (list "id" "username" "email" "created_at" "updated_at"
                    "last_login")
                  "users"
                  (append (list "deleted_at is null") where)
                  values
                  (list (format nil "~a ~a"
                          sort-by
                          (if descending "desc" "asc")))
                  page
                  page-size))))
  (:documentation "List users sorted by SORT-BY and filtered by FILTERS.
SORT-BY is a string consisting of the name of a field. DESCENDING is a boolean
that indicates whether the sort is descending or not. FILTERS is a list of
filters, where each filter is a list of three elements: field name, operator,
and value. The supported operators are =, <>, <, >, <=, >=, like, ilike, not
like, not ilike, is, is not. Return PAGE-SIZE users starting from PAGE. PAGE
starts from 1. PAGE-SIZE is an integer between 1 and 1000."))

(defun filter-structure-correct-p (rbac filters)
  "Check that FILTERS is a list of filters, where each filter is a list of
three elements: field name, operator, and value, and that the field names
exist in the users table."
  (every
    (lambda (filter)
      (and
        (listp filter)
        (= (length filter) 3)
        (field-exists-p rbac (field-no-prefix (car filter)))))
    filters))

(defun filter-operators-valid-p (filters)
  "Check that the operators in FILTERS are valid. A FILTER is a list of three
elements: field name, operator, and value. This function ignores the field
name and value, and checks that the operator is one of the supported operators."
  (every
    (lambda (filter)
      (member
        (cadr filter)
        '("=" "<>" "<" ">" "<=" ">=" "is" "is not"
           "like" "ilike" "not like" "not ilike")
        :test 'equal))
    filters))

(defgeneric list-users-filtered-count (rbac filters)
  (:method ((rbac rbac-pg) (filters list))
    (u:log-it :debug "list-users-filtered-count")
    (let (errors)
      (check errors (filter-structure-correct-p rbac filters)
        "Bad filter field for users table: ~a" filters)
      (check errors (filter-operators-valid-p filters)
        "Bad filter operator: ~{~a~^, ~}." (mapcar #'second filters))
      (report-errors errors))
    (loop
      for (field operator value) in filters
      collect (format nil "~a ~a $1" field operator) into where
      collect value into values
      finally (return
                (count-rows
                  rbac
                  "users"
                  (append (list "deleted_at is null") where)
                  values))))
  (:documentation "Returns the count of users filtered by FILTERS. FILTERS is
a list of filters, where each filter is a list of three elements: field name,
operator, and value. The supported operators are =, <>, <, >, <=, >=, like,
ilike, not like, not ilike, is, is not."))

(defgeneric add-permission (rbac permission description actor)
  (:method ((rbac rbac-pg)
             (permission string)
             (description string)
             (actor string))
    (u:log-it :debug "add-permission '~a'" permission)
    (with-rbac (rbac)
      (db:with-transaction (add-permission)
        (let* ((actor-id (validate-add-permission-params
                           rbac permission description actor))
                (details (ds:ds `(:map
                                   :title "Created permission"
                                   :actor ,actor
                                   :actor_id ,actor-id
                                   :permission ,permission
                                   :description ,description))))
          (setf (gethash :permission_id details)
            (insert-permission rbac permission description actor-id))
          (audit rbac details)
          (gethash :permission_id details)))))
  (:documentation "Add a new permission and return its ID."))

(defgeneric remove-permission (rbac permission actor)
  (:method ((rbac rbac-pg)
             (permission string)
             (actor string))
    (u:log-it :debug "remove-permission '~a'" permission)
    (let* (errors
            (permission-id (check errors
                             (get-id rbac "permissions" permission)
                             "Unknown permission '~a'." permission))
            (actor-id (check errors (get-id rbac "users" actor)
                        "Unknown actor '~a'." actor)))
      (report-errors errors)
      (let ((delete-permission-sql (soft-delete-sql
                                     rbac
                                     "permissions"
                                     (list "id" permission-id)
                                     actor-id))
             (delete-refs-sql (delete-refs-sql
                                rbac
                                "permissions"
                                (list "id" permission-id)
                                actor-id))
             (details (ds:ds `(:map
                                :title "Deleted permission"
                                :permission ,permission
                                :permission_id ,permission-id
                                :actor ,actor
                                :actor_id ,actor-id))))
        (soft-delete rbac delete-permission-sql delete-refs-sql details nil)
        permission-id)))
  (:documentation "Remove (soft delete) PERMISSION from the database."))

(defgeneric list-permissions (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-permissions")
    (list-rows
      rbac
      (list "id" "permission_name" "permission_description" "created_at"
        "updated_at")
      "permissions"
      (list "deleted_at is null")
      nil
      (list "permission_name")
      page
      page-size))
  (:documentation "List permissions, returning PAGE-SIZE permissions starting
on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-permissions-count (rbac)
  (:method ((rbac rbac-pg))
    (u:log-it :debug "list-permissions-count")
    (count-rows rbac "permissions" (list "deleted_at is null") nil))
  (:documentation "Return the count of permissions in the database."))

(defgeneric add-role (rbac role description exclusive permissions actor)
  (:method ((rbac rbac-pg)
             (role string)
             (description string)
             exclusive
             (permissions list)
             (actor string))
    (u:log-it :debug "add-role '~a'" role)
    (multiple-value-bind (actor-id permission-ids)
      (validate-add-role-params
        rbac role description exclusive permissions actor)
      (with-rbac (rbac)
        (db:with-transaction (add-role)
          (let* ((role-id (insert-role rbac role description exclusive actor-id))
                  (details (ds:ds `(:map
                                     :title "Created role"
                                     :role_name ,role
                                     :role_id ,role-id
                                     :description ,description
                                     :exclusive ,exclusive
                                     :actor ,actor
                                     :actor_id ,actor-id))))
            (setf (gethash :permission_ids details) permission-ids)
            (loop for permission-id being the hash-values in permission-ids do
              (upsert-link rbac "roles" "permissions" role-id permission-id actor-id))
            (audit rbac details)
            role-id)))))
  (:documentation "Add a new role."))

(defgeneric remove-role (rbac role actor)
  (:method ((rbac rbac-pg) (role string) (actor string))
    (u:log-it :debug "remove-role '~a'" role)
    (let* (errors
            (role-id (check errors (get-id rbac "roles" role)
                       "Role '~a' doesn't exist." role))
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor '~a' doesn't exist." actor)))
      (report-errors errors)
      (let ((delete-role-sql (soft-delete-sql
                               rbac
                               "roles"
                               (list "id" role-id)
                               actor-id))
             (delete-refs-sql (delete-refs-sql
                                rbac "roles" (list "id" role-id) actor-id))
             (details (ds:ds `(:map
                                :title "Deleted role"
                                :role ,role
                                :role_id ,role-id
                                :actor ,actor
                                :actor_id ,actor-id))))
        (soft-delete rbac delete-role-sql delete-refs-sql details nil))))
  (:documentation "Remove (soft delete) a role from the database."))

(defgeneric add-exclusive-role (rbac username actor)
  (:method ((rbac rbac-pg) (username string) (actor string))
    (u:log-it :debug "add-exclusive-role '~a'" username)
    (let ((errors nil)
           (role (format nil "~a:exclusive" username))
           (description (format nil "Exclusive role for user ~a." username)))
      (check errors (valid-username-p rbac username)
        "Invalid username '~a'" username)
      (report-errors errors)
      (add-role rbac role description t *default-permissions* actor)))
  (:documentation "Add an exclusive role for USER, returning the ID of the new
role"))

(defgeneric list-roles (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-roles")
    (list-rows
      rbac
      (list "id" "role_name" "role_description" "exclusive" "created_at"
        "updated_at")
      "roles"
      (list "deleted_at is null")
      nil
      (list "role_name")
      page
      page-size))
  (:documentation "List roles, returning PAGE-SIZE roles starting on page PAGE.
PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-roles-count (rbac)
  (:method ((rbac rbac-pg))
    (u:log-it :debug "list-roles-count")
    (count-rows rbac "roles" (list "deleted_at is null") nil))
  (:documentation "Return the count of roles in the database."))

(defgeneric list-roles-regular (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-roles-regular")
    (list-rows
      rbac
      (list "id" "role_name" "role_description" "exclusive" "created_at"
        "updated_at")
      "roles"
      (list 
        "deleted_at is null"
        "exclusive = false"
        "role_name not like '%:exclusive'"
        "role_name not in ('guest', 'logged-in', 'system')")
      nil
      (list "role_name")
      page
      page-size))
  (:documentation "List non-exclusive roles, returning PAGE-SIZE roles starting"))

(defgeneric list-roles-regular-count (rbac)
  (:method ((rbac rbac-pg))
    (u:log-it :debug "list-roles-regular-count")
    (count-rows
      rbac
      "roles"
      (list 
        "deleted_at is null"
        "exclusive = false"
        "role_name not like '%:exclusive'"
        "role_name not in ('guest', 'logged-in', 'system')")
      nil))
  (:documentation "Return the count of regular roles in the database."))

(defgeneric add-role-permission (rbac role permission actor)
  (:method ((rbac rbac-pg)
             (role string)
             (permission string)
             (actor string))
    (u:log-it :debug "add-role-permission '~a' to role '~a'" permission role)
    (let* (errors
            (actor-id (check errors  (get-id rbac "users" actor)
                        "User '~a' doesn't exist" actor))
            (role-id (check errors (get-id rbac "roles" role)
                       "Role '~a' doesn't exist." role))
            (permission-id (check errors (get-id rbac "permissions" permission)
                             "Permission '~a' doesn't exist." permission)))
      (check errors (not (get-value rbac "role_permissions" "id"
                           "role_id" role-id
                           "permission_id" permission-id))
        "Role '~a' already has permission '~a'." role permission)
      (report-errors errors)
      (with-rbac (rbac)
        (db:with-transaction (add-role-permission)
          (let ((details (ds:ds `(:map
                                   :title "Added role permission"
                                   :role ,role
                                   :role_id ,role-id
                                   :permission ,permission
                                   :permission_id ,permission-id
                                   :actor ,actor
                                   :actor_id ,actor-id))))
            (audit rbac details))
          (upsert-link
            rbac "roles" "permissions" role-id permission-id actor-id)))))
  (:documentation "Add a permission to a role."))

(defgeneric remove-role-permission (rbac role permission actor)
  (:method ((rbac rbac-pg)
             (role string)
             (permission string)
             (actor string))
    (u:log-it :debug "remove-role-permission '~a' from role '~a'"
      permission role)
    (let* (errors
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor '~a' doesn't exist." actor))
            (role-id (check errors (get-id rbac "roles" role)
                       "Role '~a' doesn't exist." role))
            (permission-id (check errors
                             (get-id rbac "permissions" permission)
                             "Permission '~a' doesn't exist." permission))
            (role-permission-id (check errors
                                  (get-value rbac "role_permissions" "id"
                                    "role_id" role-id
                                    "permission_id" permission-id)
                                  "Role '~a' does not have permission '~a'."
                                  role permission))
            (params (soft-delete-sql
                      rbac
                      "role_Permissions"
                      (list "id" role-permission-id)
                      actor-id))
            (details (ds:ds `(:map
                               :title "Deleted role permission"
                               :role_permission_id ,role-permission-id
                               :role ,role
                               :role_id ,role-id
                               :permission ,permission
                               :permission_id ,permission-id
                               :actor ,actor
                               :actor_id ,actor-id))))
      (report-errors errors)
      (with-rbac (rbac)
        (db:with-transaction (remove-role-permission)
          (audit rbac details)
          (rbac-query params)
          permission-id))))
  (:documentation "Remove (soft delete) a permission from a role."))

(defgeneric list-role-permissions (rbac role page page-size)
  (:method ((rbac rbac-pg)
             (role string)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-role-permissions '~a'" role)
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
      (list
        "r.role_name = $1"
        "r.deleted_at is null"
        "p.deleted_at is null"
        "rp.deleted_at is null")
      (list role)
      (list "p.permission_name")
      page
      page-size))
  (:documentation "List permissions for a role, returning PAGE-SIZE permissions
starting on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and"))

(defgeneric list-role-permissions-count (rbac role)
  (:method ((rbac rbac-pg) (role string))
    (u:log-it-pairs :debug :detail "list-role-permissions-count" :role role)
    (count-rows
      rbac
      "role_permissions rp
       join roles r on rp.role_id = r.id
       join permissions p on rp.permission_id = p.id"
      (list
        "r.role_name = $1"
        "r.deleted_at is null"
        "p.deleted_at is null"
        "rp.deleted_at is null")
      (list role)))
  (:documentation "Return the count of permissions for a role."))

(defgeneric add-role-user (rbac role user actor)
  (:method ((rbac rbac-pg)
             (role string)
             (user string)
             (actor string))
    (u:log-it :debug "add-role-user role '~a' user '~a'" role user)
    (let* (errors
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor '~a' doesn't exist." actor))
            (role-id (check errors (get-id rbac "roles" role)
                       "Role '~a' doesn't exist." role))
            (user-id (check errors (get-id rbac "users" user)
                       "User '~a' doesn't exist." user)))
      (check errors (not (get-value rbac "role_users" "id"
                           "role_id" role-id
                           "user_id" user-id))
        "Role '~a' already has user '~a'." role user)
      (report-errors errors)
      (with-rbac (rbac)
        (db:with-transaction (add-role-user)
          (let* ((role-user-id (upsert-link rbac "roles" "users"
                                 role-id user-id actor-id))
                  (details (ds:ds `(:map
                                     :title "Added role user"
                                     :role ,role
                                     :role_id ,role-id
                                     :user ,user
                                     :user_id ,user-id
                                     :role_user_id ,role-user-id
                                     :actor ,actor
                                     :actor_id ,actor-id))))
            (audit rbac details)
            role-user-id)))))
  (:documentation "Add a user to a role."))

(defgeneric add-new-user-roles (rbac user roles actor)
  (:method ((rbac rbac-pg)
             (user string)
             (roles list)
             (actor string))
    (u:log-it :debug "add-new-user-roles user '~a' roles ~{~a~^, ~}" user roles)
    (loop
      with role-ids = (get-role-ids rbac roles)
      for role being the hash-keys in role-ids using (hash-value role-id)
      do (add-role-user rbac role user actor)
      finally (return role-ids)))
  (:documentation "Add USER to the list of ROLES. Returns a hash table
mapping role names to role IDs."))

(defgeneric remove-role-user (rbac role user actor)
  (:method ((rbac rbac-pg)
             (role string)
             (user string)
             (actor string))
    (u:log-it :debug "remove-role-user role '~a' user '~a'" role user)
    (let* (errors
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor '~a' doesn't exist." actor))
            (role-id (check errors (get-id rbac "roles" role)
                       "Role '~a' doesn't exist." role))
            (user-id (check errors (get-id rbac "users" user)
                       "User '~a' doesn't exist." user)))
      (report-errors errors)
      (let* ((params (soft-delete-sql
                       rbac
                       "role_users"
                       (list "role_id" role-id "user_id" user-id)
                       actor-id))
              (details (ds:ds `(:map
                                 :title "Deleted role user"
                                 :role ,role
                                 :role_id ,role-id
                                 :user ,user
                                 :user_id ,user-id
                                 :actor ,actor
                                 :actor_id ,actor-id))))
        (check errors (get-value rbac "role_users" "id"
                        "role_id" role-id
                        "user_id" user-id)
          "Role '~a' does not include user '~a'." role user)
        (report-errors errors)
        (with-rbac (rbac)
          (db:with-transaction (remove-role-user)
            (audit rbac details)
            (rbac-query-single params)
            (list role-id user-id))))))
  (:documentation "Remove (soft delete) a user from a role."))

(defgeneric list-role-users (rbac role page page-size)
  (:method ((rbac rbac-pg)
             (role string)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-role-users '~a'" role)
    (list-rows
      rbac
      (list
        "ru.id as role_user_id"
        "ru.created_at"
        "ru.updated_at"
        "u.id as user_id"
        "u.username"
        "u.email")
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list "r.role_name = $1"
        "r.deleted_at is null"
        "u.deleted_at is null"
        "ru.deleted_at is null")
      (list role)
      (list "u.username")
      page
      page-size))
  (:documentation "List users for a role, returning PAGE-SIZE users starting
on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-role-users-count (rbac role)
  (:method ((rbac rbac-pg) (role string))
    (u:log-it-pairs :debug :detail "list-role-users-count" :role role)
    (count-rows
      rbac
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list
        "r.role_name = $1"
        "r.deleted_at is null"
        "u.deleted_at is null"
        "ru.deleted_at is null")
      (list role)))
  (:documentation "Return the count of users for a role."))

(defgeneric list-user-roles (rbac user page page-size)
  (:method ((rbac rbac-pg)
             (user string)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-user-roles '~a'" user)
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
      (list "u.username = $1"
        "u.deleted_at is null"
        "r.deleted_at is null"
        "ru.deleted_at is null")
      (list user)
      (list "r.role_name")
      page
      page-size))
  (:documentation "List the roles for a given user, returning PAGE-SIZE roles
starting on page PAGE. Page starts at 1. PAGE-SIZE is an integer between 1 and
1000."))

(defgeneric list-user-roles-count (rbac user)
  (:method ((rbac rbac-pg) (user string))
    (u:log-it-pairs :debug :detail "list-user-roles-count" :user user)
    (count-rows
      rbac
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list
        "u.username = $1"
        "u.deleted_at is null"
        "r.deleted_at is null"
        "ru.deleted_at is null")
      (list user)))
  (:documentation "Return the count of roles for USER."))

(defgeneric list-user-roles-regular (rbac user page page-size)
  (:method ((rbac rbac-pg)
             (user string)
             (page integer)
             (page-size integer))
    (u:log-it-pairs :debug :detail "list-user-roles-regular" :user user)
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
      (list "u.username = $1"
        "r.exclusive = false"
        "r.role_name not like '%:exclusive'"
        "r.role_name not in ('guest', 'logged-in', 'system')"
        "u.deleted_at is null"
        "r.deleted_at is null"
        "ru.deleted_at is null")
      (list user)
      (list "r.role_name")
      page
      page-size))
  (:documentation "List the roles for USER excluding the user's exclusive
role, the guest role, and the logged-in role, returning PAGE-SIZE roles starting
on page PAGE."))

(defgeneric list-user-roles-regular-count (rbac user)
  (:method ((rbac rbac-pg) (user string))
    (u:log-it-pairs :debug :detail "list-user-roles-regular-count" :user user)
    (count-rows
      rbac
      "role_users ru
       join roles r on ru.role_id = r.id
       join users u on ru.user_id = u.id"
      (list
        "u.username = $1"
        "r.exclusive = false"
        "r.role_name not like '%:exclusive'"
        "r.role_name not in ('guest', 'logged-in', 'system')"
        "u.deleted_at is null"
        "r.deleted_at is null"
        "ru.deleted_at is null")
      (list user)))
  (:documentation "Return the count of roles for USER excluding the user's
exclusive role, the guest role, and the logged-in role."))

(defgeneric add-resource (rbac name description roles actor)
  (:method ((rbac rbac-pg)
             (resource string)
             (description string)
             (roles list)
             (actor string))
    (u:log-it :debug "add-resource '~a'" resource)
    (let* (errors
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor '~a' doesn't exist." actor))
            (role-ids (get-role-ids rbac roles)))
      (check errors (valid-resource-p rbac resource)
        "Invalid resource name '~a'." resource)
      (check errors
        (not (get-id rbac "resources" resource))
        "Resource '~a' already exists." resource)
      (check errors (valid-description-p rbac description)
        "Invalid description '~a'." description)
      (report-errors errors)
      (with-rbac (rbac)
        (db:with-transaction (add-resource)
          (let* ((resource-id (insert-resource
                                rbac resource description actor-id))
                  (details (ds:ds `(:map
                                     :title "Created resource"
                                     :resource ,resource
                                     :resource_id ,resource-id
                                     :description ,description
                                     :actor ,actor
                                     :actor_id ,actor-id))))
            (setf (gethash :roles details) role-ids)
            (loop for role-id being the hash-values in role-ids
              do (upsert-link rbac "resources" "roles"
                   resource-id role-id actor-id))
            (audit rbac details)
            resource-id)))))
  (:documentation "Add a new resource."))

(defgeneric remove-resource (rbac resource actor)
  (:method ((rbac rbac-pg) (resource string) (actor string))
    (u:log-it :debug "remove-resource '~a'" resource)
    (let* (errors
            (resource-id (check errors
                           (get-id rbac "resources" resource)
                           "Resource '~a' doesn't exist." resource))
            (actor-id (check errors
                        (get-id rbac "users" actor)
                        "Actor '~a' doesn't exist." actor)))
      (report-errors errors)
      (let ((delete-resource-sql (soft-delete-sql
                                   rbac
                                   "resources"
                                   (list "id" resource-id)
                                   actor-id))
             (delete-refs-sql (delete-refs-sql
                                rbac
                                "resources"
                                (list "id" resource-id)
                                actor-id))
             (details (ds:ds `(:map
                                :title "Deleted resource"
                                :resource ,resource
                                :resource_id ,resource-id
                                :actor ,actor
                                :actor_id ,actor-id))))
        (soft-delete rbac delete-resource-sql delete-refs-sql details nil))))
  (:documentation "Remove (soft delete) RESOURCE from the database."))

(defgeneric list-resources (rbac page page-size)
  (:method ((rbac rbac-pg)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-resources")
    (list-rows
      rbac
      (list "id" "resource_name" "resource_description" "created_at"
        "updated_at" "updated_by")
      "resources"
      (list "deleted_at is null")
      nil
      (list "resource_name")
      page
      page-size))
  (:documentation "List resources, returning PAGE-SIZE resources starting on
page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-resources-count (rbac)
  (:method ((rbac rbac-pg))
    (u:log-it :debug "list-resources-count")
    (count-rows rbac "resources" (list "deleted_at is null") nil))
  (:documentation "Return the count of resources in the database."))

(defgeneric list-user-resources (rbac user page page-size)
  (:method ((rbac rbac-pg)
             (user string)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-user-resources '~a'" user)
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
         join users u on ru.user_id = u.id"
      (list
        "u.username = $1"
        "u.deleted_at is null"
        "s.deleted_at is null"
        "sr.deleted_at is null"
        "ru.deleted_at is null"
        "r.deleted_at is null")
      (list user)
      (list "s.resource_name")
      page
      page-size))
  (:documentation "List the resources that USER has access to, returning PAGE-SIZE rows from
PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-user-resources-count (rbac user)
  (:method ((rbac rbac-pg) (user string))
    (u:log-it-pairs :debug :detail "list-user-resources-count" :user user)
    (count-rows
      rbac
      "resources s
         join resource_roles sr on s.id = sr.resource_id
         join roles r on sr.role_id = r.id
         join role_users ru on r.id = ru.role_id
         join users u on ru.user_id = u.id"
      (list
        "u.username = $1"
        "u.deleted_at is null"
        "s.deleted_at is null"
        "sr.deleted_at is null"
        "ru.deleted_at is null"
        "r.deleted_at is null")
      (list user)))
  (:documentation "Return the count of resources that USER has access to."))

(defgeneric list-resource-users
  (rbac resource permission page page-size)
  (:method ((rbac rbac-pg)
             (resource string)
             permission
             (page integer)
             (page-size integer))
    (u:log-it-pairs :debug
      :details "list-resource-users"
      :resource resource
      :permission permission)
    (list-rows
      rbac
      (list
        "distinct u.id as user_id"
        "u.username")
      "users u
         join role_users ru on u.id = ru.user_id
         join roles r on ru.role_id = r.id
         join role_permissions rp on r.id = rp.role_id
         join permissions p on rp.permission_id = p.id
         join resource_roles sr on r.id = sr.role_id
         join resources s on sr.resource_id = s.id"
      (list
        "s.resource_name = $1"
        (if permission "p.permission_name = $2" "1=1")
        "u.deleted_at is null"
        "r.deleted_at is null"
        "s.deleted_at is null"
        "sr.deleted_at is null"
        "ru.deleted_at is null"
        "rp.deleted_at is null"
        "p.deleted_at is null")
      (remove-if-not #'identity (list resource permission))
      (list "u.username")
      page
      page-size))
  (:documentation "List the users have PERMISSION on RESOURCE, returning PAGE-SIZE rows
from PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-resource-users-count (rbac resource permission)
  (:method ((rbac rbac-pg)
             (resource string)
             permission)
    (u:log-it-pairs :debug
      :details "list-resource-users-count"
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
        (if permission "p.permission_name = $2" "1=1")
        "u.deleted_at is null"
        "r.deleted_at is null"
        "s.deleted_at is null"
        "sr.deleted_at is null"
        "ru.deleted_at is null"
        "rp.deleted_at is null"
        "p.deleted_at is null")
      (remove-if-not #'identity (list resource permission))))
  (:documentation "Return the count of users who have PERMISSION on RESOURCE."))

(defgeneric add-resource-role (rbac resource role actor)
  (:method ((rbac rbac-pg)
             (resource string)
             (role string)
             (actor string))
    (u:log-it :debug "add-resource-role resource '~a' role '~a'" resource role)
    (let* (errors
            (resource-id (check errors
                           (get-id rbac "resources" resource)
                           "Resource '~a' doesn't exist." resource))
            (role-id (check errors (get-id rbac "roles" role)
                       "Role '~a' doesn't exist." role))
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor '~a' doesn't exist." actor)))
      (check errors (not (get-value rbac "resource_roles" "id"
                           "resource_id" resource-id
                           "role_id" role-id))
        "Resource '~a' already has role '~a'." resource role)
      (report-errors errors)
      (with-rbac (rbac)
        (db:with-transaction (add-resource-role)
          (let* ((id (upsert-link rbac "resources" "roles"
                       resource-id role-id actor-id))
                  (details (ds:ds `(:map
                                     :title "Added resource role"
                                     :resource ,resource
                                     :resource_id ,resource-id
                                     :role ,role
                                     :role_id ,role-id
                                     :resource-role-id ,id
                                     :actor ,actor
                                     :actor_id ,actor-id))))
            (audit rbac details)
            id)))))
  (:documentation "Add a role permission to a resource."))

(defgeneric remove-resource-role (rbac resource role actor)
  (:method ((rbac rbac-pg)
             (resource string)
             (role string)
             (actor string))
    (u:log-it :debug "remove-resource-role resource '~a' role '~a'"
      resource role)
    (let* (errors
            (resource-id (check errors
                           (get-id rbac "resources" resource)
                           "Resource '~a' doesn't exist." resource))
            (role-id (check errors (get-id rbac "roles" role)
                       "Role '~a' doesn't exist." role))
            (actor-id (check errors (get-id rbac "users" actor)
                        "Actor '~a' doesn't exist." actor))
            (resource-role-id (check errors
                                (get-value rbac "resource_roles" "id"
                                  "resource_id" resource-id
                                  "role_id" role-id)
                                "Resource '~a' does not have role '~a'."
                                resource role))
            (params (soft-delete-sql
                      rbac
                      "resource_roles"
                      (list "id" resource-role-id)
                      actor-id))
            (details (ds:ds `(:map
                               :title "Deleted resource role"
                               :resource_role_id ,resource-role-id
                               :resource ,resource
                               :resource_id ,resource-id
                               :role ,role
                               :role_id ,role-id
                               :actor ,actor
                               :actor_id ,actor-id))))
      (report-errors errors)
      (with-rbac (rbac)
        (db:with-transaction (remove-resource-role)
          (rbac-query params)
          (audit rbac details)
          resource-role-id))))
  (:documentation "Remove (soft delete) a role permission from a resource."))

(defgeneric list-resource-roles (rbac resource page page-size)
  (:method ((rbac rbac-pg)
             (resource string)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-resource-roles '~a'" resource)
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
        "re.deleted_at is null"
        "ro.deleted_at is null"
        "rr.deleted_at is null")
      (list resource)
      (list "ro.role_name")
      page
      page-size))
  (:documentation "List roles for a resource, returning PAGE-SIZE roles starting
on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and 1000."))

(defgeneric list-resource-roles-count (rbac resource)
  (:method ((rbac rbac-pg) (resource string))
    (u:log-it-pairs :debug :detail "list-resource-roles-count" :resource resource)
    (count-rows
      rbac
      "resource_roles rr
       join resources re on rr.resource_id = re.id
       join roles r on rr.role_id = r.id"
      (list
        "re.resource_name = $1"
        "re.deleted_at is null"
        "r.deleted_at is null"
        "rr.deleted_at is null")
      (list resource)))
  (:documentation "Return the count of roles for a resource."))

(defgeneric list-resource-roles-regular (rbac resource page page-size)
  (:method ((rbac rbac-pg)
             (resource string)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-resource-roles-regular '~a'" resource)
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
        "ro.role_name not in ('guest', 'logged-in', 'system')"
        "re.deleted_at is null"
        "ro.deleted_at is null"
        "rr.deleted_at is null")
      (list resource)
      (list "ro.role_name")
      page
      page-size))
  (:documentation "List non-exclusive roles for a resource, returning PAGE-SIZE"))

(defgeneric list-resource-roles-regular-count (rbac resource)
  (:method ((rbac rbac-pg) (resource string))
    (u:log-it-pairs :debug :detail "list-resource-roles-regular-count"
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
        "r.role_name not in ('guest', 'logged-in', 'system')"
        "re.deleted_at is null"
        "r.deleted_at is null"
        "rr.deleted_at is null")
      (list resource)))
  (:documentation "Return the count of non-exclusive roles for a resource."))

(defgeneric list-role-resources (rbac role page page-size)
  (:method ((rbac rbac-pg)
             (role string)
             (page integer)
             (page-size integer))
    (u:log-it :debug "list-role-resources '~a'" role)
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
      (list "ro.role_name = $1"
        "ro.deleted_at is null"
        "re.deleted_at is null"
        "rr.deleted_at is null")
      (list role)
      (list "ro.resource_name")
      page
      page-size))
  (:documentation "List resources associated with ROLE, returning PAGE-SIZE
resources on page PAGE. PAGE starts at 1. PAGE-SIZE is an integer between 1 and
1000."))

(defgeneric list-role-resources-count (rbac role)
  (:method ((rbac rbac-pg) (role string))
    (u:log-it-pairs :debug :detail "list-role-resources-count" :role role)
    (count-rows
      rbac
      "resource_roles rr
       join resources re on rr.resource_id = re.id
       join roles r on rr.role_id = r.id"
      (list
        "r.role_name = $1"
        "r.deleted_at is null"
        "re.deleted_at is null"
        "rr.deleted_at is null")
      (list role)))
  (:documentation "Return the count of resources associated with ROLE."))

(defgeneric user-allowed (rbac username permission resource)
  (:method ((rbac rbac-pg)
             (username string)
             (permission string)
             (resource string))
    "Returns a list of plists showing how the user USERNAME has PERMISSION access to
RESOURCE. If the list is empty, the user does not have access."
    (u:log-it :debug
      "Checking if user '~a' has permission '~a' on resource '~a'"
      username permission resource)
    (with-rbac (rbac)
      (db:query
        "select
             rp.id,
             rp.deleted_at,
             u.username,
             u.deleted_at,
             ru.id as role_user_id,
             ru.deleted_at,
             r.role_name,
             r.deleted_at,
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
             rp.deleted_at is null
             and u.deleted_at is null
             and ru.deleted_at is null
             and rp.deleted_at is null
             and r.deleted_at is null
             and p.deleted_at is null
             and s.deleted_at is null
             and u.username = $1
             and s.resource_name = $2
             and p.permission_name = $3
           order by
             u.username,
             r.role_name,
             p.permission_name,
             s.resource_name"
        username resource permission :plists)))
  (:documentation "Determine if user with USER-ID has PERMISSION on RESOURCE."))

(defgeneric login (rbac username password actor)
  (:method ((rbac rbac-pg)
             (username string)
             (password string)
             (actor string))
    (u:log-it :debug "login '~a'" username)
    (validate-login-params rbac username password actor)
    (let* ((hash (password-hash username password))
            (user-id (get-value rbac "users" "id"
                       "username" username
                       "password_hash" hash)))
      (if user-id
        (progn
          (u:log-it :debug "login successful for user '~a'" username)
          (with-rbac (rbac)
            (db:query
              "update users set last_login = now() where id = $1"
              user-id))
          user-id)
        (progn
          (u:log-it :debug "login failed for user '~a'" username)
          nil))))
  (:documentation "If USERNAME exists and PASSWORD is correct, update last_login
for USERNAME and return the user ID. Otherwise, return NIL."))

(defgeneric audit (rbac details)
  (:method ((rbac rbac) (details hash-table))
    (u:log-it :debug "audit")
    (unless (gethash :actor details)
      (error "No actor: ~a" (ds:human details)))
    (unless (gethash :title details)
      (error "No title"))
    (u:log-it-pairs :info :details "audit" :data (ds:to-json details))
    nil)
  (:documentation "Log the DETAILS hash-table as an audit record."))

(defmacro define-list-functions (rbac-type &rest function-specs)
  "Define multiple list functions with common structure. Each spec is a
list: (function-name documentation list-function return-key extra-arg)"
  `(progn
     ,@(loop for spec in function-specs
         collect (let ((func-name (first spec))
                        (documentation (second spec))
                        (list-func (third spec))
                        (return-key (fourth spec))
                        (extra-arg (fifth spec)))
                   (if extra-arg
                     ;; Function with additional parameter
                     `(defgeneric ,func-name (,rbac-type ,extra-arg &key page page-size)
                        (:documentation ,documentation)
                        (:method ((rbac ,rbac-type)
                                   (,extra-arg string)
                                   &key (page 1) (page-size *default-page-size*))
                          (u:log-it :debug "~(~a~)" ',func-name)
                          (sort
                            (mapcar
                              (lambda (r) (getf r ,return-key))
                              (,list-func rbac ,extra-arg page page-size))
                            #'string<)))
                     ;; Function without additional parameter
                     `(defgeneric ,func-name (,rbac-type &key page page-size)
                        (:documentation ,documentation)
                        (:method ((rbac ,rbac-type)
                                   &key (page 1) (page-size *default-page-size*))
                          (u:log-it :debug "~(~a~)" ',func-name)
                          (sort
                            (mapcar
                              (lambda (r) (getf r ,return-key))
                              (,list-func rbac page page-size))
                            #'string<))))))))

(define-list-functions rbac
  ;; Functions without extra arg
  (list-usernames "List all usernames" list-users :username)
  (list-role-names "List all roles" list-roles :role-name)
  (list-role-names-regular "List all regular roles"
    list-roles-regular :role-name)
  (list-permission-names "List all permissions"
    list-permissions :permission-name)
  (list-resource-names "List all resources"
    list-resources :resource-name)

  ;; Functions with extra arg
  (list-role-usernames "List users for role"
    list-role-users :username role)
  (list-user-role-names "List roles for user"
    list-user-roles :role-name user)
  (list-user-role-names-regular "List regular roles for user"
    list-user-roles-regular :role-name user)
  (list-role-permission-names "List permissions for role"
    list-role-permissions :permission-name role)
  (list-resource-role-names "List roles for resource"
    list-resource-roles :role-name resource)
  (list-resource-role-names-regular "List regular roles for resource"
    list-resource-roles-regular :role-name resource)
  (list-role-resource-names "List resources for role"
    list-role-resources :resource-name role)
  (list-user-resource-names "List resources for user"
    list-user-resources :resource-name user))

(defgeneric list-resource-usernames (rbac resource permission
                                      &key page page-size)
  (:documentation "List usernames that have PERMISSION on RESOURCE.")
  (:method ((rbac rbac-pg)
             (resource string)
             permission
             &key
             (page 1)
             (page-size *default-page-size*))
    (u:log-it :debug "list-resource-usernames")
    (sort
      (mapcar
        (lambda (r) (getf r :username))
        (list-resource-users rbac resource permission page page-size))
      #'string<)))

(defgeneric d-add-role (rbac role &key description exclusive permissions actor)
  (:documentation "Add a role with defaults.")
  (:method ((rbac rbac-pg)
             (role string)
             &key
             (description role)
             exclusive
             (permissions *default-permissions*)
             (actor "system"))
    (add-role rbac role description exclusive permissions actor)))

(defgeneric d-remove-role (rbac role &key actor)
  (:documentation "Remove ROLE with defauls.")
  (:method ((rbac rbac-pg) (role string) &key (actor "system"))
    (remove-role rbac role actor)))

(defgeneric d-add-permission (rbac permission &key description actor)
  (:documentation "Add a permission with defaults.")
  (:method ((rbac rbac-pg) (permission string)
             &key (description permission) (actor "system"))
    (add-permission rbac permission description actor)))

(defgeneric d-remove-permission (rbac permission &key actor)
  (:documentation "Remove permission with defaults.")
  (:method ((rbac rbac-pg) (permission string) &key (actor "system"))
    (remove-permission rbac permission actor)))

(defgeneric d-add-resource (rbac resource &key description roles actor)
  (:documentation "Add a resource with defaults.")
  (:method ((rbac rbac-pg) (resource string)
             &key
             (description resource)
             (roles '("logged-in"))
             (actor "system"))
    (add-resource rbac resource description roles actor)))

(defgeneric d-remove-resource (rbac resource &key actor)
  (:documentation "Remove resource with defaults.")
  (:method ((rbac rbac-pg) (resource string) &key (actor "system"))
    (remove-resource rbac resource actor)))

(defgeneric d-add-resource-role (rbac resource role &key actor)
  (:documentation "Add a role to a resource with defaults.")
  (:method ((rbac rbac-pg) (resource string) (role string)
             &key (actor "system"))
    (add-resource-role rbac resource role actor)))

(defgeneric d-remove-resource-role (rbac resource role &key actor)
  (:documentation "Remove a role from a resource with defaults.")
  (:method ((rbac rbac-pg) (resource string) (role string)
             &key (actor "system"))
    (remove-resource-role rbac resource role actor)))

(defgeneric d-add-role-permission (rbac role permission &key actor)
  (:documentation "Add a permission to a role with defaults.")
  (:method ((rbac rbac-pg) (role string) (permission string)
             &key (actor "system"))
    (add-role-permission rbac role permission actor)))

(defgeneric d-remove-role-permission (rbac role permission &key actor)
  (:documentation "Remove a permission from a role with defaults.")
  (:method ((rbac rbac-pg) (role string) (permission string)
             &key (actor "system"))
    (remove-role-permission rbac role permission actor)))

(defgeneric d-add-role-user (rbac role user &key actor)
  (:documentation "Add a user to a role with defaults.")
  (:method ((rbac rbac-pg) (role string) (user string)
             &key (actor "system"))
    (add-role-user rbac role user actor)))

(defgeneric d-add-user-role (rbac user role &key actor)
  (:documentation "Add a role to a user with defaults.")
  (:method ((rbac rbac-pg) (user string) (role string)
             &key (actor "system"))
    (add-role-user rbac role user actor)))

(defgeneric d-remove-role-user (rbac role user &key actor)
  (:documentation "Remove a user from a role with defaults.")
  (:method ((rbac rbac-pg) (role string) (user string)
             &key (actor "system"))
    (remove-role-user rbac role user actor)))

(defgeneric d-remove-user-role (rbac user role &key actor)
  (:documentation "Remove a role from a user with defaults.")
  (:method ((rbac rbac-pg) (user string) (role string)
             &key (actor "system"))
    (remove-role-user rbac role user actor)))

(defgeneric d-add-user (rbac username password &key email roles actor)
  (:documentation "Add a user with defaults.")
  (:method ((rbac rbac-pg) (username string) (password string)
             &key
             (email "no-email")
             roles
             (actor "system"))
    (add-user rbac username email password roles actor)))

(defgeneric d-remove-user (rbac username &key actor)
  (:documentation "Remove a user with defaults.")
  (:method ((rbac rbac-pg) (username string) &key (actor "system"))
    (remove-user rbac username actor)))

(defgeneric d-login (rbac username password &key actor)
  (:documentation "Log in user.")
  (:method ((rbac rbac-pg)
             (username string)
             (password string)
             &key (actor "system"))
    (login rbac username password actor)))
