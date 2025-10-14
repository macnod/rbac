(defpackage :rbac
  (:use :cl)
  (:local-nicknames 
    (:ds :dc-ds)
    (:u :dc-eclectic)
    (:re :ppcre)
    (:db :postmodern))
  (:export
    *default-permissions*
    *default-roles*
    *email-regex*
    *password-regexs*
    *permission-regex*
    *resource-regex*
    *role-regex*
    *username-regex*
    
    ;; Macros
    with-rbac
    check

    ;; Functions
    password-hash
    rbac-query
    rbac-query-single
    report-errors
    sql-next-placeholder
    table-name-field
    usql

    ;; Classses
    rbac
    resource-regex
    resource-length-max
    username-length-max
    username-regex
    password-length-min
    password-length-max
    password-regexes
    email-length-max
    email-regex
    role-length-max
    role-regex
    permission-length-max
    permission-regex

    rbac-pg
    username
    password
    host
    port

    ;; Generic functions
    add-permission
    add-resource
    add-resource-role
    add-role
    add-role-permission
    add-role-user
    add-user
    get-id
    get-permission-ids
    get-role-ids
    get-value
    list-permissions
    list-resource-roles
    list-resources
    list-role-permissions
    list-role-users
    list-roles
    list-rows
    list-users
    login
    remove-permission
    remove-resource
    remove-resource-role
    remove-role
    remove-role-permission
    remove-role-user
    remove-user
    soft-delete
    sql-for-list
    to-hash-table
    to-hash-tables
    user-allowed
    valid-description-p
    valid-email-p
    valid-password-p
    valid-permission-p
    valid-resource-p
    valid-role-p
    valid-username-p

    ;; Funcions with defaults
    d-add-permission
    d-add-resource
    d-add-resource-role
    d-add-role
    d-add-role-permission
    d-add-role-user
    d-add-user
    d-add-user-role
    d-login
    d-remove-permission
    d-remove-resource
    d-remove-resource-role
    d-remove-role
    d-remove-role-permission
    d-remove-role-user
    d-remove-user
    d-remove-user-role

    ;; Simple list functions
    list-usernames
    list-role-names
    list-permission-names
    list-resource-names
    list-role-usernames
    list-user-role-names
    list-role-permission-names
    list-resource-role-names
    list-role-resource-names
    ))
