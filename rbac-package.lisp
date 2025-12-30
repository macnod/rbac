(defpackage :rbac
  (:use :cl)
  (:local-nicknames
    (:ds :dc-ds)
    (:u :dc-eclectic)
    (:re :ppcre)
    (:l :p-log)
    (:db :postmodern)
    (:c :lru-cache))
  (:export
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
    cache

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
    list-permissions-count
    list-resource-roles
    list-resource-roles-count
    list-resource-roles-regular
    list-resource-roles-regular-count
    list-resource-users
    list-resource-users-count
    list-resources
    list-resources-count
    list-role-permissions
    list-role-permissions-count
    list-role-users
    list-role-users-count
    list-roles
    list-roles-count
    list-roles-regular
    list-roles-regular-count
    list-rows
    list-users
    list-users-count
    list-users-filtered
    list-users-filtered-count
    list-user-roles
    list-user-roles-count
    list-user-roles-regular
    list-user-roles-regular-count
    list-user-resources
    list-user-resources-count
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
    user-has-role
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
    list-user-resource-names
    list-role-names
    list-role-names-regular
    list-permission-names
    list-resource-names
    list-resource-usernames
    list-role-usernames
    list-user-role-names
    list-user-role-names-regular
    list-role-permission-names
    list-resource-role-names
    list-resource-role-names-regular
    list-role-resource-names
    ))
