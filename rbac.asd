(asdf:defsystem #:rbac
  :description "Role-based access control in Common Lisp"
  :author "Donnie Cameron <macnod@gmail.com>"
  :license "MIT License"
  :depends-on (:postmodern :cl-ppcre :dc-eclectic)
  :serial t
  :components ((:file "rbac-package")
                (:file "rbac")))
