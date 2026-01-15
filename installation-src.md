### Roswell

You'll need to install some dependencies first:

```sh
ros install postmodern
ros install fiveam
ros install cl-csv
ros install trivial-utf-8
ros install ironclad
ros install swank
ros install macnod/dc-dlist/v1.0
ros install macnod/dc-ds/v0.5
ros install macnod/dc-time/v0.5
ros install macnod/p-log/v0.9
ros install macnod/dc-eclectic/v0.51
```

Then, you can install `rbac` like this:

`ros install macnod/rbac/vX.X`

where X.X is the release. You can find the latest release in [the repo](https://github.com/macnod/rbac).

### GitHub
Clone the repo to a directory that Quicklisp or ASDF can see, such as ~/common-lisp. For example:

```sh
cd ~/common-lisp
git clone git@github.com:macnod/rbac.git
cd rbac
```

Then, install the macnod dependencies in a similar fashion. If use Quicklisp, then Quicklisp will take care of installing the other dependencies (non-macnod) when you do `(ql:quickload :rbac)`.

## Usage
One way to use the RBAC library is to create a project that includes the RBAC init.sql file. You might want to edit the init.sql file to change the database name, for example, or to add some tables.

Your project should start PostgreSQL, initialize the database with init.sql (if that hasn't already been done), and load the RBAC library.

Your project can then use the library via the RBAC API.
