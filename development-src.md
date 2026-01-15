This section describes tools to improve the efficiency and accuracy of the development of this software.

### Tests

The tests are located in rbac-tests.lisp.

#### Running all the tests

`make test`

This will start PostreSQL as a Docker container, initialize the database, run all the tests, then stop the database container.

#### Running a swank server

`make test-repl`

This will start PostgreSQL as a Docker container, initialize the database, load the RBAC and RBAC-TEST packages, and wait for you to connect with a client such as Slime. This enables you modify the library's code and the tests in a REPL environment. Go Common Lisp!

The tests are in the `:rbac-test` package. You can run a specific test like this:

```lisp
(in-package :rbac-test)
(run! 'name-of-test)
```

The database is cleared at the beginning of each test. Therefore, any changes that the tests makes to the database are available to you after you run the test. For example, if the test adds a user, then after the test ends, you'll find the user among the results of calling `(list-user-names *rbac*)`. The `:rbac-tests` package uses the `:rbac` package, so in these types of situation, you don't have to switch to the `:rbac` package to call `list-user-names`.

Compiling a function, auto-completion, and so forth all work in the usual way. If you want, you can switch to the `:rbac` package first. That way, you don't have to worry about some not-yet-exported function being available in the `:rbac-test` package.

```lisp
(in-package :rbac)
(list-user-names *rbac*)
```

When you quit the REPL environment, the PostgreSQL container stops.

#### GitHub Actions

This project contains a GitHub Action to run tests. It uses `make test-ci`. The repo is configured to run tests whenever code is pushed to the repo.

### Exports

The exported functions are listed in the usual fashion in the package file, rbac-package.lisp, in alphabetical order.

### Generating Documentation

This README is generated. The code to generate the README is in rbac-docs.lisp. The MGL-PAX library fetches the documentation strings from the variables, functions, accessors, and macros in the code, and uses them to help build the README.

You can generate the README from the command line with `make docs`, or by starting a REPL (see "Running a swank server" above) and then calling `(generate-readme)`.

When adding a documentation string to a variable, function, class accessor, or macro, it's important to start the documentation string with ":public:" or ":private:", to indicate if the symbol should be exported. The `generate-readme` function removes these strings (and the space that follows the string) from the documentation when generating the README.

There's a lot of macro business going on in `rbac-docs.lisp`. If you don't see some new text you edited appearing in the README after calling `generate-readme`, simply evaluate the whole buffer. In Emacs, you can do that with M-x slime-eval-buffer, for example.

### Exports and documentation checks

When you remove a function from the library, it can be easy to forget to update the documentation or the exports section of the package file. This project provides functions to help ensure that nothing is out of sync. Those functions are in the exports.lisp file. The most important function in that file is `check-exports`.

The `check-exports` function returns a plist with the following keys:

- **:missing-in-exports** A list of the variables, functions, class accessors, and macros in the `:rbac` package that have a documentation string that starts with ":public:" and that don't appear in the `:exports` section of the `rbac-package.lisp` file.
- **:stale-exports** A list of symbols that appear in the `:exports` section of the `rbac-package.lisp` file that are not defined in the package, or that no longer have a documentation string that starts with ":public:".
- **:missing-in-docs** A list of the symbols that have a documentation string that starts with ":public:" and that do not appear in the `rbac-docs.lisp` file.
- **:stale-docs** A list of the symbols in `rbac-docs.lisp` that no longer exist or that no longer have a documentation string that starts with ":public:".

Thus, you can easily determine if something is missing from the documentation or the exports.

### Summary of `make` targets

#### **`make test`**
Runs the tests. Run from command line.

#### **`make test-ci`**
Runs the tests. Run from GitHub Actions. (See `.github/workflows/ci.yaml`.)

#### **`make repl`**
Start a Swank server so that you can connect to RBAC and to the RBAC tests with a REPL. Please note the Swank port number, which this command prints when the server is ready.

#### **`make docs`**
Generate the README.md file.
