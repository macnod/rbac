This library provides functions and initial SQL for supporting Role-Based Access Control (RBAC).

The system provides users, roles, permissions, and resources. Users have roles. Roles have permissions. Resources also have roles. However, resources do not have users. To determine if user 'adam' has 'read' access to resource 'book', the user and the book must both have the same role and the role must have the 'read' permission.

A role can be exclusive, which means that it can be associated with only one user. Exclusive roles are managed by the system, so there's never any need to create or delete exclusive roles. However, you can manage the permission for an exclusive role. Whenever a user is created with the `add-user` function, the library creates the user's exclusive role. The user's exclusive role is also removed when the user is removed. Thus, the exclusive role represents that user only. In this way, it's possible to give a specific user access to the resource. All users have a corresponding exclusive role, except for the `guest` user. You can obtain the name of a user's exclusive role  with the `exclusive-role-for` function.

All new users are created with default roles: 'logged-in', 'public', and the exclusive role for that user. If a resource has the 'logged-in' role, then every logged-in user (that is, every user except for 'guest') has access to the resource. If a resource has the 'public' role, then all users, including the guest user (not logged in), have access to the resource. The 'public' and 'logged-in' roles have 'read' permission by default.

Unless you specify specific permissions when creating a new role, its permission defaults to 'create', 'read', 'update', and 'delete'. These are general, default permissions, but you can add any permission you like to the system.

All new resources are created with the default role 'admin'.
