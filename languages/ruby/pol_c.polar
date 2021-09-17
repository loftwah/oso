# Now roles are involved -- users have roles
# on repositories, granting them permissions
# specific to each repository.
resource Repository {
    permissions = ["read", "delete"];
      roles = ["reader", "admin"];

        "delete" if "admin";
          "read" if "reader";

            "reader" if "admin";
}

has_role(actor, role_name, resource) if
  role in actor.roles and
    role.name = role_name and
      role.resource = resource;

      allow(_actor, "read", repository: Repository) if
        repository.isPublic;

        allow(actor, action, resource) if
          has_permission(actor, action, resource);
