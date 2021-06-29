# GITCLUB POLICY

# # Users can see each other.
# allow(_: User, "read", _: User);

# # Users can see their own profiles
# allow(_: User{id: id}, "read_profile", _: User{id: id});


# # docs: org-create-rule
# # Any logged-in user can create a new org.
# allow(_: User, "create", _: Org);

# # end: org-create-rule

# # ROLES

# resource(_type: Org, "org", actions, roles) if
#     # TODO(gj): might be able to cut down on some repetition with namespacing, e.g., `role_assignments::{create, list, update, delete}`
#     actions = ["read", "create_repos", "list_repos",
#                "create_role_assignments", "list_role_assignments", "update_role_assignments", "delete_role_assignments"] and
#     roles = {
#         member: {
#             permissions: ["read", "list_repos", "list_role_assignments"],
#             implies: ["repo:reader"]
#         },
#         owner: {
#             permissions: ["create_repos", "create_role_assignments", "update_role_assignments", "delete_role_assignments"],
#             implies: ["member", "repo:admin"]
#         }
#     };

# resource(_type: Repo, "repo", actions, roles) if
#     actions = ["read", "create_issues", "list_issues",
#                "create_role_assignments", "list_role_assignments", "update_role_assignments", "delete_role_assignments"] and
#     roles = {
#         admin: {
#             permissions: ["create_role_assignments", "list_role_assignments", "update_role_assignments", "delete_role_assignments"],
#             implies: ["repo:writer"]
#         },
#         writer: {
#             permissions: ["create_issues"],
#             implies: ["repo:reader"]
#         },
#         reader: {
#             permissions: ["read", "list_issues", "issue:read"]
#         }
#     };

# resource(_type: Issue, "issue", actions, _) if
#     actions = ["read"];

# parent_child(parent_repo: Repo, issue: Issue) if
#     issue.repo = parent_repo;

# parent_child(parent_org: Org, repo: Repo) if
#     repo.org = parent_org;

# allow(actor, action, resource) if
#     Roles.role_allows(actor, action, resource);


# Relationship types
# - relationship(actor, HAS_ROLE, role, resource)
# - relationship(resource, IS_PARENT, resource)
# - relationship(role, IMPLIES, role)

# Oso-defined
allow(user: User, action, resource) if
	relationship(user, "HAS_ROLE", role, resource) and
	allow(role, action, resource) and
	role.resource = resource or
	relationship(role.resource, "IS_PARENT", resource);



allow(user: User, action, resource) if
	relationship(parent_resource, "IS_PARENT", resource) and
	relationship(role, "HAS_PERMISSION", action, parent_resource);

allow(user: User, action, )
# User-defined

relationship(user: User, "HAS_ROLE", role, resource) if
	role = user.get_role(resource);

allow(role: {resource: role_resource, name: "READER"}, "read", resource: Repository);















# ## RELATIONSHIP DEFINITIONS
# relationship(actor: User, "OWNS", resource: Repository) if
# 	resource.created_by = actor;

# not used in above rules but this is the version of `parent` that we'd have
# in this version of relationship definitions
relationship(parent: Organization, "IS_PARENT", child: Repository) if
	parent = child.org;

relationship(group: Group, "HAS_ROLE", role, resource: Repository) if
	# TODO: this is currently not something you can do in Polar--we do all this
	# for you in the SQLAlchemy lib
	role in OsoRoles.get_group_roles(group, resource);








# resource(_type: Org, "org", actions, roles) if
#     # TODO(gj): might be able to cut down on some repetition with namespacing, e.g., `role_assignments::{create, list, update, delete}`
#     actions = ["read", "create_repos", "list_repos",
#                "create_role_assignments", "list_role_assignments", "update_role_assignments", "delete_role_assignments"] and
#     roles = {
#         member: {
#             permissions: ["read", "list_repos", "list_role_assignments"],
#             implies: ["repo:reader"]
#         },
#         owner: {
#             permissions: ["create_repos", "create_role_assignments", "update_role_assignments", "delete_role_assignments"],
#             implies: ["member", "repo:admin"]
#         }
#     };


# allow(actor, action, resource) if
# 	user_in_role(actor, role, resource) and
# 	parent_child(resource, role_resource) and
# 	role_allow(role, action, role_resource);

# parent_child(resource, resource);

# role_allow(role: OrganizationRole{name: "owner"}, action, resource: Org) if
# 	action in ["create_repos", "create_role_assignments", "update_role_assignments", "delete_role_assignments"];

## ReBAC policy

# Organization definitions

r(parent: Org, "IS_PARENT", child: Repo) if
	child.org = parent;

r(resource: Org, "HAS_ROLE", role) if
	role in ["org:member", "org:owner"];

# Org member role
r("org:member", "HAS_PERMISSION", action, resource: Org) if
	action in ["read", "list_repos", "list_role_assignments"];

r("org:member", "IMPLIES", "repo:reader");

# Org owner role
r("org:owner", "HAS_PERMISSION", action, resource: Org) if
	action in ["create_repos", "create_role_assignments", "update_role_assignments", "delete_role_assignments"];

r("org:owner", "IMPLIES", role) if
	role in ["org:member", "repo:admin"];

# Repo definitions

r(parent: Repo, "IS_PARENT", child: Issue) if
	child.issue = parent;

r(resource: Repo, "HAS_ROLE", role) if
	role in ["repo:reader", "repo:writer"];

r("repo:reader", "HAS_PERMISSION", action, resource: Repo) if
	action in ["read", "list_repos", "list_role_assignments"];

r("org:member", "IMPLIES", "repo:reader");






# resource(_type: Repo, "repo", actions, roles) if
#     actions = ["read", "create_issues", "list_issues",
#                "create_role_assignments", "list_role_assignments", "update_role_assignments", "delete_role_assignments"] and
#     roles = {
#         admin: {
#             permissions: ["create_role_assignments", "list_role_assignments", "update_role_assignments", "delete_role_assignments"],
#             implies: ["repo:writer"]
#         },
#         writer: {
#             permissions: ["create_issues"],
#             implies: ["repo:reader"]
#         },
#         reader: {
#             permissions: ["read", "list_issues", "issue:read"]
#         }
#     };

# resource(_type: Issue, "issue", actions, _) if
#     actions = ["read"];

# parent_child(parent_repo: Repo, issue: Issue) if
#     issue.repo = parent_repo;

# parent_child(parent_org: Org, repo: Repo) if
#     repo.org = parent_org;