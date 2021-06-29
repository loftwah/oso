
##### USER-DEFINED #####

# User
actor(_: User);
actor_role(actor: User, role) if
	actor.has_role_for_resource(role.name, role.resource);

# Org Resource
resource(_: Org);
permission(action, _resource: Org) if
	action in
	[
		"read",
		"invite",
		"create_repo",
		"list_repos",
		"create_role_assignments",
		"list_role_assignments",
		"update_role_assignments",
		"delete_role_assignments"
	];

resource_role(resource: Org, role) if
	# Get the roles for a resource
	role_name in ["owner", "member"] and # For now let's say role names are globally unique
	role = {name: role_name, resource: resource};

resource_role(resource, role) if
	# Get the roles for a resource's ancestors
	ancestor_descendant(ancestor, resource) and
	resource_role(ancestor, role);

# Necessary (only if) conditions must be met in order for this rule to hold
role_permission(role, "invite", resource) if
	# resource_role(resource, role) and
	role.name = "owner";

role_permission(role, "create_repo", resource) if
	# resource_role(resource, role) and
	role.name = "member";

# Must check that resource = implied_resource OR ancestor_descendent(resource, implied_resource)
role_implication(role, _implied_role: {name: "member", resource: resource}) if
	resource_role(resource, role) and
	role.name = "owner";

role_implication(role, _implied_role: {name: "reader", resource: repo}) if
	resource_role(repo, role) and
	role.name = "member";

role_implication(role, _implied_role: {name: "writer", resource: repo}) if
	resource_role(repo, role) and
	role.name = "owner";

parent_child(parent, child: Repo) if
	child.org = parent;

# Repo Resource
resource(_: Repo);
permission(action, _resource: Repo) if
	action in
	[
		"pull",
		"push",
		"create_issues",
		"list_issues",
        "create_role_assignments",
		"list_role_assignments",
		"update_role_assignments",
		"delete_role_assignments"
	];
resource_role(resource: Repo, role) if
	role_name in ["reader", "writer"] and # For now let's say role names are globally unique
	role = {name: role_name, resource: resource};

# Necessary (only if) conditions must be met in order for this rule to hold
role_permission(role, "pull", resource: Repo) if
	# resource_role(resource, role) and
	role.name = "reader";

role_permission(role, "push", resource: Repo) if
	# resource_role(resource, role) and
	role.name = "writer";

# Necessary (only if) conditions must be met in order for this rule to hold
role_implication(role, _implied_role: {name: "reader", resource: repo}) if
	resource_role(repo, role) and
	role.name = "writer";

# Issue Resource
resource(_: Issue);
permission(action, _resource: Issue) if
	action in
	[
		"edit",
		"delete"
	];

role_permission(role, "delete", resource: Issue) if
	# resource_role(resource, role) and
	role.name = "owner";

role_permission(role, "edit", resource: Issue) if
	# resource_role(resource, role) and
	role.name = "writer";

parent_child(parent, child: Issue) if
	child.repo = parent;

##### OSO-DEFINED #####

allow(actor, action, resource) if
	resource(resource) and
	actor(actor) and
	permission(action, resource) and
	INTERNAL_role_permission(implied_role, action, resource) and
	# debug(implied_role) and
	NESTED_role_implication(role, implied_role) and
	# debug(role) and
	actor_role(actor, role);

# TODO: implications--probably port this from polar_roles

INTERNAL_role_permission(role, action, resource) if
	resource_role(resource, role) and
	role_permission(role, action, resource);

INTERNAL_role_implication(role, implied_role) if
	resource_role(implied_role.resource, role) and
	NESTED_role_implication(role, implied_role);

NESTED_role_implication(role, role);
NESTED_role_implication(role, implied_role) if
	role_implication(intermediate, implied_role) and
	NESTED_role_implication(role, intermediate);

ancestor_descendant(ancestor, descendant) if
	parent_child(parent, descendant) and
	parent = ancestor or
	ancestor_descendant(ancestor, parent);


## ISSUES WITH THIS POLICY
# - Less structured and therefore harder to read than the resource predicate structure
# - necessary conditions have to be written by the user, but we know that many always have to be enforced so we would like to build these in
#    - e.g., parent_child() relationships are necessary for role implications and cross-resource role permission assignment
# - we have to know what is bound/unbound and structure the policy accordingly, which removes some of the benefits of a declarative language
#     - e.g., I can't specialize on roles when the role will be passed in as unbound (like in resource_role()), but I can when the role will be bound (like the second argument to role_implication())
# - The bug Gabe already found about grounding external instances reared its head
# - doesn't support cross-resource permissions (but Gabe's does)

## GOOD THINGS ABOUT THIS POLICY
# - The evaluation and structure of predicates matches our mental model for ReBAC
# - Relationships are explicitly defined
# - Actors, resources, roles, and permissions are explicitly defined
# - The directionality of relationships is taking shape, and providing hints for
#   how to break relationships into an OOP model.

## NEXT STEPS
# - document what we did
# - come up with ideas to improve ^^
# - add another rebac feature to gain confidence in/stress test model
# - confirm parity with existing RBAC with tests?


### OLD ###

# # Necessary condition: a path must exist from role->resource->action in order to create a role_permission
# resource_role_permission(resource, role, action) only if
# 	resource_role(resource, role) and
# 	resource_action(resource, action);

# Hacky version of necessary condition (this is the rule that gets called by evaluation logic)
# TODO: add ancestor checks
# resource_role_permission_ONLY_IF(resource, role, action) if
# 	resource_role(resource, role) and
# 	resource_action(resource, action) and
# 	# Call the user-defined rule
# 	resource_role_permission(resource, role, action);

# a role implies itself
# resource_role_implication_ONLY_IF(resource, role, resource, role);

# # Necessary condition: a path must exist from role->resource->implied_resource->implied_role in order to create a role implication
# resource_role_implication(resource, role, implied_resource, implied_role) only if
# 	resource_role(resource, role) and
# 	parent_child(resource, implied_resource) and
# 	resource_role(implied_resource, implied_role);

# resource_role_implication_ONLY_IF(resource, role, implied_resource, implied_role) if
# 	resource_role(resource, role) and
# 	resource_role_implication(resource, role, implied_resource, implied_role) and
# 	(resource = implied_resource or
# 	ancestor_descendant(resource, implied_resource)) and
# 	resource_role(implied_resource, implied_role);
	# Call the user-defined rule

