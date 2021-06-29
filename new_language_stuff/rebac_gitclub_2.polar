
##### USER-DEFINED #####

# User
actor(_: User);
actor_resource_role(actor: User, resource, role_name) if
	role in actor.roles(resource);

# Org Resource
resource(_: Org);
resource_action(resource: Org, action) if
	action in
	[
		"read",
		"create_repos",
		"list_repos",
		"create_role_assignments",
		"list_role_assignments",
		"update_role_assignments",
		"delete_role_assignments"
	];
resource_role(resource: Org, role) if
	role in ["org:owner", "org:member"]; # For now let's say role names are globally unique

# Necessary (only if) conditions must be met in order for this rule to hold
resource_role_permission(resource: Org, "org:owner", "create_repos");
resource_role_permission(resource: Org, "org:owner", "list_repos");

# Necessary (only if) conditions must be met in order for this rule to hold
resource_role_implication(resource: Org, "org:owner", implied_resource: Org, "org:member");
resource_role_implication(resource: Org, "org:member", implied_resource: Repo, "repo:reader");

parent_child(parent: Org, child: Repo) if
	child.org = parent;

# Repo Resource
resource(_: Repo);
resource_action(resource: Repo, action) if
	action in
	[
		"read",
		"create_issues",
		"list_issues",
        "create_role_assignments",
		"list_role_assignments",
		"update_role_assignments",
		"delete_role_assignments"
	];
resource_role(resource: Repo, role) if
	role in ["repo:reader", "repo:writer"]; # For now let's say role names are globally unique

# Necessary (only if) conditions must be met in order for this rule to hold
resource_role_permission(resource: Repo, "repo:reader", "read");

# Necessary (only if) conditions must be met in order for this rule to hold
resource_role_implication(resource: Repo, "repo:writer", implied_resource: Repo, "repo:reader");


##### OSO-DEFINED #####

allow(actor, action, resource) if
	resource(resource) and
	actor(actor) and
	actor_resource_role(actor, resource, role) and
	resource_role_implication_ONLY_IF(resource, role, implied_resource, implied_role) and
	resource_role_permission_ONLY_IF(implied_resource, implied_role, action);

# TODO: implications--probably port this from polar_roles

# # Necessary condition: a path must exist from role->resource->action in order to create a role_permission
# resource_role_permission(resource, role, action) only if
# 	resource_role(resource, role) and
# 	resource_action(resource, action);

# Hacky version of necessary condition (this is the rule that gets called by evaluation logic)
resource_role_permission_ONLY_IF(resource, role, action) if
	resource_role(resource, role) and
	resource_action(resource, action) and
	# Call the user-defined rule
	resource_role_permission(resource, role, action);

# # Necessary condition: a path must exist from role->resource->implied_resource->implied_role in order to create a role implication
# resource_role_implication(resource, role, implied_resource, implied_role) only if
# 	resource_role(resource, role) and
# 	parent_child(resource, implied_resource) and
# 	resource_role(implied_resource, implied_role);

resource_role_implication_ONLY_IF(resource, role, implied_resource, implied_role) if
	resource_role(resource, role) and
	(resource = implied_resource or
	ancestor_descendant(resource, implied_resource)) and
	resource_role(implied_resource, implied_role) and
	# Call the user-defined rule
	resource_role_implication(resource, role, implied_resource, implied_role);

# a role implies itself
resource_role_implication_ONLY_IF(resource, role, resource, role);

ancestor_descendant(ancestor, descendant) if
	parent_child(parent, descendant) and
	parent = ancestor or
	ancestor(ancestor, parent);