
##### USER-DEFINED #####

# Org Resource
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

# For now let's say role names are globally unique
resource_role(resource: Org, "org:owner");

# THIS IS A PENDING RULE
# Necessary (only if) conditions must be met in order for this rule to hold
role_permission("org:owner", "create_repos", resource: Org);

parent_child(parent: Org, child: Repo) if
	child.org = parent;

resource_role()


##### OSO-DEFINED #####

# Necessary condition: a path must exist from role->resource->action in order to create a role_permission
role_permission(role, action, resource) only if
	resource_role(resource, role) and
	resource_action(resource, action);

