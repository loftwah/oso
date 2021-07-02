

# Permission definition: rule prototype
rule has_permission(user: User, "create_repo", org: Org);
rule has_permission(user: User, "invite_user", org: Org);


# User->permission assignment: rule implementation
# This is not a case we optimize for
has_permission(user: User, "create_repo", org: Org) if
	# This would be a custom attribute that must be declared through a user type,
	# and maybe we should only allow custom attributes to be bools
	user.is_super_admin;

# Role definition: rule prototype
rule has_role(user: User, "owner", org: Org);
rule has_role(user: User, "member", org: Org);

# User->role assignment: rule implementation
has_role(user: User, role_name, org: Org) if
	# how would the rule prototypes work for something like this?
	user.has_role(role_name, org);

# Role->permission (same resource)
has_permission(user: User, "create_repo", org: Org) if
	has_role(user, "member", org);
has_permission(user: User, "invite_user", org: Org) if
	has_role(user, "owner", org);

# Role->permission (related resource)
has_permission(user: User, "edit", issue: Issue) if
	has_role(user, "owner", issue.parent.parent);

# Role implication (same resource)
has_role(user: User, "member", org: Org) if
	has_role(user, "owner", org);

# Role implication (related resource)
has_role(user: User, "reader", repo: Repo) if
	has_role(user, "member", repo.parent);


# user can edit issue if user has_role owner issue.parent.parent;
