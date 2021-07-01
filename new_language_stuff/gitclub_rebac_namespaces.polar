
# Leina policy

resource Org: Org {

	permission(action) if
		action in [
			"read",
			"invite",
			"create_repo",
			"list_repos",
			"create_role_assignments",
			"list_role_assignments",
			"update_role_assignments",
			"delete_role_assignments"];

	role(role) if
		# Get the roles for a resource
		role_name in ["owner", "member"]; # For now let's say role names are globally unique

	role_permission(_role: {name: "owner"}, "invite");
	role_permission(_role: {name: "member"}, "create_repo");

	role_implication(_role: {name: "owner"}, _implied_role: {name: "member"});
	role_implication(_role: {name: "member"}, _implied_role: {name: "reader"});
	role_implication(_role: {name: "owner"}, _implied_role: {name: "writer"});
}

resource Repo: Repo {
	permission(action) if
		action in [
			"pull",
			"push",
			"create_issues",
			"list_issues",
			"create_role_assignments",
			"list_role_assignments",
			"update_role_assignments",
			"delete_role_assignments"];

	role(role) if
		role_name in ["reader", "writer"]; # For now let's say role names are globally unique

	# Necessary (only if) conditions must be met in order for this rule to hold
	role_permission(_role: {name: "reader"}, "pull");
	role_permission(_role: {name: "writer"}, "push");

	# Necessary (only if) conditions must be met in order for this rule to hold
	role_implication(_role: {name: "writer"}, _implied_role: {name: "reader"});

	parent(self, parent_org) if self.org = parent_org;
}

resource Issue: Issue {
	permission(action) if
		action in [
			"edit",
			"delete"];

	# Necessary (only if) conditions must be met in order for this rule to hold
	role_permission(_role: {name: "owner"}, "delete");
	role_permission(_role: {name: "writer"}, "edit");

	parent(self, parent_repo) if self.repo = parent_repo;

}