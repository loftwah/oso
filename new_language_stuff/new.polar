####################
# TYPE DEFINITIONS
####################

type User(Actor) {
	# Required attributes/methods
	id -> int: this.uuid	# mapping an app attribute to the required attribute name in Polar
	has_role(role_name, org) -> bool

	# Custom attributes/method declarations (can only be bools for now)
	is_super_admin -> bool
}

type Org(Resource) {
	# Required attributes/methods
	id -> int: this.org_id 	# mapping an app attribute to the required attribute name in Polar
}

type Repo(Resource) {
	# Required attributes/methods
	id -> int: this.repo_id	# mapping an app attribute to the required attribute name in Polar

	# Optional attributes defined by interface
	parent -> Org: this.org

	# Idea for rules inside of types
	rules {
		user can...
		user has_role...

		user has_role role if user.has_role(role)
		user has_role "member" if user has_role "owner"

		user can "pull" if user has_role "reader"
		user has_role "reader" if user has_role "member" on this.parent

		user can "push" if user has_role "writer"
		user has_role "writer" if user has_role "owner" on this.parent
	}
}

type Issue(Resource) {
	# Required attributes/methods
	id -> int

	# Optional attributes defined by interface
	parent -> Repo: this.repo
}

union OrgRoleName = "MEMBER" | "OWNER" | "BILLING"

type OrgRole(Role) {
	# Required attributes/methods
	id -> int
	name -> OrgRoleName
	resource -> Org: this.org
}

####################
# RULE DEFINITIONS
####################

# Permission definition: rule prototype
# EDIT: don't know if this actually makes sense for users to write, also not sure it actually functions well as a
# permission definition
rule has_permission(user: User, "create_repo", org: Org);
rule has_permission(user: User, "invite_user", org: Org);


# User->permission assignment: rule implementation
# This is not a case we optimize for
has_permission(user: User, "create_repo", org: Org) if
	# This would be a custom attribute that must be declared through a user type,
	# and maybe we should only allow custom attributes to be bools
	user.is_super_admin;

# Role definition: rule prototype
rule has_role(user: User, role: OrgRole{name: "OWNER" });
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
