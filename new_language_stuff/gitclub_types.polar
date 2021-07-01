
HasPermission{
	actor
	action
	resource
}

HasPermission {
	role
	action
	resource
}

InRole {
	user: computed_userset: $user where $user.has_role(role_name, resource)
	role_name
	resource

	# condition: user.has_role(role_name, resource)
}
Resource {
	Permission {}


	Role {
		user: Actor
		implied_by: Role

		@internal
		computed_userset: $user where Role($user, implied_by) and implied_by.resource == self.resource or Parent(implied_by.resource, self.resource)

	}

}

Org {
	Member(Role) {
		user: User
		implied_by: Owner

		permissions: "read", "write", "..."
	}
}

Repo {
	Reader(Role) {
		user: User
		implied_by: Org.Owner

		permissions: "read", "write", "..."
	}
}

InRole {
	user: computed_userset: $user where InRole($user, "owner", resource)
	role_name: "member"
	resource

	# implied_by: "owner"

	# condition: InRole{user, "owner", resource}
}


### INTERFACE

Resource {
	action(action);
	role(role);


	# Relationships
	parent(resource);

	role_allow()
}

Relation {
	actor: Actor | ActorSet
	name
	resource
}

# Oso interface
Role(Relation) {
	actor: Actor | ActorSet
	name: RoleEnum
	resource: Resource
}

# User implementation
OrgRole(Role) {
	actor: User
	name: "owner" | "member" | "billing"
	resource: Org

	condition: APP_LOOKUP(has_role(actor, name, resource))
}


# Oso interface
Permission(Relation) {
	actor: Role	# is Role a userset?
	name: ActionEnum
	resource: Resource

	condition: Relation(actor, _, resource)
}



### IMPLEMENTATION

User(Actor) {

}

OrgRole(Role) {
	name: "member" | "owner" | "billing"
	org: Org

	permission("owner", "invite", self.org)
	permission("member", "create_repo", self.org)
	permission("member", "read", repo) if
		repo.parent = self.org;
	@internal
	permission()
}

Org(Resource) {

}


Repo(Resource) {

}

Group(Resource) {

}

RepoRole(Role) {

}


# Oso auth lib type interfaces

# Base enum interface for Actions
# `Enum` is a native interface;
# the `enum` keyword is syntactic sugar for implementing the `Enum` interface
interface OsoAction extends Enum;

interface OsoResource {
	interface Action extends OsoAction;

	namespace relationships {
	}

	# TODO: how to express this: trying to say that any number of allow rules
	# matching the following prototype may be defined within this namespace
	namespace allowed {
		rule allow(user: OsoUser, action: OsoAction, resource: OsoResource);



	}

	# TODO: again, trying to say that any number of implementations of OsoRole
	# may be defined within this namespace
	namespace roles {
		interface RoleName extends Enum;

		interface OsoRole {
			name: RoleName
			user: OsoUser
			resource: OsoResource
		}

		# NEW ROLE->PERMISSION ASSIGNMENT (done through allow rules)

		# TODO: how to express stuff about which actions/resources certain
		# roles can allow?
		# E.g., "there must be a valid relationship." We could implement this in
		# the evaluation code but then the rules just wouldn't work, rather than
		# give parse-time errors?
		#    - See `precondition` idea below
		fact allow(role: OsoRole, action: OsoAction, resource: OsoResource);

		# maybe we have some kind of `precondition` thing where all matching rules
		# have to meet this precondition in order to continue to evaluate?
		# Still would only have runtime errors, but at least we can be more specific with
		# the error (e.g., did not meet precondition ___)
		precondition allow(role: OsoRole, action: OsoAction, resource: OsoResource) if
			role.resource = resource or
			# Need this evaluation to be recursive
			relationship(role.resource, Re.IS_PARENT, resource);

		# NEW ROLE->ROLE IMPLICATIONS (done through relationship rules)
		fact relationship(role: OsoRole, Re.IMPLIES, implied_role: OsoRole);

		# need another precondition for implications
		precondition relationship(role: OsoRole, Re.IMPLIES, implied_role: OsoRole) if
			# Roles can imply roles for the same resource
			role.resource = implied_role.resource or
			# Roles can imply roles for child resources (needs to be recursive)
			relationship(role.resource, Re.IS_PARENT, implied_role.resource);
	}

}
interface OsoUser {}
interface OsoGroup {
	rule relationship(group: OsoGroup, Re.IN_GROUP, group: OsoGroup);
}

# Policy
implement OsoGroup for MyGroup {
	relationship(group, Re.IN_GROUP, parent_group) if
		group.parent_group = group;
}


# Example user policy
type Repository implements OsoResource {
	enum Action implements OsoAction {
		PULL,
		PUSH
	}
}