## Oso "Auth" lib.
# Users can import the auth lib into their own policies, then they have access
# to the enums and rule prototypes defined here.

# ENUMS
# - Like classes, in that they can be inherited (e.g. OsoAction),
#   otherwise act like an Enum

# Relationship types Oso supports
enum Re {
	OWNS,
	HAS_ROLE,
	IN_GROUP,
	SHARED_WITH,
	IS_PARENT
}

# Base enum for actions
enum OsoAction;

# RULE PROTOTYPES
# - If a rule prototype is defined, you can't define a predicate with
#   the same name/arity unless it matches the prototype
# - The `rule` keyword means it can have a body. The `fact` prototype means
#   that it can't

# Relationship Rule prototypes
# - `OsoUser`, `OsoResource`, etc. are the base Polar classes to represent
#    auth primitives
#      - When you register a class, you tell Oso what kind of object it is

# Users can own resources
rule relationship(user: OsoUser, Re.OWNS, resource: OsoResource);
# Users can have roles on resources
rule relationship(user: OsoUser, Re.HAS_ROLE, role: OsoRole, resource: OsoResource);
# Groups can have roles on resources
rule relationship(group: OsoGroup, Re.HAS_ROLE, role: OsoRole, resource: OsoResource);
# Users can be in groups (TODO: maybe there should be a resource arg too?)
rule relationship(user: OsoUser, Re.IN_GROUP, group: OsoGroup);
# Groups can be in groups
rule relationship(group: OsoGroup, Re.IN_GROUP, group: OsoGroup);
# Resources can be shared with users
rule relationship(resource: OsoResource, Re.SHARED_WITH, user: OsoUser);
# Resources can be shared with groups
rule relationship(resource: OsoResource, Re.SHARED_WITH, group: OsoGroup);
# Resources can be parents of resources
rule relationship(resource: OsoResource, Re.IS_PARENT, resource: OsoResource);
# Resources can be parents of groups???
rule relationship(resource: OsoResource, Re.IS_PARENT, group: OsoGroup);

# Questions
# - Is `IN_GROUP` just a form of `IS_PARENT`?
#     - idk I think it's worth breaking it out if it's specific to groups,
#     - but then maybe the name for `IS_PARENT` should be more specific
#     - to resources

# Allow rule prototypes (OOOOOHHHHH SHIT)

# Grant a permission to individual users
rule allow(user: OsoUser, action: OsoAction, resource: OsoResource);
# Grant a permission to a group of users
rule allow(group: OsoGroup, action: OsoAction, resource: OsoResource);
# Grant a permission to a role (fact because can't have a body)
fact allow(role: OsoRole, action: OsoAction, resource: OsoResource);