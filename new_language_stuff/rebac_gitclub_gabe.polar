allow(actor, action, resource) if
  internal(action, "IS_VALID_ACTION_FOR", resource) and
  internal(permitted_role, "HAS_PERMISSION", action, resource) and
  internal(role, "IMPLIES", permitted_role) and
  relationship(actor, "CAN_ASSUME_ROLE", role);

internal(role, "IMPLIES", role);
internal(role, "IMPLIES", implied_role) if
  relationship(intermediate, "IMPLIES", implied_role) and
  internal(role, "IMPLIES", intermediate);

# Role has local permission.
internal({name: name, resource: resource}, "HAS_PERMISSION", action, resource) if
  relationship(name, "HAS_PERMISSION", action, resource);

# Role has cross-resource permission.
internal({name: name, resource: ancestor}, "HAS_PERMISSION", action, resource) if
  internal(ancestor, "IS_ANCESTOR", resource) and
  relationship(ancestor, name, "HAS_PERMISSION", action, resource);

internal(ancestor, "IS_ANCESTOR", resource) if
  relationship(ancestor, "IS_PARENT", resource);
internal(ancestor, "IS_ANCESTOR", resource) if
  relationship(intermediate, "IS_PARENT", resource) and
  internal(ancestor, "IS_ANCESTOR", intermediate);

internal(action, "IS_VALID_ACTION_FOR", resource) if
  relationship(_, "HAS_PERMISSION", action, resource) or
  relationship(_, _, "HAS_PERMISSION", action, resource);

internal(name, "IS_VALID_ROLE_FOR", resource) if
  relationship(name, "HAS_PERMISSION", _, resource) or
  relationship(_, name, "HAS_PERMISSION", _, resource);

# User's policy

relationship("owner", "HAS_PERMISSION", "invite", _: Org);
relationship("member", "HAS_PERMISSION", "create_repo", _: Org);
relationship("reader", "HAS_PERMISSION", "pull", _: Repo);
relationship("writer", "HAS_PERMISSION", "push", _: Repo);
relationship(_: Org, "owner", "HAS_PERMISSION", "delete", _: Issue);
relationship(_: Repo, "writer", "HAS_PERMISSION", "edit", _: Issue);

relationship(actor, "CAN_ASSUME_ROLE", role) if
  actor.has_role_for_resource(role.name, role.resource);

# org:owner implies org:member
relationship(role, "IMPLIES", _: {name: "member", resource: org}) if
  org matches Org and # necessary if you have roles w/ the same name on different resource types
  role = {name: "owner", resource: org};
# org:owner implies repo:writer
relationship(role, "IMPLIES", _: {name: "writer", resource: repo}) if
  repo matches Repo and
  relationship(org, "IS_PARENT", repo) and
  role = {name: "owner", resource: org};
# org:member implies repo:reader
relationship(role, "IMPLIES", _: {name: "reader", resource: repo}) if
  repo matches Repo and
  relationship(org, "IS_PARENT", repo) and
  role = {name: "member", resource: org};
# repo:writer implies repo:reader
relationship(role, "IMPLIES", _: {name: "reader", resource: repo}) if
  repo matches Repo and
  role = {name: "writer", resource: repo};

relationship(org, "IS_PARENT", repo: Repo) if
  org = repo.org;
relationship(repo, "IS_PARENT", issue: Issue) if
  repo = issue.repo;
