allow(actor, action, resource) if
  relationship(action, "IS_VALID_ACTION_FOR", resource) and
  relationship(permitted_role, "internal_HAS_PERMISSION", action, resource) and
  relationship(role, "internal_IMPLIES", permitted_role) and
  relationship(actor, "CAN_ASSUME_ROLE", role);

relationship(role, "internal_IMPLIES", role);
relationship(role, "internal_IMPLIES", implied_role) if
  relationship(intermediate, "IMPLIES", implied_role) and
  relationship(role, "internal_IMPLIES", intermediate);

# Role has local permission.
relationship({name: name, resource: resource}, "internal_HAS_PERMISSION", action, resource) if
  relationship(name, "HAS_PERMISSION", action, resource);

# Role has cross-resource permission.
relationship({name: name, resource: ancestor}, "internal_HAS_PERMISSION", action, resource) if
  relationship(ancestor, "IS_ANCESTOR", resource) and
  relationship(ancestor, name, "HAS_PERMISSION", action, resource);

relationship(ancestor, "IS_ANCESTOR", resource) if
  relationship(ancestor, "IS_PARENT", resource);
relationship(ancestor, "IS_ANCESTOR", resource) if
  relationship(intermediate, "IS_PARENT", resource) and
  relationship(ancestor, "IS_ANCESTOR", intermediate);

relationship(action, "IS_VALID_ACTION_FOR", resource) if
  relationship(_, "HAS_PERMISSION", action, resource) or
  relationship(_, _, "HAS_PERMISSION", action, resource);

relationship(name, "IS_VALID_ROLE_FOR", resource) if
  relationship(name, "HAS_PERMISSION", _, resource) or
  relationship(_, name, "HAS_PERMISSION", _, resource);

# User's policy

relationship("owner", "HAS_PERMISSION", "invite", _: Org);
relationship("member", "HAS_PERMISSION", "create_repo", _: Org);
relationship("reader", "HAS_PERMISSION", "pull", _: Repo);
relationship("writer", "HAS_PERMISSION", "push", _: Repo);
relationship(_: Org, "owner", "HAS_PERMISSION", "delete", _issue: Issue);
relationship(_: Repo, "writer", "HAS_PERMISSION", "edit", _issue: Issue);

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
