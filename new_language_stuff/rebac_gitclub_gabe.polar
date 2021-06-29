allow(actor, action, resource) if
  relationship(action, "IS_VALID_ACTION_FOR", resource) and
  relationship(permitted_role, "internal_ROLE_HAS_PERMISSION", action, resource) and
  relationship(role, "internal_IMPLIES", permitted_role) and
  relationship(actor, "CAN_ASSUME_ROLE", role);

relationship(role, "internal_IMPLIES", role);
relationship(role, "internal_IMPLIES", implied_role) if
  relationship(intermediate, "IMPLIES", implied_role) and
  relationship(role, "internal_IMPLIES", intermediate);

relationship({name: name, resource: resource}, "internal_ROLE_HAS_PERMISSION", action, resource) if
  relationship({name: name, resource: resource}, "ROLE_HAS_PERMISSION", action, resource);

relationship({name: name, resource: ancestor}, "internal_ROLE_HAS_PERMISSION", action, resource) if
  relationship(ancestor, "IS_ANCESTOR", resource) and
  relationship({name: name, resource: ancestor}, "ROLE_HAS_PERMISSION", action, resource);

relationship(ancestor, "IS_ANCESTOR", resource) if
  relationship(ancestor, "IS_PARENT", resource);
relationship(ancestor, "IS_ANCESTOR", resource) if
  relationship(intermediate, "IS_PARENT", resource) and
  relationship(ancestor, "IS_ANCESTOR", intermediate);

# User's policy

relationship(action, "IS_VALID_ACTION_FOR", _: Org) if
  action in ["create_repo", "invite"];
relationship(action, "IS_VALID_ACTION_FOR", _: Repo) if
  action in ["pull", "push"];
relationship(action, "IS_VALID_ACTION_FOR", _: Issue) if
  action in ["delete", "edit"];

# org:owner can invite to the org
relationship(role, "ROLE_HAS_PERMISSION", action, org: Org) if
  action in ["invite"] and
  role = {name: "owner", resource: org};
# org:member can create repos in the org
relationship(role, "ROLE_HAS_PERMISSION", action, org: Org) if
  action in ["create_repo"] and
  role = {name: "member", resource: org};
# repo:reader can pull repos
relationship(role, "ROLE_HAS_PERMISSION", action, repo: Repo) if
  action in ["pull"] and
  role = {name: "reader", resource: repo};
# repo:writer can push repos
relationship(role, "ROLE_HAS_PERMISSION", action, repo: Repo) if
  action in ["push"] and
  role = {name: "writer", resource: repo};
# org:owner can delete issues
relationship(role, "ROLE_HAS_PERMISSION", action, _issue: Issue) if
  action in ["delete"] and
  role = {name: "owner", resource: _org};
# repo:writer can edit issues
relationship(role, "ROLE_HAS_PERMISSION", action, _issue: Issue) if
  action in ["edit"] and
  role = {name: "writer", resource: _repo};

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
