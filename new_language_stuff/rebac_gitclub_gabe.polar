allow(actor, action, resource) if
  relationship(action, "IS_VALID_ACTION_FOR", resource) and
  relationship(permitted_role, "ROLE_HAS_PERMISSION", action, resource) and
  relationship(role, "internal_IMPLIES", permitted_role) and
  relationship(actor, "CAN_ASSUME_ROLE", role);

relationship(role, "internal_IMPLIES", role);
relationship(role, "internal_IMPLIES", implied_role) if
  relationship(intermediate, "IMPLIES", implied_role) and
  relationship(role, "internal_IMPLIES", intermediate);

# User's policy

relationship(action, "IS_VALID_ACTION_FOR", _: Org) if
  action in ["create_repos", "list_repos"];
relationship(action, "IS_VALID_ACTION_FOR", _: Repo) if
  action in ["read"];
relationship(action, "IS_VALID_ACTION_FOR", _: Issue) if
  action in ["edit"];

relationship(role, "ROLE_HAS_PERMISSION", "create_repos", org: Org) if
  role = {name: "owner", resource: org};
relationship(role, "ROLE_HAS_PERMISSION", "list_repos", org: Org) if
  role = {name: "member", resource: org};
relationship(role, "ROLE_HAS_PERMISSION", "read", repo: Repo) if
  role = {name: "reader", resource: repo};
relationship(role, "ROLE_HAS_PERMISSION", "edit", issue: Issue) if
  relationship(repo, "IS_PARENT", issue) and
  role = {name: "writer", resource: repo};

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
