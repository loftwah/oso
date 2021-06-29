allow(actor, action, resource) if
  relationship(action, "IS_VALID_ACTION_FOR", resource) and
  relationship(permitted_role, "ROLE_HAS_PERMISSION", action, resource) and
  relationship(role, "IMPLIES", permitted_role) and
  relationship(actor, "CAN_ASSUME_ROLE", role);

relationship(role, "IMPLIES", role);

# User's policy

relationship(action, "IS_VALID_ACTION_FOR", _: Org) if
  action in ["create_repos", "list_repos"];
relationship(action, "IS_VALID_ACTION_FOR", _: Repo) if
  action in ["read"];

relationship(role, "ROLE_HAS_PERMISSION", "create_repos", org: Org) if
  role = {name: "owner", resource: org};
relationship(role, "ROLE_HAS_PERMISSION", "list_repos", org: Org) if
  role = {name: "member", resource: org};
relationship(role, "ROLE_HAS_PERMISSION", "read", repo: Repo) if
  role = {name: "writer", resource: repo}; # should probably be 'reader'

relationship(actor, "CAN_ASSUME_ROLE", role) if
  actor.has_role_for_resource(role.name, role.resource);

relationship(role, "IMPLIES", _: {name: "member", resource: org}) if
  org matches Org and # necessary if you have roles w/ the same name on different resource types
  role = {name: "owner", resource: org};
relationship(role, "IMPLIES", _: {name: "writer", resource: repo}) if
  repo matches Repo and
  relationship(org, "IS_PARENT", repo) and
  role = {name: "owner", resource: org};

relationship(org, "IS_PARENT", repo: Repo) if
  org = repo.org;
