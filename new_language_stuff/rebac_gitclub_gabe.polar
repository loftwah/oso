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
relationship(role, "ROLE_HAS_PERMISSION", action, issue: Issue) if
  action in ["delete"] and
  relationship(repo, "IS_PARENT", issue) and
  relationship(org, "IS_PARENT", repo) and
  role = {name: "owner", resource: org};
# repo:writer can edit issues
relationship(role, "ROLE_HAS_PERMISSION", action, issue: Issue) if
  action in ["edit"] and
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
