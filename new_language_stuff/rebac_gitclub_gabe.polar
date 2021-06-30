allow(actor, action, resource) if
  valid_action_for_resource(action, resource) and
  internal_role_has_permission(permitted_role, action, resource) and
  internal_role_implication(role, permitted_role) and
  actor_can_assume_role(actor, role);

internal_role_implication(role, role);
internal_role_implication(role, implied_role) if
  role_implication(resource, name, implied_role.resource, implied_role.name) and
  internal_role_implication(role, {name: name, resource: resource});

# Role has local permission.
internal_role_has_permission({name: name, resource: resource}, action, resource) if
  role_grants_permission(name, action, resource);

# Role has cross-resource permission.
internal_role_has_permission({name: name, resource: ancestor}, action, resource) if
  ancestor_resource(ancestor, resource) and
  role_grants_permission(ancestor, name, action, resource);

ancestor_resource(ancestor, resource) if
  parent_child(ancestor, resource);
ancestor_resource(ancestor, resource) if
  parent_child(intermediate, resource) and
  ancestor_resource(ancestor, intermediate);

valid_action_for_resource(action, resource) if
  role_grants_permission(_, action, resource) or
  role_grants_permission(_, _, action, resource);

valid_role_for_resource(name, resource) if
  role_grants_permission(name, _, resource) or
  role_grants_permission(_, name, _, resource);

# User's policy

role_grants_permission("owner", "invite", _: Org);
role_grants_permission("member", "create_repo", _: Org);
role_grants_permission("reader", "pull", _: Repo);
role_grants_permission("writer", "push", _: Repo);
role_grants_permission(_: Org, "owner", "delete", _: Issue);
role_grants_permission(_: Repo, "writer", "edit", _: Issue);

actor_can_assume_role(actor, role) if
  actor.has_role_for_resource(role.name, role.resource);

role_implication(org, "owner", org: Org, "member");
role_implication(org, "owner", repo: Repo, "writer") if parent_child(org, repo);
role_implication(org, "member", repo: Repo, "reader") if parent_child(org, repo);
role_implication(repo, "writer", repo: Repo, "reader");

parent_child(org, repo: Repo) if
  org = repo.org;
parent_child(repo, issue: Issue) if
  repo = issue.repo;
