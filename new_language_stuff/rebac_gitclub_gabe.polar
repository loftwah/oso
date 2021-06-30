allow(actor, action, resource) if
  valid_action_for_resource(action, resource) and
  role_grants_local_permission(permitted_role, action, resource) or
  role_grants_cross_resource_permission(permitted_role, action, resource) and
  internal_role_implication(role, permitted_role) and
  actor_can_assume_role(actor, role);

internal_role_implication(role, role);
# Local role implication.
internal_role_implication(role, {name: implied_name, resource: implied_resource}) if
  role_implication(implied_resource, name, implied_name) and
  internal_role_implication(role, {name: name, resource: implied_resource});
# Cross-resource role implication.
internal_role_implication(role, {name: implied_name, resource: implied_resource}) if
  parent_child(parent, implied_resource) and
  role_implication(parent, name, implied_resource, implied_name) and
  internal_role_implication(role, {name: name, resource: parent});

role_grants_local_permission({name: name, resource: resource}, action, resource) if
  role_grants_permission(resource, name, action);

role_grants_cross_resource_permission({name: name, resource: ancestor}, action, resource) if
  ancestor_resource(ancestor, resource) and
  role_grants_permission(ancestor, name, action, resource);

ancestor_resource(ancestor, resource) if
  parent_child(ancestor, resource);
ancestor_resource(ancestor, resource) if
  parent_child(intermediate, resource) and
  ancestor_resource(ancestor, intermediate);

valid_action_for_resource(action, resource) if
  role_grants_local_permission(_, action, resource) or
  role_grants_cross_resource_permission(_, action, resource);

# valid_role_for_resource(name, resource) if
#   role_grants_permission(name, _, resource) or
#   role_grants_permission(_, name, _, resource);

# User's policy

role_grants_permission(_: Org, "owner", "invite");
role_grants_permission(_: Org, "member", "create_repo");
role_grants_permission(_: Repo, "reader", "pull");
role_grants_permission(_: Repo, "writer", "push");
role_grants_permission(_: Org, "owner", "delete", _: Issue);
role_grants_permission(_: Repo, "writer", "edit", _: Issue);

actor_can_assume_role(actor, role) if
  actor.has_role_for_resource(role.name, role.resource);

role_implication(_: Org, "owner", "member");
role_implication(_: Org, "owner", _: Repo, "writer");
role_implication(_: Org, "member", _: Repo, "reader");
role_implication(_: Repo, "writer", "reader");

parent_child(org, repo: Repo) if
  org = repo.org;
parent_child(repo, issue: Issue) if
  repo = issue.repo;
