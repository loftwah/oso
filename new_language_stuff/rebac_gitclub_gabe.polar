############################# START INTERNAL POLICY ############################

allow(actor, action, resource) if
  valid_action_for_resource(action, resource) and
  role_grants_permission(permitted_role, action, resource) and
  role_implies_permitted_role(role, permitted_role) and
  actor_can_assume_role(actor, role);

role_implies_permitted_role(role, role);
# Local role implication.
role_implies_permitted_role(role, {name: implied_name, resource: implied_resource}) if
  implies(implied_resource, name, implied_name) and
  role_implies_permitted_role(role, {name: name, resource: implied_resource});
# Cross-resource role implication.
role_implies_permitted_role(role, {name: implied_name, resource: implied_resource}) if
  parent_child(parent, implied_resource) and
  implies(parent, name, implied_resource, implied_name) and
  role_implies_permitted_role(role, {name: name, resource: parent});

# Role grants local permission.
role_grants_permission({name: name, resource: resource}, action, resource) if
  can(resource, name, action);
# Role grants cross-resource permission.
role_grants_permission({name: name, resource: ancestor}, action, resource) if
  ancestor_resource(ancestor, resource) and
  can(ancestor, name, action, resource);

ancestor_resource(ancestor, resource) if
  parent_child(ancestor, resource);
ancestor_resource(ancestor, resource) if
  parent_child(intermediate, resource) and
  ancestor_resource(ancestor, intermediate);

valid_action_for_resource(action, resource) if
  can(resource, _, action) or
  can(_, _, action, resource);

############################## END INTERNAL POLICY #############################

############################### START USER POLICY ##############################

can(_: Org, "owner", "invite");
can(_: Org, "member", "create_repo");
can(_: Repo, "reader", "pull");
can(_: Repo, "writer", "push");
can(_: Org, "owner", "delete", _: Issue);
can(_: Repo, "writer", "edit", _: Issue);

actor_can_assume_role(actor, role) if
  actor.has_role_for_resource(role.name, role.resource);

implies(_: Org, "owner", "member");
implies(_: Org, "owner", _: Repo, "writer");
implies(_: Org, "member", _: Repo, "reader");
implies(_: Repo, "writer", "reader");

parent_child(org, repo: Repo) if
  org = repo.org;
parent_child(repo, issue: Issue) if
  repo = issue.repo;

################################ END USER POLICY ###############################
