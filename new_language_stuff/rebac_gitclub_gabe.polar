############################### START RBAC POLICY ##############################

allow(user: User, "invite", org: Org) if
  has_role(user, "owner", org);
allow(user: User, "create_repo", org: Org) if
  has_role(user, "member", org);
allow(user: User, "pull", repo: Repo) if
  has_role(user, "reader", repo);
allow(user: User, "push", repo: Repo) if
  has_role(user, "writer", repo);
allow(user: User, "delete", issue: Issue) if
  has_role(user, "owner", issue.repo.org);
allow(user: User, "edit", issue: Issue) if
  has_role(user, "writer", issue.repo);

has_role(user: User, role, resource) if
  user.has_role_for_resource(role, resource);

has_role(user: User, "member", org: Org) if
  has_role(user, "owner", org);
has_role(user: User, "writer", repo: Repo) if
  has_role(user, "owner", repo.org);
has_role(user: User, "reader", repo: Repo) if
  has_role(user, "member", repo.org);
has_role(user: User, "reader", repo: Repo) if
  has_role(user, "writer", repo);

################################ END RBAC POLICY ###############################

############################# START OWNERSHIP POLICY ###########################

allow(user: User, "delete", issue: Issue) if
  user created issue or
  user owns issue.repo.org;

created(user: User, issue: Issue) if
  issue.created_by = user;

# NOTE(gj): is owns/2 (or created/2, or any other similar relationship) always
# going to be a dot lookup?
owns(user: User, org: Org) if
  user = org.owner;

############################## END OWNERSHIP POLICY ############################
