############################### START RBAC POLICY ##############################

allow(user: User, "invite", org: Org) if
  user has_role "owner" on org;
allow(user: User, "create_repo", org: Org) if
  user has_role "member" on org;
allow(user: User, "pull", repo: Repo) if
  user has_role "reader" on repo;
allow(user: User, "push", repo: Repo) if
  user has_role "writer" on repo;
allow(user: User, "delete", issue: Issue) if
  user has_role "owner" on issue.repo.org;
allow(user: User, "edit", issue: Issue) if
  user has_role "writer" on issue.repo;

has_role_on(user: User, role, resource) if
  user.has_role_for_resource(role, resource);

has_role_on(user: User, "member", org: Org) if
  user has_role "owner" on org;
has_role_on(user: User, "writer", repo: Repo) if
  user has_role "owner" on repo.org;
has_role_on(user: User, "reader", repo: Repo) if
  user has_role "member" on repo.org;
has_role_on(user: User, "reader", repo: Repo) if
  user has_role "writer" on repo;

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
