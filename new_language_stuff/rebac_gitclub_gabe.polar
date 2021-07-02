############################# START INTERNAL POLICY ############################

############################## END INTERNAL POLICY #############################

############################### START USER POLICY ##############################

allow(user, "invite", org: Org) if
  has_role(user, "owner", org);
allow(user, "create_repo", org: Org) if
  has_role(user, "member", org);
allow(user, "pull", repo: Repo) if
  has_role(user, "reader", repo);
allow(user, "push", repo: Repo) if
  has_role(user, "writer", repo);
allow(user, "delete", issue: Issue) if
  has_role(user, "owner", issue.repo.org);
allow(user, "edit", issue: Issue) if
  has_role(user, "writer", issue.repo);

has_role(user, role, resource) if
  user.has_role_for_resource(role, resource);

has_role(user, "member", org: Org) if
  has_role(user, "owner", org);
has_role(user, "writer", repo: Repo) if
  has_role(user, "owner", repo.org);
has_role(user, "reader", repo: Repo) if
  has_role(user, "member", repo.org);
has_role(user, "reader", repo: Repo) if
  has_role(user, "writer", repo);

################################ END USER POLICY ###############################
