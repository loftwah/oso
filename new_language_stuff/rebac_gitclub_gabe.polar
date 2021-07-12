allow(user: User, action, resource) if user can action to resource;

############################### START RBAC POLICY ##############################

user can "invite" to org: Org if user has_role "owner" on org;
user can "create_repo" for org: Org if user has_role "member" on org;
user can "pull" from repo: Repo if user has_role "reader" on repo;
user can "push" to repo: Repo if user has_role "writer" on repo;
user can "delete" an issue: Issue if user has_role "owner" on issue.repo.org;
user can "edit" an issue: Issue if user has_role "writer" on issue.repo;

user has_role role on resource if user.has_role_for_resource(role, resource);

user has_role "member" on org: Org if user has_role "owner" on org;
user has_role "writer" on repo: Repo if user has_role "owner" on repo.org;
user has_role "reader" on repo: Repo if user has_role "member" on repo.org;
user has_role "reader" on repo: Repo if user has_role "writer" on repo;

############################# START OWNERSHIP POLICY ###########################

user can "delete" an issue: Issue if user created issue;
user can "delete" an issue: Issue if user owns issue.repo.org;

user created issue: Issue if issue.created_by = user;
user owns org: Org if org.owner = user;
