allow(user: User, action, resource) if user can action on resource;

user can "invite" on org: Org if user has_role "owner" for org;
user can "create_repo" on org: Org if user has_role "member" for org;
user can "pull" on repo: Repo if user has_role "reader" for repo;
user can "push" on repo: Repo if user has_role "writer" for repo;
user can "delete" on issue: Issue if user has_role "owner" for issue.repo.org;
user can "edit" on issue: Issue if user has_role "writer" for issue.repo;

user has_role role for resource if user.has_role_for_resource(role, resource);

user has_role "member" for org: Org if user has_role "owner" for org;
user has_role "writer" for repo: Repo if user has_role "owner" for repo.org;
user has_role "reader" for repo: Repo if user has_role "member" for repo.org;
user has_role "reader" for repo: Repo if user has_role "writer" for repo;

################################ END RBAC POLICY ###############################

############################# START OWNERSHIP POLICY ###########################

user can "delete" on issue: Issue if user created issue;
user can "delete" on issue: Issue if user owns issue.repo.org;

user created _: Issue{created_by: user};
user owns _: Org{owner: user};

############################## END OWNERSHIP POLICY ############################
