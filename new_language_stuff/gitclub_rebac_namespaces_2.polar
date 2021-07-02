
# Leina policy
# This could maybe evaluate if we did some hacky parser stuff and rewrote some
# of the rules based on the namespace

Resource Org:
	Actions:
		invite,
		create_repo

	Role member:
		implies(Repo.reader);

	Role owner:
		implies(member);
		implies(Repo.writer);

	allow(member, invite);
	allow(owner, create_repo);

Resource Repo:
	Actions:
		pull,
		push

	Role reader
	Role writer:
		implies(reader);

	allow(reader, pull);
	allow(writer, push);

	parent(self, parent_org) if self.org = parent_org;


resource Issue: Issue {
	permission(action) if
		action in [
			"edit",
			"delete"];

	# Necessary (only if) conditions must be met in order for this rule to hold
	role_permission(_role: {name: "owner"}, "delete");
	role_permission(_role: {name: "writer"}, "edit");

	parent(self, parent_repo) if self.repo = parent_repo;

}