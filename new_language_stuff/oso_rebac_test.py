from enum import Enum
from oso import Oso
from dataclasses import dataclass

ROLES_DB = {}


class User:
    def __init__(self, name):
        self.name = name
        self.role_map = {}

    def assign_role(self, resource, role_name):
        # role = ROLES_DB.get((resource.name, self.name))
        # ROLES_DB[(resource.name, self.name)] = Role(
        #     name=role_name, user=self, resource=resource
        # )

        roles = self.role_map.get(resource.name)
        if roles is not None:
            roles.append(role_name)
        else:
            self.role_map[resource.name] = [role_name]

    def has_role(self, role, resource):
        # return role == ROLES_DB.get(role.resource.name, self.name)
        role = self.role_map.get(resource.name)
        return role is not None


@dataclass
class Role:
    name: str
    user: User
    resource: object


@dataclass
class Org:
    name: str


@dataclass
class Repo:
    name: str
    org: Org


oso = Oso()
oso.register_class(User)
oso.register_class(Repo)
oso.register_class(Org)
oso.register_class(Role)
oso.load_file("rebac_gitclub_2.polar")

leina = User("leina")
gabe = User("gabe")
oso_hq = Org("Oso")
apple = Org("Apple")
oso_repo = Repo(name="oso_repo", org=oso_hq)
ios_repo = Repo(name="ios", org=apple)
leina.assign_role(oso_hq, "org:owner")
gabe.assign_role(oso_repo, "repo:writer")

# from direct role assignment
assert oso.is_allowed(leina, "create_repos", oso_hq)

# from same-resource implication
assert oso.is_allowed(leina, "list_repos", oso_hq)

# from child-resource implication
assert oso.is_allowed(leina, "read", oso_repo)

assert not oso.is_allowed(leina, "read", ios_repo)

# from same-resource implication
assert oso.is_allowed(gabe, "read", oso_repo)
