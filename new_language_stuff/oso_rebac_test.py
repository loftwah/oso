from enum import Enum
from typing import Union
from oso import Oso
from dataclasses import dataclass


class User:
    def __init__(self, name):
        self.name = name
        self.role_map = {}

    def assign_role(self, resource, role_name):
        self.role_map[resource] = role_name

    def has_role_for_resource(self, role_name, resource):
        print(f"checking if {self.name} has {role_name} on {resource.name}")
        return self.role_map.get(resource) == role_name


@dataclass(frozen=True)
class Org:
    name: str


@dataclass(frozen=True)
class Repo:
    name: str
    org: Org


@dataclass(frozen=True)
class Issue:
    name: str
    repo: Repo


oso = Oso()
oso.register_class(User)
oso.register_class(Repo)
oso.register_class(Org)
oso.register_class(Issue)
oso.load_file("rebac_gitclub_gabe.polar")

leina = User("leina")
gabe = User("gabe")
oso_hq = Org("Oso")
apple = Org("Apple")
oso_repo = Repo(name="oso_repo", org=oso_hq)
ios_repo = Repo(name="ios", org=apple)
bug = Issue(name="bug", repo=oso_repo)
laggy = Issue(name="laggy", repo=ios_repo)
leina.assign_role(oso_hq, "owner")
gabe.assign_role(oso_repo, "writer")

# from direct role assignment
assert oso.is_allowed(leina, "create_repos", oso_hq)

# from same-resource implication
assert oso.is_allowed(leina, "list_repos", oso_hq)

# from child-resource implication
assert oso.is_allowed(leina, "read", oso_repo)
assert not oso.is_allowed(leina, "read", ios_repo)

# from same-resource implication
assert oso.is_allowed(gabe, "read", oso_repo)

# from cross-resource permission
assert oso.is_allowed(leina, "edit", bug)
assert not oso.is_allowed(leina, "edit", laggy)
