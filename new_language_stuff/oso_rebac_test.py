from enum import Enum
from typing import Union
from oso import Oso
from dataclasses import dataclass

ROLES_DB = {}


class User:
    def __init__(self, name):
        self.name = name
        self.role_map = {}

    def assign_role(self, resource, role_name):
        self.role_map[resource] = role_name

    def has_role_for_resource(self, role_name, resource):
        # print(f"checking if {self.name} has the {role_name} role on {resource}")
        return self.role_map.get(resource) == role_name


@dataclass(frozen=True)
class Org:
    name: str

    def __repr__(self):
        return f"Org({self.name})"


@dataclass(frozen=True)
class Repo:
    name: str
    org: Org

    def __repr__(self):
        return f"Repo({self.name})"


@dataclass(frozen=True)
class Issue:
    name: str
    repo: Repo


def test_policy(policy_file):
    print(f"\nTesting: {policy_file}\n")
    oso = Oso()
    oso.register_class(User)
    oso.register_class(Repo)
    oso.register_class(Org)
    oso.register_class(Issue)
    oso.load_file(policy_file)

    leina = User("leina")
    gabe = User("gabe")
    steve = User("steve")
    oso_hq = Org("OsoHQ")
    apple = Org("Apple")
    oso_repo = Repo(name="oso", org=oso_hq)
    ios_repo = Repo(name="ios", org=apple)
    bug = Issue(name="bug", repo=oso_repo)
    laggy = Issue(name="laggy", repo=ios_repo)
    leina.assign_role(oso_hq, "owner")
    gabe.assign_role(oso_repo, "writer")
    steve.assign_role(oso_hq, "member")

    # from direct role assignment
    assert oso.is_allowed(leina, "invite", oso_hq)
    assert not oso.is_allowed(leina, "invite", apple)
    assert not oso.is_allowed(steve, "invite", oso_hq)
    assert not oso.is_allowed(steve, "invite", apple)

    # from same-resource implication
    assert oso.is_allowed(leina, "create_repo", oso_hq)
    assert not oso.is_allowed(leina, "create_repo", apple)
    assert oso.is_allowed(steve, "create_repo", oso_hq)
    assert not oso.is_allowed(steve, "create_repo", apple)

    # from child-resource implication
    assert oso.is_allowed(leina, "push", oso_repo)
    assert not oso.is_allowed(leina, "push", ios_repo)
    assert oso.is_allowed(leina, "pull", oso_repo)
    assert not oso.is_allowed(leina, "pull", ios_repo)
    assert not oso.is_allowed(steve, "push", oso_repo)
    assert not oso.is_allowed(steve, "push", ios_repo)
    assert oso.is_allowed(steve, "pull", oso_repo)
    assert not oso.is_allowed(steve, "pull", ios_repo)

    # from cross-resource permission
    assert oso.is_allowed(leina, "edit", bug)
    assert not oso.is_allowed(leina, "edit", laggy)
    assert not oso.is_allowed(steve, "edit", bug)
    assert not oso.is_allowed(steve, "edit", laggy)

    # from cross-resource permission over two levels of hierarchy
    assert oso.is_allowed(leina, "delete", bug)
    assert not oso.is_allowed(leina, "delete", laggy)
    assert not oso.is_allowed(steve, "delete", bug)
    assert not oso.is_allowed(steve, "delete", laggy)

    # from same-resource implication
    assert oso.is_allowed(gabe, "pull", oso_repo)


def main():
    test_policy("rebac_gitclub_gabe.polar")
    # test_policy("rebac_gitclub_leina.polar")


if __name__ == "__main__":
    main()
