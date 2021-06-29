from enum import Enum
from oso import Oso


class OsoActor:
    pass


class OsoAction(Enum):
    pass


class OsoResource:
    pass


class OsoRole:
    pass


oso = Oso()
oso.register_class(OsoActor)
oso.register_class(OsoAction)
oso.register_class(OsoResource)
oso.register_class(OsoRole)