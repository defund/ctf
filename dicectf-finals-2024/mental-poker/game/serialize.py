import json

from fastecdsa.point import Point

from .card import Card, Shuffle
from .params import curve


def wrap_point(P):
    return {
        "x": P.x,
        "y": P.y,
    }


def wrap_card(card):
    return {
        "P": wrap_point(card.P),
        "Q": wrap_point(card.Q),
    }


def wrap_shuffle(shuffle):
    return {
        "perm": shuffle.perm,
        "masks": shuffle.masks,
    }


def wrap_mix(new, proof):
    chall, shuffles = proof
    return {
        "new": [wrap_card(c) for c in new],
        "proof": {
            "chall": chall,
            "shuffles": [wrap_shuffle(s) for s in shuffles],
        },
    }


def wrap_reveal(share, proof):
    c, y = proof
    return {
        "share": wrap_point(share),
        "proof": {
            "c": c,
            "y": y,
        },
    }


def serialize_msg0(pub):
    return json.dumps(wrap_point(pub))


def serialize_msg1(pub, new, proof):
    return json.dumps(
        {
            "pub": wrap_point(pub),
            "mix": wrap_mix(new, proof),
        }
    )


def serialize_msg2(choice, share, proof):
    return json.dumps(
        {
            "choice": choice,
            "reveal": wrap_reveal(share, proof),
        }
    )


def serialize_msg3(share, proof):
    return json.dumps(wrap_reveal(share, proof))


def unwrap_bool(obj):
    assert isinstance(obj, bool)
    return obj


def unwrap_int(obj):
    assert isinstance(obj, int)
    return obj


def unwrap_list(obj, f):
    assert isinstance(obj, list)
    return [f(x) for x in obj]


def unwrap_point(obj):
    assert isinstance(obj, dict)
    x = obj["x"]
    y = obj["y"]
    assert isinstance(x, int) and isinstance(y, int)
    return Point(x, y, curve=curve)


def unwrap_card(obj):
    assert isinstance(obj, dict)
    P = unwrap_point(obj["P"])
    Q = unwrap_point(obj["Q"])
    return Card(P, Q)


def unwrap_shuffle(obj):
    assert isinstance(obj, dict)
    perm = unwrap_list(obj["perm"], unwrap_int)
    masks = unwrap_list(obj["masks"], unwrap_int)
    return Shuffle(perm, masks)


def unwrap_mix(obj):
    assert isinstance(obj, dict)
    assert isinstance(obj["proof"], dict)
    new = unwrap_list(obj["new"], unwrap_card)
    chall = unwrap_list(obj["proof"]["chall"], unwrap_bool)
    shuffles = unwrap_list(obj["proof"]["shuffles"], unwrap_shuffle)
    return new, (chall, shuffles)


def unwrap_reveal(obj):
    assert isinstance(obj, dict)
    assert isinstance(obj["proof"], dict)
    share = unwrap_point(obj["share"])
    c = unwrap_int(obj["proof"]["c"])
    y = unwrap_int(obj["proof"]["y"])
    return share, (c, y)


def deserialize_msg0(buf: str):
    obj = json.loads(buf)
    return unwrap_point(obj)


def deserialize_msg1(buf: str):
    obj = json.loads(buf)
    assert isinstance(obj, dict)
    pub = unwrap_point(obj["pub"])
    new, proof = unwrap_mix(obj["mix"])
    return pub, new, proof


def deserialize_msg2(buf: str):
    obj = json.loads(buf)
    assert isinstance(obj, dict)
    choice = unwrap_int(obj["choice"])
    share, proof = unwrap_reveal(obj["reveal"])
    return choice, share, proof


def deserialize_msg3(buf: str):
    obj = json.loads(buf)
    return unwrap_reveal(obj)
