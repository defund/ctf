from random import SystemRandom

import fastecdsa.keys

from .base import Game, Alice, Bob
from .params import curve
from . import mix, reveal
from .serialize import *

random = SystemRandom()


class MonteGame(Game):

    jack = 11 * curve.G
    queen = 12 * curve.G

    @classmethod
    def check(cls, transcript, par=True):
        try:
            pub_a = deserialize_msg0(transcript[0])
        except Exception:
            return True, "alice's public key is malformed"

        try:
            pub_b, new, mix_proof = deserialize_msg1(transcript[1])
        except Exception as e:
            return False, "bob's public key or mix is malformed"

        pub = pub_a + pub_b
        old = [Card.new(cls.jack), Card.new(cls.queen)]

        try:
            mix.verify(pub, old, new, mix_proof, par=par)
        except Exception:
            return False, "bob's mix proof is invalid"

        try:
            choice, share_a, proof_a = deserialize_msg2(transcript[2])
            card = new[choice]
        except Exception:
            return True, "alice's choice or reveal is malformed"

        try:
            reveal.verify(card, pub_a, share_a, proof_a)
        except Exception:
            return True, "alice's reveal proof is invalid"

        try:
            share_b, proof_b = deserialize_msg3(transcript[3])
        except Exception:
            return False, "bob's reveal is malformed"

        try:
            reveal.verify(card, pub_b, share_b, proof_b)
        except Exception:
            return False, "bob's reveal proof is invalid"

        if card.Q - share_a - share_b == cls.queen:
            return False, "alice found the queen"
        else:
            return True, "alice didn't find the queen"


class MonteGuesser(Alice):

    def __init__(self):
        self.priv, self.pub_a = fastecdsa.keys.gen_keypair(curve)

    def first_message(self):
        return serialize_msg0(self.pub_a)

    def second_message(self, transcript):
        _, new, _ = deserialize_msg1(transcript[1])
        choice = random.randrange(2)
        card = new[choice]
        share, proof = reveal.reveal_and_prove(card, self.pub_a, self.priv)
        return serialize_msg2(choice, share, proof)


class MonteSetter(Bob):

    def __init__(self):
        self.priv, self.pub_b = fastecdsa.keys.gen_keypair(curve)

    def first_response(self, transcript):
        pub_a = deserialize_msg0(transcript[0])
        pub = pub_a + self.pub_b
        old = [Card.new(MonteGame.jack), Card.new(MonteGame.queen)]
        self.new, proof = mix.mix_and_prove(pub, old)
        return serialize_msg1(self.pub_b, self.new, proof)

    def second_response(self, transcript):
        choice, _, _ = deserialize_msg2(transcript[2])
        card = self.new[choice]
        share, proof = reveal.reveal_and_prove(card, self.pub_b, self.priv)
        return serialize_msg3(share, proof)

if __name__ == '__main__':
    # sanity check
    alice = MonteGuesser()
    bob = MonteSetter()
    transcript = []
    transcript.append(alice.first_message())
    transcript.append(bob.first_response(transcript))
    transcript.append(alice.second_message(transcript))
    transcript.append(bob.second_response(transcript))
    res = MonteGame.check(transcript)
    assert res in ((False, "alice found the queen"), (True, "alice didn't find the queen"))
    print(res)
