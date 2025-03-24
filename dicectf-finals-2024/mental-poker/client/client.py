import random
import time
import requests
import traceback
from game.base import Alice, Bob


class PokerClient:
    def __init__(
        self,
        alice: type[Alice],
        bob: type[Bob],
        root: str,
        token: str,
    ):
        self.Alice = alice
        self.Bob = bob

        self.alice_clients = {}
        self.bob_clients = {}

        self.alice = None
        self.bob = None
        self.root = root
        self.token = token
        self.game = None
        self.round = None

    def _on_turn(self):
        assert self.game is not None
        assert self.round is not None

        print(f"running game {self.game} turn {self.round}")

        matchups = requests.post(
            f"{self.root}/game/living_matchups", json={"token": self.token}
        ).json()

        print(f"...found {len(matchups)} matchups")

        if isinstance(matchups, dict):
            print(matchups)

        transcripts = requests.post(
            f"{self.root}/game/transcripts",
            json={"token": self.token, "matchups": [x[0] for x in matchups]},
        ).json()

        turns = []
        for (reference, side, player_one), transcript in zip(matchups, transcripts):
            del player_one  # team id of Alice, unused for now

            if self.round % 2 == 0:
                if side != "evens":
                    continue

                if reference not in self.alice_clients:
                    self.alice_clients[reference] = self.Alice()
                alice = self.alice_clients[reference]

                if self.round == 0:
                    [] = transcript
                    try:
                        response = alice.first_message()
                    except Exception:
                        response = ""
                elif self.round == 2:
                    [a, b] = transcript
                    try:
                        response = alice.second_message((a, b))
                    except Exception:
                        response = ""
                else:
                    raise ValueError("unexpected round")

            else:
                if side != "odds":
                    continue

                if reference not in self.bob_clients:
                    self.bob_clients[reference] = self.Bob()
                bob = self.bob_clients[reference]

                if self.round == 1:
                    [a] = transcript
                    try:
                        response = bob.first_response((a,))
                    except Exception:
                        response = ""
                elif self.round == 3:
                    [a, b, c] = transcript
                    try:
                        response = bob.second_response((a, b, c))
                    except Exception:
                        response = ""
                else:
                    raise ValueError("unexpected round")

            turns.append([reference, response])

        response = requests.post(
            f"{self.root}/game/take_turns",
            json={
                "token": self.token,
                "turns": turns
            },
        ).json()

        print("...completed")
        if self.round == 3:
            print("all messages sent for the round, can restart now before next round starts")

    def _on_game(self):
        if not self.alice_clients:
            # if you want to detect cheats when restarting the client you can impl it :)
            pass
        else:
            transcripts = requests.post(
                f"{self.root}/game/transcripts",
                json={
                    "token": self.token,
                    "matchups": list(self.alice_clients.keys()),
                },
            ).json()
            for (ref, client), transcript in zip(
                self.alice_clients.items(), transcripts
            ):
                if len(transcript) == 4 and client.cheated(tuple(transcript)):
                    print(f"reporting {ref}...")
                    requests.post(
                        f"{self.root}/game/report_matchup",
                        json={"token": self.token, "matchup": ref},
                    )

        # basically just purge old clients we no longer need
        self.alice_clients = {}
        self.bob_clients = {}

    def crank(self):
        status = requests.get(f"{self.root}/public/round").json()
        if self.game != status["game_id"]:
            self.game = status["game_id"]
            self.round = status["round_id"]
            self._on_game()
            self._on_turn()
        elif self.round != status["round_id"]:
            self.game = status["game_id"]
            self.round = status["round_id"]
            self._on_turn()

    def run(self, interval=5):
        while True:
            try:
                self.crank()
            except Exception as e:
                print(f"error: {e}")
                print("".join(traceback.format_exception(None, e, e.__traceback__)))

            time.sleep(interval + random.random() * 4 - 2)
