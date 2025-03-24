import json
import sqlite3
import sys
from game.monte import MonteGame
from tqdm import tqdm
from multiprocessing import Pool
import os

UUID_MAP = {
    "Blue Water": "dc63d39b-272f-4ac8-884b-8636b27e9421",
    "*0xA": "66fb75f0-0e36-4ded-8681-e71fc077f64e",
    "idek": "f8e5982b-a3a8-4f9c-bcf0-ca4984031744",
    "rev mains fr": "389d1dce-77ba-4d2a-86a1-1057f1aad295",
    "BunkyoWesterns": "ffecc8a6-6b4a-4012-9716-0133b46a11b2",
    "Thehackerscrew": "7b6c9999-6f3b-4bb0-bf06-a5fb2f8f6f0d",
    "View Source": "c2f4a824-e33c-4257-a81c-e2eaf309f4be",
    "les amateurs": "ff204dab-621c-4bd3-a027-ad195057f177",
    "organizers": "65a9d3a0-fad4-4f30-9ea2-a6c34638a05c",
    "P1G SEKAI": "fe72b5b9-faad-411e-a8c6-c32ddfe7006a",
    "goose guild": "80be5a61-b8e2-4c04-a5a6-899a3f774b32",
    "Maple Bacon": "005af6be-701c-4cec-aabd-87c9df9c55b8",
}


class Grader:
    conn: sqlite3.Connection

    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)

    def get_transcript(self, ref: str) -> list[str]:
        res = self.conn.execute(
            """
            SELECT message
            FROM rounds
            WHERE matchup = ?
            ORDER BY round_id
        """,
            (ref,),
        ).fetchall()
        return [x for [x] in res]

    @staticmethod
    def check(x):
        return MonteGame.check(x, par=False)

    def head_to_head(self, defender: int, attacker: int) -> list[tuple[bool, bool]]:
        """
        Returns a list of (defense win, attack win) tuples.
        """
        with Pool(max(os.cpu_count() or 0, 64)) as p:
            matchups = self.conn.execute(
                """
                SELECT set_id, game_id, reference, reported
                FROM matchups
                WHERE
                    team_1 = ?
                    AND team_2 = ?
                    AND game_id >= 60
                ORDER BY
                    set_id ASC,
                    game_id ASC
                """,
                (defender, attacker),
            ).fetchall()
            history = {}
            checks = p.map(self.check, [self.get_transcript(x[2]) for x in matchups])
            for ((set_id, game_id, _ref, reported), check) in zip(matchups, checks):
                if reported:
                    winner = False
                else:
                    winner, _ = check
                k = (set_id, game_id)
                pair = history.setdefault(k, [True, True])
                pair[0] = pair[0] and not winner
                pair[1] = pair[1] and winner
            history = [x[1] for x in sorted(history.items(), key=lambda x: x[0])]
            return history
    
    @staticmethod
    def count_streaks(history: list[bool]) -> int:
        curr_streak = 0
        total = 0
        for b in history + [False]:
            if b:
                curr_streak = curr_streak + 1
            else:
                if curr_streak >= 3:
                    total += curr_streak
                curr_streak = 0
        return total
    
    def pairwise_score(self, team_a: int, team_b: int) -> tuple[float, float]:
        a_attack = self.head_to_head(team_b, team_a)
        a_score = self.count_streaks([x[1] for x in a_attack])
        b_attack = self.head_to_head(team_a, team_b)
        b_score = self.count_streaks([x[1] for x in b_attack])
        if a_score == b_score == 0:
            return (0.0, 0.0)
        else:
            tot = a_score + b_score
            return (a_score / tot, b_score / tot)


if __name__ == "__main__":
    # grader = Grader("state/game.db")
    grader = Grader(sys.argv[1])
    scores = {k: 0.0 for k in range(1, 13)}
    for team_1 in tqdm(range(1, 13)):
        for team_2 in tqdm(range(team_1 + 1, 13)):
            (a, b) = grader.pairwise_score(team_1, team_2)
            scores[team_1] += a
            scores[team_2] += b
    print(scores)
    # print(grader.get_transcript("9da3d52901f17fe03e51129dc79505e8"))

    # grader.head_to_head(11, 22)
