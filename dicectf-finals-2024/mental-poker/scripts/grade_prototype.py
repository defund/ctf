import json
import sqlite3
import sys
from game.monte import MonteGame

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

    def get_transcripts(
        self, set_id: int, game_id: int
    ) -> dict[tuple[int, int, int], tuple[list[str], bool, bool]]:
        res = self.conn.execute(
            """
            SELECT team_1, team_2, replica, round_id, message, admin_match, reported
            FROM rounds
            INNER JOIN matchups
            ON
                matchup = reference
                AND set_id = ?
                AND game_id = ?
        """,
            (set_id, game_id),
        ).fetchall()
        ret = {}
        for team1, team2, replica, round_id, message, admin_match, reported in res:
            ret.setdefault((team1, team2, replica), ([None] * 4, admin_match, reported))[0][
                round_id
            ] = message
        return ret

    def compute_scores(self, set_id: int, game_id: int) -> dict[str, int]:
        ret: dict[int, int] = {}
        transcripts = self.get_transcripts(set_id, game_id)
        for (team1, team2, _), (msgs, admin_match, reported) in transcripts.items():
            ret.setdefault(team1, 0)
            ret.setdefault(team2, 0)
            if reported:
                if admin_match:
                    ret[team1] -= 10
                else:
                    ret[team1] += 1
                    ret[team2] -= 1
            elif not admin_match:
                winner, _ = MonteGame.check(msgs)
                if winner:
                    ret[team1] -= 1
                    ret[team2] += 1
                else:
                    ret[team1] += 1
                    ret[team2] -= 1
        user_map: dict[int, str] = dict(
            self.conn.execute(
                "SELECT team_id, username FROM teams WHERE NOT is_admin"
            ).fetchall()
        )
        return {UUID_MAP[user_map[k]]: v for (k, v) in ret.items() if k in user_map}


if __name__ == "__main__":
    grader = Grader("state/game.db")
    set_id = int(sys.argv[1])
    game_id = int(sys.argv[2])
    print(json.dumps(grader.compute_scores(set_id, game_id)))
