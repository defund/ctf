# NOTTODO: toctou not all over the place :slight_smile:

import secrets
import sqlite3

GAME_ROUNDS = 4
ROUND_DURATION = 30


class Game:
    def __init__(self, path: str, start_time: int) -> None:
        self.connection = sqlite3.connect(path)
        cursor = self.connection.cursor()

        cursor.execute("pragma journal_mode=wal")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS teams (
                team_id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                token TEXT UNIQUE NOT NULL,
                is_admin BOOLEAN NOT NULL
            )
        """)

        # start_time is the set id
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS current_set (
                start_time INTEGER NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS matchups (
                reference TEXT PRIMARY KEY,
                set_id INTEGER NOT NULL,
                game_id INTEGER NOT NULL,
                team_1 INTEGER NOT NULL,
                team_2 INTEGER NOT NULL,
                replica INTEGER NOT NULL, -- only here for uniqueness constraint
                admin_match BOOLEAN NOT NULL,
                reported BOOLEAN NOT NULL,
                UNIQUE(set_id, game_id, replica, team_1, team_2)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS matchups_set_game ON matchups (set_id, game_id);
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rounds (
                matchup TEXT NOT NULL,
                round_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY (matchup) REFERENCES matchups(reference),
                UNIQUE(round_id, matchup)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS round_matchup ON rounds (matchup);
        """)

        cursor.execute("""
            DELETE FROM current_set
        """)

        cursor.execute(
            """
            INSERT INTO current_set (start_time) VALUES (?)
        """,
            (start_time,),
        )

        self.connection.commit()

    def get_team(self, token: str) -> int:
        result = self.connection.execute(
            """
            SELECT team_id FROM teams WHERE token = ?
        """,
            (token,),
        ).fetchone()

        assert result is not None, "team not found"
        (team_id,) = result
        return team_id

    def add_team(self, username: str, is_admin: bool = False) -> str:
        token = secrets.token_hex(16)
        (db_token,) = self.connection.execute(
            """
                INSERT INTO teams (
                    username,
                    token,
                    is_admin
                ) VALUES (?, ?, ?)
                ON CONFLICT (username) DO UPDATE
                    SET token = token -- dumb workaround to return token always
                RETURNING token
            """,
            (username, token, is_admin),
        ).fetchone()
        self.connection.commit()
        return db_token

    def current_round_time(self, now: int) -> tuple[int, int, int, int]:
        result = self.connection.execute("""
            SELECT start_time FROM current_set
        """).fetchone()

        assert result is not None, "no set started"

        (start_time,) = result
        current_time = now

        assert current_time >= start_time, "set has not started yet"

        game_seconds = ROUND_DURATION * GAME_ROUNDS
        time_in_set = current_time - start_time
        game_id = time_in_set // game_seconds

        time_in_game = time_in_set % game_seconds
        round_id = time_in_game // ROUND_DURATION

        remaining = ROUND_DURATION - (time_in_game % ROUND_DURATION)

        return start_time, game_id, round_id, remaining

    def current_round(self, now: int) -> tuple[int, int, int]:
        start_time, game_id, round_id, _ = self.current_round_time(now)
        return start_time, game_id, round_id

    def get_created_matchups(
        self,
        set_id: int,
        game_id: int,
        team_id: int,
    ) -> list[tuple[str, str, str]]:
        return self.connection.execute(
            # """
            #     SELECT
            #         reference,
            #         CASE WHEN team_1 = :team
            #             THEN 'evens'
            #             ELSE 'odds'
            #         END AS turn,
            #     FROM matchups
            #     WHERE
            #         set_id = :set
            #         AND game_id = :game
            #         AND (team_1 = :team OR team_2 = :team)
            # """,
            """
                SELECT
                    matchups.reference,
                    CASE WHEN team_1 = :team
                        THEN 'evens'
                        ELSE 'odds'
                    END AS turn,
                    teams.username
                FROM matchups
                INNER JOIN teams
                ON
                    teams.team_id = matchups.team_1
                    AND matchups.set_id = :set
                    AND matchups.game_id = :game
                    AND (matchups.team_1 = :team OR matchups.team_2 = :team)
                ORDER BY matchups.reference ASC
            """,
            {"team": team_id, "set": set_id, "game": game_id},
        ).fetchall()

    def create_new_matchups(
        self,
        set_id: int,
        game_id: int,
    ):
        teams = self.connection.execute("""
            SELECT team_id, is_admin FROM teams
        """).fetchall()
        cursor = self.connection.cursor()

        for team_1, admin_1 in teams:
            # team 1 should never be an admin
            if admin_1:
                continue
            for team_2, admin_2 in teams:
                if team_1 == team_2:
                    continue
                for replica in range(8):
                    reference = secrets.token_hex(16)
                    cursor.execute(
                        """
                            INSERT INTO matchups (
                                reference,
                                set_id,
                                game_id,
                                team_1,
                                team_2,
                                admin_match,
                                reported,
                                replica
                            )
                            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                        """,
                        (reference, set_id, game_id, team_1, team_2, admin_2, replica),
                    )

        self.connection.commit()

    def get_matchups(
        self, set_id: int, game_id: int, team_id: int
    ) -> list[tuple[str, str, str]]:
        matchups = self.get_created_matchups(set_id, game_id, team_id)

        if len(matchups) == 0:
            self.create_new_matchups(set_id, game_id)
            matchups = self.get_created_matchups(set_id, game_id, team_id)

        assert matchups, "what happened"
        return matchups

    def get_created_living_matchups(
        self, set_id: int, game_id: int, team_id: int, round_id: int
    ) -> list[tuple[str, str, str]]:
        if round_id == 0:
            return self.get_created_matchups(set_id, game_id, team_id)
        return self.connection.execute(
            """
                SELECT
                    reference,
                    CASE WHEN team_1 = :team
                        THEN 'evens'
                        ELSE 'odds'
                    END AS turn,
                    teams.username
                FROM matchups
                INNER JOIN teams
                ON
                    set_id = :set
                    AND game_id = :game
                    AND (team_1 = :team OR team_2 = :team)
                    AND EXISTS (
                        SELECT message FROM rounds
                        WHERE
                            matchup = matchups.reference
                            AND round_id = :round - 1                           
                    )
                    AND teams.team_id = matchups.team_1
                ORDER BY reference ASC
            """,
            {"set": set_id, "game": game_id, "team": team_id, "round": round_id},
        ).fetchall()

    def get_living_matchups(
        self, set_id: int, game_id: int, team_id: int, round_id: int
    ) -> list[tuple[str, str, str]]:
        matchups = self.get_created_living_matchups(
            set_id,
            game_id,
            team_id,
            round_id,
        )

        if len(matchups) == 0:
            if (
                self.connection.execute(
                    "SELECT reference FROM matchups WHERE set_id = ? AND game_id = ?",
                    (set_id, game_id),
                ).fetchone()
                is None
            ):
                self.create_new_matchups(set_id, game_id)
            matchups = self.get_created_living_matchups(
                set_id,
                game_id,
                team_id,
                round_id,
            )

        return matchups

    def get_matchup(self, set_id: int, game_id: int, reference: str) -> tuple[str, str]:
        result = self.connection.execute(
            """
                SELECT
                    team_1,
                    team_2
                FROM matchups
                WHERE
                    reference = ?
                    AND set_id = ?
                    AND game_id = ?
            """,
            (reference, set_id, game_id),
        ).fetchone()

        assert result is not None, "matchup not found"
        return result

    def get_transcript(
        self, set_id: int, game_id: int, round_id: int, reference: str
    ) -> list[str]:
        result = self.connection.execute(
            """
                SELECT message FROM rounds
                INNER JOIN matchups
                ON
                    matchup = reference
                    AND matchup = :ref
                    AND (
                        set_id < :set
                        OR game_id < :game
                        OR round_id < :round
                    )
                ORDER BY round_id
            """,
            {"ref": reference, "set": set_id, "game": game_id, "round": round_id},
        ).fetchall()

        return [message for (message,) in result]

    def submit_round(
        self,
        set_id: int,
        game_id: int,
        round_id: int,
        reference: str,
        team_id: int,
        message: str,
    ):
        team_1, team_2 = self.get_matchup(set_id, game_id, reference)

        # team_1 goes on evens, team_2 goes on odds
        current_team = team_1 if round_id % 2 == 0 else team_2

        assert current_team == team_id, "not your turn"

        assert len(message) < 20000, "message should be <20kb"

        self.connection.execute(
            """
                INSERT INTO rounds (
                    round_id,
                    message,
                    matchup
                )
                VALUES (?, ?, ?)
            """,
            (round_id, message, reference),
        )
        self.connection.commit()

    def check_winner_by_timeout(
        self,
        set_id: int,
        game_id: int,
        round_id: int,
        reference: str,
    ) -> bool:
        result = self.connection.execute(
            """
                SELECT message FROM rounds
                INNER JOIN matchups
                ON
                    matchup = reference
                    AND matchup = ?
                    AND set_id = ?
                    AND game_id = ?
                    AND round_id < ?
            """,
            (reference, set_id, game_id, round_id),
        ).fetchall()

        if len(result) < round_id:
            return True

        return False

    def report_matchup(
        self,
        set_id: int,
        current_game_id: int,
        team_id: int,
        matchup: str,
    ):
        cursor = self.connection.cursor()
        cursor.execute(
            """
                UPDATE matchups
                SET reported = 1
                WHERE
                    set_id = ?
                    AND game_id >= ?
                    AND team_1 = ?
                    AND reference = ?
            """,
            (set_id, current_game_id - 1, team_id, matchup),
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def get_reports(
        self,
        set_id: int,
        game_id: int,
        team_id: int
    ) -> list[str]:
        res = self.connection.execute(
            """
                SELECT DISTINCT username
                FROM matchups
                INNER JOIN teams
                ON
                    set_id = ?
                    AND game_id = ?
                    AND team_2 = ?
                    AND reported
                    AND teams.team_id = team_1
                ORDER BY username ASC
            """,
            (set_id, game_id - 1, team_id)
        ).fetchall()
        return [x for [x] in res]

    def __del__(self):
        self.connection.close()
