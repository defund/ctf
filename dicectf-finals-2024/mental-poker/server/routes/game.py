import time
from dataclasses import dataclass
from ..state import game
from ..server import JsonApiRouter, RouteException


@dataclass
class GameRequest:
    set_id: int
    game_id: int
    round_id: int
    team: int
    data: dict


async def game_handler(request) -> GameRequest:
    if request.method == "POST":
        data = await request.json()
    else:
        data = request.query

    token = data.get("token", None)
    if token is None:
        raise RouteException(400, "token required")

    try:
        team = game.get_team(token)
    except AssertionError:
        raise RouteException(404, "team not found")

    now = int(time.time())
    try:
        set_id, game_id, round_id = game.current_round(now)
    except AssertionError:
        raise RouteException(404, "game is not running")

    return GameRequest(set_id, game_id, round_id, team, data)


game_route: JsonApiRouter[GameRequest] = JsonApiRouter("/game", game_handler)


@game_route.post("/matchups")
async def get_matchups(request):
    set_id = request.set_id
    game_id = request.game_id
    team_id = request.team
    return game.get_matchups(set_id, game_id, team_id)

@game_route.post("/living_matchups")
async def get_living_matchups(request):
    set_id = request.set_id
    game_id = request.game_id
    team_id = request.team
    round_id = request.round_id
    m = game.get_living_matchups(set_id, game_id, team_id, round_id)
    return m

@game_route.post("/transcripts")
async def get_transcripts(request):
    set_id = request.set_id
    game_id = request.game_id
    round_id = request.round_id
    references = request.data.get("matchups", [])
    return [game.get_transcript(set_id, game_id, round_id, reference) for reference in references]


@game_route.post("/take_turns")
async def take_turns(request):
    set_id = request.set_id
    game_id = request.game_id
    round_id = request.round_id
    team_id = request.team

    turns = request.data.get("turns", [])

    ret = []
    for turn in turns:
        if not isinstance(turn, list) or len(turn) != 2:
            raise RouteException(400, "turns must be list of (matchup, message) tuples")
        [reference, message] = turn

        if reference is None:
            raise RouteException(400, "matchup required")
        if message is None:
            raise RouteException(400, "message required")

        if game.check_winner_by_timeout(set_id, game_id, round_id, reference):
            ret.append({"message": "game has already been won"})
        else:
            try:
                game.submit_round(
                    set_id,
                    game_id,
                    round_id,
                    reference,
                    team_id,
                    message,
                )
            except AssertionError as e:
                raise RouteException(400, str(e))
            ret.append({"message": "round submitted"})
    return ret

@game_route.post("/report_matchup")
async def report_matchup(request):
    set_id = request.set_id
    game_id = request.game_id
    team_id = request.team
    round_id = request.round_id

    reference = request.data.get("matchup", None)
    if reference is None:
        raise RouteException(400, "matchup required")

    if game.check_winner_by_timeout(set_id, game_id, round_id, reference):
        return {"message": "game was not played through"}

    if game.report_matchup(set_id, game_id, team_id, reference):
        return {"message": "matchup reported"}
    else:
        return {"message": "reported too late"}

@game_route.post("/reports")
async def get_reports(request):
    set_id = request.set_id
    game_id = request.game_id
    team_id = request.team
    return game.get_reports(set_id, game_id, team_id)
