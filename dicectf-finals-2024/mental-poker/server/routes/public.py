import time
from dataclasses import dataclass
from ..state import game
from ..server import JsonApiRouter, RouteException


@dataclass
class PublicRequest:
    set_id: int
    game_id: int
    round_id: int
    remaining: int
    data: dict


async def public_handler(request) -> PublicRequest:
    if request.method == "POST":
        data = await request.json()
    else:
        data = request.query

    try:
        (
            set_id,
            game_id,
            round_id,
            remaining,
        ) = game.current_round_time(int(time.time()))
    except AssertionError:
        raise RouteException(404, "game is not running")

    return PublicRequest(set_id, game_id, round_id, remaining, data)


public_route = JsonApiRouter("/public", public_handler)


@public_route.get("/round")
async def get_round(request):
    game_id = request.game_id
    round_id = request.round_id
    time_left = request.remaining
    return {"game_id": game_id, "round_id": round_id, "time_left": time_left}
