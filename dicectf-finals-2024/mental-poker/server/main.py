from aiohttp import web
from .server import static

from .routes.game import game_route
from .routes.public import public_route


def make_app():
    app = web.Application(client_max_size=16 * 1024 * 1024)
    app.add_routes(game_route.routes())
    app.add_routes(public_route.routes())
    app.add_routes([static("static")])
    return app


web.run_app(make_app())
