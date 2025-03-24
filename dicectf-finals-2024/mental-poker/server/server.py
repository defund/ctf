from typing import Any, Awaitable, Callable, TypeVar, Generic
from pathlib import Path
from aiohttp import web


class RouteException(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message


def static(directory):
    async def serve_static(request):
        path = Path(request.path).relative_to("/")
        file = Path(directory) / path
        if file.is_dir():
            file = file / "index.html"
        if not file.exists():
            return web.HTTPNotFound()
        return web.FileResponse(file)

    return web.get("/{_:.*}", serve_static)


T = TypeVar("T")

class JsonApiRouter(Generic[T]):
    def __init__(self, prefix, middle: Callable[[web.Request], Awaitable[T]]):
        self.prefix = prefix
        self.middle = middle
        self._routes = []

    def get(self, path):
        def handle(handler: Callable[[T], Any]):
            decorated_handler = self._handle_factory(handler)
            self._routes.append(web.get(f"{self.prefix}{path}", decorated_handler))

        return handle

    def post(self, path):
        def handle(handler: Callable[[T], Any]):
            decorated_handler = self._handle_factory(handler)
            self._routes.append(web.post(f"{self.prefix}{path}", decorated_handler))

        return handle

    def _handle_factory(self, handler: Callable[[T], Any]):
        async def decorated_handler(request: web.Request):
            try:
                status, data = 200, await handler(await self.middle(request))
            except RouteException as e:
                status, data = e.status, {"error": e.message}
            except Exception as e:
                status, data = 500, {"error": str(e)}
            return web.json_response(data, status=status)

        return decorated_handler

    def routes(self):
        return self._routes
