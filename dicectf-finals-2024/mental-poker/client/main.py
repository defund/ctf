import os

from game.monte import MonteGuesser, MonteSetter
from .client import PokerClient

ROOT = 'http://localhost:8080'
TOKEN = os.environ.get('TOKEN', None)

assert TOKEN is not None

client = PokerClient(MonteGuesser, MonteSetter, ROOT, TOKEN)
client.run()
