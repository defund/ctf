import time
from .game import Game

USERNAMES = [
    "Blue Water",
    "*0xA",
    "idek",
    "rev mains fr",
    "BunkyoWesterns",
    "Thehackerscrew",
    "View Source",
    "les amateurs",
    "organizers",
    "P1G SEKAI",
    "goose guild",
    "Maple Bacon",
]

game = Game("state/game.db", 1719759600)

print("=== NORMAL TEAMS ===")
for user in USERNAMES:
    token = game.add_team(user)
    print(f"{user}: {token}")

print("=== ADMIN BOTS ===")
for i in range(len(USERNAMES) - 1):
    admin = f"admin_{i:02}"
    token = game.add_team(admin, is_admin=True)
    print(f"{admin}: {token}")
