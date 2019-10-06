from .punish import Punish
from redbot.core.bot import Red

async def setup(bot: Red):
    cog = Punish(bot)
    bot.add_cog(cog)