from .antihoist import AntiHoist
from redbot.core.bot import Red

async def setup(bot: Red):
    cog = AntiHoist(bot)
    bot.add_cog(cog)