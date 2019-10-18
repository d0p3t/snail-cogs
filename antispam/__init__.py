from .antispam import AntiSpam
from redbot.core.bot import Red


async def setup(bot: Red):
    cog = AntiSpam(bot)
    bot.add_cog(cog)
