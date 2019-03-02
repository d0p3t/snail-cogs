from .strikes import Strikes

async def setup(bot):
    cog = Strikes(bot)
    bot.add_cog(cog)