from .punish import Punish

async def setup(bot):
    cog = Punish(bot)
    await cog.load_data()
    bot.add_cog(cog)