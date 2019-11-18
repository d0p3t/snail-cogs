import discord
import homoglyphs as hg

from redbot.core import Config, checks, commands
from redbot.core.bot import Red


class AntiHoist(commands.Cog):

    default_guild = {
        "enabled": True,
        "unallowed_chars": [
            "!",
            '"',
            "#",
            "$",
            "%",
            "&",
            "'",
            "(",
            ")",
            "*",
            "+",
            ",",
            "-",
            ".",
            "/",
        ],
        "replacement_chars": [
            "\u01C3",
            "\u201C",
            "\u2D4C",
            "\uFF04",
            "\u2105",
            "\u214B",
            "\u2018",
            "\u2768",
            "\u2769",
            "\u2217",
            "\u2722",
            "\u201A",
            "\u2013",
            "\u2024",
            "\u2044",
        ],
    }

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=2599124365)

        self.config.register_guild(**self.default_guild)

    def dehoist(self, user: discord.Member):
        print('something')

    @commands.Cog.listener()
    async def on_member_join(self, member):
        """Check nickname if user leaves/rejoins"""
        nickname = member.nick
        first_char = nickname[0]

        unallowed_chars = await self.config.guild(member.guild).unallowed_chars()
        replacement_chars = await self.config.guild(member.guild).replacement_chars()
        
        newname = member.nick

        for in in range(unallowed_chars):
            if first_char == unallowed_chars[i]:
                newname = replacement_chars[i] + nickname[1:]
                break

        if newname != nickname:
            await member.edit(nick=newname)