import asyncio
import re
import discord

from redbot.core import Config, checks, commands, modlog
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import pagify, box, warning, error, info, bold


class AntiSpam(commands.Cog):

    default_guild = {"enabled": False, "excluded_channels": [], "excluded_roles": []}

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(
            self, identifier=2599124364
        )  # identifier is a random number

        self.config.register_guild(**self.default_guild)

        self.regex = re.compile(
            r"<?(https?:\/\/)?(www\.)?(discord\.gg|discordapp\.com\/invite|discord\.me)\b([-a-zA-Z0-9/]*)>?"
        )

    @commands.group(pass_context=True, invoke_without_command=True, no_pm=True)
    async def antispamset(self, ctx):
        """Manages the settings for antispam."""
        if ctx.invoked_subcommand is None:
            await self.bot.send_help_for(ctx, ctx.command)

    @antispamset.command(pass_context=True, no_pm=True, name="toggle")
    @checks.admin_or_permissions(administrator=True)
    async def toggle(self, ctx):
        """Enable/disables antispam in the guild"""
        guild = ctx.message.guild

        enabled = await self.config.guild(guild).enabled()

        enabled = not enabled
        await self.config.guild(guild).enabled.set(enabled)

        if enabled is True:
            await ctx.send("AntiSpam has been enabled")
        else:
            await ctx.send("AntiSpam has been disabled")

    @antispamset.command(pass_context=True, no_pm=True, name="addrole")
    @checks.admin_or_permissions(manage_messages=True)
    async def addrole(self, ctx, role: discord.Role):
        guild = ctx.message.guild
        excluded_roles = await self.config.guild(guild).excluded_roles()

        for excluded_role in excluded_roles:
            if excluded_role == role.id:
                await ctx.send("%s already added to role exclusion list" % role.name)
                return

        excluded_roles.append(role.id)
        await self.config.guild(guild).excluded_roles.set(excluded_roles)

        await ctx.send("%s added to role exclusion list" % role.name)

    @antispamset.command(pass_context=True, no_pm=True, name="addchannel")
    @checks.admin_or_permissions(manage_messages=True)
    async def addchannel(self, ctx, channel: discord.TextChannel):
        guild = ctx.message.guild
        excluded_channels = await self.config.guild(guild).excluded_channels()

        for excluded_channel in excluded_channels:
            if excluded_channel == channel.id:
                await ctx.send(
                    "%s already added to channel exclusion list" % channel.name
                )
                return

        excluded_channels.append(channel.id)
        await self.config.guild(guild).excluded_channels.set(excluded_channels)
        await ctx.send("%s added to channel exclusion list" % channel.name)

    @antispamset.command(pass_context=True, no_pm=True, name="removerole")
    @checks.admin_or_permissions(manage_messages=True)
    async def removerole(self, ctx, role: discord.Role):
        guild = ctx.message.guild
        excluded_roles = await self.config.guild(guild).excluded_roles()

        if role.id in excluded_roles:
            excluded_roles.remove(role.id)
            await self.config.guild(guild).excluded_roles.set(excluded_roles)
            await ctx.send("Removed %s from role exclusion list." % role.name)
        else:
            await ctx.send("%s is not an excluded role." % role.name)

    @antispamset.command(pass_context=True, no_pm=True, name="removechannel")
    @checks.admin_or_permissions(manage_messages=True)
    async def removechannel(self, ctx, channel: discord.TextChannel):
        guild = ctx.message.guild
        excluded_channels = await self.config.guild(guild).excluded_channels()

        if channel.id in excluded_channels:
            excluded_channels.remove(channel.id)
            await self.config.guild(guild).excluded_channels.set(excluded_channels)
            await ctx.send("Removed %s from channel exclusion list." % channel.name)
        else:
            await ctx.send("%s is not excluded channel." % channel.name)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        """Checks message against regex and deletes if necessary."""
        user = message.author
        guild = message.guild

        if guild is None:
            return

        # If it's the bot, return
        if user == guild.me:
            return

        enabled = await self.config.guild(guild).enabled()

        if enabled is True:
            excluded_channels = await self.config.guild(guild).excluded_channels()

            for channel in excluded_channels:
                if channel == message.channel.id:
                    return

            user_roles = [r.id for r in user.roles]
            excluded_roles = await self.config.guild(guild).excluded_roles()

            # If the user has an excluded role, return
            for role in excluded_roles:
                if role in user_roles:
                    return

            if self.regex.search(message.content) is not None:
                await asyncio.sleep(0.5)
                await message.delete()
