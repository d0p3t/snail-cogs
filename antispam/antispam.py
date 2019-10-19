import asyncio
import re
import discord
import time

from difflib import SequenceMatcher
from redbot.core import Config, checks, commands
from redbot.core.bot import Red


class AntiSpam(commands.Cog):

    default_guild = {
        "enabled": False,
        "excluded_channels": [],
        "excluded_roles": [],
        "similarity_threshold": 0.8,
        "spam_threshold": 5,
        "spam_punish_hours": 12,
    }

    default_member = {"last_message": None, "last_message_time": None, "spam_count": 0}

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(
            self, identifier=2599124364
        )  # identifier is a random number

        self.config.register_guild(**self.default_guild)
        self.config.register_member(**self.default_member)

        self.regex = re.compile(
            r"<?(https?:\/\/)?(www\.)?(discord\.gg|discordapp\.com\/invite|discord\.me)\b([-a-zA-Z0-9/]*)>?"
        )

        self.task = self.bot.loop.create_task(self.clean_up_task())

    async def __unload(self):
        await self.task.cancel()

    async def clean_up_task(self):
        await self.bot.wait_until_ready()

        while True:
            try:
                await self.config.clear_all_members()
                await asyncio.sleep(6000 * 60)

            except asyncio.CancelledError:
                break
            except Exception:
                pass

    def similarity(self, a, b):
        return SequenceMatcher(None, a, b).ratio()

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

    @antispamset.command(pass_context=True, no_pm=True, name="reset")
    @checks.admin_or_permissions(manage_messages=True)
    async def reset(self, ctx):
        """Resets all settings of guild to default values. Does not clear member data (use forceclear)"""
        await self.config.clear_all_guilds()
        await ctx.send("Reset all settings to default values.")

    @antispamset.command(pass_context=True, no_pm=True, name="forceclear")
    @checks.admin_or_permissions(manage_messages=True)
    async def forceclear(self, ctx):
        """Force clear all historical spam data of members."""
        guild = ctx.message.guild
        await self.config.clear_all_members(guild)
        await ctx.send("Force cleared all members data")

    @antispamset.command(pass_context=True, no_pm=True, name="simthreshold")
    @checks.admin_or_permissions(manage_messages=True)
    async def simthreshold(self, ctx, amount=None):
        """Sets the similarity threshold of the sequence matcher. Default: 0.8"""
        guild = ctx.message.guild

        if amount is None:
            current = await self.config.guild(guild).similarity_threshold()
            await ctx.send("Current similarity threshold is %s" % current)
            return

        try:
            threshold = float(amount)

            if threshold > 1.0 or threshold < 0.0:
                await ctx.send("Similarity Threshold must be between 0.0 and 1.0")
                return

            await self.config.guild(guild).similarity_threshold.set(threshold)
            await ctx.send("Set similarity threshold to %s" % threshold)
        except ValueError:
            await ctx.send("Could not convert similarity threshold to float. Woopsie")
            pass

    @antispamset.command(pass_context=True, no_pm=True, name="spamthreshold")
    @checks.admin_or_permissions(manage_messages=True)
    async def spamthreshold(self, ctx, amount=None):
        """Sets the amount of spam messages should be sent before punishing. Default: 5"""
        guild = ctx.message.guild

        if amount is None:
            current = await self.config.guild(guild).spam_threshold()
            await ctx.send("Current spam messages threshold is %s per member" % current)
            return

        try:
            threshold = int(amount)

            if threshold < 1:
                await ctx.send("Spam Threshold must be more than 0.")
                return

            await self.config.guild(guild).spam_threshold.set(threshold)
            await ctx.send("Set spam threshold to %s" % threshold)
        except ValueError:
            await ctx.send("Could not convert spam threshold to int. Woopsie")
            pass

    @antispamset.command(pass_context=True, no_pm=True, name="punishhours")
    @checks.admin_or_permissions(manage_messages=True)
    async def punishhours(self, ctx, amount=None):
        """Sets the amount of hours a member should be punished for exceeding spam threshold. Default: 12"""
        guild = ctx.message.guild

        if amount is None:
            current = await self.config.guild(guild).spam_punish_hours()
            await ctx.send("Current amount of hours punished on spam is %s" % current)
            return

        try:
            hours = int(amount)

            if hours < 1:
                await ctx.send("Punish hours must be more than 0.")
                return

            await self.config.guild(guild).spam_punish_hours.set(hours)
            await ctx.send("Set spam punish hours to %s" % hours)
        except ValueError:
            await ctx.send("Could not convert given hours to int. Woopsie")
            pass

    @antispamset.command(pass_context=True, no_pm=True, name="addrole")
    @checks.admin_or_permissions(manage_messages=True)
    async def addrole(self, ctx, role: discord.Role):
        """Adds a role to the exclusion list."""
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
        """Adds a channel to the exclusion list"""
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
        """Removes a role from the exclusion list"""
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
        """Removes a channel from the exclusion list"""
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
        """Checks message against spam threshold and regex. Deletes if necessary."""
        user = message.author
        guild = message.guild

        if guild is None:
            return

        # If it's the bot, return
        if user == guild.me:
            return

        content = message.content

        # Empty string so we return
        if not content.strip():
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

            is_spam = await self.check_for_spam(message)

            if is_spam is True:
                return

            if self.regex.search(message.content) is not None:
                await asyncio.sleep(0.5)
                await message.delete()

    async def check_for_spam(self, message: discord.Message):
        """Checks a members message similarity against their previous message. Punishes if necessary"""
        user = message.author
        guild = message.guild

        similarity_threshold = await self.config.guild(guild).similarity_threshold()

        last_message = await self.config.member(user).last_message()
        current_message = message.content

        if last_message is None:
            await self.config.member(user).last_message.set(current_message)
            return False

        last_message_time = await self.config.member(user).last_message_time()

        if last_message_time is None:
            await self.config.member(user).last_message_time.set(
                message.created_at.timestamp()
            )
            return False

        current_message_time = message.created_at.timestamp()
        time_difference_in_seconds = current_message_time - last_message_time

        await self.config.member(user).last_message.set(current_message)
        await self.config.member(user).last_message_time.set(current_message_time)

        if time_difference_in_seconds < 1800:
            similarity = self.similarity(last_message, message.content)

            if similarity > similarity_threshold:
                spam_count = await self.config.member(user).spam_count()
                spam_count = spam_count + 1

                spam_threshold = await self.config.guild(guild).spam_threshold()

                if spam_count > spam_threshold:
                    punish = self.bot.get_cog("Punish")
                    punish_hours = await self.config.guild(guild).spam_punish_hours()
                    async with punish.config.member(user)() as current:
                        now = time.time()
                        duration = now + 3600 * punish_hours
                        punish_role = await punish.get_role(guild, user, quiet=True)

                        if punish_role is None:
                            return

                        current["start"] = (
                            current["start"] or now
                        )  # don't override start time if updating
                        current["until"] = duration
                        current["by"] = (
                            current["by"] or guild.me.id
                        )  # don't override original moderator
                        current["reason"] = "Spamming messages"
                        current["unmute"] = False
                        current["caseno"] = None

                        await user.add_roles(punish_role)

                        await punish.schedule_unpunish(duration, user)
                        await message.channel.send(
                            "%s has been muted for 12 hours for Spamming Messages"
                            % user.name
                        )

                        # Reset spam counter since we punished
                        await self.config.member(user).spam_count.set(0)
                else:
                    await self.config.member(user).spam_count.set(spam_count)

                # We delete the message in any case
                await asyncio.sleep(0.5)
                await message.delete()

                return True

        return False
