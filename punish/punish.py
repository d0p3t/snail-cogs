import asyncio
from datetime import datetime
import discord
from collections import namedtuple
from redbot.core import Config, checks, commands
from redbot.core.bot import Red
from redbot.core.utils.chat_formatting import pagify, box, warning, error, info, bold
from redbot.core.utils.mod import is_allowed_by_hierarchy, is_admin_or_superior
import logging
import os
import re
import textwrap
import time

MockedMember = namedtuple("MockedMember", "id guild")

try:
    import tabulate
except ImportError as e:
    raise RuntimeError(
        "Punish requires tabulate. To install it, run `pip3 install tabulate` from the console or "
        "`[p]pipinstall tabulate` from in Discord."
    ) from e

log = logging.getLogger("red.punish")

try:
    from redbot.core import modlog

    ENABLE_MODLOG = True
except ImportError:
    log.warn(
        "Could not import modlog exceptions from mod cog, most likely because mod.py was deleted or Red is out of "
        "date. Modlog integration will be disabled."
    )
    ENABLE_MODLOG = False

__version__ = "3.0.1"

ACTION_STR = (
    "Timed mute \N{HOURGLASS WITH FLOWING SAND} \N{SPEAKER WITH CANCELLATION STROKE}"
)
PURGE_MESSAGES = 1  # for cpunish
PATH = "data/punish/"
JSON = PATH + "settings.json"

DEFAULT_ROLE_NAME = "Actually muted"
DEFAULT_TEXT_OVERWRITE = discord.PermissionOverwrite(
    send_messages=False, send_tts_messages=False, add_reactions=False
)
DEFAULT_VOICE_OVERWRITE = discord.PermissionOverwrite(speak=False)
DEFAULT_TIMEOUT_OVERWRITE = discord.PermissionOverwrite(
    send_messages=True, read_messages=True
)

QUEUE_TIME_CUTOFF = 30

DEFAULT_TIMEOUT = "30m"
DEFAULT_CASE_MIN_LENGTH = (
    "30m"
)  # only create modlog cases when length is longer than this

UNIT_TABLE = (
    (("weeks", "wks", "w"), 60 * 60 * 24 * 7),
    (("days", "dys", "d"), 60 * 60 * 24),
    (("hours", "hrs", "h"), 60 * 60),
    (("minutes", "mins", "m"), 60),
    (("seconds", "secs", "s"), 1),
)


class BadTimeExpr(Exception):
    pass


def _find_unit(unit):
    for names, length in UNIT_TABLE:
        if any(n.startswith(unit) for n in names):
            return names, length
    raise BadTimeExpr("Invalid unit: %s" % unit)


def _parse_time(time):
    time = time.lower()
    if not time.isdigit():
        time = re.split(r"\s*([\d.]+\s*[^\d\s,;]*)(?:[,;\s]|and)*", time)
        time = sum(map(_timespec_sec, filter(None, time)))
    return int(time)


def _timespec_sec(expr):
    atoms = re.split(r"([\d.]+)\s*([^\d\s]*)", expr)
    atoms = list(filter(None, atoms))

    if len(atoms) > 2:  # This shouldn't ever happen
        raise BadTimeExpr("invalid expression: '%s'" % expr)
    elif len(atoms) == 2:
        names, length = _find_unit(atoms[1])
        if atoms[0].count(".") > 1 or not atoms[0].replace(".", "").isdigit():
            raise BadTimeExpr("Not a number: '%s'" % atoms[0])
    else:
        names, length = _find_unit("seconds")

    try:
        return float(atoms[0]) * length
    except ValueError:
        raise BadTimeExpr("invalid value: '%s'" % atoms[0])


def _generate_timespec(sec: int, short=False, micro=False) -> str:
    timespec = []
    sec = int(sec)
    neg = sec < 0
    sec = abs(sec)

    for names, length in UNIT_TABLE:
        n, sec = divmod(sec, length)

        if n:
            if micro:
                s = "%d%s" % (n, names[2])
            elif short:
                s = "%d%s" % (n, names[1])
            else:
                s = "%d %s" % (n, names[0])
            if n <= 1 and not (micro and names[2] == "s"):
                s = s.rstrip("s")

            timespec.append(s)

    if len(timespec) > 1:
        if micro:
            spec = "".join(timespec)

        segments = timespec[:-1], timespec[-1:]
        spec = " and ".join(", ".join(x) for x in segments)
    elif timespec:
        spec = timespec[0]
    else:
        return "0"

    if neg:
        spec += " ago"

    return spec


def format_list(*items, join="and", delim=", "):
    if len(items) > 1:
        return (" %s " % join).join((delim.join(items[:-1]), items[-1]))
    elif items:
        return items[0]
    else:
        return ""


def permissions_for_roles(channel, *roles):
    """
    Calculates the effective permissions for a role or combination of roles.
    Naturally, if no roles are given, the default role's permissions are used
    """
    default = guildChannel.guild.default_role
    base = discord.Permissions(default.permissions.value)

    # Apply all role values
    for role in roles:
        base.value |= role.permissions.value

    # Server-wide Administrator -> True for everything
    # Bypass all channel-specific overrides
    if base.administrator:
        return discord.Permissions.all()

    role_ids = set(map(lambda r: r.id, roles))
    denies = 0
    allows = 0

    # Apply channel specific role permission overwrites
    for overwrite in channel._permission_overwrites:
        # Handle default role first, if present
        if overwrite.id == default.id:
            base.handle_overwrite(allow=overwrite.allow, deny=overwrite.deny)

        if overwrite.type == "role" and overwrite.id in role_ids:
            denies |= overwrite.deny
            allows |= overwrite.allow

    base.handle_overwrite(allow=allows, deny=denies)

    # default channels can always be read
    if channel.is_default:
        base.read_messages = True

    # if you can't send a message in a channel then you can't have certain
    # permissions as well
    if not base.send_messages:
        base.send_tts_messages = False
        base.mention_everyone = False
        base.embed_links = False
        base.attach_files = False

    # if you can't read a channel then you have no permissions there
    if not base.read_messages:
        denied = discord.Permissions.all_channel()
        base.value &= ~denied.value

    # text channels do not have voice related permissions
    if channel.type is discord.ChannelType.text:
        denied = discord.Permissions.voice()
        base.value &= ~denied.value

    return base


def overwrite_from_dict(data):
    allow = discord.Permissions(data.get("allow", 0))
    deny = discord.Permissions(data.get("deny", 0))
    return discord.PermissionOverwrite.from_pair(allow, deny)


def overwrite_to_dict(overwrite):
    allow, deny = overwrite.pair()
    return {"allow": allow.value, "deny": deny.value}


def format_permissions(permissions, include_null=False):
    entries = []

    for perm, value in sorted(permissions, key=lambda t: t[0]):
        if value is True:
            symbol = "\N{WHITE HEAVY CHECK MARK}"
        elif value is False:
            symbol = "\N{NO ENTRY SIGN}"
        elif include_null:
            symbol = "\N{RADIO BUTTON}"
        else:
            continue

        entries.append(
            symbol + " " + perm.replace("_", " ").title().replace("Tts", "TTS")
        )

    if entries:
        return "\n".join(entries)
    else:
        return "No permission entries."


def getmname(mid, server):
    member = discord.utils.get(server.members, id=mid)

    if member:
        return str(member)
    else:
        return "(absent user #%s)" % mid


class Punish(commands.Cog):
    """
    Put misbehaving users in timeout where they are unable to speak, read, or
    do other things that can be denied using discord permissions. Includes
    auto-setup and more.
    """

    default_guild = {
        "role_id": None,
        "channel_id": None,
        "case_min_length": _parse_time(DEFAULT_CASE_MIN_LENGTH),
        "TEXT_OVERWRITE": None,
        "VOICE_OVERWRITE": None,
        "PENDING_UNMUTE": [],
    }

    default_member = {
        "start": 0,
        "until": 0,
        "reason": None,
        "by": None,
        "caseno": 0,
        "unmute": False,
    }

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(
            self, identifier=4579024764
        )  # identifier is a random number

        self.config.register_guild(**self.default_guild)
        self.config.register_member(**self.default_member)

        # queue variables
        self.queue = asyncio.PriorityQueue(loop=bot.loop)
        self.queue_lock = asyncio.Lock(loop=bot.loop)
        self.pending = {}
        self.enqueued = set()

        self.task = self.bot.loop.create_task(self.on_load())
        self.bot.loop.create_task(self._register_casetype())

    @staticmethod
    async def _register_casetype():
        casetype = {
            "name": "punish",
            "default_setting": True,
            "image": "\N{SPEAKER WITH CANCELLATION STROKE}",
            "case_str": ACTION_STR,
        }
        try:
            await modlog.register_casetype(**casetype)
        except RuntimeError:
            pass

    async def __unload(self):
        await self.task.cancel()

    @commands.group(pass_context=True, invoke_without_command=True, no_pm=True)
    @checks.mod_or_permissions(manage_messages=True)
    async def punish(
        self, ctx, user: discord.Member, duration: str = None, *, reason: str = None
    ):
        if ctx.invoked_subcommand:
            return
        elif user:
            await ctx.invoke(
                self.punish_start, user=user, duration=duration, reason=reason
            )
        else:
            await self.bot.send_cmd_help(ctx)

    @punish.command(pass_context=True, no_pm=True, name="start")
    @checks.mod_or_permissions(manage_messages=True)
    async def punish_start(
        self, ctx, user: discord.Member, duration: str = None, *, reason: str = None
    ):
        """
        Puts a user into timeout for a specified time, with optional reason.

        Time specification is any combination of number with the units s,m,h,d,w.
        Example: !punish @idiot 1.1h10m Enough bitching already!
        """

        await self._punish_cmd_common(ctx, user, duration, reason)

    @punish.command(pass_context=True, no_pm=True, name="cstart")
    @checks.mod_or_permissions(manage_messages=True)
    async def punish_cstart(
        self, ctx, user: discord.Member, duration: str = None, *, reason: str = None
    ):
        """
        Same as [p]punish start, but cleans up the target's last message.
        """

        success = await self._punish_cmd_common(ctx, user, duration, reason, quiet=True)

        if not success:
            return

        def check(m):
            return m.id == ctx.message.id or m.author == user

        try:
            await ctx.message.channel.purge(limit=PURGE_MESSAGES + 1, check=check)
        except discord.errors.Forbidden:
            await ctx.send(
                "Punishment set, but I need permissions to manage messages to clean up."
            )

    @punish.command(pass_context=True, no_pm=True, name="list")
    @checks.mod_or_permissions(manage_messages=True)
    async def punish_list(self, ctx, user: discord.Member = None):
        """
        Shows a table of punished users with time, mod and reason.

        Displays punished users, time remaining, responsible moderator and
        the reason for punishment, if any.
        """

        server = ctx.guild
        server_id = server.id
        table = []
        now = time.time()
        headers = ["Member", "Remaining", "Moderator", "Reason"]
        msg = ""

        # Multiline cell/header support was added in 0.8.0
        if tabulate.__version__ >= "0.8.0":
            headers = [";\n".join(headers[i::2]) for i in (0, 1)]
        else:
            msg += warning(
                "Compact formatting is only supported with tabulate v0.8.0+ (currently v%s). "
                "Please update it.\n\n" % tabulate.__version__
            )

        members = await self.config.all_members(server)

        if user:
            if user.id in members:
                data = members[user.id]
                member_name = getmname(user.id, server)
                moderator = getmname(data["by"], server)
                reason = data["reason"]
                until = data["until"]
                sort = until or float("inf")
                remaining = (
                    _generate_timespec(until - now, short=True) if until else "forever"
                )
                row = [member_name, remaining, moderator, reason or "No reason set."]

                if tabulate.__version__ >= "0.8.0":
                    row[-1] = textwrap.fill(row[-1], 35)
                    row = [";\n".join(row[i::2]) for i in (0, 1)]

                table.append((sort, row))
        else:
            for member_id in members.keys():
                if not isinstance(member_id, int):
                    continue

                data = members[member_id]
                member_name = getmname(member_id, server)
                moderator = getmname(data["by"], server)
                reason = data["reason"]
                until = data["until"]
                sort = until or float("inf")

                remaining = (
                    _generate_timespec(until - now, short=True) if until else "forever"
                )

                row = [member_name, remaining, moderator, reason or "No reason set."]

                if tabulate.__version__ >= "0.8.0":
                    row[-1] = textwrap.fill(row[-1], 35)
                    row = [";\n".join(row[i::2]) for i in (0, 1)]

                table.append((sort, row))

        if not table:
            if user:
                await ctx.send("User is currently not punished.")
            else:
                await ctx.send("No users are currently punished.")
            return

        table.sort()
        msg += tabulate.tabulate([k[1] for k in table], headers, tablefmt="grid")

        for page in pagify(msg):
            await ctx.send(box(page))

    @punish.command(pass_context=True, no_pm=True, name="clean")
    @checks.mod_or_permissions(manage_messages=True)
    async def punish_clean(self, ctx, clean_pending: bool = False):
        """
        Removes absent members from the punished list.

        If run without an argument, it only removes members who are no longer
        present but whose timer has expired. If the argument is 'yes', 1,
        or another trueish value, it will also remove absent members whose
        timers have yet to expire.

        Use this option with care, as removing them will prevent the punished
        role from being re-added if they rejoin before their timer expires.
        """

        count = 0
        now = time.time()
        server = ctx.guild
        data = await self.config.all_members(server)

        for mid, mdata in data.copy().items():
            if not isinstance(mid, int) or server.get_member(mid):
                continue
            elif clean_pending or ((data[mid]["until"] or 0) < now):
                member = MockedMember(mid, server)
                await self.config.member(member).clear()
                count += 1

        await ctx.send("Cleaned %i absent members from the list." % count)

    @punish.command(pass_context=True, no_pm=True, name="warn")
    @checks.mod_or_permissions(manage_messages=True)
    async def punish_warn(self, ctx, user: discord.Member, *, reason: str = None):
        """
        Warns a user with boilerplate about the rules
        """

        msg = ["Hey %s, " % user.mention]
        msg.append(
            "you're doing something that might get you muted if you keep " "doing it."
        )
        if reason:
            msg.append(" Specifically, %s." % reason)

        msg.append("Be sure to review the server rules in #start-here.")
        await ctx.send(" ".join(msg))

    @punish.command(pass_context=True, no_pm=True, name="end", aliases=["remove"])
    @checks.mod_or_permissions(manage_messages=True)
    async def punish_end(self, ctx, user: discord.Member, *, reason: str = None):
        """
        Removes punishment from a user before time has expired

        This is the same as removing the role directly.
        """

        role = await self.get_role(user.guild, ctx, quiet=True)
        sid = user.guild.id
        now = time.time()
        async with self.config.member(user)() as data:
            if role and role in user.roles:
                msg = "Punishment manually ended early by %s." % ctx.message.author

                original_start = data["start"]
                original_end = data["until"]
                remaining = original_end and (original_end - now)

                if remaining:
                    msg += " %s was left" % _generate_timespec(round(remaining))

                    if original_start:
                        msg += " of the original %s." % _generate_timespec(
                            round(original_end - original_start)
                        )
                    else:
                        msg += "."

                if reason:
                    msg += "\n\nReason for ending early: " + reason

                if data["reason"] is not None:
                    msg += "\n\nOriginal reason was: " + data["reason"]

                if not await self._unpunish(user, msg, update=True):
                    msg += "\n\n(failed to send punishment end notification DM)"

                await ctx.send(msg)
            elif data:  # This shouldn't happen, but just in case
                now = time.time()
                until = data["until"]
                remaining = (
                    until and _generate_timespec(round(until - now)) or "forever"
                )

                data_fmt = "\n".join(
                    [
                        "**Reason:** %s" % (data["reason"] or "no reason set"),
                        "**Time remaining:** %s" % remaining,
                        "**Moderator**: %s"
                        % (
                            user.guild.get_member(data["by"])
                            or "Missing ID#%s" % data["by"]
                        ),
                    ]
                )
                await self.config.member(user).clear()
                # self.data[sid].pop(user.id, None)
                # await self.save_data()
                await ctx.send(
                    "That user doesn't have the %s role, but they still have a data entry. I removed it, "
                    "but in case it's needed, this is what was there:\n\n%s"
                    % (role.name, data_fmt)
                )
            elif role:
                await ctx.send("That user doesn't have the %s role." % role.name)
            else:
                await ctx.send("The punish role couldn't be found in this server.")

    @punish.command(pass_context=True, no_pm=True, name="reason")
    @checks.mod_or_permissions(manage_messages=True)
    async def punish_reason(self, ctx, user: discord.Member, *, reason: str = None):
        """
        Updates the reason for a punishment, including the modlog if a case exists.
        """
        server = ctx.message.guild

        async with self.config.member(user)() as data:
            if not data:
                await ctx.send(
                    "That user doesn't have an active punishment entry. To update modlog "
                    "cases manually, use the `%sreason` command." % ctx.prefix
                )
                return

            data["reason"] = reason
            if reason:
                msg = "Reason updated."
            else:
                msg = "Reason cleared"

            caseno = data.get("caseno")

            if caseno and ENABLE_MODLOG:
                moderator = ctx.message.author
                case_error = None

                try:
                    if moderator.id != data["by"] and not await is_admin_or_superior(
                        self.bot, moderator
                    ):
                        moderator = (
                            server.get_member(data["by"]) or server.me
                        )  # fallback gracefully

                    case = await modlog.get_case(caseno, server, self.bot)
                    await case.edit({reason: reason, mod: moderator})
                except RuntimeError:
                    case_error = "the case message could not be found"
                except Exception:
                    pass

                if case_error:
                    msg += "\n\n" + warning(
                        "There was an error updating the modlog case: %s." % case_error
                    )

            await ctx.send(msg)

    @commands.group(pass_context=True, invoke_without_command=True, no_pm=True)
    @checks.admin_or_permissions(administrator=True)
    async def punishset(self, ctx):
        if ctx.invoked_subcommand is None:
            await self.bot.send_cmd_help(ctx)

    @punishset.command(pass_context=True, no_pm=True, name="setup")
    async def punishset_setup(self, ctx):
        """
        (Re)configures the punish role and channel overrides
        """
        server = ctx.message.guild
        default_name = DEFAULT_ROLE_NAME
        # role_id = self.data.get(server.id, {}).get('ROLE_ID')
        role_id = await self.config.guild(server).role_id()

        if role_id:
            role = discord.utils.get(server.roles, id=role_id)
        else:
            role = discord.utils.get(server.roles, name=default_name)

        perms = server.me.guild_permissions
        if not perms.manage_roles and perms.manage_channels:
            await ctx.send(
                "I need the Manage Roles and Manage Channels permissions for that command to work."
            )
            return

        if not role:
            msg = "The %s role doesn't exist; Creating it now... " % default_name

            msgobj = await ctx.send(msg)

            perms = discord.Permissions.none()
            role = await server.create_role(
                server, name=default_name, permissions=perms
            )
        else:
            msgobj = await ctx.send("%s role exists... " % role.name)

        if role.position != (server.me.top_role.position - 1):
            if role < server.me.top_role:
                msgobj = msgobj.edit(
                    msgobj.content + "moving role to higher position... "
                )
                await role.edit(position=server.me.top_role.position - 1)
            else:
                await msgobj.edit(
                    msgobj.content + "role is too high to manage."
                    " Please move it to below my highest role."
                )
                return

        msgobj = await msgobj.edit(msgobj.content + "(re)configuring channels... ")

        for channel in server.channels:
            await self.setup_channel(channel, role)

        await msgobj.edit(msgobj.content + "done.")

        if role and role.id != role_id:
            await self.config.guild(server).role_id.set(role.id)

    @punishset.command(pass_context=True, no_pm=True, name="channel")
    async def punishset_channel(self, ctx, channel: discord.channel = None):
        """
        Sets or shows the punishment "timeout" channel.

        This channel has special settings to allow punished users to discuss their
        infraction(s) with moderators.

        If there is a role deny on the channel for the punish role, it is
        automatically set to allow. If the default permissions don't allow the
        punished role to see or speak in it, an overwrite is created to allow
        them to do so.
        """
        server = ctx.message.guild
        current = await self.config.guild(server).channel_id()
        current = current and server.get_channel(current)

        if channel is None:
            if not current:
                await ctx.send("No timeout channel has been set.")
            else:
                await ctx.send("The timeout channel is currently %s." % current.mention)
        else:
            if current == channel:
                await ctx.send(
                    "The timeout channel is already %s. If you need to repair its permissions, use "
                    "`%spunishset setup`." % (current.mention, ctx.prefix)
                )
                return

            await self.config.guild(server).channel_id.set(channel.id)

            role = await self.get_role(server, ctx, create=True)
            update_msg = "{} to the %s role" % role
            grants = []
            denies = []
            perms = permissions_for_roles(channel, role)
            overwrite = channel.overwrites_for(role) or discord.PermissionOverwrite()

            for perm, value in DEFAULT_TIMEOUT_OVERWRITE:
                if value is None:
                    continue

                if getattr(perms, perm) != value:
                    setattr(overwrite, perm, value)
                    name = perm.replace("_", " ").title().replace("Tts", "TTS")

                    if value:
                        grants.append(name)
                    else:
                        denies.append(name)

            # Any changes made? Apply them.
            if grants or denies:
                grants = grants and ("grant " + format_list(*grants))
                denies = denies and ("deny " + format_list(*denies))
                to_join = [x for x in (grants, denies) if x]
                update_msg = update_msg.format(format_list(*to_join))

                if current and current.id != channel.id:
                    if current.permissions_for(server.me).manage_roles:
                        msg = info(
                            "Resetting permissions in the old channel (%s) to the default..."
                        )
                    else:
                        msg = error(
                            "I don't have permissions to reset permissions in the old channel (%s)"
                        )

                    await ctx.send(msg % current.mention)
                    await self.setup_channel(current, role)

                if channel.permissions_for(server.me).manage_roles:
                    await ctx.send(
                        info(
                            "Updating permissions in %s to %s..."
                            % (channel.mention, update_msg)
                        )
                    )
                    await channel.set_permissions(role, overwrite)
                else:
                    await ctx.send(
                        error("I don't have permissions to %s." % update_msg)
                    )

            await ctx.send("Timeout channel set to %s." % channel.mention)

    @punishset.command(pass_context=True, no_pm=True, name="clear-channel")
    async def punishset_clear_channel(self, ctx):
        """
        Clears the timeout channel and resets its permissions
        """
        server = ctx.message.guild
        current = await self.config.guild(server).channel_id()
        current = current and server.get_channel(current)

        if current:
            msg = None
            await self.config.guild(server).channel_id.set(None)

            if current.permissions_for(server.me).manage_roles:
                role = await self.get_role(server, ctx, quiet=True)
                await self.setup_channel(current, role)
                msg = " and its permissions reset"
            else:
                msg = ", but I don't have permissions to reset its permissions."

            await ctx.send("Timeout channel has been cleared%s." % msg)
        else:
            await ctx.send("No timeout channel has been set yet.")

    @punishset.command(pass_context=True, allow_dm=False, name="case-min")
    async def punishset_case_min(self, ctx, *, timespec: str = None):
        """
        Set/disable or display the minimum punishment case duration

        If the punishment duration is less than this value, a case will not be created.
        Specify 'disable' to turn off case creation altogether.
        """
        server = ctx.message.guild
        current = await self.config.guild(server).case_min_length()

        if not timespec:
            if current:
                await ctx.send(
                    "Punishments longer than %s will create cases."
                    % _generate_timespec(current)
                )
            else:
                await ctx.send("Punishment case creation is disabled.")
        else:
            if timespec.strip("'\"").lower() == "disable":
                value = None
            else:
                try:
                    value = _parse_time(timespec)
                except BadTimeExpr as e:
                    await ctx.send(error(e.args[0]))
                    return

            await self.config.guild(server).case_min_length.set(value)

    @punishset.command(pass_context=True, no_pm=True, name="overrides")
    async def punishset_overrides(self, ctx, *, channel: discord.channel = None):
        """
        Copy or display the punish role overrides

        If a channel is specified, the allow/deny settings for it are saved
        and applied to new channels when they are created. To apply the new
        settings to existing channels, use [p]punishset setup.

        An important caveat: voice channel and text channel overrides are
        configured separately! To set the overrides for a channel type,
        specify the name of or mention a channel of that type.
        """

        server = ctx.message.guild
        async with self.config.guild(server)() as settings:
            role = await self.get_role(server, ctx, quiet=True)
            timeout_channel_id = settings["channel_id"]
            confirm_msg = None

            if not role:
                await ctx.send(
                    error(
                        "Punish role has not been created yet. Run `%spunishset setup` first."
                        % ctx.prefix
                    )
                )
                return

            if channel:
                overwrite = channel.overwrites_for(role)
                if channel.id == timeout_channel_id:
                    confirm_msg = "Are you sure you want to copy overrides from the timeout channel?"
                elif overwrite is None:
                    overwrite = discord.PermissionOverwrite()
                    confirm_msg = "Are you sure you want to copy blank (no permissions set) overrides?"

                if channel.type is discord.ChannelType.text:
                    key = "text"
                elif channel.type is discord.ChannelType.voice:
                    key = "voice"
                else:
                    await ctx.send(error("Unknown channel type!"))
                    return

                if confirm_msg:
                    await ctx.send(
                        warning(confirm_msg + "(reply `yes` within 30s to confirm)")
                    )
                    reply = await self.bot.wait_for_message(
                        channel=ctx.message.channel,
                        author=ctx.message.author,
                        timeout=30,
                    )

                    if reply is None:
                        await ctx.send("Timed out waiting for a response.")
                        return
                    elif reply.content.strip(" `\"'").lower() != "yes":
                        await ctx.send("Commmand cancelled.")
                        return

                settings[key.upper() + "_OVERWRITE"] = overwrite_to_dict(overwrite)
                await ctx.send(
                    "{} channel overrides set to:\n".format(key.title())
                    + format_permissions(overwrite)
                    + "\n\nRun `%spunishset setup` to apply them to all channels."
                    % ctx.prefix
                )

            else:
                msg = []
                for key, default in [
                    ("text", DEFAULT_TEXT_OVERWRITE),
                    ("voice", DEFAULT_VOICE_OVERWRITE),
                ]:
                    data = settings[key.upper() + "_OVERWRITE"]
                    title = "%s permission overrides:" % key.title()

                    if not data:
                        data = overwrite_to_dict(default)
                        title = title[:-1] + " (defaults):"

                    msg.append(
                        bold(title)
                        + "\n"
                        + format_permissions(overwrite_from_dict(data))
                    )

                await ctx.send("\n\n".join(msg))

    @punishset.command(pass_context=True, no_pm=True, name="reset-overrides")
    async def punishset_reset_overrides(self, ctx, channel_type: str = "both"):
        """
        Resets the punish role overrides for text, voice or both (default)

        This command exists in case you want to restore the default settings
        for newly created channels.
        """
        async with self.config.guild(ctx.message.guild)() as settings:
            channel_type = channel_type.strip("`\"' ").lower()

            msg = []
            for key, default in [
                ("text", DEFAULT_TEXT_OVERWRITE),
                ("voice", DEFAULT_VOICE_OVERWRITE),
            ]:
                if channel_type not in ["both", key]:
                    continue

                # settings.pop(key.upper() + '_OVERWRITE', None) # Not too sure about this
                settings[key.upper() + "_OVERWRITE"] = default
                title = "%s permission overrides reset to:" % key.title()
                msg.append(bold(title) + "\n" + format_permissions(default))

            if not msg:
                await ctx.send(
                    "Invalid channel type. Use `text`, `voice`, or `both` (the default, if not specified)"
                )
                return

            msg.append(
                "Run `%spunishset setup` to apply them to all channels." % ctx.prefix
            )

            await ctx.send("\n\n".join(msg))

    async def get_role(self, server, ctx, quiet=False, create=False):
        default_name = DEFAULT_ROLE_NAME
        role_id = await self.config.guild(server).role_id()

        if role_id:
            role = discord.utils.get(server.roles, id=role_id)
        else:
            role = discord.utils.get(server.roles, name=default_name)

        if create and not role:
            perms = server.me.guild_permissions
            if not perms.manage_roles and perms.manage_channels:
                await ctx.send(
                    "The Manage Roles and Manage Channels permissions are required to use this command."
                )
                return

            else:
                msg = "The %s role doesn't exist; Creating it now..." % default_name

                if not quiet:
                    msgobj = await ctx.send(msg)

                log.debug("Creating punish role in %s" % server.name)
                perms = discord.Permissions.none()
                role = await server.create_role(name=default_name, permissions=perms)
                await role.edit(position=server.me.top_role.position - 1)

                if not quiet:
                    await msgobj.edit(
                        content=msgobj.content + "configuring channels... "
                    )

                for channel in server.channels:
                    await self.setup_channel(channel, role)

                if not quiet:
                    await msgobj.edit(content=msgobj.content + "done.")

        if role and role.id != role_id:
            await self.config.guild(server).role_id.set(role.id)

        return role

    async def setup_channel(self, channel, role):
        async with self.config.guild(channel.guild)() as settings:
            timeout_channel_id = settings["channel_id"]

            if channel.id == timeout_channel_id:
                # maybe this will be used later:
                # config = settings.get('TIMEOUT_OVERWRITE')
                config = None
                defaults = DEFAULT_TIMEOUT_OVERWRITE
            elif isinstance(channel, discord.VoiceChannel):
                config = settings["VOICE_OVERWRITE"]
                defaults = DEFAULT_VOICE_OVERWRITE
            else:
                config = settings["TEXT_OVERWRITE"]
                defaults = DEFAULT_TEXT_OVERWRITE

            if config:
                perms = overwrite_from_dict(config)
            else:
                perms = defaults

            await channel.set_permissions(role, overwrite=perms)

    async def on_load(self):
        await self.bot.wait_until_ready()

        members_dict = await self.config.all_members()

        for guild_id in members_dict.keys():
            guild = self.bot.get_guild(guild_id)

            if not guild:
                members_dict[guild_id].clear()
                continue

            me = guild.me

            role = await self.get_role(guild, me, quiet=True, create=True)

            if not role:
                log.error(
                    "Needed to create punish role in %s, but couldn't." % guild.name
                )
                continue

            for member_id in members_dict[guild_id].keys():
                if not isinstance(member_id, int):
                    continue

                data = members_dict[guild_id][member_id]

                until = data["until"]
                member = guild.get_member(member_id)

                if until and (until - time.time()) < 0:
                    if member:
                        reason = (
                            "Punishment removal overdue, maybe the bot was offline. "
                        )
                        current_reason = data["reason"]
                        if current_reason:
                            reason += current_reason

                        await self._unpunish(member, reason)
                    else:  # member disappeared
                        del members_dict[guild_id][member_id]
                elif member:
                    if role not in member.roles:
                        if role >= me.top_role:
                            log.error(
                                "Needed to re-add punish role to %s in %s, but couldn't."
                                % (member, guild.name)
                            )
                            continue

                        await member.add_roles(role)

                    if until:
                        await self.schedule_unpunish(until, member)

        while True:
            try:
                async with self.queue_lock:
                    while await self.process_queue_event():
                        pass

                await asyncio.sleep(5)

            except asyncio.CancelledError:
                break
            except Exception:
                pass

        log.debug("queue manager dying")

        while not self.queue.empty():
            self.queue.get_nowait()

        for fut in self.pending.values():
            fut.cancel()

    async def cancel_queue_event(self, *args) -> bool:
        if args in self.pending:
            self.pending.pop(args).cancel()
            return True
        else:
            events = []
            removed = None

            async with self.queue_lock:
                while not self.queue.empty():
                    item = self.queue.get_nowait()

                    if args == item[1:]:
                        removed = item
                        break
                    else:
                        events.append(item)

                for item in events:
                    self.queue.put_nowait(item)

            return removed is not None

    async def put_queue_event(self, run_at: float, *args):
        diff = run_at - time.time()

        if args in self.enqueued:
            return False

        self.enqueued.add(args)

        if diff < 0:
            self.execute_queue_event(*args)
        elif run_at - time.time() < QUEUE_TIME_CUTOFF:
            self.pending[args] = self.bot.loop.call_later(
                diff, self.execute_queue_event, *args
            )
        else:
            await self.queue.put((run_at, *args))

    async def process_queue_event(self):
        if self.queue.empty():
            return False

        now = time.time()
        item = await self.queue.get()
        next_time, *args = item

        diff = next_time - now

        if diff < 0:
            if self.execute_queue_event(*args):
                return True
        elif diff < QUEUE_TIME_CUTOFF:
            self.pending[args] = self.bot.loop.call_later(
                diff, self.execute_queue_event, *args
            )
            return True

        await self.queue.put(item)
        return False

    def execute_queue_event(self, *args) -> bool:
        self.enqueued.discard(args)

        try:
            return self.execute_unpunish(*args)
        except Exception:
            log.exception("failed to execute scheduled event")

    async def _punish_cmd_common(self, ctx, member, duration, reason, quiet=False):
        server = ctx.message.guild
        using_default = False
        updating_case = False
        case_error = None

        async with self.config.member(member)() as current:
            reason = reason or current["reason"]  # don't clear if not given
            hierarchy_allowed = ctx.message.author.top_role > member.top_role
            case_min_length = await self.config.guild(server).case_min_length()

            if ENABLE_MODLOG:
                hierarchy_allowed = await is_allowed_by_hierarchy(
                    self.bot, self.config, server, ctx.message.author, member
                )

            if not hierarchy_allowed:
                await ctx.send("Permission denied due to role hierarchy.")
                return
            elif member == server.me:
                await ctx.send("You can't punish the bot.")
                return

            if duration and duration.lower() in ["forever", "inf", "infinite"]:
                duration = None
            else:
                if not duration:
                    using_default = True
                    duration = DEFAULT_TIMEOUT

                try:
                    duration = _parse_time(duration)
                    if duration < 1:
                        await ctx.send("Duration must be 1 second or longer.")
                        return False
                except BadTimeExpr as e:
                    await ctx.send("Error parsing duration: %s." % e.args)
                    return False

            role = await self.get_role(server, ctx, quiet=quiet, create=True)
            if role is None:
                return

            if role >= server.me.top_role:
                await ctx.send("The %s role is too high for me to manage." % role)
                return

            # Call time() after getting the role due to potential creation delay
            now = time.time()
            until = (now + duration + 0.5) if duration else None
            duration_ok = (case_min_length is not None) and (
                (duration is None) or duration >= case_min_length
            )

            if duration_ok and ENABLE_MODLOG:
                mod_until = until and datetime.utcfromtimestamp(until)

                try:
                    if current["caseno"]:
                        case_number = current["caseno"]
                        moderator = ctx.message.author
                        updating_case = True

                        # update_case does ownership checks, we need to cheat them in case the
                        # command author doesn't qualify to edit a case
                        if moderator.id != current[
                            "by"
                        ] and not await is_admin_or_superior(self.bot, moderator):
                            moderator = (
                                server.get_member(current["by"]) or server.me
                            )  # fallback gracefully

                        case = await modlog.get_case(case_number, server, self.bot)
                        modify = {
                            "reason": reason,
                            "mod": moderator,
                            "until": mod_until and mod_until.timestamp() or False
                        }
                        await case.edit(modify)
                    else:
                        case_number = await modlog.create_case(
                            ctx.bot,
                            server,
                            ctx.message.created_at,
                            ACTION_STR,
                            member,
                            ctx.message.author,
                            reason,
                            mod_until,
                            ctx.message.channel
                        )
                except Exception as e:
                    log.error(e)
                    case_error = e
            else:
                case_number = None

            subject = "the %s role" % role.name
            members = await self.config.all_members(server)

            if member.id in members.keys():
                if role in member.roles:
                    msg = "{0} already had the {1.name} role; resetting their timer."
                else:
                    msg = "{0} is missing the {1.name} role for some reason. I added it and reset their timer."
            elif role in member.roles:
                msg = "{0} already had the {1.name} role, but had no timer; setting it now."
            else:
                msg = "Applied the {1.name} role to {0}."
                subject = "it"

            msg = msg.format(member.mention, role)

            if duration:
                timespec = _generate_timespec(duration)

                if using_default:
                    timespec += " (the default)"

                msg += " I will remove %s in %s." % (subject, timespec)

            if duration_ok and not ENABLE_MODLOG:
                msg += "\n\n" + warning(
                    "If you can, please update the bot so I can create modlog cases."
                )
            elif case_error and ENABLE_MODLOG:
                if isinstance(case_error, RuntimeError):
                    case_error = "the case message could not be found"
                else:
                    case_error = None

                if case_error:
                    verb = "updating" if updating_case else "creating"
                    msg += "\n\n" + warning(
                        "There was an error %s the modlog case: %s."
                        % (verb, case_error)
                    )
            elif case_number:
                verb = "updated" if updating_case else "created"
                msg += " I also %s case #%i in the modlog." % (verb, case_number)

            voice_overwrite = await self.config.guild(server).VOICE_OVERWRITE()

            if voice_overwrite:
                voice_overwrite = overwrite_from_dict(voice_overwrite)
            else:
                voice_overwrite = DEFAULT_VOICE_OVERWRITE

            overwrite_denies_speak = (voice_overwrite.speak is False) or (
                voice_overwrite.connect is False
            )

            current["start"] = (
                current["start"] or now
            )  # don't override start time if updating
            current["until"] = until
            current["by"] = (
                current["by"] or ctx.message.author.id
            )  # don't override original moderator
            current["reason"] = reason
            current["unmute"] = (
                overwrite_denies_speak
                and member.voice is not None
                and not member.voice.mute
            )
            current["caseno"] = case_number

            await member.add_roles(role)

            if (
                member.voice is not None
                and member.voice.channel
                and overwrite_denies_speak
            ):
                await member.edit(mute=True)

            # schedule callback for role removal
            if until:
                await self.schedule_unpunish(until, member)

            if not quiet:
                await ctx.send(msg)

            return True

    # Functions related to unpunishing

    async def schedule_unpunish(self, until, member):
        """
        Schedules role removal, canceling and removing existing tasks if present
        """

        await self.put_queue_event(until, member.guild.id, member.id)

    def execute_unpunish(self, server_id, member_id) -> bool:
        server = self.bot.get_guild(server_id)

        if not server:
            return False

        member = server.get_member(member_id)

        if member:
            self.bot.loop.create_task(self._unpunish(member))
            return True
        else:
            self.bot.loop.create_task(self.bot.request_offline_members(server))
            return False

    async def _unpunish(
        self, member, reason=None, remove_role=True, update=False, moderator=None
    ) -> bool:
        """
        Remove punish role, delete record and task handle
        """
        server = member.guild
        role = await self.get_role(server, member, quiet=True)

        if role:
            async with self.config.guild(member.guild)() as data:
                async with self.config.member(member)() as member_data:
                    caseno = member_data["caseno"]

                    # Has to be done first to prevent triggering listeners
                    await self._unpunish_data(member)
                    await self.cancel_queue_event(member.guild.id, member.id)

                    if remove_role:
                        await member.remove_roles(role)

                    if update and caseno and mod:
                        until = member_data["until"] or False

                        if until:
                            until = datetime.utcfromtimestamp(until).timestamp()

                        if (
                            moderator
                            and moderator.id != member_data["by"]
                            and not await is_admin_or_superior(self.bot, moderator)
                        ):
                            moderator = None

                        # fallback gracefully
                        moderator = (
                            moderator
                            or server.get_member(member_data["by"])
                            or server.me
                        )

                        try:
                            case = await modlog.get_case(caseno, server, self.bot)
                            await case.edit({"reason": reason, mod: moderator, until: until})
                        except Exception:
                            pass

                    if member_data["unmute"]:
                        if member.voice.channel:
                            await member.edit(mute=False)
                        else:
                            unmute_list = data["PENDING_UNMUTE"]

                            if member.id not in unmute_list:
                                unmute_list.append(member.id)

                    msg = "Your punishment in %s has ended." % member.guild.name

                    if reason:
                        msg += "\nReason: %s" % reason

                    try:
                        await member.send(msg)
                        return True
                    except Exception:
                        return False

    async def _unpunish_data(self, member):
        """Removes punish data entry and cancels any present callback"""
        await self.config.member(member).clear()

    # Listeners
    @commands.Cog.listener()
    async def on_channel_create(self, channel):
        """Run when new channels are created and set up role permissions"""
        if channel.is_private:
            return

        role = await self.get_role(channel.guild, ctx, quiet=True)
        if not role:
            return

        await self.setup_channel(channel, role)

    @commands.Cog.listener()
    async def on_member_update(self, before, after):
        """Remove scheduled unpunish when manually removed"""
        async with self.config.member(before)() as member_data:
            role = await self.get_role(before.guild, before, quiet=True)
            if role and role in before.roles and role not in after.roles:
                msg = "Punishment manually ended early by a moderator/admin."
                if member_data["reason"]:
                    msg += "\nReason was: " + member_data["reason"]

                await self._unpunish(after, msg, remove_role=False, update=True)

    @commands.Cog.listener()
    async def on_member_join(self, member):
        """Restore punishment if punished user leaves/rejoins"""
        role = await self.get_role(member.guild, member, quiet=True)

        async with self.config.member(member)() as data:
            if not role or data is None:
                return

            until = data["until"]
            duration = until - time.time()
            if duration > 0:
                await member.add_roles(role)
                await self.schedule_unpunish(until, member)
