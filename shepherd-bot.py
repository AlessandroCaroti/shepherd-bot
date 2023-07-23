#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import re
from typing import List
import requests, os, json

from telegram import (InlineKeyboardButton, Bot,
                      InlineKeyboardMarkup, Update)
from telegram.ext import (Updater,
                          CommandHandler,
                          CallbackQueryHandler, CallbackContext, 
                          ContextTypes, ApplicationBuilder)
# from telegram.utils.request import Request
# from telegram.request import BaseRequest as Request

import requests, asyncio
from paramiko.ssh_exception import (SSHException)

import version
import config.config as config
import lib.wol as wol
import lib.sshcontrol as ssh_control
import lib.permission as perm
from lib.storage import (read_machines_file, read_commands_file)
from lib.types import Machine
from lib.utils import (find_by_name, check_ssh_setup, ping_server)
from lib.commands import (execute_command)

logging.basicConfig(
    format=config.LOG_FORMAT,
    level=config.LOG_LEVEL)
logger = logging.getLogger(__name__)

machines = []
commands = []
keyboard_wol  = []
keyboard_ping = []


#################################################################################
# Command Handlers ##############################################################
#################################################################################

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    asyncio.create_task(log_call(update))
    # await context.bot.send_message(chat_id=update.effective_chat.id, text="I'm a bot, please talk to me!")
    await update.message.reply_text("Hi!")
    

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    asyncio.create_task(log_call(update))
    
    if not (await identify(update)):
        return
    
    help_message = """
/help
    Display this help

/wake [name]
    Wake saved machine with name

/shutdown [name]
    Shutdown saved machine with name
    
/command [name] <command>
    Run command on machine via SSH. If neither machine name nor command are specified, a list of supported commands is sent

/ping [name]
    Ping a server to check if it is online and reachable by the bot

/list
    List all saved machines

/ip
    Get the public IP address of the network Shepherd is in

Names are only required if more than one machine is configured and may only contain a-z, 0-9 and _
Mac addresses use the separator '{separator}'
    """.format(separator=config.MAC_ADDR_SEPARATOR)
    await update.message.reply_text(help_message)


### WAKE-ON-LAN SECTION ##########################################################

async def cmd_wake(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    asyncio.create_task(log_call(update))
    
    # Check correctness of call
    cmd_permission = config.PERM_WAKE
    if not (await identify(update)) or not (await authorize(update, cmd_permission)):
        return

    # When no args are supplied
    args = context.args
    if len(args) == 0:
        if not len(machines):
            await update.message.reply_text('Please add a machine in the configuration first!')
        wake_menu_keyboard = InlineKeyboardMarkup(keyboard_wol)
        await update.message.reply_text('Select a machine to wake up:', reply_markup=wake_menu_keyboard)
        return

    if len(args) > 1:
        await update.message.reply_text('Please supply only a machine name')
        return

    # Parse arguments and send WoL packets
    machine_name = args[0]
    for m in machines:
        if m.name == machine_name:
            send_magic_packet(update, m.addr, m.name)
            return
    await update.message.reply_text('Could not find ' + machine_name)
    
async def cmd_wake_keyboard_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        n = int(update.callback_query.data[1:])
    except ValueError:
        pass
    
    send_magic_packet(update, machines[n].addr, machines[n].name)
    

### SHUTDOWN SECTION ##########################################################

async def cmd_shutdown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    asyncio.create_task(log_call(update))
    
    # Check correctness of call
    cmd_permission = config.PERM_SHUTDOWN
    if not (await identify(update)) or not (await authorize(update, cmd_permission)):
        return

    args = context.args
    # When no args are supplied
    if len(args) < 1 and len(machines) != 1:
        if not len(machines):
            await update.message.reply_text('Please add a machine in the configuration first!')   # TODO: FIX
        markup = InlineKeyboardMarkup(generate_machine_keyboard(machines))
        await update.message.reply_text('Select a machine to shutdown:', reply_markup=markup)
        return

    # Parse arguments and send shutdown command
    if len(args) == 0:
        machine_name = machines[0].name
    else:
        machine_name = args[0]

    machine = find_by_name(machines, machine_name)

    if machine is None:
        await update.message.reply_text('Could not find ' + machine_name)
        return

    if check_ssh_setup(machine):
        logger.info(
            'host: {host}| user: {user}| port: {port}'.format(host=machine.host, user=machine.user, port=machine.port))
        send_shutdown_command(update, machine.host,
                              machine.port, machine.user, machine.name)
    else:
        logger.info('Machine {name} not set up for SSH connections.'.format(
            name=machine.name))
        await update.message.reply_text(
            machine.name + ' is not set up for SSH connection')
    return

async def cmd_shutdown_keyboard_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        n = int(update.callback_query.data[1:])
    except ValueError:
        pass
    
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(text=f"TESTS_SHUTDOWN {update.callback_query.data} - {n}")
    print("NON ANCORA IMPLEMENTATO!!!!!!!!!!!!!!!!!!!!!!!!!")


### PING SECTION ##########################################################

async def cmd_ping(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    asyncio.create_task(log_call(update))
    
    # Check correctness of call
    cmd_permission = config.PERM_PING
    if not (await identify(update)) or not (await authorize(update, cmd_permission)):
        return

    # When no args are supplied
    args = context.args
    if len(args) == 0:
        if not len(machines):
            await update.message.reply_text('Please add a machine with in the configuration first!')
        ping_menu_keyboard = InlineKeyboardMarkup(keyboard_ping)
        await update.message.reply_text('Select a machine to ping:', reply_markup=ping_menu_keyboard)
        return
    
    if len(args) > 1:
        await update.message.reply_text('Please supply only a machine name')
        return

    # Parse arguments and send WoL packets
    machine_name = args[0]
    for m in machines:
        if m.name == machine_name:
            if ping_server(m.host):
                await update.message.reply_text(f'Pong\nServer \'{m.name}\' is running.')
            else:
                await update.message.reply_text(f'Could not reach {m.name} under IP {m.host}')
            return
    await update.message.reply_text('Could not find ' + machine_name)

async def cmd_ping_keyboard_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        n = int(update.callback_query.data[1:])
    except ValueError:
        pass
    
    m = machines[n]
    if ping_server(m.host):
        await update.callback_query.edit_message_text(f'Pong \U0001F3D3\nServer \'{m.name}\' is running \u2705')
    else:
        await update.callback_query.edit_message_text(f'\u274C Could not reach \'{m.name}\' under IP {m.host}')
    return


async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    asyncio.create_task(log_call(update))
    # Check correctness of call
    cmd_permission = config.PERM_LIST
    if not (await identify(update)) or not (await authorize(update, cmd_permission)):
        return

    # Print all stored machines
    msg = '{num} Stored Machines:\n'.format(num=len(machines))
    for m in machines:
        msg += f'{m.id}) {m.name}\n'
    await update.message.reply_text(msg)


async def cmd_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    asyncio.create_task(log_call(update))
    
    # Check correctness of call
    if not (await identify(update)):
        return

    try:
        # Get IP from webservice
        r = requests.get(config.IP_WEBSERVICE)
        # Extract IP using regex
        pattern = re.compile(config.IP_REGEX)
        match = pattern.search(r.text)

        if not match:
            raise RuntimeError('Could not find IP in webpage response')
        await update.message.reply_text(match.group())
    except RuntimeError as e:
        await update.message.reply_text('Error: ' + str(e))


### RUN_COMMAND SECTION ##########################################################

async def cmd_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    asyncio.create_task(log_call(update))

    if not (await identify(update)):
        return

    if len(machines) == 0:
        await update.message.reply_text(
            'No machines are registered. Please add a machine in the configuration first!')
        return

    args = context.args
    if len(args) == 0:
        list_commands(update)
        return

    if len(args) > 2:
        await update.message.reply_text(
            'Only one command can be processed at a time.')
        return

    if len(args) == 1:
        machine_name = machines[0].name
        command_name = args[0]
    else:
        machine_name = args[0]
        command_name = args[1]

    command = find_by_name(commands, command_name)

    if command is None:
        await update.message.reply_text(
            'Could not find command "{cmd}"'.format(cmd=command_name))
        return

    cmd_permission = command.permission
    if not authorize(update, cmd_permission):
        return

    machine = find_by_name(machines, machine_name)

    if machine is None:
        await update.message.reply_text(
            'Could not find machine {machine}.'.format(machine=machine_name))
        return

    if not check_ssh_setup(machine):
        await update.message.reply_text(
            'Machine {machine} is not set up for SSH connections.'.format(machine=machine_name))
        return

    try:
        logger.info('Attempting to run command on machine {m}: {c}'.format(
            m=machine.name, c=command.name))
        msg = execute_command(command, machine)
        await update.message.reply_text('Command executed:\n{m}'.format(m=msg))
    except SSHException as e:
        await update.message.reply_text(
            'Error in SSH messaging: {e}'.format(e=str(e)))
        return
    except RuntimeError as e:
        await update.message.reply_text(
            'An unexpected error occurred: {e}'.format(e=str(e)))
        return

async def list_commands(update: Update) -> None:
    msg = '{num} Stored Commands:\n'.format(num=len(commands))
    for c in commands:
        msg += '{name}: {description}\n'.format(
            name=c.name, description=c.description)

    msg += '\nRun a command with /command [machine_name] <cmd_name>'

    await update.message.reply_text(msg)

async def cmd_cancel_handler(update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(text="Operation canceled")
    
#################################################################################
# Other Functions ###############################################################
#################################################################################

async def error(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.warning('Update "{u}" caused error "{e}"'.format(
        u=update, e=context.error))


async def log_call(update: Update) -> None:
    uid = update.message.from_user.id
    cmd = update.message.text.split(' ', 1)
    if len(cmd) > 1:
        logger.info('User [{u}] invoked command {c} with arguments [{a}]'
                    .format(c=cmd[0], a=cmd[1], u=uid))
    else:
        logger.info('User [{u}] invoked command {c}'
                    .format(c=cmd[0], u=uid))


async def send_magic_packet(update: Update, mac_address: str, display_name: str) -> None:
    try:
        wol.wake(mac_address)
    except ValueError as e:
        await update.message.reply_text(str(e))
        return
    poke = f'Sending magic packets  to {display_name} ...'

    if update.callback_query:
        await update.callback_query.edit_message_text(poke)
    else:
        await update.message.reply_text(poke)


async def send_shutdown_command(update: Update, hostname: str, port: int, user: str, display_name: str) -> None:
    try:
        cmd_output = ssh_control.shutdown(hostname, port, user)
    except ValueError as e:
        await update.message.reply_text(str(e))
        return
    except SSHException as e:
        await update.message.reply_text(
            'An error occurred while trying to send the shutdown command over SSH.\n{e}\n'.format(e=str(e)))
        return

    poke = 'Shutdown command sent to {name}. Output:\n{output}'.format(
        name=display_name, output=cmd_output)

    if update.callback_query:
        await update.callback_query.edit_message_text(poke)
    else:
        await update.message.reply_text(poke)


def generate_machine_keyboard(machine_list: List[Machine]) -> List[List[InlineKeyboardButton]]:
    kbd: List[List[InlineKeyboardButton]] = []
    for m in machine_list:
        btn = InlineKeyboardButton(m.name, callback_data=str(m.id))
        kbd.append([btn])
    return kbd


### PERMISSION SECTION ##########################################################

async def identify(update: Update) -> bool:
    if not perm.is_known_user(update.message.from_user.id):
        logger.warning('Unknown User {fn} {ln} [{i}] tried to call bot'.format(
            fn=update.message.from_user.first_name,
            ln=update.message.from_user.last_name,
            i=update.message.from_user.id))
        await update.message.reply_text('You are not authorized to use this bot.')
        return False
    return True


async def authorize(update: Update, permission: str) -> bool:
    if not permission:
        # Permission name in config is empty, which is interpreted as the command being deactivated
        name = perm.get_user_name(update.message.from_user.id)
        logger.warning('User {na} [{id}] tried to use a deactivated feature'
            .format(na=name, id=update.message.from_user.id))
        await update.message.reply_text('Sorry, but this command is deactivated.')
        return False

    if not perm.has_permission(update.message.from_user.id, permission):
        name = perm.get_user_name(update.message.from_user.id)
        logger.warning('User {na} [{id}] tried to use permission "{pe}" but does not have it'.format(
            na=name,
            id=update.message.from_user.id,
            pe=permission))
        await update.message.reply_text('Sorry, but you are not authorized to run this command.\n'
                                  + 'Ask your bot admin if you think you should get access.')
        return False
    return True


#################################################################################
### MAIN ########################################################################
#################################################################################

def main() -> None:
    logger.info('Starting Shepherd bot version {v}'.format(v=version.V))
    if not config.VERIFY_HOST_KEYS:
        logger.warning(
            'Verification of host keys for SSH connections is deactivated.')
    global machines
    global commands
    machines = read_machines_file(config.MACHINES_STORAGE_PATH)
    commands = read_commands_file(config.COMMANDS_STORAGE_PATH)
    perm.load_users()

    # Set up bot
    application = ApplicationBuilder().token(config.TOKEN).build()

    # Add commands info
    cmd = [("help", "Display commands"),
           ("wake", "Wake saved machine"),
           ("list", "List all saved machines"),
           ("ping", "Ping a server")]
    # my_bot.set_my_commands(cmd)

    global keyboard_wol, keyboard_ping
    # Create menu Keyboards TODO: add shutdown
    for idx, m in enumerate(machines):
        keyboard_wol.append([InlineKeyboardButton(f'{idx+1}) {m.name}', callback_data=f'w{idx}')])
        keyboard_ping.append([InlineKeyboardButton(f'{idx+1}) {m.name}', callback_data=f'p{idx}')])
    cnl_btn = [InlineKeyboardButton(f'<< Cancel', callback_data="C")]
    keyboard_wol.append(cnl_btn)
    keyboard_ping.append(cnl_btn)
        
    # Add handlers
    application.add_handler(CommandHandler('help', cmd_help))
    application.add_handler(CommandHandler('list', cmd_list))
    application.add_handler(CommandHandler('ip', cmd_ip))
    application.add_handler(CommandHandler('wake', cmd_wake))
    application.add_handler(CommandHandler('shutdown', cmd_shutdown))
    application.add_handler(CommandHandler('command', cmd_command))
    application.add_handler(CommandHandler('ping', cmd_ping))
    application.add_handler(CommandHandler('start', start))
    
    application.add_handler(CallbackQueryHandler(cmd_wake_keyboard_handler, pattern='w+'))
    application.add_handler(CallbackQueryHandler(cmd_ping_keyboard_handler, pattern='p+'))
    application.add_handler(CallbackQueryHandler(cmd_cancel_handler, pattern="C"))
    
    
    application.add_error_handler(error)

    # Start bot
    application.run_polling()


if __name__ == '__main__':
    main()
