#!/usr/bin/env python
"""
Script to push a raw VFF config to a waiting VFF Menu prompt.
Can be used for serial, telnet, pty, or virsh
cloudgenix_vff_push_config@ebob9.com
"""
import os
import sys
import socket
import argparse
import telnetlib
from time import sleep

# PySerial, check for library. Disable serial if it does not exist.
try:
    import serial
except ImportError:
    serial = False

# PyExpect for virsh and ssh Disable these if it does not exist.
try:
    import pexpect
    import pexpect.pxssh
except ImportError as e:
    print(e)
    pexpect = False

# Globals
CONFIG_PROMPT_READY = "Choose a Number or (Q)uit:"
CONFIG_HIDDEN_MENU_ITEM = "Read RAW config from STDIN"
CONFIG_PUSH_READY = "End entry with <ENTER>EOM<ENTER>."
CONFIG_PUSH_SUCCESS = "Building configuration..."
SERIAL_DEFAULT_BAUDRATE = 115200
SERIAL_DEFAULT_WAIT = 10  # seconds per poll for prompt.
SERIAL_DEFAULT_WAIT_LIMIT = 30  # x SERIAL_DEFAULT_WAIT seconds
TELNET_DEFAULT_TIMEOUT = 30  # seconds
TELNET_DEFAULT_WAIT = 10  # seconds per poll for prompt.
TELNET_DEFAULT_WAIT_LIMIT = 30  # x SERIAL_DEFAULT_WAIT seconds
VIRSH_DEFAULT_TIMEOUT = 30  # seconds
VIRSH_DEFAULT_WAIT = 10  # seconds per poll for prompt.
VIRSH_DEFAULT_WAIT_LIMIT = 30  # x SERIAL_DEFAULT_WAIT seconds
SSH_DEFAULT_TIMEOUT = 30  # seconds
SSH_DEFAULT_WAIT = 10  # seconds per poll for prompt.
SSH_DEFAULT_WAIT_LIMIT = 30  # x SERIAL_DEFAULT_WAIT seconds



# dynamic Globals
CONFIG_FILE_DATA = ""
ARGS = {}


def do_serial():
    """
    Connect to serial
    :return:
    """
    print("[VFF_PUSH_SERIAL] Opening {0}".format(ARGS['pty']))
    with serial.Serial(str(ARGS['pty']), baudrate=SERIAL_DEFAULT_BAUDRATE,
                       timeout=None, parity=serial.PARITY_NONE,
                       bytesize=serial.EIGHTBITS, stopbits=serial.STOPBITS_ONE,
                       xonxoff=False) as serial_con:

        if not serial_con.isOpen():
            print("[VFF_PUSH_SERIAL] ERROR: Could not open {0}. Exiting.".format(ARGS['pty']))
            sys.exit(1)

        # flush input
        serial_con.flushInput()

        # start a loop waiting for a prompt.
        got_prompt = False
        wait_count = 1
        while not got_prompt:
            # send a CR
            serial_con.write("\n")
            # wait for data
            sleep(SERIAL_DEFAULT_WAIT * .20)  # 1/5 of default wait
            # read the waiting buffer
            input_data = serial_con.read(serial_con.inWaiting())
            # parse response and see if we are at VFF prompt.
            if CONFIG_PROMPT_READY in input_data:
                print("[VFF_PUSH_SERIAL] {0} Got config prompt. Continuing.".format(wait_count))
                got_prompt = True
                continue
            else:
                # need to wait full cycle
                print("[VFF_PUSH_SERIAL] {0} No prompt. (last line:'{1}')".format(wait_count,
                                                                                  input_data.split('\n')[-1]))
                sleep(SERIAL_DEFAULT_WAIT * .80)  # 4/5 of default wait
                wait_count += 1
                # check the limit
                if wait_count > SERIAL_DEFAULT_WAIT_LIMIT:
                    print("[VFF_PUSH_SERIAL] Did not get the "
                          "login prompt in {0} seconds. Exiting.".format(SERIAL_DEFAULT_WAIT *
                                                                         SERIAL_DEFAULT_WAIT_LIMIT))
                    sys.exit(1)

        # Send commands to allow raw config push.
        print("[VFF_PUSH_SERIAL] Setting up config push.")
        serial_con.write("hidden\n")
        sleep(1)  # wait in case of baud issues.
        input_data = serial_con.read(serial_con.inWaiting())
        data_l = input_data.split("\n")
        parseline = []
        for line in data_l:
            if CONFIG_HIDDEN_MENU_ITEM in line:
                print("[VFF_PUSH_SERIAL] {0} Got RAW hidden menu prompt. Continuing.".format(wait_count))
                parseline = line.split(")")
        if parseline:
            print("[VFF_PUSH_SERIAL] Sending option{0}".format(parseline[0]))
            serial_con.write(parseline[0] + "\n")
        else:
            print("[VFF_PUSH_SERIAL] ERROR: Did not get RAW hidden menu prompt"
                  " ready prompt. Last input buffer: \n{0}\n".format(input_data))
            print("[VFF_PUSH_SERIAL] ERROR: End input buffer. Exiting.")
            sys.exit(1)

        sleep(1)  # wait in case of baud issues.
        # read the waiting buffer
        input_data = serial_con.read(serial_con.inWaiting())

        if CONFIG_PUSH_READY not in input_data:
            # did not get needed prompt. Something wrong, exit out.
            print("[VFF_PUSH_SERIAL] ERROR: did not get config push"
                  " ready prompt. Last input buffer: \n{0}\n".format(input_data))
            print("[VFF_PUSH_SERIAL] ERROR: End input buffer. Exiting.")
            sys.exit(1)

        # send config file.
        serial_con.write(CONFIG_FILE_DATA)
        sleep(1)  # wait in case of baud issues.
        serial_con.write("\nEOM\n")
        sleep(1)  # wait in case of baud issues.
        # read the waiting buffer
        input_data = serial_con.read(serial_con.inWaiting())

        if CONFIG_PUSH_SUCCESS not in input_data:
            # did not get needed prompt. Something wrong, exit out.
            print("[VFF_PUSH_SERIAL] ERROR: did not get config push success"
                  " prompt. Last input buffer: \n{0}\n".format(input_data))
            print("[VFF_PUSH_SERIAL] ERROR: End input buffer. Exiting.")
            sys.exit(1)
        # if got here, success!
        print("[VFF_PUSH_SERIAL] Config successfully sent! Exiting.")


def do_telnet(host, port):
    """
    Connect via telnet
    :return:
    """
    # open socket
    print("[VFF_PUSH_TELNET] Opening {0}:{1}".format(host, port))
    try:
        telnet_con = telnetlib.Telnet()
        telnet_con.open(host=host, port=port, timeout=TELNET_DEFAULT_TIMEOUT)
    except socket.error as e:
        print("[VFF_PUSH_TELNET] ERROR: Could not connect to {0}:{1}: Error {2}. \nExiting.".format(host, port, e))
        sys.exit(1)
    print("[VFF_PUSH_TELNET] {0}:{1} Opened".format(host, port))
    # start a loop waiting for a prompt.
    got_prompt = False
    wait_count = 1

    while not got_prompt:
        # send a CR
        telnet_con.write("\n")
        # wait for data
        sleep(TELNET_DEFAULT_WAIT * .20)  # 1/5 of default wait
        # read the waiting buffer
        input_data = telnet_con.read_until(CONFIG_PROMPT_READY, timeout=(TELNET_DEFAULT_WAIT * .80))
        # parse response and see if we are at VFF prompt.
        if CONFIG_PROMPT_READY in input_data:
            print("[VFF_PUSH_TELNET] {0} Got config prompt. Continuing.".format(wait_count))
            got_prompt = True
            continue
        else:
            # need to wait full cycle
            print("[VFF_PUSH_TELNET] {0} No prompt. (last line:'{1}')".format(wait_count,
                                                                              input_data.split('\n')[-1]))
            # no need to sleep here, sleep done at read_until function.
            wait_count += 1
            # check the limit
            if wait_count > TELNET_DEFAULT_WAIT_LIMIT:
                print("[VFF_PUSH_TELNET] Did not get the "
                      "login prompt in {0} seconds. Exiting.".format(TELNET_DEFAULT_WAIT *
                                                                     TELNET_DEFAULT_WAIT_LIMIT))
                sys.exit(1)

    # Send commands to allow raw config push.
    print("[VFF_PUSH_TELNET] Setting up config push.")
    telnet_con.write("hidden\n")
    sleep(1)  # wait in case of baud issues.
    input_data = telnet_con.read_until(CONFIG_PROMPT_READY, timeout=TELNET_DEFAULT_WAIT)
    data_l = input_data.split("\n")
    parseline = []
    for line in data_l:
        if CONFIG_HIDDEN_MENU_ITEM in line:
            print("[VFF_PUSH_TELNET] {0} Got RAW hidden menu prompt. Continuing.".format(wait_count))
            parseline = line.split(")")
    if parseline:
        print("[VFF_PUSH_TELNET] Sending option{0}".format(parseline[0]))
        telnet_con.write(parseline[0] + "\n")
    else:
        print("[VFF_PUSH_TELNET] ERROR: Did not get RAW hidden menu prompt"
              " ready prompt. Last input buffer: \n{0}\n".format(input_data))
        print("[VFF_PUSH_TELNET] ERROR: End input buffer. Exiting.")
        sys.exit(1)

    sleep(1)  # wait in case of baud issues.
    # read the waiting buffer
    input_data = telnet_con.read_until(CONFIG_PUSH_READY, timeout=TELNET_DEFAULT_WAIT)

    if CONFIG_PUSH_READY not in input_data:
        # did not get needed prompt. Something wrong, exit out.
        print("[VFF_PUSH_TELNET] ERROR: did not get config push"
              " ready prompt. Last input buffer: \n{0}\n".format(input_data))
        print("[VFF_PUSH_TELNET] ERROR: End input buffer. Exiting.")
        sys.exit(1)

    # send config file.
    telnet_con.write(CONFIG_FILE_DATA)
    sleep(1)  # wait in case of baud issues.
    telnet_con.write("\nEOM\n")
    sleep(1)  # wait in case of baud issues.
    # read the waiting buffer
    input_data = telnet_con.read_until(CONFIG_PUSH_SUCCESS, timeout=TELNET_DEFAULT_WAIT)

    if CONFIG_PUSH_SUCCESS not in input_data:
        # did not get needed prompt. Something wrong, exit out.
        print("[VFF_PUSH_TELNET] ERROR: did not get config push success"
              " prompt. Last input buffer: \n{0}\n".format(input_data))
        print("[VFF_PUSH_TELNET] ERROR: End input buffer. Exiting.")
        sys.exit(1)
    # if got here, success!
    print("[VFF_PUSH_TELNET] Config successfully sent! Exiting.")


def do_pexpect(pexpect_con, ntype, pex_default_timeout, pex_default_wait, pex_default_wait_limit):
    """
    Connect via pexpect for multiple protocols
    :param pexpect_con: PyExpect object
    :param ntype: string with type of protocol for logging
    :param pex_default_timeout: Default timeout (in sec)
    :param pex_default_wait: Default wait (in sec)
    :param pex_default_wait_limit: Default wait (in loops)
    :return:
    """

    got_prompt = False
    wait_count = 1
    while not got_prompt:
        # send a CR
        pexpect_con.send("\n")
        # wait for data
        sleep(pex_default_wait * .20)  # 1/5 of default wait
        # wait for the prompt.
        input_data = pexpect_con.read_nonblocking(size=8192, timeout=pex_default_wait)
        # parse response and see if we are at VFF prompt.
        if CONFIG_PROMPT_READY in input_data:
            print("[VFF_PUSH_{0}] {1} Got config prompt. Continuing.".format(ntype, wait_count))
            got_prompt = True
            continue
        else:
            # need to wait full cycle
            print("[VFF_PUSH_{0}] {1} No prompt. (last line:'{2}')".format(ntype, wait_count,
                                                                           input_data.split('\n')[-1]))
            # no need to sleep here, sleep done at read_until function.
            wait_count += 1
            # check the limit
            if wait_count > pex_default_wait_limit:
                print("[VFF_PUSH_{0}] Did not get the "
                      "login prompt in {1} seconds. Exiting.".format(ntype, pex_default_wait *
                                                                     pex_default_wait_limit))
                sys.exit(1)

    # Send commands to allow raw config push.
    print("[VFF_PUSH_{0}] Setting up config push.".format(ntype))
    pexpect_con.send("hidden\n")
    sleep(1)  # wait in case of baud issues.
    input_data = pexpect_con.read_nonblocking(size=8192, timeout=pex_default_wait)
    data_l = input_data.split("\n")
    parseline = []
    for line in data_l:
        if CONFIG_HIDDEN_MENU_ITEM in line:
            print("[VFF_PUSH_{0}] {1} Got RAW hidden menu prompt. Continuing.".format(ntype, wait_count))
            parseline = line.split(")")
    if parseline:
        print("[VFF_PUSH_{0}] Sending option{1}".format(ntype, parseline[0]))
        pexpect_con.send(parseline[0] + "\n")
    else:
        print("[VFF_PUSH_{0}] ERROR: Did not get RAW hidden menu prompt"
              " ready prompt. Last input buffer: \n{1}\n".format(ntype, input_data))
        print("[VFF_PUSH_{0}] ERROR: End input buffer. Exiting.".format(ntype))
        sys.exit(1)

    # read the waiting buffer
    input_data = pexpect_con.read_nonblocking(size=8192, timeout=pex_default_wait)

    if CONFIG_PUSH_READY in input_data:
        # did not get needed prompt. Something wrong, exit out.
        input_data = pexpect_con.read_nonblocking(size=8192, timeout=pex_default_wait)
        print("[VFF_PUSH_{0}] ERROR: did not get config push"
              " ready prompt. Last input buffer: \n{1}\n".format(ntype, input_data))
        print("[VFF_PUSH_{0}] ERROR: End input buffer. Exiting.".format(ntype))
        sys.exit(1)

    # send config file.
    pexpect_con.send(CONFIG_FILE_DATA)
    sleep(1)  # wait in case of baud issues.
    pexpect_con.send("\nEOM\n")

    # read the waiting buffer
    input_data = pexpect_con.read_nonblocking(size=8192, timeout=pex_default_wait)

    if CONFIG_PUSH_SUCCESS in input_data:
        # did not get needed prompt. Something wrong, exit out.
        input_data = pexpect_con.read_nonblocking(size=8192, timeout=pex_default_wait)
        print("[VFF_PUSH_{0}] ERROR: did not get config push success"
              " prompt. Last input buffer: \n{1}\n".format(ntype, input_data))
        print("[VFF_PUSH_{0}] ERROR: End input buffer. Exiting.".format(ntype))
        sys.exit(1)
    # if got here, success!
    print("[VFF_PUSH_{0}] Config successfully sent! Exiting.".format(ntype))
    pexpect_con.terminate(force=True)


def go():
    """
    Main Program
    :return: No return
    """
    global ARGS
    global CONFIG_FILE_DATA
    # Start program.
    parser = argparse.ArgumentParser(description="CloudGenix VFF Push Config Client.")
    subparsers = parser.add_subparsers(dest="parser_name", metavar="[commands]")
    subparsers.required = True

    # Serial logic
    serial_parser = subparsers.add_parser('serial', help='Connect via serial PTY device file')
    serial_parser.add_argument("--pty", help="PTY File to connect to", required=False,
                               default="/dev/pts/0")
    serial_parser.add_argument('--file', required=True, help='VFF Config/INI/YAML or JSON file location.', type=str)
    # debug_serial = serial_parser.add_argument_group('Debug', 'These options enable debugging output')
    # debug_serial.add_argument("--debug", help="Verbose Debug info, levels 0-2",
    #                           default=0)

    # Telnet logic
    telnet_parser = subparsers.add_parser('telnet', help='Connect to a TCP/Telnet serial socket')
    telnet_parser.add_argument("--host", help="Host/IP to connect to", required=False,
                               default="127.0.0.1")
    telnet_parser.add_argument("--port", help="TCP port to connect to", required=False,
                               default="4000")
    telnet_parser.add_argument('--file', required=True, help='VFF Config/INI/YAML or JSON file location.', type=str)
    # debug_telnet = telnet_parser.add_argument_group('Debug', 'These options enable debugging output')
    # debug_telnet.add_argument("--debug", help="Verbose Debug info, levels 0-2",
    #                           default=0)

    # VIRSH logic
    virsh_parser = subparsers.add_parser('virsh', help='Connect via VIRSH console')
    virsh_parser.add_argument("--domain", help="domain/VM name to connect to", required=True,
                              default="ION")
    virsh_parser.add_argument('--file', required=True, help='VFF Config/INI/YAML or JSON file location.', type=str)
    # debug_virsh = virsh_parser.add_argument_group('Debug', 'These options enable debugging output')
    # debug_virsh.add_argument("--debug", help="Verbose Debug info, levels 0-2",
    #                        default=0)

    # SSH logic
    ssh_parser = subparsers.add_parser('ssh', help='Connect via SSH')
    ssh_parser.add_argument("--host", help="Host/IP to connect to", required=True,
                            default="127.0.0.1")
    ssh_parser.add_argument("--port", help="TCP port to connect to", required=False,
                            default="22")
    ssh_parser.add_argument("--user", help="Username for SSH", required=False,
                            default="virtualsetup")
    ssh_auth = ssh_parser.add_mutually_exclusive_group()
    ssh_auth.add_argument("--pass", help="Password for SSH authentication", type=str,
                          default='')
    ssh_auth.add_argument("--privkey", help="Path to private Key for SSH authentication", type=str,
                          default=None)
    ssh_parser.add_argument('--file', required=True, help='VFF Config/INI/YAML or JSON file location.', type=str)
    # debug_ssh = ssh_parser.add_argument_group('Debug', 'These options enable debugging output')
    # debug_ssh.add_argument("--debug", help="Verbose Debug info, levels 0-2",
    #                        default=0)

    # parse args
    ARGS = vars(parser.parse_args())

    # load Config file.
    cwd = os.getcwd()
    print("[VFF_PUSH] Starting VFF Config Push script.")
    print("[VFF_PUSH] Current directory is {0}".format(cwd))

    try:
        with open(ARGS['file']) as data_file:
            CONFIG_FILE_DATA = data_file.read()
        print("[VFF_PUSH]   Successfully loaded {0} chars from {1}.".format(len(CONFIG_FILE_DATA), ARGS['file']))
        loop = False
    except (ValueError, IOError) as e:
        print("[VFF_PUSH] ERROR: could not load {0}: {1}.".format(ARGS['file'], e))

    # print repr(args)
    #
    # print args['parser_name']

    # do the parsing
    if ARGS['parser_name'] == 'serial':
        # serial requested
        if not serial:
            print(
                "[VFF_PUSH_SERIAL] ERROR: Serial requested but could not load 'PySerial' module. Please add to system."
                "Exiting.")
            exit(1)
        do_serial()

    elif ARGS['parser_name'] == 'telnet':
        do_telnet(ARGS['host'], ARGS['port'])

    elif ARGS['parser_name'] == 'virsh':
        # virsh requested
        if not pexpect:

            print("[VFF_PUSH_VIRSH] ERROR: Virsh requested but could not load 'pexpect' module. Please add to system. "
                  "Exiting.")
            exit(1)
        pex_obj = pexpect.spawn("virsh", args=['console', ARGS['domain']])
        print("[VFF_PUSH_VIRSH] Launched '{0}', waiting for prompt.".format(str(" ".join(pex_obj.args))))
        do_pexpect(pex_obj, 'VIRSH', VIRSH_DEFAULT_TIMEOUT, VIRSH_DEFAULT_WAIT, VIRSH_DEFAULT_WAIT_LIMIT)

    elif ARGS['parser_name'] == 'ssh':
        # ssh requested
        if not pexpect:

            print("[VFF_PUSH_SSH] ERROR: SSH requested but could not load 'pexpect' module. Please add to system. "
                  "Exiting.")
            exit(1)
        pex_obj = pexpect.pxssh.pxssh(options={
            "StrictHostKeyChecking": "no",
            "UserKnownHostsFile": "/dev/null"})
        if ARGS['privkey']:
            privkey_stat = "Yes"
        else:
            privkey_stat = "No"

        if ARGS['pass']:
            pass_stat = "Yes"
        else:
            pass_stat = "No"
        print("[VFF_PUSH_SSH] Connecting to {0}@{1}:{2}, "
              "Password: {3}, Private Key: {4}. Waiting for prompt.".format(ARGS['user'],
                                                                            ARGS['host'],
                                                                            ARGS['port'],
                                                                            pass_stat,
                                                                            privkey_stat))
        pex_obj.login(ARGS['host'], ARGS['user'], password=ARGS['pass'], ssh_key=ARGS['privkey'], port=ARGS['port'],
                      auto_prompt_reset=False)

        do_pexpect(pex_obj, 'SSH', SSH_DEFAULT_TIMEOUT, SSH_DEFAULT_WAIT, SSH_DEFAULT_WAIT_LIMIT)

    else:
        sys.exit(1)


if __name__ == "__main__":
    go()
