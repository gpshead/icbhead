#!/usr/bin/python3

import getopt
import getpass
import os
import select
import signal
import socket
import sys
try:
    import termios
except ImportError:
    termios = None
import textwrap
import time

import goo_gl


# This is my API key for icbhead on goo.gl.  If it gets abused I will
# simply burn it and keep it out of source control in the future.
_ICBHEAD_URL_SHORTENER_API_KEY = 'AIzaSyDtceai_ZCBqny5SQf8ccvRCAEAnG8tOZI'


_now = time.time  # Used for convenience, testing & readability.
_now_tuple = time.localtime


class IcbConn(object):
    _debug = False
    default_server = 'default'
    config_file = '~/.icbheadrc'
    server_dict = {'default': ['default.icb.net', 7326]}

    # While the ICB wire protocol could pass UTF-8 just fine, the
    # existing icbd server implementations strip off all high bits.
    codec = 'ascii'
    # We will, however, be optimistic and hope that a server capable
    # of sending us utf8 is run some day; we decode assuming utf8.
    recv_codec = 'utf8'

    MAX_LINE = 239
    MAX_INPUT_LINE = MAX_LINE * 2

    # Help avoid NAT timeouts or other network disconnect issues.  If no
    # communication between client and server has happened in this long,
    # send a ping and ignore the response.
    KEEPALIVE_SECONDS = 1543

    M_LOGIN = b'a'
    M_OPENMSG = b'b'
    M_PERSONAL = b'c'
    M_STATUS = b'd'
    M_ERROR = b'e'
    M_IMPORTANT = b'f'
    M_EXIT = b'g'
    M_COMMAND = b'h'
    M_CMD_OUTPUT = b'i'
    M_PROTO = b'j'
    M_BEEP = b'k'
    M_PING = b'l'
    M_PONG = b'm'

    def __init__(self, nic=None, group=None, logid=None, server=None,
                 port=None):
        self.read_config_file()
        if logid is not None:
            self.logid = logid.encode(self.codec)
        else:
            self.logid = getpass.getuser().encode(self.codec)
        if nic is not None:
            self.nickname = nic.encode(self.codec)
        else:
            self.nickname = self.logid
        if group is not None:
            self.group = group.encode(self.codec)
        else:
            self.group = b'~IDLE~'
        if server is not None:
            server = server.lower()
            if server in self.server_dict:
                self.server = self.server_dict[server][0]
                self.server_name = self.server_dict[server][2]
            else:
                self.server = server
                self.server_name = server
        else:
            self.server = self.server_dict[self.default_server][0]
            self.server_name = self.default_server
        if port is not None:
            self.port = port
        else:
            self.port = self.server_dict[self.default_server][1]
        self.socket = None
        # Time we last sent or received data over the socket.
        self._last_data_time = 0

    def read_config_file(self, config_file=None):
        if config_file is None:
            config_file = self.config_file
        try:
            f = open(config_file, 'r')
        except IOError:
            self.print_line("can't read config file %s, using defaults." %
                            config_file)
            return
        i = f.readline()
        first_one = True
        line = 0
        while i != '':
            line += 1
            if i.startswith('#'):
                i = f.readline()
                continue
            i_split = i.split()
            if len(i_split) < 4:
                self.print_line('config file syntax error line %d' % line)
                i = f.readline()
                continue
            s_name = i_split[0].lower()
            self.server_dict[s_name] = [i_split[1], int(i_split[3]), i_split[0]]
            if first_one:
                self.default_server = s_name
                first_one = False
            i = f.readline()

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server, self.port))
        self._last_data_time = _now()

    def fileno(self):
        return self.socket.fileno()

    def __recv(self, length):
        retval = bytearray()
        amt_read = 0
        while amt_read < length:
            retval += self.socket.recv(length - amt_read)
            amt_read = len(retval)
        return retval

    def recv(self):
        msg = b''
        length = ord(self.socket.recv(1))
        while length == 0:
            msg += self.__recv(255)
            length = ord(self.socket.recv(1))
        if length != 1:
            msg += self.__recv(length)
        self._last_data_time = _now()
        return_list = [bytes(msg[0:1])]
        if len(msg) > 2:
            return_list.extend(bytes(m) for m in msg[1:-1].split(b'\001'))
        if self._debug:
            print('DBG: recv {}'.format(return_list))
        return return_list

    def send(self, msglist):
        if self._debug:
            print('DBG: send {}'.format(msglist))
        msg = bytearray(1)  # Room at the front for a one byte length.
        msg += msglist[0]
        try:
            msg += msglist[1]
        except Exception as e:
            print('send ignoring exception on msglist[1] append: {}'.format(e))
            pass  # XXX(gps): what is exception expected for ??
        for i in msglist[2:]:
            msg += b'\001' + i
        msg += b'\000'
        if len(msg) > 255:
            print('*** mesg too long, truncating ***')
            msg = msg[:255]
        msg[0] = len(msg) - 1  # Fill in the length (sans length byte).
        self.socket.send(msg)
        self._last_data_time = _now()

    def login(self, command=b'login'):
        self.send([self.M_LOGIN, self.logid, self.nickname, self.group,
                   command, b''])
        # TODO(gps): Turn echoback verbose on and change our code to not
        # display what we just typed unless it was changed by openmsg().

    def close(self):
        self.socket.close()

    def _encode(self, message):
        if isinstance(message, str):
            return message.encode(self.codec, 'replace')
        return message

    def _decode(self, message):
        if isinstance(message, str):
            return message
        return message.decode(self.recv_codec)

    def _wrap_and_encode(self, msg, max_bytes):
        """Wrap and encode a message into a list of byte strings to be sent.

        Given a message, wrap it and encode it using our codec into bytes
        such that each individual message is less than max_bytes long.

        Args:
            msg: A non-empty unicode message to encode to a sequence of byte
                strings each no longer than max_bytes.
            max_bytes: The maximum number of bytes in any output element.
        Returns:
            A list of byte strings containing the contents of msg.
        Raises:
            ValueError: If wrapping and encoding for some reason cannot
                be done within the given constraints or if msg was empty.
        """
        min_len = 20  # Way shorter than is reasonable.
        wrap_width = max_bytes
        while wrap_width > min_len:
            messages = textwrap.wrap(msg, width=wrap_width)
            if not messages:
                raise ValueError('msg was empty or 100% whitespace.')
            encoded_messages = [self._encode(msg) for msg in messages]
            encoded_lengths = sorted(len(emsg) for emsg in encoded_messages)
            max_encoded_length = encoded_lengths[-1]
            # If one of the encoded messages is longer than max_bytes,
            # reduce max_bytes based roughly on how far over it was
            # and retry wrapping and encoding.
            if max_encoded_length > max_bytes:
                scale_factor = (max_bytes / max_encoded_length) ** 0.6
                assert scale_factor < 1
                wrap_width = int((wrap_width - 1) * scale_factor)
                continue
            return encoded_messages
        raise ValueError('Unable to text wrap and encode {0!r} into bytes'
                         ' of length {1} or less.'.format(msg, max_bytes))

    def openmsg(self, msg):
        msg = goo_gl.shorten_long_urls(msg, api_key=_ICBHEAD_URL_SHORTENER_API_KEY)
        encoded_messages = self._wrap_and_encode(msg, self.MAX_LINE)
        for encoded_msg in encoded_messages:
            self.send([self.M_OPENMSG, encoded_msg])

    def command(self, cmd, args):
        self.send([self.M_COMMAND, self._encode(cmd), self._encode(args)])


class IcbSimple(IcbConn):
    last_packet = []
    beeps_ok = 1
    alert_mode = 0
    last_alert = 0
    term_width = 80
    term_height = 24
    right_margin = 2
    input_file = sys.stdin
    output_file = sys.stdout
    class IcbQuitException(Exception):
        """Used internally to signal when to close this icb session."""
    m_personal_history = []
    # Last day of the month we printed a message so that we can print
    # the month and day once anytime it changes.
    _day_of_month = -1
    # Used by the keepalive mechanism to ignore a keepalive self ping.
    _ignore_next_ping = False

    def pretty_time(self, secs):
        if secs == 0:
            return '-'
        if secs < 60:
            return '%ds' % secs
        if secs < 3600:
            return '%dm%ds' % (int(secs/60), secs % 60)
        if secs >= 3600:
            return '%dh%dm' % (int(secs/3600), int((secs%3600)/60))

    def print_line(self, line):
        output_line = line
        now = _now()
        if (self.alert_mode == 1) and (now - self.last_alert > 0.5):
            output_line = '\007' + output_line
            self.last_alert = now
        output_line = output_line + '\n'
        self.output_file.write(output_line)

    def indent_print(self, indent, msg):
        left = 0
        max_line = self.term_width - len(indent) - 1 - self.right_margin
        wrapped_msgs = textwrap.wrap(msg, max_line)
        for msg in wrapped_msgs:
            self.print_line('{} {}'.format(indent, msg))

    @property
    def _time(self):
        localtime = _now_tuple()
        day_of_month = localtime[2]
        if day_of_month == self._day_of_month:
            return time.strftime('%H:%M', localtime)
        else:
            self._day_of_month = day_of_month
            return time.strftime('%b %d %H:%M', localtime)

    def do_M_LOGIN(self, p):
        self.print_line('Logged in.')

    def do_M_OPENMSG(self, p):
        username = self._decode(p[1])
        msg = self._decode(p[2])
        # This breaks and wraps lines including useful things like
        # URLs. eek! ugh.
        #self.indent_print('<'+prefix+'>', msg)
        self.print_line('{time} <{user}> {msg}'.format(
                time=self._time, user=username, msg=msg))

    def do_M_PERSONAL(self, p):
        username = self._decode(p[1])
        msg = self._decode(p[2])
        # This breaks and wraps lines including useful things like
        # URLs. eek! ugh.
        #self.indent_print('<*'+prefix+'*>', msg)
        self.print_line('{time} <*{user}*> {msg}'.format(
                time=self._time, user=username, msg=msg))

    def do_M_STATUS(self, p):
        prefix = self._decode(p[1])
        msg = self._decode(p[2])
        self.indent_print('[='+prefix+'=]', msg)

    def do_M_ERROR(self, p):
        error_msg = self._decode(p[1])
        self.indent_print('[*Error*]', error_msg)

    def do_M_IMPORTANT(self, p):
        prefix = self._decode(p[1])
        msg = self._decode(p[2])
        self.indent_print('[** '+prefix+' **]', msg)

    def do_M_EXIT(self, p):
        raise self.IcbQuitException

    ##
    ## command-output handler
    ##
    C_GENERIC = b'co'
    C_END = b'ec'
    C_WHO_LIST = b'wl'
    C_WHO_GROUP = b'wg'
    C_WHO_HEAD = b'wh'
    C_GROUP_HEAD = b'gh'
    C_CLIENT_CMD_LIST = b'ch'
    C_CLIENT_LIST = b'c'

    def do_C_GENERIC(self, p):
        self.print_line(self._decode(p[2]))

    def do_C_END(self, p):
        self.print_line('** got C_END **')

    def do_C_WHO_LIST(self, p):
        t = time.localtime(int(p[6]))
        if p[2] != b' ':
            mod_char = '*'
        else:
            mod_char = ' '
        self.print_line(' %c %-12s  %6s  %5s  %s@%s %s' % (
                mod_char,
                self._decode(p[3]),
                self.pretty_time(int(p[4])),
                '%2d:%02d' % ( t[3], t[4] ),
                self._decode(p[7]),
                self._decode(p[8]),
                self._decode(p[9])))

    def do_C_WHO_GROUP(self, p):
        self.print_line(repr(p)) # XXX

    def do_C_WHO_HEAD(self, p):
        self.print_line('   Nickname        Idle Signon  Account')

    def do_C_GROUP_HEAD(self, p):
        pass

    def do_C_CLIENT_CMD_LIST(self, p):
        pass

    def do_C_CLIENT_LIST(self, p):
        pass

    def do_C_unknown(self, p):
        self.print_line('** unknown command output: ' + repr(p))

    def do_M_CMD_OUTPUT(self, p):
        # TODO(gps): make a decorated dispatch table.
        cmd = p[1]
        if   cmd == self.C_GENERIC:
            self.do_C_GENERIC(p)
        elif cmd == self.C_END:
            self.do_C_END(p)
        elif cmd == self.C_WHO_LIST:
            self.do_C_WHO_LIST(p)
        elif cmd == self.C_WHO_GROUP:
            self.do_C_WHO_GROUP(p)
        elif cmd == self.C_WHO_HEAD:
            self.do_C_WHO_HEAD(p)
        elif cmd == self.C_GROUP_HEAD:
            self.do_C_GROUP_HEAD(p)
        elif cmd == self.C_CLIENT_CMD_LIST:
            self.do_C_CLIENT_CMD_LIST(p)
        elif cmd == self.C_CLIENT_LIST:
            self.do_C_CLIENT_LIST(p)
        else:
            self.do_C_unknown(p)

    def do_M_PROTO(self, p):
        if len(p) > 3:
            server_id = self._decode(p[3])
        else:
            server_id = '(unknown)'
        if len(p) > 2:
            host_id = self._decode(p[2])
        else:
            host_id = self.server_name
        self.print_line('connected to the %s ICB server (%s)' %
                        (host_id, server_id))

    def do_M_BEEP(self, p):
        if self.beeps_ok:
            if self.alert_mode == 0:
                self.output_file.write('\007')
            self.show([self.M_STATUS, 'Beep',
                       '%s has annoyingly beeped you.' % self._decode(p[1])])

    def do_M_PING(self, p):
        if self._ignore_next_ping:
            self._ignore_next_ping = False
            return
        print('received a server ping.')

    def do_M_PONG(self, p):
        print('pong')

    def do_M_unknown(self, p):
        self.print_line('unknown packet: ' + repr(p))

    def recv(self):
        self.last_packet = IcbConn.recv(self)
        return self.last_packet

    def show(self, p=None):
        if p is None:
            p = self.last_packet
        c = p[0]

        # TODO(gps): make a decorated dispatch table.
        if   c == self.M_LOGIN:
            self.do_M_LOGIN(p)
        elif c == self.M_OPENMSG:
            self.do_M_OPENMSG(p)
        elif c == self.M_PERSONAL:
            self.do_M_PERSONAL(p)
        elif c == self.M_STATUS:
            self.do_M_STATUS(p)
        elif c == self.M_ERROR:
            self.do_M_ERROR(p)
        elif c == self.M_IMPORTANT:
            self.do_M_IMPORTANT(p)
        elif c == self.M_EXIT:
            self.do_M_EXIT(p)
        elif c == self.M_CMD_OUTPUT:
            self.do_M_CMD_OUTPUT(p)
        elif c == self.M_PROTO:
            self.do_M_PROTO(p)
        elif c == self.M_BEEP:
            self.do_M_BEEP(p)
        elif c == self.M_PING:
            self.do_M_PING(p)
        elif c == self.M_PONG:
            self.do_M_PONG(p)
        else:
            self.do_M_unknown(p)

    @property
    def _keepalive_expire_time(self):
        return self._last_data_time + self.KEEPALIVE_SECONDS

    def select(self):
        user_ready = 0
        server_ready = 0
        server_error = 0
        iobjs = []
        oobjs = []
        eobjs = []
        keepalive_timeout = max(self._keepalive_expire_time - _now(), 10)
        try:
            iobjs, oobjs, eobjs = select.select(
                    [self.input_file, self],
                    [],
                    [self],
                    keepalive_timeout)
        except select.error:
            pass
        if self.input_file in iobjs:
            user_ready = 1
        if self in iobjs:
            server_ready = 1
        if self in eobjs:
            server_error = 1
        return user_ready, server_ready

    def user_recv(self):
        return self.input_file.readline().rstrip()

    def _truncate_long_userinput(self, userline):
        if len(userline) > self.MAX_LINE:
            userline = userline[:MAX_LINE]
            self.indent_print('[ Error ]', 'input line too long.')
            self.indent_print('[ Error ]', 'truncated to: \'%s\'' % userline)
        return userline

    def process_cmd(self, cmd, line):
        if cmd == 'q':
            raise self.IcbQuitException
        elif cmd == 'alert':
            if self.alert_mode == 0:
                self.alert_mode = 1
                self.show([self.M_STATUS, 'Status',
                           'alert mode enabled (beep).'])
            else:
                self.show([self.M_STATUS, 'Status',
                           'd00d: alert mode already enabled.'])
        elif cmd == 'noalert':
            if self.alert_mode == 1:
                self.alert_mode = 0
                self.show([self.M_STATUS, 'Status',
                           'alert mode disabled (shhhh).'])
            else:
                self.show([self.M_STATUS, 'Status',
                           'd00d: alert mode already disabled.'])
        elif cmd == 'beep':
            if line != '':
                self.command(cmd, line)
            elif self.beeps_ok == 1:
                self.show([self.M_STATUS, 'Status', 'beeps already allowed.'])
            else:
                self.beeps_ok = 1
                self.show([self.M_STATUS, 'Status',
                           'folks can now annoyingly beep you.'])
        elif cmd == 'nobeep':
            if self.beeps_ok == 0:
                self.show([self.M_STATUS, 'Status', 'beeps already disabled.'])
            else:
                self.beeps_ok = 0
                self.show([self.M_STATUS, 'Status',
                           'folks can no longer annoyingly beep you.'])
        elif cmd == 'm':
            s = line.split()
            if len(s) > 0:
                if s[0] in self.m_personal_history:
                    self.m_personal_history.remove(s[0])
                self.m_personal_history.append(s[0])
            self.command(cmd, line)
        elif cmd == 'debug':
            self._debug = not self._debug
            on_off = self._debug and 'ON' or 'OFF'
            self.show([self.M_STATUS, 'Status',
                       'icbhead debug mode turned {}.'.format(on_off)])
        else:
            self.command(cmd, line)

    def _parse_cmd(self, command_line):
        cmd_split = command_line.split(None, 1)
        cmd = ''
        if cmd_split:
            cmd = cmd_split.pop(0)
        args = ''
        if cmd_split:
            args = cmd_split[0]
        self.process_cmd(cmd, args)

    def process_user(self, userline):
        if not userline:
            return
        if userline.startswith('/'):
            if len(userline) > 1:
                if userline[1] == '/':
                    self.openmsg(userline[1:])
                else:
                    userline = self._truncate_long_userinput(userline)
                    self._parse_cmd(userline[1:])
            else:
                self.show([self.M_STATUS, 'Error', 'empty command'])
        else:
            self.openmsg(userline)


class IcbTerminalApp(IcbSimple):
    old_termios = None
    last_m_personal = 0
    default_display_buffer = 200

    def on_stop(self, sig, stack):
        self.restore_termios()
        signal.signal(signal.SIGTSTP, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGTSTP)
        signal.signal(signal.SIGTSTP, self.on_stop)
        self.set_cbreak()

    def set_cbreak(self):
        if not termios:
            return
        self.old_termios = termios.tcgetattr(self.input_file.fileno())
        new_termios = termios.tcgetattr(self.input_file.fileno())
        new_termios[3] = new_termios[3] & ~termios.ICANON
        new_termios[3] = new_termios[3] & ~termios.ECHO
        new_termios[6][termios.VMIN] = 1
        new_termios[6][termios.VTIME] = 0
        termios.tcsetattr(self.input_file.fileno(), termios.TCSANOW,
                          new_termios)
        new_termios = termios.tcgetattr(self.input_file.fileno())

    def restore_termios(self):
        if not termios:
            return
        if self.old_termios is not None:
            termios.tcsetattr(self.input_file.fileno(),
                              termios.TCSANOW, self.old_termios)

    def do_display_cmd(self, cmd, line):
        try:
            s = line.split()
            if len ( s ) > 0:
                show_lines = int ( s[0] )
            else:
                show_lines = self.display_buffer_length
        except ValueError:
            self.show([self.M_ERROR, 'Number of lines must be numeric.'])
            return
        for i in self.display_buffer[-show_lines:]:
            self.print_line(i, remember=False)

    def process_cmd(self, cmd, line):
        if cmd == 'display':
            self.do_display_cmd(cmd, line)
        elif cmd == 'page':
            if not self.page_mode:
                self.show([self.M_STATUS, 'Status', 'Page mode enabled.'])
            else:
                self.show([self.M_STATUS, 'Status',
                           'd00d: Page mode already enabled.'])
            self.page_mode = 1
        elif cmd == 'nopage':
            if self.page_mode:
                self.show([self.M_STATUS, 'Status', 'Page mode enabled.'])
            else:
                self.show([self.M_STATUS, 'Status',
                           'd00d: Page mode already enabled.'])
            self.page_mode = 0
        elif cmd == 'm':
            self._remember_line('/m %s' % line)
            IcbSimple.process_cmd(self, cmd, line)
        else:
            IcbSimple.process_cmd(self, cmd, line)

    def openmsg(self, msg):
        self._remember_line('--> ' + msg)
        IcbSimple.openmsg(self, msg)

    def _remember_line(self,line):
        self.display_buffer.append(line)
        self.display_buffer = self.display_buffer[-self.display_buffer_length:]

    def print_line(self, line, remember=True):
        if remember:
            self._remember_line(line)
        self.num_lines += 1
        if self.page_mode and (self.num_lines >= self.term_height - 1):
            self.output_file.write('\r-- more --')
            self.output_file.flush()
            self.input_file.read(1)
            self.num_lines = 0
            self.output_file.write('\r           \r')
            self.output_file.flush()
        IcbSimple.print_line(self,line)

    def _backspace(self, n):
        while n > 0:
            self.output_file.write('\b \b')
            n -= 1

    ##
    ## process_char returns two-tuple (r, line)
    ##   r:
    ##     0 - process next character
    ##     1 - line done, return
    ##   line:
    ##     line after this character has been processed
    ##
    def process_char(self, c, line):
        if   c in ('\r', '\n'):
            self.output_file.write('\n')
            self.output_file.flush()
            return (1, line)
        elif c == '\022': # redraw line
            self.output_file.write('\r' + line)
            self.output_file.flush()
        elif (c == '\025' or
              (termios and
               c == self.old_termios[6][termios.VKILL])): # kill-line
            self._backspace(len(line))
            self.output_file.flush()
            line = ''
            return (1, line)
        elif (c == '\010' or c == '\x7f' or
              (termios and
               c == self.old_termios[6][termios.VERASE])): # backspace
            if len(line) > 0:
                line = line[:-1]
                self._backspace(1)
                self.output_file.flush()
            if len(line) == 0:
                return (1, line)
        elif (c == '\027' or
              (termios and
               c == self.old_termios[6][termios.VWERASE])): # word-erase
            oldlen = len(line)
            while line != '' and line[-1] in ' \t':
                line = line[:-1]
            while line != '' and line[-1] not in ' \t':
                line = line[:-1]
            if oldlen > 0:
                self._backspace(oldlen - len(line))
                self.output_file.flush()
        elif ord(c) >= 0x20 and ord(c) < 0x7f: # YUK, there should be a string.printable
            if len(line) > self.MAX_INPUT_LINE:
                self.output_file.write('\007')
                self.output_file.flush()
            else:
                line += c
                self.output_file.write(c)
                self.output_file.flush()
                self.do_history = 0
        elif self.do_history and c == '\t': # tab, cycle through m_personal_history
            if self.m_personal_history != []:
                if line != '':
                    self._backspace(len(line))
                line = '/m %s ' % self.m_personal_history[self.last_m_personal]
                self.output_file.write(line)
                self.output_file.flush()
                self.last_m_personal = self.last_m_personal - 1
                if self.last_m_personal < 0:
                    self.last_m_personal = len(self.m_personal_history) - 1
        else:
            ## unknown character, ignore
            pass
        if line == '':
            return (1, line)
        else:
            return (0, line)

    def readline(self, fileobj):
        self.num_lines = 0
        line = ''
        self.last_m_personal = len(self.m_personal_history) - 1
        self.do_history = 1
        while True:
            try:
                c = fileobj.read(1)
                done, line = self.process_char(c, line)
                if done:
                    break
            except IOError:
                pass
        return line

    def user_recv(self):
        return self.readline(self.input_file).rstrip()

    def mainloop(self):
        self.set_cbreak()
        signal.signal(signal.SIGTSTP, self.on_stop)
        try:
            while True:
                try:
                    user_ready, server_ready = self.select()
                    if user_ready:
                        userline = self.user_recv()
                        self.process_user(userline)
                    if server_ready:
                        self.recv()
                        self.show()
                    if _now() > self._keepalive_expire_time:
                        self._ignore_next_ping = True
                        self.command('ping', '')

                except KeyboardInterrupt:
                    self.output_file.write('really exit? [Yn]')
                    ans = self.input_file.read(1)
                    if ans[0] in 'yY\n':
                        self.output_file.write('\nexiting...\n')
                        self.close()
                        break

                except self.IcbQuitException:
                    self.close()
                    break

                except socket.error:
                    # TODO(gps): Implement periodic connection retry.
                    self.output_file.write(
                            '\nError: lost connection with server. Exiting.\n')
                    self.close()
                    break

        finally:
            self.restore_termios()

    def __init__(self):
        nick = None
        logid = None
        group = None
        server = None

        self.display_buffer_length = self.default_display_buffer
        self.display_buffer = []

        self.page_mode = 0
        self.num_lines = 0

        try:
            self.term_width = int(os.environ['COLUMNS'])
            self.term_height = int(os.environ['LINES'])
        except (KeyError, ValueError):
            pass

        # process args
        try:
            optlist, args = getopt.getopt(sys.argv[1:],'g:n:l:s:w')
        except getopt.error as detail:
            self.print_line('error: %r' % detail)
            self.print_line('usage: %s [-g group] [-n nickname] [-l login] [-s server] [-w]' % (sys.argv[0]))
            return
        for i in optlist:
            if i[0] == '-g':
                group = i[1]
            elif i[0] == '-n':
                nick = i[1]
            elif i[0] == '-l':
                logid = i[1]
            elif i[0] == '-w':
                command = b'w'
            elif i[0] == '-s':
                server = i[1]

        self.print_line(
                'Welcome to icbhead: An Internet Citizens Band client'
                ' written in Python.')
        IcbSimple.__init__(self,nick,group,logid,server)
        # TODO(gps): Remove this connect/login/mainloop from the constructor.
        try:
            self.connect()
        except socket.error as detail:
            self.print_line("can't connect to server: %s" % (detail))
            return
        self.login()
        self.mainloop()


class IcbPersonalized(IcbTerminalApp):
    pass


if __name__ == '__main__':
    customfile = os.environ['HOME'] + '/.icbrc'
    try:
        # TODO(gps): eew!  die.  die.
        exec(open(customfile).read())
    except IOError:
        pass
    session = IcbPersonalized()
