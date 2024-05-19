from datetime import datetime
import socket
try:
    import libemu
except ImportError:
    libemu = None
import sys
import errno
import time
import threading
import asyncore
import asynchat
import json

sys.path.append("../")
import mailoney

output_lock = threading.RLock()
hpc, hpfeeds_prefix = mailoney.connect_hpfeeds()

def string_escape(s, encoding='utf-8'):
    return (s.encode('latin1')
             .decode('unicode-escape')
             .encode('latin1')
             .decode(encoding))

def log_to_file(file_path, log_entry):
    with output_lock:
        with open(file_path, "a") as f:
            json_entry = json.dumps(log_entry)
            f.write(json_entry + "\n")

def log_to_hpfeeds(channel, data):
    if hpc:
        message = json.dumps(data)
        hpfchannel = hpfeeds_prefix + "." + channel
        hpc.publish(hpfchannel, message)

def process_packet_for_shellcode(packet, ip, port):
    if libemu is None:
        return
    emulator = libemu.Emulator()
    r = emulator.test(packet)
    if r is not None:
        log_to_file(mailoney.logpath+"/shellcode.log", ip, port, "We have some shellcode")
        log_to_file(mailoney.logpath+"/shellcode.log", ip, port, packet)
        log_to_hpfeeds("shellcode",  json.dumps({ "Timestamp":format(time.time()), "ServerName": self.__fqdn, "SrcIP": self.__addr[0], "SrcPort": self.__addr[1],"Shellcode" :packet}))

def generate_version_date():
    now = datetime.now()
    week_days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    return "{0}, {1} {2} {3} {4}:{5}:{6}".format(week_days[now.weekday()], now.day, months[now.month - 1], now.year, str(now.hour).zfill(2), str(now.minute).zfill(2), str(now.second).zfill(2))

__version__ = 'ESMTP Exim 4.69 #1 {0} -0700'.format(generate_version_date())
EMPTYSTRING = b''
NEWLINE = b'\n'

class SMTPChannel(asynchat.async_chat):
    COMMAND = 0
    DATA = 1

    def __init__(self, server, conn, addr):
        asynchat.async_chat.__init__(self, conn)
        self.__rolling_buffer = b""
        self.__server = server
        self.__conn = conn
        self.__addr = addr
        self.__line = []
        self.__state = self.COMMAND
        self.__greeting = 0
        self.__mailfrom = None
        self.__rcpttos = []
        self.__data = ''
        self.__session_log = []  # Log for the entire session
        from mailoney import srvname
        self.__fqdn = srvname
        try:
            self.__peer = conn.getpeername()
        except socket.error as err:
            self.close()
            if err[0] != errno.ENOTCONN:
                raise
            return
        self.set_terminator(b'\n')
        self.push('220 %s %s' % (self.__fqdn, __version__))

    def push(self, msg):
        if type(msg) == str:
            encoded_msg = msg.encode() 
        elif type(msg) == bytes:
            encoded_msg = msg

        asynchat.async_chat.push(self, encoded_msg + self.terminator)

    def collect_incoming_data(self, data):
        self.__line.append(data)
        self.__rolling_buffer += data
        if len(self.__rolling_buffer) > 1024 * 1024:
            self.__rolling_buffer = self.__rolling_buffer[len(self.__rolling_buffer) - 1024 * 1024:]
        process_packet_for_shellcode(self.__rolling_buffer, self.__addr[0], self.__addr[1])
        del data

    def found_terminator(self):
        line = EMPTYSTRING.join(self.__line).decode()
        self.__session_log.append(line)  # Add each line to the session log

        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "src_ip": self.__addr[0],
            "src_port": self.__addr[1],
            "data": string_escape(line),
            "smtp_input": []
        }

        log_to_file(mailoney.logpath + "/commands.log", log_entry)
        log_to_hpfeeds("commands", log_entry)

        self.__line = []
        if self.__state == self.COMMAND:
            if not line:
                self.push('500 Error: bad syntax')
                return
            method = None
            i = line.find(' ')
            if i < 0:
                command = line.upper()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i+1:].strip()
            method = getattr(self, 'smtp_' + command, None)
            if not method:
                self.push('502 Error: command "%s" not implemented' % command)
                return
            method(arg)
            return
        else:
            if self.__state != self.DATA:
                self.push('451 Internal confusion')
                return
            data = []
            for text in line.split('\r\n'):
                if text and text[0] == '.':
                    data.append(text[1:])
                else:
                    data.append(text)
            self.__data = NEWLINE.join(data)
            self.__session_log.append(self.__data)  # Add data to the session log
            status = self.__server.process_message(self.__peer, self.__mailfrom, self.__rcpttos, self.__data)
            self.__rcpttos = []
            self.__mailfrom = None
            self.__state = self.COMMAND
            self.set_terminator('\r\n')
            if not status:
                self.push('250 Ok')
            else:
                self.push(status)
            
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "src_ip": self.__addr[0],
                "src_port": self.__addr[1],
                "session_data": self.__session_log
            }

            log_to_file(mailoney.logpath + "/sessions.log", log_entry)
            self.__session_log = []  # Reset session log for the next session

class SMTPServer(asyncore.dispatcher):
    def __init__(self, localaddr, remoteaddr):
        self._localaddr = localaddr
        self._remoteaddr = remoteaddr
        asyncore.dispatcher.__init__(self)
        try:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            self.bind(localaddr)
            self.listen(5)
        except:
            self.close()
            raise
        else:
            pass

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            conn, addr = pair
            channel = SMTPChannel(self, conn, addr)

    def handle_close(self):
        self.close()

    def process_message(self, peer, mailfrom, rcpttos, data, mail_options=None,rcpt_options=None):
        raise NotImplementedError

def module():
    class SchizoOpenRelay(SMTPServer):
        def process_message(self, peer, mailfrom, rcpttos, data, mail_options=None,rcpt_options=None):
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "server_name": mailoney.srvname,
                "src_ip": peer[0],
                "src_port": peer[1],
                "mail_from": mailfrom,
                "rcpt_to": rcpttos,
                "data": data
            }

            log_to_file(mailoney.logpath + "/mail.log", log_entry)
            log_to_hpfeeds("mail", log_entry)

    def run():
        honeypot = SchizoOpenRelay((mailoney.bind_ip, mailoney.bind_port), None)
        print('[*] Mail Relay listening on {}:{}'.format(mailoney.bind_ip, mailoney.bind_port))
        try:
            asyncore.loop()
            print("exiting for some unknown reason")
        except KeyboardInterrupt:
            print('Detected interruption, terminating...')

    run()
