__author__ = "@botnet_hunter"

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
from time import gmtime, strftime
import asyncore
import asynchat
import re
import json

sys.path.append("../")
import mailoney

output_lock = threading.RLock()
hpc, hpfeeds_prefix = mailoney.connect_hpfeeds()


def string_escape(s, encoding="utf-8"):
    return (
        s.encode("latin1")  # To bytes, required by 'unicode-escape'
        .decode("unicode-escape")  # Perform the actual octal-escaping decode
        .encode("latin1")  # 1:1 mapping back to bytes
        .decode(encoding)
    )  # Decode original encoding


def log_to_file(file_path, ip, port, data):
    with output_lock:
        try:
            with open(file_path, "a") as f:
                emails = re.findall(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b", data
                )
                if len(data) > 4096:
                    data = "BIGSIZE"
                dictmap = {
                    "timestamp": strftime("20%y-%m-%dT%H:%M:%S.000000Z", gmtime()),
                    "src_ip": ip,
                    "src_port": port,
                    "data": data,
                    "smtp_input": emails,
                }
                json_data = json.dumps(dictmap)
                f.write(json_data + "\n")
                message = "[{0}][{1}:{2}] {3}".format(time.time(), ip, port, repr(data))
                print(file_path + " " + message)
        except Exception as e:
            print("An error occurred while logging to file: ", str(e))


def log_to_hpfeeds(channel, data):
    if hpc:
        message = data
        hpfchannel = hpfeeds_prefix + "." + channel
        hpc.publish(hpfchannel, message)


def process_packet_for_shellcode(packet, ip, port):
    if libemu is None:
        return
    emulator = libemu.Emulator()
    r = emulator.test(packet)
    if r is not None:
        log_to_file(
            mailoney.logpath + "/shellcode.log", ip, port, "We have some shellcode"
        )
        log_to_file(mailoney.logpath + "/shellcode.log", ip, port, packet)
        log_to_hpfeeds(
            "shellcode",
            json.dumps(
                {
                    "Timestamp": format(time.time()),
                    "ServerName": mailoney.srvname,
                    "SrcIP": ip,
                    "SrcPort": port,
                    "Shellcode": packet,
                }
            ),
        )


def generate_version_date():
    now = datetime.now()
    week_days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    months = [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    ]
    return "{0}, {1} {2} {3} {4}:{5}:{6}".format(
        week_days[now.weekday()],
        now.day,
        months[now.month - 1],
        now.year,
        str(now.hour).zfill(2),
        str(now.minute).zfill(2),
        str(now.second).zfill(2),
    )


__version__ = "ESMTP Exim 4.69 #1 {0} -0700".format(generate_version_date())
EMPTYSTRING = b""
NEWLINE = b"\n"


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
        self.__data = ""
        from mailoney import srvname

        self.__fqdn = srvname
        try:
            self.__peer = conn.getpeername()
        except socket.error as err:
            self.close()
            if err.errno != errno.ENOTCONN:
                raise
            return
        self.set_terminator(b"\n")
        self.push("220 %s %s" % (self.__fqdn, __version__))

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
            self.__rolling_buffer = self.__rolling_buffer[
                len(self.__rolling_buffer) - 1024 * 1024 :
            ]
        process_packet_for_shellcode(
            self.__rolling_buffer, self.__addr[0], self.__addr[1]
        )
        del data

    def found_terminator(self):
        if self.__state == self.DATA:
            self.__state = self.COMMAND
            self.set_terminator("\r\n")
            status = self.__server.process_message(
                self.__peer, self.__mailfrom, self.__rcpttos, self.__data
            )
            self.__rcpttos = []
            self.__mailfrom = None
            self.__data = ""  # Reset data after processing
            if not status:
                self.push("250 Ok")
            else:
                self.push(status)
            return
        else:
            line = EMPTYSTRING.join(self.__line).decode()
            log_to_file(
                mailoney.logpath + "/commands.log",
                self.__addr[0],
                self.__addr[1],
                string_escape(line),
            )
            log_to_hpfeeds(
                "commands",
                json.dumps(
                    {
                        "Timestamp": format(time.time()),
                        "ServerName": self.__fqdn,
                        "SrcIP": self.__addr[0],
                        "SrcPort": self.__addr[1],
                        "Commmand": string_escape(line),
                    }
                ),
            )

            self.__line = []
            if not line:
                self.push("500 Error: bad syntax")
                return
            method = None
            i = line.find(" ")
            if i < 0:
                command = line.upper()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i + 1 :].strip()
            method = getattr(self, "smtp_" + command, None)
            if not method:
                self.push('502 Error: command "%s" not implemented' % command)
                return
            method(arg)
            return

    def smtp_HELO(self, arg):
        if not arg:
            self.push("501 Syntax: HELO hostname")
            return
        if self.__greeting:
            self.push("503 Duplicate HELO/EHLO")
        else:
            self.__greeting = arg
            self.push("250 %s" % self.__fqdn)

    def smtp_EHLO(self, arg):
        if not arg:
            self.push("501 Syntax: EHLO hostname")
            return
        if self.__greeting:
            self.push("503 Duplicate HELO/EHLO")
        else:
            self.__greeting = arg
            self.push(
                "250-{0} Hello {1} [{2}]".format(self.__fqdn, arg, self.__addr[0])
            )
            self.push("250-SIZE 52428800")
            self.push("250 AUTH LOGIN PLAIN")

    def smtp_NOOP(self, arg):
        if arg:
            self.push("501 Syntax: NOOP")
        else:
            self.push("250 Ok")

    def smtp_QUIT(self, arg):
        self.push("221 Bye")
        self.close_when_done()

    def smtp_AUTH(self, arg):
        self.push("235 Authentication succeeded")

    def __getaddr(self, keyword, arg):
        address = None
        keylen = len(keyword)
        if arg[:keylen].upper() == keyword:
            address = arg[keylen:].strip()
            if not address:
                pass
            elif address[0] == "<" and address[-1] == ">" and address != "<>":
                address = address[1:-1]
        return address

    def smtp_MAIL(self, arg):
        address = self.__getaddr("FROM:", arg) if arg else None
        if not address:
            self.push("501 Syntax: MAIL FROM:<address>")
            return
        if self.__mailfrom:
            self.push("503 Error: nested MAIL command")
            return
        self.__mailfrom = address
        self.push("250 Ok")

    def smtp_RCPT(self, arg):
        if not self.__mailfrom:
            self.push("503 Error: need MAIL command")
            return
        address = self.__getaddr("TO:", arg) if arg else None
        if not address:
            self.push("501 Syntax: RCPT TO: <address>")
            return
        self.__rcpttos.append(address)
        self.push("250 Ok")

    def smtp_RSET(self, arg):
        if arg:
            self.push("501 Syntax: RSET")
            return
        self.__mailfrom = None
        self.__rcpttos = []
        self.__data = ""
        self.__state = self.COMMAND
        self.push("250 Ok")

    def smtp_DATA(self, arg):
        if not self.__rcpttos:
            self.push("503 Error: need RCPT command")
            return
        if arg:
            self.push("501 Syntax: DATA")
            return
        self.__state = self.DATA
        self.set_terminator(b"\r\n.\r\n")  # Set the terminator for DATA
        self.push("354 End data with <CR><LF>.<CR><LF>")

        # Clear previous data
        self.__data = ""

    def collect_incoming_data_data(self, data):
        # Collect data for DATA command
        self.__data += data

    def found_terminator_data(self):
        # Process the collected data
        log_to_file(
            mailoney.logpath + "/mail.log", self.__addr[0], self.__addr[1], self.__data
        )
        log_to_hpfeeds(
            "mail",
            json.dumps(
                {
                    "Timestamp": format(time.time()),
                    "ServerName": self.__fqdn,
                    "SrcIP": self.__addr[0],
                    "SrcPort": self.__addr[1],
                    "MailFrom": self.__mailfrom,
                    "MailTo": ", ".join(self.__rcpttos),
                    "Data": self.__data,
                }
            ),
        )

        # Reset state and data
        self.__state = self.COMMAND
        self.set_terminator(b"\r\n")
        self.push("250 Ok: queued")


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

    def process_message(
        self, peer, mailfrom, rcpttos, data, mail_options=None, rcpt_options=None
    ):
        raise NotImplementedError


def module():
    class SchizoOpenRelay(SMTPServer):
        def process_message(
            self, peer, mailfrom, rcpttos, data, mail_options=None, rcpt_options=None
        ):
            log_to_file(mailoney.logpath + "/mail.log", peer[0], peer[1], "")
            log_to_file(mailoney.logpath + "/mail.log", peer[0], peer[1], "*" * 50)
            log_to_file(
                mailoney.logpath + "/mail.log",
                peer[0],
                peer[1],
                "Mail from: {0}".format(mailfrom),
            )
            log_to_file(
                mailoney.logpath + "/mail.log",
                peer[0],
                peer[1],
                "Mail to: {0}".format(", ".join(rcpttos)),
            )
            log_to_file(mailoney.logpath + "/mail.log", peer[0], peer[1], "Data:")
            log_to_file(mailoney.logpath + "/mail.log", peer[0], peer[1], data)

            loghpfeeds = {}
            loghpfeeds["ServerName"] = mailoney.srvname
            loghpfeeds["Timestamp"] = format(time.time())
            loghpfeeds["SrcIP"] = peer[0]
            loghpfeeds["SrcPort"] = peer[1]
            loghpfeeds["MailFrom"] = mailfrom
            loghpfeeds["MailTo"] = format(", ".join(rcpttos))
            loghpfeeds["Data"] = data
            log_to_hpfeeds("mail", json.dumps(loghpfeeds))

    def run():
        honeypot = SchizoOpenRelay((mailoney.bind_ip, mailoney.bind_port), None)
        print(
            "[*] Mail Relay listening on {}:{}".format(
                mailoney.bind_ip, mailoney.bind_port
            )
        )
        try:
            asyncore.loop()
            print("exiting for some unknown reason")
        except KeyboardInterrupt:
            print("Detected interruption, terminating...")

    run()
