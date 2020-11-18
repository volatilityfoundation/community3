# (c) Björn Stelte 2020
#
# SYSLOG for volatility3
#
# Donated under VFI Individual Contributor Licensing Agreement

import socket
import os

class Facility:
  "Syslog facilities"
  KERN, USER, MAIL, DAEMON, AUTH, SYSLOG, \
  LPR, NEWS, UUCP, CRON, AUTHPRIV, FTP = range(12)

  LOCAL0, LOCAL1, LOCAL2, LOCAL3, \
  LOCAL4, LOCAL5, LOCAL6, LOCAL7 = range(16, 24)

class Level:
  "Syslog levels"
  EMERG, ALERT, CRIT, ERR, \
  WARNING, NOTICE, INFO, DEBUG = range(8)

class Syslog:
  """A syslog client that logs to a remote server.

  Example:
  >>> log = Syslog(host="foobar.example")
  >>> log.send("hello", Level.WARNING)
  """
  def __init__(self,
               host="localhost",
               port=514,
               facility=Facility.DAEMON):
    self.host = host
    self.port = port
    self.facility = facility
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  def write(self, message):
    hostname = socket.gethostname()
    self.notice(hostname+" volatility["+str(os.getpid())+"]: "+message)

  def send(self, message, level):
    "Send a syslog message to remote host using UDP."
    data = "<%d>%s" % (level + self.facility*8, message)
    self.socket.sendto(bytes(data.encode("UTF-8")), (self.host, self.port))

  def warn(self, message):
    "Send a syslog warning message."
    self.send(message, Level.WARNING)

  def notice(self, message):
    "Send a syslog notice message."
    self.send(message, Level.NOTICE)

  def error(self, message):
    "Send a syslog error message."
    self.send(message, Level.ERR)
