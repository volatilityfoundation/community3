
#!/usr/bin/env python3

# (c) Björn Stelte 2020
#
# SYSLOG for volatility3
#
# Donated under VFI Individual Contributor Licensing Agreement

import datetime
import sys
import socket
import configparser
import io

from volatility.cli.text_renderer import CLIRenderer, quoted_optional, hex_bytes_as_text, multitypedata_as_text, display_disassembly
from volatility.framework.interfaces.renderers import RenderOption
from volatility.framework.renderers import format_hints
from volatility.framework import interfaces, renderers

import syslog_client

class SYSLOGRenderer(CLIRenderer):
    _type_renderers = {
        format_hints.Bin: quoted_optional(lambda x: "0b{:b}".format(x)),
        format_hints.Hex: quoted_optional(lambda x: "0x{:x}".format(x)),
        format_hints.HexBytes: quoted_optional(hex_bytes_as_text),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        interfaces.renderers.Disassembly: quoted_optional(display_disassembly),
        bytes: quoted_optional(lambda x: " ".join(["{0:2x}".format(b) for b in x])),
        datetime.datetime: quoted_optional(lambda x: x.strftime("%Y-%m-%d %H:%M:%S.%f %Z")),
        'default': quoted_optional(lambda x: "{}".format(x))
    }

    name = "syslog"
    structured_output = True
    
    def __init__(self):
        # Load the configuration file
        config = configparser.ConfigParser()
        config.read('config_syslog.ini')

        self.host = str(config["server"]["host"])
        self.port = int(config["server"]["port"])

        #print("\n connecting to Syslog-Server "+self.host)

    def get_render_options(self):
        pass

    def set_sysloghost(self, to):
        self.host = to

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        """Renders each row to syslog server.

        Args:
            grid: The TreeGrid object to render
        """

        log = syslog_client.Syslog(self.host,self.port)

        outfd = sys.stdout

        #line = ['"TreeDepth"']
        #for column in grid.columns:
        #    # Ignore the type because namedtuples don't realize they have accessible attributes
        #    line.append("{}".format('"' + column.name + '"'))
        #outfd.write("{}".format(",".join(line)))

        buffer = []
 
        def visitor(node, accumulator):
            #accumulator.write("\n")
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            #accumulator.write(str(max(0, node.path_depth - 1)) + ",")
#            line = []
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(column.type, self._type_renderers['default'])
#                line.append(renderer(node.values[column_index]))
                buffer.append(renderer(node.values[column_index]))
            #accumulator.write("{} ".format(",".join(line)))
            return accumulator

        if not grid.populated:
            grid.populate(visitor, log)
        else:
            grid.visit(node = None, function = visitor, initial_accumulator = log)

        log.write("{}".format(",".join(buffer)))
        outfd.write("\n")
