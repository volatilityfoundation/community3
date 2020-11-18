
# (c) Björn Stelte 2020
#
# EVTX for volatility3
#
# Donated under VFI Individual Contributor Licensing Agreement
#
# License and Attribution included below from python-evtx and EVTXtract since
# this plugin includes code from those two projects.
#
#
# Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#               while at Mandiant <http://www.mandiant.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# 

from typing import List
import logging
from volatility.framework import exceptions, renderers, interfaces, automagic, plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import pe
from volatility.plugins import timeliner
from volatility.plugins.windows import pslist
import pefile
import hashlib
import requests
import collections
import mmap
from xml.dom import minidom
import evtxtract.utils
import evtxtract.carvers
import evtxtract.templates
from typing import Optional
import datetime

logger = logging.getLogger(__name__)

class Mmap(object):
    """
    Convenience class for opening a read-only memory map for a file path.
    """
    def __init__(self, filename):
        super(Mmap, self).__init__()
        self._filename = filename
        self._f = None
        self._mmap = None

    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._mmap = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        return self._mmap

    def __exit__(self, type, value, traceback):
        self._mmap.close()
        self._f.close()


class EvtxLogs(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """
    class for extracting EVTX logs
    """


    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:        
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            #requirements.VersionRequirement(name = 'info', component = info.Info, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = str,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True),
            requirements.BooleanRequirement(name = 'include-corrupt',
                                            description = "Include non-valid records (substitutions)",
                                            default = False,
                                            optional = True),                        
        ]

    def decode_binary_string(self, s):
        try:            
            result = "".join(map(chr,s))
        except:
            result = s
        return result
    
    def _generator(self, show_corrupt_results: Optional[bool] = None, pids = None):

        #generator - load memory dump and extract EVTX data
        
        VALUE = 1

        image_path = self.config.get('primary.memory_layer.location',None)
        if image_path is None:
            image_path = self.config.get('primary.memory_layer.base_layer.location',None)
        image_path = image_path.replace('file://', '')
        image_path = image_path.replace('file:', '')
        image_path = image_path.replace('%28', '(')
        image_path = image_path.replace('%29', ')')
        
        if show_corrupt_results:
            sub = 2
        else:
            sub = 0

        with Mmap(image_path) as buf:
            # this does a full scan of the file (#1)
            chunks = set(evtxtract.carvers.find_evtx_chunks(buf))
            
            valid_record_offsets = set([])
            for chunk in chunks:
                for record in evtxtract.carvers.extract_chunk_records(buf, chunk):
                    valid_record_offsets.add(record.offset)                   
                    try:
                        xmldoc = minidom.parseString(record.xml)
                        xml_event = xmldoc.documentElement                  
                        xml_erid = xmldoc.getElementsByTagName('EventRecordID')[0].firstChild.nodeValue
                        xml_channel = xmldoc.getElementsByTagName('Channel')[0].firstChild.nodeValue
                        xml_pid = xmldoc.getElementsByTagName('Execution')[0].getAttribute("ProcessID")
                        xml_tid = xmldoc.getElementsByTagName('Execution')[0].getAttribute("ThreadID")
                        xml_time = datetime.datetime.strptime(xmldoc.getElementsByTagName('TimeCreated')[0].getAttribute("SystemTime"),"%Y-%m-%d %H:%M:%S.%f")
                        #xml_provider = xmldoc.getElementsByTagName('Provider')[0].getAttribute("Name")
                        xml_keywords = xmldoc.getElementsByTagName('Keywords')[0].firstChild.nodeValue
                        xml_secuserid = xmldoc.getElementsByTagName('Security')[0].getAttribute("UserID")  
                        xml_data = xmldoc.getElementsByTagName('Data')[0].firstChild.nodeValue
                        if (not pids) or (xml_pid in pids):                       
                            yield (0, (str(record.offset), str(record.eid), "y", xml_time, str(xml_pid), str(xml_tid), str(xml_erid), str(xml_channel), str(xml_keywords), str(xml_secuserid), str(xml_data)))
                    except Exception as e:
                        logger.info('Error generator %s', str(e))
                        pass
                    
                # map from eid to dictionary mapping from templateid to template
                templates = collections.defaultdict(dict)
                for chunk in chunks:
                    for template in evtxtract.carvers.extract_chunk_templates(buf, chunk):
                        templates[template.eid][template.get_id()] = template

                # this does a full scan of the file (#2).
                # needs to be distinct because we must have collected all the templates
                # first.
                for record_offset in evtxtract.carvers.find_evtx_records(buf):
                    if record_offset in valid_record_offsets:
                        continue

                    try:
                        record = evtxtract.carvers.extract_record(buf, record_offset)
                    except evtxtract.carvers.ParseError as e:
                        logger.info('parse error for record at offset: 0x%x: %s', record_offset, str(e))
                        continue
                    except ValueError as e:
                        logger.info('timestamp parse error for record at offset: 0x%x: %s', record_offset, str(e))
                        continue
                    except Exception as e:
                        logger.info('unknown parse error for record at offset: 0x%x: %s', record_offset, str(e))
                        continue

                    if len(record.substitutions) < 4:
                        logger.info('too few substitutions for record at offset: 0x%x', record_offset)
                        continue

                    # we just know that the EID is substitution index 3
                    eid = record.substitutions[3][VALUE]

                    matching_templates = set([])
                    for template in templates.get(eid, {}).values():
                        if template.match_substitutions(record.substitutions):
	                         matching_templates.add(template)                                          
                  
                    if (sub > 0) & (len(matching_templates) == 0):                        
                        logger.info('no matching templates for record at offset: 0x%x', record_offset)
                        xml_time = "?"
                        xml_erid = "?"
                        xml_pid = "?"
                        xml_tid = "?"
                        xml_time = "?"
                        xml_keywords = "?"
                        xml_secuserid = "?"
                        xml_last = "?"
                        for i, (type_, value) in enumerate(record.substitutions):
                            if (type_ == 10):
                                   xml_erid = str(value)
                            if (type_ == 17):
                                   xml_time = value
                            if (type_ == 8) & (xml_pid is "?"):
                                   xml_pid = str(value)
                            if (type_ == 8):
                                   xml_tid = str(value)
                            if (type_ == 19):
                                   xml_secuserid = str(value)
                            #if (type_ == 5):
                            #       xml_keywords = str(value)
                            xml_last = self.decode_binary_string(value)
                        xml_keywords = record.substitutions[5][VALUE]  
                        if (not pids) or (xml_pid in pids):                      
                            yield (0, (str(record_offset), str(eid), "n", xml_time, str(xml_pid), str(xml_tid), str(xml_erid), "?", str(xml_keywords), str(xml_secuserid), str(xml_last)))                        
                        continue

                    if (sub > 1) & (len(matching_templates) > 1):
                        logger.info('too many templates for record at offset: 0x%x', record_offset)
                        xml_time = "?"
                        xml_erid = "?"
                        xml_pid = "?"
                        xml_tid = "?"
                        xml_time = "?"
                        xml_keywords = "?"
                        xml_secuserid = "?"
                        xml_last = "?"
                        for i, (type_, value) in enumerate(record.substitutions):
                            if (type_ == 10):
                                   xml_erid = str(value)
                            if (type_ == 17):
                                   xml_time = value
                            if (type_ == 8) & (xml_pid is "?"):
                                   xml_pid = str(value)
                            if (type_ == 8):
                                   xml_tid = str(value)
                            if (type_ == 19):
                                   xml_secuserid = str(value)
                            #if (type_ == 5):
                            #       xml_keywords = str(value)
                            xml_last = self.decode_binary_string(value)
                        xml_keywords = record.substitutions[5][VALUE]    
                        if (not pids) or (xml_pid in pids):         
                            yield (0, (str(record_offset), str(eid), "n", xml_time, str(xml_pid), str(xml_tid), str(xml_erid), "?", str(xml_keywords), str(xml_secuserid), str(xml_last)))
                        continue
                    
                    try:
                        template = list(matching_templates)[0]

                        record_xml = template.insert_substitutions(record.substitutions)
                    
                        xmldoc = minidom.parseString(record_xml)
                        xml_event = xmldoc.documentElement                  
                        xml_erid = xmldoc.getElementsByTagName('EventRecordID')[0].firstChild.nodeValue
                        xml_channel = xmldoc.getElementsByTagName('Channel')[0].firstChild.nodeValue
                        xml_pid = xmldoc.getElementsByTagName('Execution')[0].getAttribute("ProcessID")
                        xml_tid = xmldoc.getElementsByTagName('Execution')[0].getAttribute("ThreadID")
                        xml_time = datetime.datetime.strptime(xmldoc.getElementsByTagName('TimeCreated')[0].getAttribute("SystemTime"),"%Y-%m-%d %H:%M:%S.%f")
                        #xml_provider = xmldoc.getElementsByTagName('Provider')[0].getAttribute("Name")
                        xml_keywords = xmldoc.getElementsByTagName('Keywords')[0].firstChild.nodeValue
                        xml_secuserid = xmldoc.getElementsByTagName('Security')[0].getAttribute("UserID") 
                        xml_data = xmldoc.getElementsByTagName('Data')[0].firstChild.nodeValue
                        if (not pids) or (xml_pid in pids):                                                
                            yield (0, (str(record_offset), str(eid), "y", xml_time, str(xml_pid), str(xml_tid), str(xml_erid), str(xml_channel), str(xml_keywords), str(xml_secuserid), str(xml_data)))
                    except Exception as e:
                        logger.info('Error generator %s', str(e))
                        pass

    def generate_timeline(self):
        for row in self._generator(show_corrupt_results = False):
            _depth, row_data = row
            # Skip entries without creation time
            if not isinstance(row_data[3], datetime.datetime):
                logger.info('Error no datetime Object found')
                continue
            row_data = [
                "N/A" if isinstance(i, renderers.UnreadableValue) or isinstance(i, renderers.UnparsableValue) else i
                for i in row_data
            ]            
            description = "Event EVTX: EID {} PID {} ThreadID {} " \
                          "EventRecordID {} Channel {} Keywords {} SecurityUserID {} Data {}".format(row_data[1], row_data[4],
                                                                              row_data[5], row_data[6],
                                                                              row_data[7], row_data[8],
                                                                              row_data[9], row_data[10])            
            yield (description, timeliner.TimeLinerType.CREATED, row_data[3])



    def run(self):     
        show_corrupt_results = self.config.get('include-corrupt', None) 
        show_pids = self.config.get('pid', None)   
        return renderers.TreeGrid([("Offset", str), ("EventID", str), ("Valid", str), ("Time", datetime.datetime), ("PID", str), ("ThreadID", str), ("EventRecordID", str), ("Channel", str), ("Provider", str), ("Sec-UserID", str), ("Data", str)], self._generator(show_corrupt_results = show_corrupt_results, pids = show_pids)) 
