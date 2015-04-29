# -*- coding: utf-8 -*-
# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Falco shopfloor proxy implementation.

Defaults to using the path /opt/sdt to communicate with the backend,
but this may be modified using the FALCO_SHOPFLOOR_BACKEND environment
variable.
"""

import binascii
import collections
import csv
import logging
import os
import re
import time

import factory_common  # pylint: disable=W0611

from cros.factory.shopfloor import ShopFloorBase
from cros.factory.l10n.regions import REGIONS
from pymssql import connect

# set to True to enable MSDB
_MSDB = True 
# TODO(bowgotsai): figure out the pattern for serial number.
MLB_SERIAL_NUMBER_RE = r'.*'
SERIAL_NUMBER_RE = r'.*'

RequestType = collections.namedtuple(
    'RequestType', ('request_dir', 'response_dir', 'request_suffix',
                    'require_line', 'msdb_host', 'msdb_user',
                    'msdb_password', 'msdb_database', 'msdb_sp',
                    'msdb_bu', 'msdb_station', 'msdb_step'))


class RequestTypes(object):
  LIGHT = RequestType(
      'CQ_Monitor/Request', 'CQ_Monitor/Response', '', None,
      '10.18.5.121', 'SDT', 'SDT#7', 'QMS', 'MonitorPortal',
      'NB5', 'RUNIN', 'ALIVE')
	  
  LIGHT_UPDATE = RequestType(
      'CQ_Monitor/Request', 'CQ_Monitor/Response', '', None,
      '10.18.5.121', 'SDT', 'SDT#7', 'QMS', 'MonitorPortal',
      'NB5', 'RUNIN', 'TEST')

  FA_START = RequestType(
      'CQ_Monitor/Request', 'CQ_Monitor/Response', '', None,
      '10.18.5.121', 'SDT', 'SDT#7', 'QMS', 'MonitorPortal',
      'NB5', 'SWDLTest', 'Request')
  FA_START_FAT = RequestType(
      'CQ_Monitor/Handshake', 'CQ_Monitor/HandShakeResp', '', None,
      '10.18.5.121', 'SDT', 'SDT#7', 'QMS', 'MonitorPortal',
      'NB5', 'SWDLTest', 'Handshake')

  FA_START_FRT = RequestType(
      'CQ_Monitor/Handshake', 'CQ_Monitor/HandShakeResp', '', None,
      '10.18.5.121', 'SDT', 'SDT#7', 'QMS', 'MonitorPortal',
      'NB5', 'FRT', 'Request')      
#adam++      'nft/Request', 'nft/Response','' , 'STATION=FAT')
  HWID_COMPLETE = RequestType(
#adam++      'CQ_Monitor/Handshake', 'CQ_Monitor/HandShakeResp', '', None)
      'CQ_Monitor2/Request', 'CQ_Monitor2/Response', '.OK', None,
      '10.18.5.121', 'SDT', 'SDT#7', 'QMS', 'MonitorPortal',
      'NB5', 'SWDL', 'Request')      #adam++
  FA_END = RequestType(
      'CQ_Monitor2/Handshak', 'CQ_Monitor2/HandResp', '.OK', None,
      '10.18.5.121', 'SDT', 'SDT#7', 'QMS', 'MonitorPortal',
      'NB5', 'SWDL', 'Handshake')
  # This is called by reset shim, after FQA testing

  ALL = [FA_START, FA_START_FAT, FA_START_FRT, HWID_COMPLETE, FA_END]

class ShopFloorBackendException(Exception):
  pass


class Response(object):
  """Shop floor server response.

  Properties:
    path: The path of the response file.
    args: A dictionary of arguments passed in the response.
  """
  def __init__(self, path, args):
    self.path = path
    self.args = args

  def CheckPass(self):
    """Checks for a passing or failing line.

    Raises:
      ShopFloorBackendException if ERR_MSG is present, or none of
        RESULT/CheckResult/SF_CFG_CHK have a PASS value.
    """
    err_msg = (self.args.get('ERR_MSG'))
    if err_msg:
       if err_msg.find('The Status: 5Q') != -1:
          pass
       else:
          raise ShopFloorBackendException(
            'Error %r in response %s' % (err_msg, self.path))

    result = (self.args.get('RESULT') or
              self.args.get('CheckResult') or
              self.args.get('SF_CFG_CHK'))
    if result != 'PASS':
       if err_msg.find('The Status: 5Q') != -1:
          pass
       else: 
          raise ShopFloorBackendException(
            'Expected PASS in response %s, but got %r' % (self.path, result))

def ParseKeyValuePairs(data, remove_set_prefix=False, msdb=False):
  """Parses key/value pairs in a request/response file.

  Invalid lines are logged and ignored.

  Args:
    data: An input string, e.g., 'A=B\nC=D\n'
    remove_set_prefix: If True, the prefix "set " (case-insensitive)
      is removed from each line.

  Returns:
    A dictionary, e.g., {'A': 'B', 'C': 'D'}
  """
  ret = {}
  # Use split('\r\n') rather than splitlines(); we want to be strict
  # (as is the real backend).
  sep = ';$;' if msdb else '\r\n'
  for line in filter(None, data.split(sep)):
    if remove_set_prefix:
      line = re.sub(r'(?i)^set ', '', line)
    key, equals, value = line.partition('=')
    if equals:
      ret[key] = value
    else:
      logging.error('Invalid line %r', line)
  return ret


def FormatKeyValuePairs(args, msdb=False):
  """Formats key/value pairs in a request/response file.

  Args:
    args: A tuple of key/value pairs, e.g., (('A', 'B'), ('C', 'D')),
      or a dictionary, e.g., {'A': 'B', 'C': 'D'}.  Values are coerced
      to strings; None represents an empty string.

  Returns:
    A string, e.g., 'A=B\nC=D\n'
  """
  if type(args) == dict:
    args = sorted(args.items())
  if msdb:
    return ''.join(
        '%s=%s;$;' % (k, "" if v is None else str(v)) for k, v in args)
  else:
    return ''.join(
        '%s=%s\r\n' % (k, "" if v is None else str(v)) for k, v in args)

def Now():
  """Returns the current time (may be stubbed out)."""
  return time.time()


def FormatBackendTime():
  """Formats the current time for use by the backend."""
  return time.strftime('%Y%m%d%H%M%S', time.localtime(Now()))


def FormatTime():
  """Formats the current time."""
  return time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(Now()))


class ShopFloor(ShopFloorBase):
  """Falco shopfloor proxy.

  Properties (may be changed by clients):
    base_path: Base path of shopfloor server.
    timeout_secs: Timeout for requests.
    initial_poll_interval_secs: Initial interval to use to poll for responses.
      The client will poll at exponentially increasing intervals (*2, *4, etc.)
      until it succeeds or the timeout interval is reached.
    request_hook: A hook that will be invoked after setting up each request.
      This can be set for testing to force the mock server to scan for request
      files.
    mlb_sn_re: Pattern that all MLBs must match.
    device_sn_re: Pattern that all device SNs must match.
  """
  base_path = os.environ.get('FALCO_SHOPFLOOR_BACKEND', '/opt/sdt')
  timeout_secs = 300
  initial_poll_interval_secs = 6
  request_hook = None
  mlb_sn_re = re.compile(MLB_SERIAL_NUMBER_RE)
  device_sn_re = re.compile(SERIAL_NUMBER_RE)

  @classmethod
  def GenerateRequestID(cls):
    """Generates a random 8-character hex string to use as a request ID."""
    return binascii.hexlify(os.urandom(4))
  @classmethod
  def CheckMLBSN(cls, mlb_sn):
    """Checks that the motherboard serial number matches the expected
    pattern.

    Args:
      mlb_sn: The MLB serial number.

    Raises:
      ShopFloorBackendException if invalid.
    """
    if not cls.mlb_sn_re.match(mlb_sn):
      raise ShopFloorBackendException(
          'MLB %r is invalid (does not match %s)' % (
              mlb_sn, cls.mlb_sn_re.pattern))

  @classmethod
  def _CheckDeviceSN(cls, device_sn):
    """Checks that the motherboard serial number matches the expected
    pattern.

    Args:
      device_sn: The device serial number.

    Raises:
      ShopFloorBackendException if invalid.
    """
    if not cls.device_sn_re.match(device_sn):
      raise ShopFloorBackendException(
          'device %r is invalid (does not match %s)' % (
              device_sn, cls.device_sn_re.pattern))

  def _CallBackend(self, request_type, mlb_sn, args, rm_response=False, msdb=False):
    """Performs a request and returns the response dictionary.

    Args:
      request_type: A RequestType object.
      mlb_sn: The MLB serial number.
      args: The request arguments, a tuple of key-value tuples.  E.g.:
        (('OPID', operator_id),).  The MB_NUM argument is automatically
        prepended to this list.

    Returns:
      A Response object.
    """
    assert self.base_path, 'Base path has not yet been set'

    args = (('MB_NUM', mlb_sn),('MB', mlb_sn)) + args
    data = FormatKeyValuePairs(args, msdb)
    logging.info('DEBUG: request data is "%s"', data)
    # Get response directly from MSDB
    if msdb:
      try:
        conn = connect(host = request_type.msdb_host,
                   user = request_type.msdb_user,
                   password = request_type.msdb_password,
                   database = request_type.msdb_database,
                   login_timeout = 30)
      except Exception as e:
        logging.info('DEBUG: connect Exception: %s', e)
        time.sleep(2)
        return None
      
      sql = '''
DECLARE @ReturnValue varchar(2400)
EXEC %s '%s','%s','%s','%s',@ReturnValue output
SELECT @ReturnValue ''' %(request_type.msdb_sp, request_type.msdb_bu, 
                     request_type.msdb_station, request_type.msdb_step, data)
      try:
        cur = conn.cursor()
        cur.execute(sql)
        data = cur.fetchall()[0]
        cur.close()
        conn.commit()
        data = ''.join(data[0])
        logging.info('DEBUG: SF response msg is "%s"', data)
      except Exception as e:
        logging.info('DEBUG: operate Exception: %s', e)
        conn.close()
        conn = None
      conn.close()
    # Get response by file exchange
    else:
      None
    
    return Response(
        None if msdb else response_path,
        ParseKeyValuePairs(data, True, msdb))

  def Light(self, mlb_sn, device_data, Info):
    response = self._CallBackend(
        RequestTypes.LIGHT, mlb_sn,
        (('Serial_Number', device_data['serial_number']),
         ('Step', Info[0]),
         ('NextStep', Info[1]),
         ('Interval', Info[2]),
         ('ErrorCode', Info[3])),
         True,
         _MSDB
         )

  def LightUpdate(self, mlb_sn, device_data, Info, ip, port):
    response = self._CallBackend(
        RequestTypes.LIGHT_UPDATE, mlb_sn,
        (('Serial_Number', device_data['serial_number']),
         ('Step', Info[0]),
         ('NextStep', Info[1]),
         ('Interval', Info[2]),
         ('ErrorCode', Info[3]),
         ('DL_SWITCHIP', device_data['switchip']),
         ('DL_PORT', device_data['switchport'])),
         True,
         _MSDB
         )
		 				
  @staticmethod
  def TranslateResponseKeys(key_translation, response):
    """Translates keys of a factory response.

    Each factory has its own convention. We use this function to convert
    response keys to factory test's convention.

    It also assumes all keys in key_mapping is required.

    Args:
      key_translation: {backend key : translated key}
      response: factory shopfloor's response.

    Returns:
      Translated response.args (only contains keys in key_translation).

    Raises:
      ShopFloorBackendException if a key in key_mapping does not exist in
      response.
    """
    # Check for missing keys.
    missing_keys = set(key_translation.keys()) - set(response.args.keys())
    if missing_keys:
      raise ShopFloorBackendException(
          'Missing keys in response %s: %s',
          response.path, ', '.join(sorted(missing_keys)))

    return dict((ret_key, response.args[backend_key])
                for backend_key, ret_key in key_translation.iteritems())

  def GetDeviceInfo(self, mlb_sn, device_data, ip, port):
    """Verifies a device serial number and gets information about the
    device's expected configuration.

    Communicates with the backend shopfloor server, verifies that the
    device SN is valid, and obtains information about the
    expected configuration of the device.

    This corresponds to 'Sent Request file', 'Get Response file',
    'Sent Request File (FAT)', and 'Get Response file (FAT)' in
    the FA Test Process Flowchart.

    Args:
      mlb_sn: The MLB serial number.

    Returns:
      A dictionary containing information about the expected
      configuration of the device.

    Raises:
      An exception if the device SN is invalid, or if unable to communicate
      with the backend shopfloor server.
    """
    self.CheckMLBSN(mlb_sn)
    response = self._CallBackend(RequestTypes.FA_START, mlb_sn, (('DL_SWITCHIP', device_data['switchip']), ('DL_PORT', device_data['switchport']),), True, _MSDB)
    response.CheckPass()

    # Translate shopfloor fields into the types we expect.
    key_translation = {
        'SN': 'serial_number',
        'aux1': 'component.main_antenna',
        'aux2': 'component.aux_antenna',
        'Family': 'component.keyboard',
        'AMT': 'component.pcb_vendor',
        'mechanical': 'component.camera',
        #YG: 'CHK_CODE': 'ubind_attribute',
        #YG: 'PART_NUMBER': 'gbind_attribute',
        'Registration_Code': 'ubind_attribute',
        'Group_code': 'gbind_attribute',
        'KB_COUNTRY': 'keyboard_back',
        'LINE': 'line',
        'HPPN': 'mpn',  # Manufacturer part number
        'SKU': 'sku_number',
        'hdd_size': 'hddsize',
        'aux2': 'ramsize',
        'bay_thi': 'bay_thi',
        'FQA_Flag':'FQA_FLAG',        
        }

    ret = self.TranslateResponseKeys(key_translation, response)

    # Checks serial number.
    self._CheckDeviceSN(ret['serial_number'])

    # Fix up 'uk'->'gb'
    #ret['region'] = re.sub('ABL', 'gb', ret['region'])
    quanta_google = {
        'ABU': ('gb','UK_API'),
        'ABA': ('us','US_API'),
        'ABF': ('fr','FR_API'),
        'ABD': ('de','DE_API'),
        'ABL': ('ca.hybrid','CAFR_API'),
        'ABG': ('au','US_API'),
        'ABH': ('nl','NL_API'),
        'UUW': ('nordic','SE_API'),
        'AB4': ('sg','US_API'),
        'ACJ': ('in','US_API'),
        'UUF': ('my','US_API'),
        'ACB': ('ru','RU_API'),
        'UUZ': ('ch','CH_API'),
        'ABM': ('latam-es-419','MX_API'),
        'AKH': ('latam-es-419','MX_API'),
        'UUG': ('be','BE_API'),
        'ABE': ('es','ES_API'),
        'ABZ': ('it','IT_API'),		
        }
    ret['region'] = quanta_google[ret['sku_number'][8:]][0]
    ret['keyboard'] = quanta_google[ret['keyboard_back']][0]
    ret['component.keyboard'] = quanta_google[ret['keyboard_back']][1]
    if ret['FQA_FLAG'] == 'Y':
      ret['status.fqa'] = True
      ret['status.notfqa'] = False
    else:
      ret['status.notfqa'] = True     
      ret['status.fqa'] = False   

    # Check region for validity.  Note that this means that if new regions
    # are added, the shopfloor par will need to be updated (or this check
    # removed), but better safe than sorry, at least at first.
    if ret['region'] not in REGIONS:
      raise ShopFloorBackendException, (
          ("Region %r (from shopfloor server response Country=%r) "
           "should be one of %r") %
          (ret['region'], response.args['Family'], sorted(REGIONS.keys())))

    # Fix up Boolean type.
    try:
      #cellular = response.args['Cellular']
      cellular = response.args['WWAN']
#      if response.args['PART_NUMBER'] == '1Y01BXU0TP2':
# 		cellular = 'Y'
      ret['component.has_cellular'] = {
          'HUAWEI': True, 'NONE': False}[cellular]
      #YG: Cancel for PV Build: 20130804: ret['ubind_attribute']='002f0888552df70796c476d99ff5e1c413853d39cf39d8db6344fbb22d966eb7df23f86e'
      #YG: Cancel for PV Build: 20130804: ret['gbind_attribute']='cf6c04eafb35afcc06f5fa7601c5a3e1e118ace4dc4bab72cc3ce43b22ebcb94b4db1bf1'
      ## YG: 
      ret['component.pcb_vendor']='ANY'
      ret['component.main_antenna']='ANY'
      ret['component.aux_antenna']='ANY'
      ret['component.antenna']='ANY'
      #ret['component.keyboard']='us_unknown'	# US_API
      #YG: cheat :p if response.args['PART_NUMBER'] == '1Y01BXU0TP2':
      #YG: ret['component.keyboard']='us_unknown'
      #YG: if !'ABA' ==> UK: if 'us' == ret['region'] 
      #ret['component.keyboard']='US_API'
      ret['component.keyboard'] = quanta_google[ret['keyboard_back']][1]
      ret['model_name']='HP Chromebook 14'
    except KeyError:
      raise ShopFloorBackendException, (
          "Invalid value %r for Cellular (should be Y or N)" % cellular)
    # if os.path.exists('/opt/sdt/CQ_Monitor/response/' + mlb_sn):
        # os.remove('/opt/sdt/CQ_Monitor/response/' + mlb_sn)

    # response = self._CallBackend(RequestTypes.FA_START_FAT, mlb_sn,
                                 # (('STATION', 'FAT'),))
    # response.CheckPass()
   # if os.path.exists('/opt/sdt/CQ_Monitor/response/' + mlb_sn):
   #     os.remove('/opt/sdt/CQ_Monitor/response/' + mlb_sn)
    # if os.path.exists('/opt/sdt/CQ_Monitor/handshakeresp/' + mlb_sn):
        # os.remove('/opt/sdt/CQ_Monitor/handshakeresp/' + mlb_sn)
    return ret

  def FinishFRT(self, mlb_sn, device_data, sn):
    response = self._CallBackend(
        RequestTypes.FA_START_FRT, mlb_sn,
        (('SN', device_data['serial_number']),),
         True,
         _MSDB
         )
    response.CheckPass()
    
  def FinishHWID(self, mlb_sn, device_data, Info ):
    """Informs the backend shopfloor server that HWID verification is complete.

    This corresponds to 'Send Handshake1 request file' and 'Get
    Handshake1 response file' in the FA Test Process Flowchart.

    Args:
      mlb_sn: The device serial number.

    Raises:
      An exception if the device SN is invalid, or if unable to communicate
      with the backend shopfloor server.
    """

    self.CheckMLBSN(mlb_sn)
    response = self._CallBackend(RequestTypes.HWID_COMPLETE, mlb_sn,
                      (('Serial_Number', device_data['serial_number']),
                       ('WL_MAC',Info[0]), #adam++
                       ('Date', FormatBackendTime())),
                       True,
                       _MSDB                       
                       )    
    response.CheckPass()
    
    key_translation = {
        'bay_thi': 'bay_thi',
        }

    ret = self.TranslateResponseKeys(key_translation, response)
    
    return ret
#adam++ Start
  def FinishFA2(self, mlb_sn, device_data, Info):
    """Informs the backend shopfloor server that the entire FA Test
    Process is complete and the machine is about to be finalized. Saves the
    report_blob to persistent storage for later uploading to Google.

    This corresponds to 'Send Handshake2 request file' and 'Get
    Handshake2 response file' in the FA Test Process Flowchart.

    Args:
      mlb_sn: The device serial number.
      device_data: The complete device data dictionary (which must
        include the 'serial_number', 'hwid', 'ubind_attribute', and
        'gbind_attribute' fields).

    Raises:
      An exception if the MLB or device SN is invalid, or if unable to
      communicate with the backend shopfloor server.
    """
    ##YG: D2 Shopfloor
    self.CheckMLBSN(mlb_sn)
    response = self._CallBackend(
        RequestTypes.FA_END, mlb_sn,
        ##(('SF_QCI_SN', device_data['serial_number']),
        (('Serial_Number', device_data['serial_number']),
         ('MOTHERBRD_SN', device_data['mlb_serial_number']),        
         # ('HWID', device_data['hwid']),
         ('WL_MAC',Info[0]), #adam++
	       ('BT_MAC',Info[1]), #adam++         
        # ('PCID', '0123456789QWERTYUIOPASDFG'), ))
	       ('ICCID',''), #adam++        
         ('Registration_Code', device_data['ubind_attribute']),
         ('Group_code', device_data['gbind_attribute']),
         ('WWAN', device_data.get('imei'))),
         True,
         _MSDB           
         )
    response.CheckPass()
#adam++ End

#adam++  def FinishFA(self, mlb_sn, device_data):
  def FinishFA(self, mlb_sn, device_data, Info):	#adam++
    """Informs the backend shopfloor server that the entire FA Test
    Process is complete and the machine is about to be finalized. Saves the
    report_blob to persistent storage for later uploading to Google.

    This corresponds to 'Send Handshake2 request file' and 'Get
    Handshake2 response file' in the FA Test Process Flowchart.

    Args:
      mlb_sn: The device serial number.
      device_data: The complete device data dictionary (which must
        include the 'serial_number', 'hwid', 'ubind_attribute', and
        'gbind_attribute' fields).

    Raises:
      An exception if the MLB or device SN is invalid, or if unable to
      communicate with the backend shopfloor server.
    """
    ##YG: D2 Shopfloor
    self.CheckMLBSN(mlb_sn)
    response = self._CallBackend(
        RequestTypes.FA_END, mlb_sn,
        ##(('SF_QCI_SN', device_data['serial_number']),
        (('Serial_Number', device_data['serial_number']),
         ('MOTHERBRD_SN', device_data['mlb_serial_number']),
         ('HWID', device_data['hwid']),
          ('WL_MAC',Info[0]), #adam++
        ('BT_MAC',Info[1]), #adam++
	# ('IMEI', Info[2]), #adam++
	       ('ICCID',''), #adam++
        # ('PCID', '0123456789QWERTYUIOPASDFG'),
        # ('SystemID', '0178'),
         ('Registration_Code', device_data['ubind_attribute']),
         ('Group_code', device_data['gbind_attribute']),
         ('WWAN', device_data.get('imei'))),
         True,
         _MSDB
         )
    # if len(Info) == 3:
    	# response = self._CallBackend(
        # RequestTypes.FA_END, mlb_sn,
        #(('SF_QCI_SN', device_data['serial_number']),
        # (('Serial_Number', device_data['serial_number']),
         # ('MOTHERBRD_SN', device_data['mlb_serial_number']),
         # ('HWID', device_data['hwid']),
	       # ('WL_MAC',Info[0]), #adam++
	       # ('BT_MAC',Info[1]), #adam++
	# ('IMEI', Info[2]), #adam++
        # ('PCID', '0123456789QWERTYUIOPASDFG'),
        # ('SystemID', '0178'),
	       # ('ICCID',''), #adam++        
         # ('Registration_Code', device_data['ubind_attribute']),
         # ('Group_code', device_data['gbind_attribute']),
         # ('WWAN', device_data.get('imei'))),
         # True,
         # _MSDB         
         # )
    # if len(Info) == 4:
    	# response = self._CallBackend(
        # RequestTypes.FA_END, mlb_sn,
        #(('SF_QCI_SN', device_data['serial_number']),
        # (('Serial_Number', device_data['serial_number']),
         # ('MOTHERBRD_SN', device_data['mlb_serial_number']),
         # ('HWID', device_data['hwid']),
	       # ('WL_MAC',Info[0]), #adam++
	       # ('BT_MAC',Info[1]), #adam++
	# ('IMEI', Info[2]), #adam++
	       # ('ICCID',''), #adam++
         # ('PCID', '0123456789QWERTYUIOPASDFG'),
         # ('SystemID', '0178'),
         # ('Registration_Code', device_data['ubind_attribute']),
         # ('Group_code', device_data['gbind_attribute']),
         # ('WWAN', device_data.get('imei'))),
         # True,
         # _MSDB    
         # )
    response.CheckPass()

    self.LogRegistrationCodeMap(
        {'user': device_data['ubind_attribute'],
         'group': device_data['gbind_attribute']},
        hwid=device_data['hwid'])

  # pylint: disable=W0221
  def UploadReport(self, serial, report_blob, report_name=None, stage='FA'):
    self.SaveReport('%s-%s-%s.rpt.xz' % (stage, serial, FormatTime()),
                    self.UnwrapBlob(report_blob))

  def Finalize(self, serial):
    pass

  # These are not used; prevent pylint errors.
  def GetRegistrationCodeMap(self, *args, **kwargs):
    raise NotImplementedError()
  def GetVPD(self, *args, **kwargs):
    raise NotImplementedError()
  def CheckSN(self, *args, **kwargs):
    raise NotImplementedError()
  def GetAuxData(self, *args, **kwargs):
    raise NotImplementedError()
  def GetHWID(self, *args, **kwargs):
    raise NotImplementedError()
