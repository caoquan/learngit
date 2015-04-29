# -*- coding: utf-8 -*-
# Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Blaze shopfloor proxy implementation.

Defaults to using the path /opt/sdt to communicate with the backend,
but this may be modified using the BLAZE_SHOPFLOOR_BACKEND environment
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


# TODO(littlecvr): Find out the SN pattern.
MLB_SERIAL_NUMBER_RE = r'.*'
SERIAL_NUMBER_RE = r'.*'

RequestType = collections.namedtuple(
    'RequestType', ('request_dir', 'response_dir',
                    'request_suffix', 'require_line'))
# Properties:
#   request_dir: Directory into which the request is written by the client.
#   response_dir: Directory into which the response is written by the backend.
#   request_suffix: A suffix to strip from request filenames (.OK, for FA
#     requests).
#   require_line: If present, a line that must be present in requests to be
#     considered to be this request type.


class RequestTypes(object):
  SMT_START = RequestType(
      'CQ_FVS/request', 'CQ_FVS/response', '', None)
  SMT_END = RequestType(
      'CQ_FVS/result', None, '', None)
  FA_START = RequestType(
      'CQ_Monitor/Request', 'CQ_Monitor/Response', '', None)
  FA_START_FAT = RequestType(
      'CQ_Monitor/Handshake', 'CQ_Monitor/HandShakeResp', '', None)
  FA_END = RequestType(
      'CQ_Monitor2/Handshak', 'CQ_Monitor2/HandResp', '.OK', None)
  # This is called by reset shim, after FQA testing
  # This is for D2 station.
  FINISH_FQA = RequestType(
      'CQ_Monitor2/Request', 'CQ_Monitor2/Response', '.OK', None)
  # This is called by reset shim, for 45 station
  FA_END2 = RequestType(
      'CQ_Monitor2/Handshak', 'CQ_Monitor2/HandResp', '.OK', None)

  LCD_BOUNDING = RequestType(
      'CQ_Bunding/AIOTest', 'CQ_Bunding/AResponse', '', None)

  ALL = [SMT_START, SMT_END, FA_START, FA_START_FAT, FA_END,
         FINISH_FQA, FA_END2, LCD_BOUNDING]

# Country/Keyboard map of HP code
HP_COUNTRY_CODE = {
    'ABU' : ('gb','UK_API'),
    'ABA' : ('us','US_API'),
    'ABF' : ('fr','FR_API'),
    'ABD' : ('de','DE_API'),
    'ABL' : ('ca.hybrid','CAFR_API'),
    'ABG' : ('au','US_API'),
    'ABH' : ('nl','NL_API'),
    'UUW' : ('nordic','SE_API'),
    'AB4' : ('sg','US_API'),
    'ACJ' : ('in','US_API'),
    'UUF' : ('my','US_API'),
    'ACB' : ('ru','RU_API'),
    'UUZ' : ('ch','CH_API'),
    'ABM' : ('latam-es-419','MX_API'),
    'AKH' : ('latam-es-419','MX_API'),
}

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
    err_msg = self.args.get('ERR_MSG')
    if err_msg:
      raise ShopFloorBackendException(
          'Error %r in response %s' % (err_msg, self.path))

    result = (self.args.get('RESULT') or
              self.args.get('CheckResult') or
              self.args.get('SF_CFG_CHK'))
    if result != 'PASS':
      raise ShopFloorBackendException(
          'Expected PASS in response %s, but got %r' % (self.path, result))

  def CheckFVS(self):
    """Check at SMT end. This make sure SMT board had passed
       ShopFloor station correctly.

    Raises:
       ShopFloorBackendException if can't find 'FVS PASS'.
    """
    result = self.args.get('CheckResult')
    if not 'FVS Pass' in result:
      raise ShopFloorBackendException(
          'Expected FVS PASS in response %s, but got %r' % (self.path, result))

def ParseKeyValuePairs(data, remove_set_prefix=False):
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
  for line in filter(None, data.split('\r\n')):
    if remove_set_prefix:
      line = re.sub(r'(?i)^set ', '', line)
    key, equals, value = line.partition('=')
    if equals:
      ret[key] = value
    else:
      logging.error('Invalid line %r', line)
  return ret


def FormatKeyValuePairs(args):
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
  """Blaze shopfloor proxy.

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
  base_path = os.environ.get('BLAZE_SHOPFLOOR_BACKEND', '/opt/sdt')
  timeout_secs = 60
  initial_poll_interval_secs = 1
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

  def _CallBackend(self, request_type, mlb_sn, args):
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

    args = (('MB_NUM', mlb_sn),) + args
    data = FormatKeyValuePairs(args)
    request_path = os.path.join(
        self.base_path, request_type.request_dir,
        mlb_sn)

    # Remove previous response file if it exist
    if request_type.response_dir:
      response_path = os.path.join(
        self.base_path, request_type.response_dir,
        os.path.basename(request_path))
      if os.path.exists(response_path):
        os.remove(response_path)

    logging.info('Writing request file %s: %r', request_path, data)
    with open(request_path, 'w') as f:
      f.write(data)
    if request_type.request_suffix:
      # e.g., rename "FOO" to "FOO.OK"
      os.rename(request_path, request_path + request_type.request_suffix)

    if self.request_hook:
      self.request_hook()  # pylint: disable=E1102

    if not request_type.response_dir:
      # No response for this request type.
      return None

    response_path = os.path.join(
      self.base_path, request_type.response_dir,
      os.path.basename(request_path) + request_type.request_suffix)
    logging.info('Waiting for response file %s', response_path)

    start_time = time.time()
    poll_interval_secs = self.initial_poll_interval_secs
    while True:
      if os.path.exists(response_path):
        logging.info('Got response file %s.', response_path)
        break

      now = time.time()
      wait_secs = min(start_time + self.timeout_secs - now,
                      poll_interval_secs)
      if wait_secs < 0:
        # Just resend request again
        logging.info('Writing request file %s: %r again', request_path, data)
        with open(request_path, 'w') as f:
          f.write(data)
        if request_type.request_suffix:
          # e.g., rename "FOO" to "FOO.OK"
          os.rename(request_path, request_path + request_type.request_suffix)
        start_time = time.time()
        poll_interval_secs = self.initial_poll_interval_secs

      if wait_secs > 0:
        time.sleep(wait_secs)

      # Exponential backoff
      poll_interval_secs *= 2

    data = open(response_path).read()
    logging.info('Received response %s: %r', response_path, data)

    # Remove response file we just got
    os.remove(response_path)

    return Response(
        response_path,
        ParseKeyValuePairs(data, remove_set_prefix=True))

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

  def GetMLBInfo(self, mlb_sn, operator_id, station_id):
    """Starts the SMT process.

    Communicates with the backend shopfloor server, verifies that the
    MLB SN, operator ID and station ID are valid, and obtains
    information about the expected configuration of the MLB.

    This corresponds to the 'Send Request file' and 'Get Response file'
    steps in the PCBA Test Process Flowchart.

    Args:
      mlb_sn: The motherboard serial number.
      operator_id: The operator ID.
      station_id: The station ID.

    Returns:
      A dictionary containing information about the expected
      configuration of the MLB.  This is currently an empty dictionary
      since there are no significant MLB variants.

    Raises:
      An exception if the MLB SN is invalid, or if unable to communicate
      with the backend shopfloor server.
    """
    self.CheckMLBSN(mlb_sn)
    response = self._CallBackend(
        RequestTypes.SMT_START, mlb_sn,
        (('OPID', operator_id),
         ('STATION', station_id),
         ('Date', FormatBackendTime())))
    response.CheckPass()

    key_translation = {}
    return self.TranslateResponseKeys(key_translation, response)

  def FinishSMT(self, mlb_sn, device_data, report_blob_xz=None):
    """Completes the SMT process.

    Informs the backend shopfloor server that the SMT process is complete
    for the giving MLB. Once this is invoked and succeeds, GetMLBInfo and
    FinishSMT will never again be invoked for this MLB, even if the device is
    re-imaged.

    This corresponds to the 'Send FVS file (PASS log)'
    step in the PCBA Test Process Flowchart.

    Args:
      mlb_sn: The motherboard serial number.
      device_data: The SMT device data dictionary (which includes
        'smt_operator_id' and 'smt_station_id' fields).
      report_blob_xz: The xzipped report blob (optional).

    Raises:
      An exception if the MLB SN is invalid, or if unable to communicate
      with the backend shopfloor server.
    """
    report_blob_xz = self.UnwrapBlob(report_blob_xz)
    self.CheckMLBSN(mlb_sn)
    if report_blob_xz:
      self.SaveReport('SMT-%s-%s.rpt.xz' % (mlb_sn, FormatTime()),
                      report_blob_xz)
    self._CallBackend(RequestTypes.SMT_END, mlb_sn,
                      (('OPID', device_data['smt_operator_id']),
                       ('STATION', device_data['smt_station_id']),
                       ('RESULT', 'PASS'),
                       ('Date', FormatBackendTime())))

    # No response

  def GetFVSStatus(self, mlb_sn, operator_id, station_id):
    """End the SMT process.

    This is only to make sure tested board has correctly passed
    SMT station. We send request again and get response include
    'FVS PASS' then we'll sure this is been passed.

    Args:
      mlb_sn: The motherboard serial number.
      operator_id: The operator ID.
      station_id: The station ID.

    Raises:
      An exception if NO 'FVS PASS'.
    """
    self.CheckMLBSN(mlb_sn)
    response = self._CallBackend(
        RequestTypes.SMT_START, mlb_sn,
        (('OPID', operator_id),
         ('STATION', station_id),
         ('Date', FormatBackendTime())))
    response.CheckFVS()

  def GetDeviceInfo(self, mlb_sn):
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
    response = self._CallBackend(RequestTypes.FA_START, mlb_sn, ())
    response.CheckPass()

    # Translate shopfloor fields into the types we expect.
    key_translation = {
        'SN': 'serial_number',
        # TODO: Shopfloor don't response KB info in PV build
        # 'KB_COUNTRY': 'keyboard',
        # TODO: temp use fixed registration code for PV
        # 'Registration_Code': 'ubind_attribute',
        # 'Group_code': 'gbind_attribute',
        # 'Country': 'region',
        'SKU': 'sku_number',
        'LINE': 'line',
        'PART_NUMBER': 'mpn',  # Manufacturer part number
        'Color': 'color',
        'MODEL':'branding_name',
        }

    ret = self.TranslateResponseKeys(key_translation, response)

    # Checks serial number.
    self._CheckDeviceSN(ret['serial_number'])

    # Covert HP country code to Google style
    ret['region'] = HP_COUNTRY_CODE[ret['sku_number'][8:]][0]
    # TODO(Chia-Hsiu Chang): Temp use SKU last three numbers to determine KB country
    # ret['component.keyboard'] = HP_COUNTRY_CODE[ret['keyboard']][1]
    ret['component.keyboard'] = HP_COUNTRY_CODE[ret['sku_number'][8:]][1]

    # Fixed HP model name for Peach 2.0
    if ret['branding_name'] == 'Y07':
      ret['model_name'] = 'HP chromebook 15'
    else:
      ret['model_name'] = 'HP chromebook 15'

    # Fix up 'uk'->'gb'
    ret['region'] = re.sub('^uk', 'gb', ret['region'])
    # Fix up 'ca' -> 'ca.fr-CA'
    if ret['region'] == 'ca':
      ret['region'] = 'ca.fr'

    # TODO(Chia-Hsiu Chang): temp use fixed registration code for PV build
    ret['ubind_attribute'] = '3be6f952e77479284670890b3ed5e391cdb4af9328c2f6342c747707e68d70096fb10bb0'
    ret['gbind_attribute'] = '3be6f952e77479284670890b3ed5e391cdb4af9328c2f6342c747707e68d70096fb10bb0'

    # Check region for validity.  Note that this means that if new regions
    # are added, the shopfloor par will need to be updated (or this check
    # removed), but better safe than sorry, at least at first.
    if ret['region'] not in REGIONS:
      raise ShopFloorBackendException, (
          ("Region %r (from shopfloor server response Country=%r) "
           "should be one of %r") %
          (ret['region'], response.args['Country'], sorted(REGIONS.keys())))

    # Fix up Boolean type.
    try:
      cellular = response.args['WWAN']
      ret['component.has_cellular'] = {
          'Y': True, 'NONE': False}[cellular]
    except KeyError:
      raise ShopFloorBackendException, (
          "Invalid value %r for WWAN (should be Y or None)" % cellular)

    # Fix up component.has_lte boolean value.
    # ret['golden_imei'] and ret['golden_iccid'] should both be 'NONE' for
    # ret['component.has_lte'] = False.
    # if IMEI or ICCID is not present, it should be treated as 'NONE'.
    # TODO (cychiang) request IMEI and ICCID present in response file once
    # backend shopfloor changes to new format with these two fields..
    if 'IMEI' in response.args:
      ret['golden_imei'] = response.args['IMEI']
    else:
      logging.warning('Old config, no IMEI field, set golden_imei = "NONE"')
      ret['golden_imei'] = 'NONE'

    if 'ICCID' in response.args:
      ret['golden_iccid'] = response.args['ICCID']
    else:
      logging.warning('Old config, no ICCID field, set golden_iccid = "NONE"')
      ret['golden_iccid'] = 'NONE'

    if ret['golden_imei'] == 'NONE' and ret['golden_iccid'] == 'NONE':
      ret['component.has_lte'] = False
    else:
      # ret['golden_imei'] and ret['golden_iccid'] should both match the
      # expected pattern for component.has_lte = True.
      self.CheckLTEIMEI(ret['golden_imei'])
      self.CheckLTEICCID(ret['golden_iccid'])
      ret['component.has_lte'] = True

      # ret['component.has_lte'] and ret['component.has_cellular'] can not
      # be True at the same time.
      if ret['component.has_cellular'] == True:
        raise ShopFloorBackendException, (
            "has_lte and has_cellular can not be True at the same time")

    response = self._CallBackend(RequestTypes.FA_START_FAT, mlb_sn,
                                 (('STATION', 'FAT'),))
    response.CheckPass()

    return ret

  def FinishHWID(self, mlb_sn):
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
    response = self._CallBackend(
        RequestTypes.HWID_COMPLETE, mlb_sn, ())
    response.CheckPass()

  def FinishFQA(self, mlb_sn, sn, mac_addr):
    """Informs the backend shopfloor server that the machine is ready to ship.

    This call is invoked by reset shim before battery cutoff happens.
    This corresponds to 'Send Handshake3 request file' and 'Get
    Handshake3 response file' in the FA Test Process Flowchart.

    Args:
      mlb_sn: The motherboard serial number.
      sn: The system serial number.

    Raises:
      An exception if the MLB or device SN is invalid, or if unable to
      communicate with the backend shopfloor server.
    """
    self.CheckMLBSN(mlb_sn)
    self._CheckDeviceSN(sn)

    response = self._CallBackend(
        RequestTypes.FINISH_FQA, mlb_sn,
        (('MB', mlb_sn),
         ('Serial_Number', sn),
         ('MAC', mac_addr),
         ('Date', FormatBackendTime())))
    response.CheckPass()

  def FinishFA2(self, mlb_sn, sn, hwid, ubind, gbind, mac_addr):
    """
    """
    self.CheckMLBSN(mlb_sn)
    self._CheckDeviceSN(sn)

    response = self._CallBackend(
        RequestTypes.FA_END2, mlb_sn,
        (('MB', mlb_sn),
         ('Serial_Number', sn),
         ('HWID', hwid),
         ('Registration_Code', ubind),
         ('Group_code', gbind),
         ('BT_MAC', mac_addr),
         ('WWAN', '')))
    response.CheckPass()

  def FinishFA(self, mlb_sn, device_data, mac_addr):
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
    self.CheckMLBSN(mlb_sn)
    response = self._CallBackend(
        RequestTypes.FA_END, mlb_sn,
        (('MB', mlb_sn),
         ('Serial_Number', device_data['serial_number']),
         ('HWID', device_data['hwid']),
         ('Registration_Code', device_data['ubind_attribute']),
         ('Group_code', device_data['gbind_attribute']),
         ('BT_MAC', mac_addr),
         ('WWAN', '')))
    response.CheckPass()

    self.LogRegistrationCodeMap(
        device_data['hwid'], {
            'user': device_data['ubind_attribute'],
            'group': device_data['gbind_attribute']})

  def FinishLcdBounding(self, lcd_sn, opid):
    """
    Args:
      lcd_sn: LCD panel serial number
      opid: Operator ID

    Raises:
      An exception if unable to communicate with the backend shopfloor server.
    """
    response = self._CallBackend(
        RequestTypes.LCD_BOUNDING, lcd_sn,
        (('SN', lcd_sn),
         ('OPID', opid),
         ('RESULT', 'PASS')))
    response.CheckPass()

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
