#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


"""A mock shop floor backend for Falco.

The backend imitates the real backend's behavior by watching a fake
SMB mount point and reading/writing files, just as the real backend would.
This can be used in a few ways:

1. For unit testing.  (It is used by falco_shopfloor_unittest.py.)
2. For end-to-end testing of the factory test bundles.  We can:
   - create a mlbs.csv that contains one line per fake MLB
   - create a directory to serve as the fake SMB mount point
   - start falco_mock_shopfloor_backend
   - start falco_shopfloor with the fake mount point
3. For a real build if shopfloor integration is not working.  Same
   as above, but with a mlbs.csv file with *real* MLB information.
"""

import argparse
import csv
import logging
import os
import shutil
import threading

import factory_common  # pylint: disable=W0611

from cros.factory.shopfloor import falco_shopfloor
from cros.factory.shopfloor.falco_shopfloor import RequestTypes
from cros.factory.test import utils


class FalcoMockShopFloorBackend(object):
  """A mock shop floor backend for Falco.

  This acts like the factory backend server, but provides data read from
  static dictionaries.

  Properties:
    base_path: The base path to watch for requests.  This imitates the
      SMB-mounted path provided by the partner.
    mlbs: A dictionary of motherboards.  The key is the MLB serial
      number, and the value is a dictionary of fields provided by the
      GetDeviceInfo request.  E.g.:

        {'MLB00001': {'SF_QCI_SN': 'SN0001',
                      'QCI_Model': '00',
                      'Locale': 'en-US',
                      ...}}
    poll_interval_secs: Interval at which to poll for request files.
    request_count: Number of requests so far.

    For testing:
      mlb_phases: A set of tuples (mlb_sn, phase), where phase is one of
        ('smt', 'hwid', 'fa'), indicating which MLBs have run through which
        phases.
      {request,response}_paths: A list to which request/response paths will
        be appended (for testing), or None not to record this data.
      {request,response}_data: A list to which request/response data will be
        appended (for testing), or None not to record this data.

    _stop_event: An event to set to stop the running server.
  """
  poll_interval_secs = 0.1

  # Class variable.
  request_count = 0

  def __init__(self, base_path, mlbs, save_path=None):
    """Constructor.

    Args:
      base_path, mlbs: See class Properties.
      save_path: If true, saves all requests/responses under this root
        directory.
    """
    self.base_path = base_path
    self.mlbs = mlbs
    self.save_path = save_path

    self.mlb_phases = set()
    self.request_paths = None
    self.response_paths = None
    self.request_data = None
    self.response_data = None

    self._stop_event = threading.Event()

    for t in RequestTypes.ALL:
      for d in filter(None, [t.request_dir, t.response_dir]):
        path = os.path.join(self.base_path, d)
        logging.info('Creating %s', path)
        if not os.path.isdir(path):
          os.makedirs(path)

  def _SavePath(self, path):
    """Preserves a request or response file.

    Writes a copy into self.save_path, adding a numeric sequence
    corresponding to the request count for uniqueness.

    If self.save_path or path are not set, no action is taken.

    Args:
      path: The path to save.
    """
    if self.save_path and path:
      dest = os.path.join(self.save_path,
                          os.path.relpath(path, self.base_path) +
                          '.%05d' % FalcoMockShopFloorBackend.request_count)
      utils.TryMakeDirs(os.path.dirname(dest))
      shutil.copyfile(path, dest)

  def HandleRequest(self, request_type, request_path, args):
    """Handles a single request.

    Args:
      request_type: A RequestType object.
      request_path: Path to the request file.
      args: The input data (a dict).

    Returns:
      The output data (a dictionary) to be placed into the response file.
    """
    logging.info('Mock backend handling request file %s',
                 request_path)
    FalcoMockShopFloorBackend.request_count += 1

    self._SavePath(request_path)
    os.unlink(request_path)

    mlb_sn = args.get('MB_NUM')
    mlb = self.mlbs.get(mlb_sn)
    if not mlb:
      return (('ERR_MSG', 'Unknown MB_NUM %r' % mlb_sn),)

    if (request_type in [RequestTypes.SMT_START, RequestTypes.SMT_END] and
        (mlb_sn, 'smt') in self.mlb_phases):
      # Backend can't process SMT start/end after SMT is over.
      return (('ERR_MSG', 'MB_NUM %r has already finished SMT' % mlb_sn),)

    def AppendPhase(mlb_sn, phase):
      """Add a phase to self.mlb_phases."""
      self.mlb_phases.add((mlb_sn, phase))

    if request_type == RequestTypes.SMT_START:
      return (
          ('MB_NUM', mlb_sn),
          ('CheckResult', 'PASS'),
          ('ReturnRepair', 'N'),
          ('Line', 'M16'),
          ('Repaired', 'N'),
          ('FULLTEST', 'N'),
          ('Date', falco_shopfloor.FormatBackendTime()),
          ('User_code', mlb['User_code']),
          ('Group_code', mlb['Group_code'])
          )
    elif request_type == RequestTypes.SMT_END:
      AppendPhase(mlb_sn, 'smt')
      return (('RESULT', 'PASS'), ('MB_NUM', mlb_sn))
    elif request_type == RequestTypes.FA_START:
      return ( (('SF_CFG_CHK', 'PASS'), ('MB_NUM', mlb_sn))
               + tuple(sorted(mlb.items())) )
    elif request_type == RequestTypes.FA_START_FAT:
      return (('SF_CFG_CHK', 'PASS'), ('MB_NUM', mlb_sn))
    elif request_type == RequestTypes.HWID_COMPLETE:
      AppendPhase(mlb_sn, 'hwid')
      return (('SF_QCI_SN', mlb['SF_QCI_SN']), ('SF_CFG_CHK', 'PASS'))
    elif request_type == RequestTypes.FA_END:
      AppendPhase(mlb_sn, 'fa')
      missing_keys = (
          set(['SF_QCI_SN', 'User_code', 'Group_code', 'HWID']) -
          set(args.keys()))
      if missing_keys:
        return (('ERR_MSG', 'Request is missing keys %r' % (
            sorted(missing_keys))),)
      if args['SF_QCI_SN'] != mlb['SF_QCI_SN']:
        return (('ERR_MSG', 'SN mismatch for MB_NUM %r '
                 '(expected %r in request, got %r)' % (mlb_sn,
                                                       mlb['SF_QCI_SN'],
                                                       args['SF_QCI_SN'])),)
      return (('SF_QCI_SN', mlb['SF_QCI_SN']), ('SF_CFG_CHK', 'PASS'))
    else:
      raise ValueError('Unknown request type %r', request_type)

  def WriteResponse(self, request_type, request_path, response):
    """Writes a response.

    Args:
      request_type: The request type.
      request_path: Path to the input file.
      response: Response data (a dict).

    Returns:
      (response_path, response_data) if the given request_type yields a
      response (i.e., request_type.response_dir is not None); else
      (None, None).
    """
    if request_type.response_dir:
      response_path = os.path.join(self.base_path, request_type.response_dir,
                                   os.path.basename(request_path))
      # Strip request suffix, if any, when constructing the response
      # path.
      if (request_type.request_suffix and
          response_path.endswith(request_type.request_suffix)):
        response_path = response_path[:-len(request_type.request_suffix)]

      tmp_path = response_path + '.part'
      response_data = falco_shopfloor.FormatKeyValuePairs(
          ('SET ' + k, v) for k, v in response)
      with open(tmp_path, 'w') as f:
        f.write(response_data)
      os.rename(tmp_path, response_path)
      self._SavePath(response_path)
      return response_path, response_data
    else:
      return None, None

  def RunOnce(self):
    """Polls for requests and generates responses."""
    for request_type in RequestTypes.ALL:
      request_dir = os.path.join(self.base_path, request_type.request_dir)
      for filename in os.listdir(request_dir):
        request_path = os.path.join(request_dir, filename)
        if (request_type.request_suffix and
            not request_path.endswith(request_type.request_suffix)):
          continue

        with open(request_path) as f:
          request_data = f.read()

        if (request_type.require_line and
            request_type.require_line not in request_data.split('\r\n')):
          continue

        try:
          response = self.HandleRequest(
              request_type, request_path,
              falco_shopfloor.ParseKeyValuePairs(request_data))
        except:  # pylint: disable=W0702
          logging.exception('Exception in request handler')
          response = (('ERR_MSG', utils.FormatExceptionOnly()),)

        response_path, response_data = self.WriteResponse(
            request_type, request_path, response)

        if self.request_paths is not None:
          self.request_paths.append(
              os.path.relpath(request_path, self.base_path))
        if self.response_paths is not None:
          self.response_paths.append(
              os.path.relpath(response_path, self.base_path)
              if response_path else None)
        if self.request_data is not None:
          self.request_data.append(request_data)
        if self.response_data is not None:
          self.response_data.append(response_data)

  def Run(self):
    """Runs forever until stopped."""
    while True:
      self.RunOnce()
      self._stop_event.wait(self.poll_interval_secs)
      if self._stop_event.is_set():
        return

  def Stop(self):
    """Stops the running server."""
    self._stop_event.set()


def ReadMLBs(csvfile):
  """Reads MLB information from a CSV file."""
  mlbs = {}
  for n, line in enumerate(csv.DictReader(csvfile)):
    mlb_sn = line.pop('MB_NUM', None)
    if not mlb_sn:
      raise ValueError('Missing MB_NUM in row %d' % (n+1))
    if mlb_sn in mlbs:
      raise ValueError('Duplicate MB_NUM in row %d' % (n+1))
    falco_shopfloor.ShopFloor.CheckMLBSN(mlb_sn)
    mlbs[mlb_sn] = line
    logging.debug('Read MLB %s: %s', mlb_sn, line)
  return mlbs


def main():
  parser = argparse.ArgumentParser(
      description='Runs a fake shopfloor server backend.')
  parser.add_argument('--verbose', '-v', action='count')
  parser.add_argument(
      '--server-path', '-p',
      default=falco_shopfloor.ShopFloor.base_path,
      help=('Root path emulating the SMB server mount (default: %(default)s)'))
  parser.add_argument('mlbs', metavar='MLBS.csv', help=(
      'A CSV file of device info.  The first row gives column titles, which '
      'must correspond to fields returned by GetDeviceInfo.  The MB_NUM column '
      'contains the MLB serial number.'))
  args = parser.parse_args()
  logging.basicConfig(level=logging.INFO - 10 * (args.verbose or 0))

  with open(args.mlbs) as f:
    mlbs = ReadMLBs(f)
  logging.info('Running server with %d MLBs at %s', len(mlbs), args.server_path)
  FalcoMockShopFloorBackend(args.server_path, mlbs).Run()


if __name__ == '__main__':
  main()
