#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import platform
import shutil
import sys
from datetime import datetime
from dateutil import parser as dateparser

from subprocess import (PIPE, Popen)

###################################################################################################
args = None
debug = False
editcapBin = None
capinfosBin = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()
pyPlatform = platform.system()

###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"

###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)
  sys.stderr.flush()

###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
  if v.lower() in ('yes', 'true', 't', 'y', '1'):
    return True
  elif v.lower() in ('no', 'false', 'f', 'n', '0'):
    return False
  else:
    raise argparse.ArgumentTypeError('Boolean value expected.')

###################################################################################################
# determine if a program/script exists and is executable in the system path
def Which(cmd, debug=False):
  result = any(os.access(os.path.join(path, cmd), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
  if debug:
    eprint(f"Which {cmd} returned {result}")
  return result

###################################################################################################
# run command with arguments and return its exit code, stdout, and stderr
def check_output_input(*popenargs, **kwargs):

  if 'stdout' in kwargs:
    raise ValueError('stdout argument not allowed, it will be overridden')

  if 'stderr' in kwargs:
    raise ValueError('stderr argument not allowed, it will be overridden')

  if 'input' in kwargs and kwargs['input']:
    if 'stdin' in kwargs:
      raise ValueError('stdin and input arguments may not both be used')
    input_data = kwargs['input']
    kwargs['stdin'] = PIPE
  else:
    input_data = None
  kwargs.pop('input', None)

  process = Popen(*popenargs, stdout=PIPE, stderr=PIPE, **kwargs)
  try:
    output, errput = process.communicate(input_data)
  except:
    process.kill()
    process.wait()
    raise

  retcode = process.poll()

  return retcode, output, errput

###################################################################################################
# run command with arguments and return its exit code and output
def run_process(command, stdout=True, stderr=True, stdin=None, cwd=None, env=None, debug=False):

  retcode = -1
  output = []

  try:
    # run the command
    retcode, cmdout, cmderr = check_output_input(command, input=stdin.encode() if stdin else None, cwd=cwd, env=env)

    # split the output on newlines to return a list
    if stderr and (len(cmderr) > 0): output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
    if stdout and (len(cmdout) > 0): output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))

  except (FileNotFoundError, OSError, IOError) as e:
    if stderr:
      output.append("Command {} not found or unable to execute".format(command))

  if debug:
    eprint("{}{} returned {}: {}".format(command, "({})".format(stdin[:80] + bool(stdin[80:]) * '...' if stdin else ""), retcode, output))

  return retcode, output

###################################################################################################
def get_pcap_first_time(pcapFile, continueOnError=False, debug=False):
  global capinfosBin

  try:
    err, out = run_process([capinfosBin, '-a', '-C', '-K', '-M', '-m', '-r', '-S', '-T', pcapFile], stderr=False, debug=debug)
    if (err not in (0,1)) or (out is None) or (len(out) <= 0):
      raise Exception(f'{capinfosBin}(pcapFile) returned {err}: {out}')

    try:
      return datetime.fromtimestamp(float(out[0].split(',')[-1]))
    except ValueError as e:
      return datetime.fromtimestamp(float(out[0].split(',')[-1].split('.')[0]))
  except Exception as e:
    if continueOnError:
      return None
    else:
      raise

###################################################################################################
def shift_pcap(pcapFile, baseTime, earliestRelativeTime, fileFormat='pcap', inPlace=False, debug=False):
  global editcapBin

  if os.path.isfile(pcapFile) and (baseTime is not None):
    inFileParts = os.path.splitext(os.path.basename(pcapFile))
    outFile = os.path.join(os.path.dirname(pcapFile), inFileParts[0] + "_shift" + inFileParts[1])
    pcapTime = get_pcap_first_time(pcapFile)
    relativeDiff = pcapTime - (earliestRelativeTime if earliestRelativeTime is not None else pcapTime)
    err, out = run_process([editcapBin, '-F', fileFormat, '-t', str(round((baseTime - pcapTime + relativeDiff).total_seconds())), pcapFile, outFile], debug=debug)
    if (err != 0):
      raise Exception(f'{editcapBin}(pcapFile) failed')

    if inPlace:
      os.remove(pcapFile)
      shutil.move(outFile, pcapFile)
      outFile = pcapFile

    return outFile

  else:
    return None

###################################################################################################
# main
def main():
  global args
  global debug
  global editcapBin
  global capinfosBin

  parser = argparse.ArgumentParser(description=script_name, add_help=False, usage='{} <arguments>'.format(script_name))
  parser.add_argument('-d', '--defaults', dest='accept_defaults', type=str2bool, nargs='?', const=True, default=False, metavar='true|false', help="Accept defaults to prompts without user interaction")
  parser.add_argument('-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, metavar='true|false', help="Verbose/debug output")
  parser.add_argument('-t', '--time', dest='startTime', type=str, default=None, required=False, metavar='<string>', help="Start time basis")
  parser.add_argument('-f', '--format', dest='fileFormat', type=str, default='pcap', required=False, metavar='<string>', help="File format")
  parser.add_argument('-r', '--relative', dest='relative', type=str2bool, nargs='?', const=True, default=False, metavar='true|false', help="Maintain PCAP files' offsets relative to each other")
  parser.add_argument('-p', '--pcap', dest='pcaps', nargs='*', type=str, default=None, required=True, metavar='<PCAP file(s)>', help="PCAP(s) to shift")
  parser.add_argument('-i', '--in-place', dest='inPlace', type=str2bool, nargs='?', const=True, default=False, metavar='true|false', help="Adjust the PCAP files in-place")

  try:
    parser.error = parser.exit
    args = parser.parse_args()
  except SystemExit:
    parser.print_help()
    exit(2)

  debug = args.debug

  args.pcaps=[os.path.realpath(x) for x in args.pcaps if os.path.isfile(x)]
  if (args.pcaps is None) or (len(args.pcaps) <= 0):
    raise Exception('PCAP file(s) not specified or do not exist')

  editcapBin = 'editcap.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('editcap.exe')) else 'editcap'
  capinfosBin = 'capinfos.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('capinfos.exe')) else 'capinfos'
  err, out = run_process([capinfosBin, '--version'], debug=args.debug)
  if (err != 0):
    raise Exception(f'{script_name} requires capinfos')
  err, out = run_process([editcapBin, '--version'], debug=args.debug)
  if (err != 0):
    raise Exception(f'{script_name} requires editcap')

  earliestTime = min([x for x in [get_pcap_first_time(pcap, continueOnError=True, debug=args.debug) for pcap in args.pcaps] if x is not None] + [datetime.now()])
  if args.startTime is None:
    # if they didn't sepecify a time, default to the earliest packet time
    args.startTime = earliestTime
  else:
    # otherwise use whatever time they specified
    args.startTime = dateparser.parse(args.startTime)

  if debug:
    eprint(os.path.join(script_path, script_name))
    eprint("Arguments: {}".format(sys.argv[1:]))
    eprint("Arguments: {}".format(args))
  else:
    sys.tracebacklimit = 0

  for pcap in args.pcaps:
    try:
      shift_pcap(pcap, args.startTime, earliestTime if args.relative else None, fileFormat=args.fileFormat, inPlace=args.inPlace, debug=args.debug)
    except Exception as e:
      eprint(f'Exception "{e}" processing {pcap}, skipping')

###################################################################################################
if __name__ == '__main__':
  main()
