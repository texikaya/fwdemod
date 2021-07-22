#!/usr/bin/env python3

from __future__ import print_function

import argparse
import logging
import os
import sys
import rtlsdr
import numpy
import csv
import time
import frequency_tables
import sample_data
import demod
import datetime

numpy.set_printoptions(threshold=sys.maxsize)

logger = logging.getLogger(__name__)

VERSION = "$Revision: 141 $"
UPDATED = "$Date: 2021-07-20 13:50:58 -0600 (Tue, 20 Jul 2021) $"


def rtlsdr_samples(sdr, center_freqs, sample_rate, symbol_rate, sample_time, dwell_time, run_time):
    sdr.sample_rate = sample_rate
    sdr.bandwidth = symbol_rate * 2  # Hz
    # sdr.freq_correction = 60   # PPM
    sdr.gain = 'auto'
    start = time.monotonic()
    while time.monotonic() < start + run_time:
        dwell = time.monotonic()
        sdr.center_freq = center_freqs[0]
        logger.debug("Sampling Frequency: %d", sdr.center_freq)
        while time.monotonic() < dwell + dwell_time:

            iq = sdr.read_samples(sample_rate * sample_time)
            logger.debug("Read %d Samples", len(iq))
            yield sample_data.Sample(center_frequency=center_freqs[0],
                                     sample_frequency=sample_rate,
                                     iq=iq,
                                     sample_end_time=datetime.datetime.now())

        center_freqs = center_freqs[1:] + center_freqs[:1]


def main(argv=None):

    argv = argv or sys.argv
    prog = os.path.basename(argv[0])

    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("-V", "--version",
                        action="version",
                        version=prog + ' ' + VERSION)
    parser.add_argument("-v", "--verbose",
                        action="count",
                        default=0,
                        help="Increase verbosity")
    parser.add_argument("-i", "--input_file",
                        help="Load samples to the provided sample file",
                        default=None)
    parser.add_argument("-o", "--output_file",
                        help="Save samples to the provided sample file",
                        default=None)
    parser.add_argument("-c", "--channel",
                        help="Center frequency channel number",
                        type=int,
                        default=None)
    parser.add_argument("-s", "--sample_freq",
                        help="Frequency to sample at",
                        type=int,
                        default=None)
    parser.add_argument("-t", "--sample_time",
                        help="Duration to sample",
                        type=float,
                        default=5.0)
    parser.add_argument("-d", "--dwell_time",
                        help="Time to dwell on one channel",
                        type=float,
                        default=1.0)
    parser.add_argument("-r", "--run_time",
                        help="Time to run",
                        type=float,
                        default=112.0)
    parser.add_argument("-x", "--rf_data_rate",
                        help="RF data rate ",
                        type=int,
                        default=3)

    subparsers = parser.add_subparsers(title="command",
                                       dest="command",
                                       help='sub-command help')

    subparsers.required = True

    grab_command = subparsers.add_parser("grab")

    dump_command = subparsers.add_parser("dump")
    dump_command.add_argument("-x", "--send_to_django",
                              action="store_true",
                              help="Send the file to the django server on localhost",
                              default=False)

    hop_command = subparsers.add_parser("hop")
    hop_command.add_argument("-s", "--serial_num",
                             help="Only count this serial number",
                             type=int)

    csv_command = subparsers.add_parser("csv")

    otp_command = subparsers.add_parser("otp")

#     stream = subparsers.add_parser("stream")
#     stream.add_argument("-x", "--send_to_django",
#                         action="store_true",
#                         help="Send the file to the django server on localhost",
#                         default=False)

    logger.info("ppid=%d, sys.argv=%s", os.getppid(), argv)

    args = parser.parse_args(argv[1:])

    if args.verbose > 2:
        args.verbose = 2

    logStream.setLevel([logging.WARNING, logging.INFO, logging.DEBUG][args.verbose])

    logger.debug(VERSION)

    if args.sample_freq is None:
        args.sample_freq = frequency_tables.symbol_rates[args.rf_data_rate] * 8

    if args.channel is None:
        args.channels = range(0, len(frequency_tables.channel_frequency))
    else:
        args.channels = [args.channel]

    if args.input_file is not None:
        samples = sample_data.Sample.load_pickle(args.input_file)
    else:
        samples = rtlsdr_samples(rtlsdr.RtlSdr(),
                                 [frequency_tables.channel_frequency[channel] for channel in args.channels],
                                 args.sample_freq,
                                 frequency_tables.symbol_rates[args.rf_data_rate],
                                 args.sample_time,
                                 args.dwell_time,
                                 args.run_time)
    if args.command in ["grab"]: # verilen dosyaya yükle

        append = False

        for sample in samples:
            if args.output_file is not None:
                sample.save_pickle(args.output_file, append)
            else: 
                logger.error("need an output file")
                return -1
            append = True

    elif args.command in ["dump"]: # bulunan radyoları listele

        append = False
        devices = dict()

        for sample in samples:
            if args.output_file is not None:
                sample.save_pickle(args.output_file, append)
            append = True

            demodulated = demod.FWDemod(sample, frequency_tables.symbol_rates[args.rf_data_rate])
            last_offset = dict()

            for offset, _, packet, packet_start_time in demodulated.find_packets():
                logger.debug((offset / sample.sample_freq(), sample.center_freq(), [hex(p) for p in packet]))
                p = demod.FWPacket(packet, packet_start_time, sample.center_freq())
                print(p)
                logger.debug(p.json_data)

                # do something smarter here if we have >1 source.
                # dict of src's and the last offset for each.

                packet_period = None
                if p["src"] in last_offset:
                    packet_period = (offset - last_offset[p["src"]]) / args.sample_freq
                    logger.debug("Packet period: %f", packet_period)
                last_offset[p["src"]] = offset

                if p["src"] not in devices:
                    devices[p["src"]] = demod.FWDevice(p["src"], args.rf_data_rate)
                    devices[p["src"]].update_from(p, packet_period)
                    if args.send_to_django:
                        devices[p["src"]].send_to_django()
                elif devices[p["src"]].update_from(p, packet_period):
                    if args.send_to_django:
                        devices[p["src"]].send_to_django()

                if p["dst"] not in devices:
                    devices[p["dst"]] = demod.FWDevice(p["dst"], args.rf_data_rate)
                    devices[p["dst"]].update_to(p)
                if args.send_to_django:
                    devices[p["dst"]].send_to_django()
                elif devices[p["dst"]].update_to(p):
                    if args.send_to_django:
                        devices[p["dst"]].send_to_django()

                if args.send_to_django:
                    p.send_to_django()

        for device in devices:
            if device != 0xffffff:
                print(devices[device])

    elif args.command in ["csv"]:
        fieldnames = ["start_time",
                      "frequency",
                      "channel",
                      "src",
                      "dst",
                      "syn",
                      "ack",
                      "offset",
                      "len"]
        fieldnames += [f"P{i:03d}" for i in range(0, 256 * 2)]
        with open(args.output_file, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore", restval="")
            writer.writeheader()
            for sample in samples:
                demodulated = demod.FWDemod(sample)
                for _, _, packet, packet_start_time in demodulated.find_packets():
                    p = demod.FWPacket(packet, packet_start_time, sample.center_freq())
                    d = dict(p)
                    if(d["len"]>0):
                        for i, b in enumerate(d["payload"]):
                            # This gets all the XOR'd data to line up.
                            i = (p["syn"] * 16 + p["ack"] + p["offset"]) % 256 + i
                            d[f"P{i:03d}"] = hex(b)
                        writer.writerow(d)

    elif args.command in ["otp"]:
        """ Build a histogram of hash values.  If what we saw in the .csv hold true,
        one will stand out """

        hist = numpy.zeros((512, 256))  # X is the "offset", Y's index is a byte value, the value is a count.
        for sample in samples:
            demodulated = demod.FWDemod(sample)
            for offset, _, packet, packet_start_time in demodulated.find_packets():
                p = demod.FWPacket(packet, packet_start_time, sample.center_freq())
                for i, b in enumerate(p["payload"]):
                    # This gets all the XOR'd data to line up.
                    i = (p["syn"] * 16 + p["ack"] + p["offset"]) % 256 + i
                    hist[i, b] += 1
        print(hist)
        otp = numpy.argmax(hist, axis=1)
        numpy.set_printoptions(formatter={'int': hex})
        c = 0
        for b in otp:
            if c == 8:
                print()
                c = 0
            c += 1
            print(f'0x{b:02x}, ', end="")

    elif args.command in ["csv"]:
        fieldnames = ["start_time", "frequency", "channel", "src", "dst", "syn", "ack", "offset", "len"]
        fieldnames += [f"P{i:03d}" for i in range(0, 256 * 2)]
        with open(args.output_file, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore", restval="")
            writer.writeheader()
            for sample in samples:
                demodulated = demod.FWDemod(sample)
                for offset, _, packet, packet_start_time in demodulated.find_packets():
                    p = demod.FWPacket(packet, packet_start_time, sample.center_freq())
                    d = dict(p)
                    for i, b in enumerate(d["payload"]):
                        # This gets all the XOR'd data to line up.
                        i = (p["syn"] * 16 + p["ack"] + p["offset"]) % 256 + i
                        d[f"P{i:03d}"] = hex(b)
                    writer.writerow(d)

    elif args.command in ["hop"]:

        channel_table = [None] * len(frequency_tables.channel_frequency)

        for sample in samples:
            demodulated = demod.FWDemod(sample)
            for offset, _, packet, packet_start_time in demodulated.find_packets(serial_num=args.serial_num):
                p = demod.FWPacket(packet, packet_start_time, sample.center_freq())
                logger.info(p)

                if channel_table[p["channel"]] is None:
                    channel_table[p["channel"]] = set([p["offset"]])
                else:
                    channel_table[p["channel"]].add(p["offset"])

                print(f"Channel:{p['channel']} Offsets:{channel_table[p['channel']]}")

        print("Channel Table:")

        offset_max = _max([_max(channel) for channel in channel_table if channel is not None])
        print(f"Max:{offset_max}")

        hop_table = [None] * (offset_max + 1)
        for channel, offsets in enumerate(channel_table):
            print(f"Channel: {channel} ({frequency_tables.channel_frequency[channel]})", end=" ")

            if offsets is not None:
                print(f"Offsets:{', '.join([str(offset) for offset in offsets])}", end="")
                for offset in offsets:
                    if hop_table[offset] is None:
                        hop_table[offset] = set([channel])
                    else:
                        logger.warning("Offset appears on multiple channels")  # this doesn't appear to happen.
                        hop_table[offset].add(channel)
            print("")

        print("Hop Table:")
        for offset, channels in enumerate(hop_table):
            for channel in channels:
                print(f"Offset:{offset} Channel:{channel} ({frequency_tables.channel_frequency[channel]})")

        print(hop_table)

#     elif args.command in ["stream"]:
#         # https://pyrtlsdr.readthedocs.io/en/latest/Overview.html
#
#         sdr = rtlsdr.RtlSdr()
#         sdr.sample_rate = args.sample_freq
#         sdr.bandwidth = frequency_tables.symbol_rate * 2  # Hz
#         sdr.center_freq = frequency_tables.channel_frequency[args.channel]
#         # sdr.freq_correction = 60   # PPM
#         sdr.gain = 'auto'
#         size = int(args.sample_freq * args.sample_time)
#         sample = sample_data.samples.Sample(center_frequency=frequency_tables.channel_frequency[args.channel],
#                                             sample_frequency=args.sample_freq)
#         devices = dict()
#
#         def cb(values, context):
#
#             context[0] -= values.shape[0]
#             context[3].append(values,
#                               sample_end_time=datetime.datetime.now())
#             offset = 0
#
#             demodulated = demod.FWDemod(context[3])
#
#             for offset, _, packet, packet_start_time in demodulated.find_packets():
#                 logger.debug(((offset + context[2]) / context[3].sample_freq(), context[3].center_freq(), packet))
#                 p = demod.FWPacket(packet, start_time=packet_start_time, frequency=context[3].center_freq())
#                 # print(p)
#                 previous_packet = context[4]
#                 if previous_packet:
#                     delta = p['start_time'] - previous_packet.start_time
#                     print(delta.total_seconds())
#                 context[4] = p
#
#                 if p['src'] not in devices:
#                     devices[p['src']] = demod.FWDevice(p['src'])
#                     devices[p['src']].update_from(p)
#                     if args.send_to_django:
#                         devices[p['src']].send_to_django()
#                 elif devices[p['src']].update_from(p):
#                     devices[p['src']].send_to_django()
#
#                 if p['dst'] not in devices:
#                     devices[p['dst']] = demod.FWDevice(p['dst'])
#                     devices[p['dst']].update_to(p)
#                     if args.send_to_django:
#                         devices[p['dst']].send_to_django()
#                 elif devices[p['dst']].update_to(p):
#                     if args.send_to_django:
#                         devices[p['dst']].send_to_django()
#
#                 if args.send_to_django:
#                     p['send_to_django']()
#
#             if offset == 0:
#                 offset = context[3].iq().shape[0] - 8 * 8 * 256
#
#             context[2] += offset
#             context[3].trim(offset)
#
#             if context[0] <= 0:
#                 context[1].cancel_read_async()
#
#         try:
#             sdr.read_samples_async(cb, num_samples=92160, context=[size, sdr, 0, sample, None])
#         except rtlsdr.LibUSBError as exception:
#             if exception.errno != -1:
#                 raise

    return 0


if __name__ == "__main__":

    logger = logging.getLogger()

    logFormatter = logging.Formatter(
        "%(process)d-%(levelname)s %(asctime)s %(name)s %(message)s")

    logStream = logging.StreamHandler()
    logStream.setFormatter(logFormatter)
    logStream.setLevel(logging.DEBUG)
    logger.addHandler(logStream)

    try:
        logFile = logging.FileHandler(os.getenv("GRAB_LOG", "~/grab.log"))
        logFile.setFormatter(logFormatter)
        logger.addHandler(logFile)
    except Exception as _:
        pass

    logger.setLevel(logging.DEBUG)

    sys.exit(main(sys.argv))
