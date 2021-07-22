#!/bin/env python3

# Install pyrtlsdr with pip
# https://pypi.org/project/pyrtlsdr/

# Install librtlsdr in c:\Windows\System32
# https://github.com/librtlsdr/librtlsdr/releases

import matplotlib.pyplot as plt
import crccheck
import sample_data
import os
import argparse
import rtlsdr
import frequency_tables
import binascii
from demod import FWDemod

import sys

import logging

logger = logging.getLogger(__name__)

VERSION = "$Revision: 141 $"
UPDATED = "$Date: 2021-07-20 13:50:58 -0600 (Tue, 20 Jul 2021) $"


def plot(sample: sample_data.Sample,rf_data_rate) -> None:
    # from pprint import pprint
    #
    # sdr = rtlsdr.RtlSdr()
    #
    # sdr.sample_rate = 115200 * 8  # Hz
    # # sdr.bandwidth = 115200 # Hz
    # sdr.center_freq = 914918400  # Hz
    # # sdr.freq_correction = 60   # PPM
    # sdr.gain = 'auto'
    #
    # # Power Density
    # samples = sdr.read_samples(sdr.sample_rate)

    demodulated = FWDemod(sample,frequency_tables.symbol_rates[rf_data_rate])
    phase_delta_time = demodulated.phase_delta_time()

    power = plt.subplot(2, 2, 1)
    power.psd(sample.iq(), Fs=sample.sample_freq())

    samples_spectrum = plt.subplot(2, 2, 2, title="Spectrum", ylabel="Hz")
    samples_spectrum.specgram(sample.iq(), Fs=sample.sample_freq(), Fc=sample.center_freq())

    samples_phase_delta = plt.subplot(2, 2, 3, sharex=samples_spectrum, ylabel="delta Hz")
    samples_phase_delta.plot(phase_delta_time, demodulated.phase_delta())

    samples_phase_sign = plt.subplot(2, 2, 4, sharex=samples_spectrum, ylabel="truthiness")
    #samples_phase_sign.set_xticks(demod.phase_delta_time[0::8])
    samples_phase_sign.plot(phase_delta_time, demodulated.phase_delta_sign())

    count = 0

    # Find each symbol preamble (e.g. a bunch of 0 symbols), decode the byte at that point, and write it to the plot
    # giriş frekansını bul ve baytı çözümle
    for point in demodulated.find_preamble():
        count += 1
        samples_phase_delta.annotate(text=count,
                                     xy=(phase_delta_time[point], 0))

        sync_byte, err = demodulated.decode_byte(point + demodulated.preamble_len)
        samples_phase_delta.annotate(text=hex(sync_byte),
                                     xy=(phase_delta_time[point + demodulated.preamble_len], 0))
        samples_phase_delta.annotate(text=err,
                                     xy=(phase_delta_time[point + demodulated.preamble_len], -0.2))

    for point, err, sync_byte in demodulated.find_sync():

        sync_byte, cumulative_error, cumulative_slew = demodulated.decode_byte_min(point)
        samples_phase_sign.annotate(text=hex(sync_byte),
                                    xy=(phase_delta_time[point], 0.5))
        samples_phase_sign.annotate(text=cumulative_error,
                                    xy=(phase_delta_time[point], 0.375))
        samples_phase_sign.annotate(text=cumulative_slew,
                                    xy=(phase_delta_time[point], 0.25))

        if sync_byte == 0xb7:
            # try and decode the next bytes
            # b7 eşleşme baytı olduğu için onu kontrol et
            packet = [0xb7]
            for byte_offset in range(0, 15):
                npoint = point + (byte_offset + 1) * 8 * 8 + cumulative_slew  # samples_per_bit * bits_per_byet
                byte, err, slew = demodulated.decode_byte_min(npoint)
                if byte_offset == 9:
                    data_len = byte

                packet.append(byte)

                cumulative_error += err
                cumulative_slew += slew

                samples_phase_sign.annotate(text=hex(byte),
                                            xy=(phase_delta_time[npoint], 0.5))
                samples_phase_sign.annotate(text=err,
                                            xy=(phase_delta_time[npoint], 0.375))
                samples_phase_sign.annotate(text=slew,
                                            xy=(phase_delta_time[npoint], 0.25))

            for byte_offset in range(15, 15 + data_len):
                npoint = point + (byte_offset + 1) * 8 * 8 + cumulative_slew  # samples_per_bit * bits_per_byet
                byte, err, slew = demodulated.decode_byte_min(npoint)
                if byte_offset == 10:
                    data_len = byte

                packet.append(byte)

                cumulative_error += err
                cumulative_slew += slew


#                 samples_phase_sign.annotate(text=hex(byte),
#                                             xy=(phase_delta_time[npoint], 0.5))
#                 samples_phase_sign.annotate(text=err,
#                                             xy=(phase_delta_time[npoint], 0.375))
#                 samples_phase_sign.annotate(text=slew,
#                                             xy=(phase_delta_time[npoint], 0.25))

            packet = bytearray(packet)
            print([hex(p) for p in packet], end=": ")
            print(cumulative_error, end=": ")

            # https://crccalc.com/
            crc = crccheck.crc.Crc16Arc().process(packet[1:14]).finalbytes()
            print([hex(p) for p in crc], end=": ")
            if crc == packet[14:16]:
                samples_phase_sign.annotate(text="CRC OK",
                                            xy=(phase_delta_time[point + 14 * 8 * 8 + cumulative_slew], 0.625))
                print("PASS")
            else:
                samples_phase_sign.annotate(text="CRC FAIL",
                                            xy=(phase_delta_time[point + 14 * 8 * 8 + cumulative_slew], 0.625))

                print("FAIL")

            print(binascii.hexlify(packet[16:-2]))

    plt.show()


def main(argv: [str] = None) -> int:
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
    parser.add_argument("-f", "--sample_file", 
                        help="Use the provided sample file", 
                        default=None)
    parser.add_argument("-c", "--channel",
                      help="Center frequency channel number",
                      type=int,
                      default=55)
    parser.add_argument("-x", "--rf_data_rate",
                        help="RF data rate",
                        type=int,
                        default=3)
    parser.add_argument("-r", "--sample_freq",
                        help="Frequency to sample at",
                        type=int,
                        default=None)
    parser.add_argument("-S", "--symbol_rate", default=115200)

    logger.info("ppid=%d, sys.argv=%s", os.getppid(), argv)

    args = parser.parse_args(argv[1:])
    
    if args.verbose > 2:
        args.verbose = 2

    logStream.setLevel([logging.WARNING, logging.INFO, logging.DEBUG][args.verbose])

    logger.debug(VERSION)
    if args.sample_freq is None:
        args.sample_freq=frequency_tables.symbol_rates[args.rf_data_rate]*8

    if args.sample_file:
        samples = sample_data.Sample.load_pickle(args.sample_file)
        sample=next(samples)
        
    else:
        sdr = rtlsdr.RtlSdr()

        sdr.sample_rate = args.sample_freq
        sdr.bandwidth = frequency_tables.symbol_rates[args.rf_data_rate] * 2
        sdr.center_freq = frequency_tables.channel_frequency[args.channel]
        # sdr.freq_correction = 60   # PPM
        sdr.gain = 'auto'

        sample = sample_data.Sample(iq=sdr.read_samples(sdr.sample_rate),
                                    center_frequency=frequency_tables.channel_frequency[args.channel],
                                    sample_frequency=args.sample_freq)

    plot(sample,args.rf_data_rate)

    return 0


if __name__ == "__main__":

    logger = logging.getLogger()

    logFormatter = logging.Formatter(
        "%(process)d-%(levelname)s %(asctime)s %(name)s %(message)s")

    logStream = logging.StreamHandler()
    logStream.setFormatter(logFormatter)
    logStream.setLevel(logging.WARNING)
    logger.addHandler(logStream)

    sys.exit(main(sys.argv))
