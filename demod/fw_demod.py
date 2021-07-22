from .fsk_demod import FSKDemod
from sample_data import Sample
import crccheck
from datetime import datetime, timedelta
import logging
logger = logging.getLogger(__name__)


class FWDemod(FSKDemod):
    def __init__(self, sample: Sample, symbol_frequency: int = 115200):
        super().__init__(sample)
        self.symbol_freq = symbol_frequency
        self.samples_per_symbol = self.sample.sample_freq() / self.symbol_freq
        self.preamble_len = int(24 * self.samples_per_symbol)
        self.sample_start_time = sample.sample_time()

    def find_preamble(self, start: int = 0) -> [int]:
        """
        Find a pattern that looks like the preamble
        It looks like a bunch of 0 followed by a 1 in the phase delta sign.
        Return the offset of the start of the preamble
        """
        
        """
        preamble bulmak için 0 ve 1 leri izle preamble 0 lardan sonra gelen
        bir 1 le başlıyor gibi. Aradaki uzaklığı döndür
        """
        if start is None or start < 0:
            start = 0

        zeros = 0
        pds = self.phase_delta_sign()
        for offset in range(start, len(pds)):
            if not pds[offset]:
                zeros += 1
            else:
                if zeros >= self.preamble_len:
                    yield offset - self.preamble_len
                zeros = 0

    def find_sync(self, start: int = 0, pattern: int = 0xb7) -> [(int, int, int)]:
        """
        Find sync bytes.  It looks like this is always 0xb7 for FW.

        :param start: The initial index of our sample array
        :param pattern: Sync byte to attempt to decode
        :return: [(initial index of sync byte, number of error symbols)]
        Returns the offset of the start of the sync byte.
        """
        """
        sync baytı bul ve döndür
        """
        if start is None or start < 0:
            start = 0

        for preamble_offset in self.find_preamble(start):

            sync_byte, errs, slew = self.decode_byte_min(preamble_offset + self.preamble_len)
            if sync_byte == pattern:
                yield preamble_offset + self.preamble_len + slew, errs, sync_byte

    def find_packets(self, start: int = 0, serial_num: int = None):
        """
        paketleri tespit et ve aradaki uzaklığı maks hatayı ve paketi döndür
        """
        for sync_offset, _, _ in self.find_sync(start):

            packet, max_errs, slew = self.decode_bytes(sync_offset, 16)

            # https://crccalc.com/
            crc = crccheck.crc.Crc16Arc().process(packet[1:14]).finalbytes()
            src = int.from_bytes(bytearray(packet[1:4]), byteorder="big")

            if list(crc) == packet[14:16] and serial_num in [src, None]:
                data_len = packet[10]
                data_bytes, errs, slew = self.decode_bytes(sync_offset + 16 * 8 * 8 + slew, data_len)
                if errs > max_errs:
                    max_errs = errs
                packet.extend(data_bytes)

                yield sync_offset, max_errs, packet, self.sample_start_time + timedelta(seconds=sync_offset / self.sample.sample_freq())

    def decode_byte(self, start: int) -> (int, int):
        """
        Try and decode a byte starting at a sample offset.

        :param start: The initial index of our sample array
        :return: (decoded_byte, number of sample errors)
        """
        
        """
        örneğin aralığında başlayan paketi çözümle
        baytı ve hata aralığını döndür
        """
        phase_delta_sign = self.phase_delta_sign()
        bits = [0] * 8
        for bit in range(0, 8):
            for offset in range(0, int(self.samples_per_symbol)):
                try:
                    if phase_delta_sign[start + int(bit * self.samples_per_symbol) + offset]:
                        bits[bit] += 1
                except IndexError:
                    # Decode leaves current sample set.
                    bits[bit] = self.samples_per_symbol / 2
        byte = 0
        errs = 0
        for bit in bits:
            byte <<= 1
            if bit > self.samples_per_symbol / 2:
                byte += 1
                errs += self.samples_per_symbol - bit
            else:
                errs += bit

        return byte, errs

    def decode_byte_min(self, start: int, slews: [int] = None) -> (int, int, int):
        """
        Decode bytes starting at at start + slews offsets
        and calculate the number of error symbols in each byte.

        Return the byte, number of errors, slew (e.g. value from slews) with the most correct decoded byte

        :param start: The initial index of our sample array
        :param slews: An array of slew offsets
        :return: (decoded_byte, num_error_symbols, slew_offset)
        """
        
        """
        başlangıç ve ani dalgalanmadaki zamanlamayı toplayarak 
        sembollerde ki hata oranını bul
        """
        if slews is None:
            slews = [0, 1, -1]
        min_errs = int(8 * self.samples_per_symbol)  # max errs
        min_slew = None
        min_byte = None
        for slew in slews:
            byte, errs = self.decode_byte(start + slew)

            if errs < min_errs:
                min_errs = errs
                min_slew = slew
                min_byte = byte

            if errs == 0:
                break

        return min_byte, min_errs, min_slew

    def decode_bytes(self, start: int, count: int) -> ([int], int):
        """
        baytları çözümle
        """
        cumulative_slew = 0
        max_errs = 0
        bytes = []

        for byte_offset in range(0, count):
            point = start + int(byte_offset * 8 * self.samples_per_symbol) + cumulative_slew
            byte, errs, slew = self.decode_byte_min(point)
            cumulative_slew += slew
            if errs > max_errs:
                max_errs = errs
            bytes.append(byte)

        return bytes, max_errs, cumulative_slew
