#!/usr/bin/env python3

from __future__ import print_function

import logging
import pickle
import numpy
import datetime
from datetime import timedelta
from nptyping import Complex128, Float64, Bool, NDArray


logger = logging.getLogger(__name__)

VERSION = "$Revision: 17 $"
UPDATED = "$Date: 2021-01-25 18:31:28 -0700 (Mon, 25 Jan 2021) $"


class Sample:
    """
    Base class for SDR samples
    """

    def __init__(self,
                 center_frequency: int,
                 sample_frequency: int,
                 iq: NDArray[Complex128] = None,
                 sample_end_time: datetime = None):
        self._iq = iq
        self._center_freq = center_frequency
        self._sample_freq = sample_frequency
        if iq is None:
            self._sample_end_time = None
        else:
            self._sample_end_time = sample_end_time

    def iq(self):
        return self._iq

    def center_freq(self):
        return self._center_freq

    def sample_freq(self):
        return self._sample_freq

    def sample_time(self):
        if self._sample_end_time is not None and self._iq is not None:
            return self._sample_end_time - datetime.timedelta(seconds=len(self._iq) / self._sample_freq)
        return None

    def append(self,
               iq: NDArray[Complex128],
               sample_end_time: datetime = None):
        if self._iq is None:
            self._iq = iq
        else:
            self._iq = numpy.concatenate((self._iq, iq))

        if self._sample_end_time is not None:
            self._sample_end_time += timedelta(seconds=len(iq)/self._sample_freq)
        elif sample_end_time is not None:
            self._sample_end_time = sample_end_time

    def trim(self, offset: int):
        if self._iq is not None:
            self._iq = self._iq[offset:]

    def save_pickle(self, file: str, append: bool = False):
        """
        Pickle this object and save it to the file

        :param file:
        :return:
        """
        mode = "wb"
        if append:
            mode = "ab"
        with open(file, mode) as f:
            pickle.Pickler(f).dump(self)

    @classmethod
    def load_pickle(cls, file) -> "Sample":
        """
        :param file:
        :return:
        """
        with open(file, "rb") as f:
            while True:
                try:
                    yield pickle.Unpickler(f).load()
                except EOFError:
                    break
