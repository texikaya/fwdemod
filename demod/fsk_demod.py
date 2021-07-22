from functools import lru_cache
from nptyping import Complex128, Float64, Bool, NDArray
from sample_data import Sample
import numpy

twopi = 2 * numpy.pi

class FSKDemod:
    def __init__(self, sample: Sample):
        self.sample = sample

    @lru_cache(1)
    def phase(self) -> [Float64]:
        """
        get the instantaneous phase angle for each sample
        """
        """
        anlık faz açsını bul
        """
        ret = numpy.array(self.sample.iq())
        ret = numpy.angle(ret)
        numpy.negative(ret, out=ret)
        return ret

    @lru_cache(1)
    def phase_delta(self) -> [Float64]:
        """
        Calculate the wrapped phase delta between pairs of angles.
        """
        """
        faz delta ikilisinde ki açıyı hesapla
        """
        ret = numpy.diff(self.phase())
        numpy.subtract(ret, twopi, ret, where=ret > numpy.pi)
        numpy.add(ret, twopi, ret, where=ret <= -numpy.pi)
        return ret

    @lru_cache(1)
    def phase_delta_time(self) -> [Float64]:
        """
        Calculate an array with the phase delta time offset from the beginning of sampling.
        """
        pd = self.phase_delta()
        return numpy.arange(0, len(pd) / self.sample.sample_freq(), 1 / self.sample.sample_freq())

    @lru_cache(1)
    def phase_delta_sign(self) -> [Bool]:
        """
        Calculate if the wrapped phase delta is positive or negative.
        """
        """
        negatif/pozitif kontrolü
        """
        return self.phase_delta() > 0
