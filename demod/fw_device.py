from threading import Thread
from datetime import datetime
import json
import requests
from demod.fw_packet import FWPacket
import frequency_tables
import logging
logger = logging.getLogger(__name__)


class FWDevice:
    def __init__(self, serial_number: int, rf_data_rate: int, start_time: datetime = None):
        self.first = True
        self.dict = dict()
        self.serial_number = serial_number
        self.dict['max_payload'] = 0
        self.dict['packet_period']={}
        self.rf_data_rate = rf_data_rate
        self.dict['minmax'] = set([(pmin, pmax) for pmin in range(0, 10) for pmax in range(0, 10)])

    def update_zones(self, packet: FWPacket):
        if "zone_int" in packet:
            if "zone_int" not in self.dict or self.dict['zone_int'] != packet['zone_int']:
                logger.debug("Updating zones: %x", packet['zone_int'])
                self.dict['zone_int'] = packet['zone_int']
                return True
        return False

    def update_frequency_key(self, packet: FWPacket):
        if 'frequency_key' in packet:
            fkey = packet['frequency_key']
        else:
            for fkey, hop_table in enumerate(frequency_tables.hop_tables):
                if packet['channel'] == hop_table[packet['offset']]:
                    break

        if fkey is not None and ('frequency_key' not in self.dict or self.dict['frequency_key'] != fkey):
            logger.debug("Updating Frequency Key: %x", fkey)
            self.dict['frequency_key'] = fkey
            return True

        return False

    def update_net_id(self, packet: FWPacket):
        if 'net_id' in packet:
            if 'net_id' not in self.dict or packet['net_id'] != self.dict['net_id']:
                logger.debug("Updating Net ID: %d", packet['net_id'])
                self.dict['net_id'] = packet['net_id']
                return True
        return False

    def update_subnet_id(self, packet: FWPacket):
        if 'subnet_id' in packet:
            if 'subnet_id' not in self.dict or packet['subnet_id'] != self.dict['subnet_id']:
                logger.debug("Updating Subnet ID: %d", packet['subnet_id'])
                self.dict['subnet_id'] = packet['subnet_id']
                return True
        return False

    def update_max_payload(self, packet: FWPacket):
        if packet['len'] > self.dict['max_payload']:
            logger.debug("Updating Max Packet Size: %d", packet['len'])
            self.dict['max_payload'] = packet['len']

            for (pmin, pmax) in list(self.dict["minmax"]):
                if self.dict['max_payload'] > frequency_tables.max_packet_size[self.rf_data_rate][pmin][pmax]:
                    self.dict["minmax"].remove((pmin, pmax))
            return True
        return False

    def update_packet_period(self, packet_period):
        if packet_period is not None:
            logger.debug("Updating Packet Period: %f", packet_period)
            if packet_period not in self.dict['packet_period']: 
                self.dict["packet_period"][packet_period]=1
            else:
                self.dict["packet_period"][packet_period]+=1
            
            max_quotient = 0  # maximum bölüm
            most_repeated_period=max(self.dict['packet_period'].keys(),key=self.dict['packet_period'].get)
            
            for period in frequency_tables.periods:
                quotient = (round(round(most_repeated_period, 8) / period, 3))
                if(quotient.is_integer()):
                    if(max_quotient < quotient):
                        logger.debug("Updating Min Max: %d", self.dict['minmax'])
                        max_quotient = quotient
                        self.dict['minmax'] = self.dict['minmax'] & frequency_tables.periods[period]
                        return True

        return False


    def update_to(self, packet: FWPacket):
        ret = False
        ret = self.update_frequency_key(packet) or ret
        ret = self.update_zones(packet) or ret
        ret = self.update_net_id(packet) or ret
        ret = self.update_subnet_id(packet) or ret
        ret = self.update_max_payload(packet) or ret
        return ret

    def update_from(self, packet: FWPacket, packet_period=None):
        ret = False
        ret = self.update_frequency_key(packet) or ret
        ret = self.update_zones(packet) or ret
        ret = self.update_net_id(packet) or ret
        ret = self.update_subnet_id(packet) or ret
        ret = self.update_max_payload(packet) or ret
        ret = self.update_packet_period(packet_period) or ret
        return ret

    @property
    def json_data(self) -> str:
        return json.dumps({
            "serial_number": self.serial_number,
            "data": str(self)
        }, default=str)

    def __str__(self):
        ret = ""
        ret += f"Serial#:{self.serial_number:6x}({int(self.serial_number / 10000):03d}-{self.serial_number % 10000:04d})"
        if 'frequency_key' in self.dict:
            ret += f" Freqency_Key:{self.dict['frequency_key']:1x}"

        if 'zone_int' in self.dict:
            ret += f" Zones:{self.dict['zone_int']:016b}"

        if 'net_id' in self.dict:
            ret += f" Net_ID:{self.dict['net_id']:04d}"

        if 'subnet_id' in self.dict:
            ret += f" Subnet_ID:{self.dict['subnet_id']:02x}"

        if 'packet_period' in self.dict:
            _max=""
            if self.dict['packet_period'] != {} : _max=max(self.dict['packet_period'].keys(),key=self.dict['packet_period'].get)
            ret += f" Packet Period:{_max}"

        if self.dict['max_payload'] > 0:
            ret += f" Max Packet Size:{self.dict['max_payload']} "

        if len(self.dict["minmax"]) > 15:
            ret += "\nMin/Max: Lots!!"
        else:
            ret += "\nMin/Max: " + ",".join([f"{i}/{j}({frequency_tables.max_packet_size[self.rf_data_rate][i][j]})" for (i,j) in self.dict['minmax']])

        return ret

    def send_to_django(self, hostname: str = "http://127.0.0.1:8000/", use_thread=False):

        def send_data(this, hostname):
            response = requests.post(
                url=f"{hostname}api/devices/",
                data=this.json_data,
                headers={'Content-Type': 'application/json'}
            )
            if not response.ok and "device with this serial number already exists" not in response.text:
                logger.error("Error publishing data: %s", response.reason)
                return
            response = requests.put(
                url=f"{hostname}api/devices/{self.serial_number}/",
                data=this.json_data,
                headers={'Content-Type': 'application/json'}
            )
            if not response.ok:
                logger.error("Error publishing data: %s", response.reason)

        if use_thread:
            Thread(target=send_data, args=(self, hostname)).start()
        else:
            send_data(self, hostname)
