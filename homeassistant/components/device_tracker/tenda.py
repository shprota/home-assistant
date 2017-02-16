import base64
import logging
import threading
from datetime import timedelta

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_PASSWORD
from homeassistant.util import Throttle
import requests

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

_LOGGER = logging.getLogger(__name__)

CONF_DEFAULT_IP = '192.168.0.40'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_HOST, default=CONF_DEFAULT_IP): cv.string,
    vol.Optional(CONF_PASSWORD): cv.string,
})


def get_scanner(hass, config):
    """Return the Tenda device scanner."""
    scanner = TendaScanner(config[DOMAIN])
    return scanner if scanner.success_init else None


class TendaScanner(DeviceScanner):

    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.password = None

        if config[CONF_PASSWORD]:
            self.password = base64.urlsafe_b64encode(config[CONF_PASSWORD].encode('ascii')).decode('ascii')

        self.lock = threading.Lock()

        self.last_results = {}

        # Test the router is accessible.
        data = self.get_tenda_data()
        self.success_init = data is not None

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return [client['mac'] for client in self.last_results.values()]

    def get_device_name(self, mac: str):
        """Return the name of the given device or None if we don't know."""
        if not self.last_results:
            return None
        client = self.last_results[mac]
        if client:
            return client.get('host')
        return None

    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """Ensure the information from the Tenda extender is up to date.

        Return boolean if scanning successful.
        """
        if not self.success_init:
            return False

        with self.lock:
            _LOGGER.info("Loading data from Tenda WiFi Extender")
            data = self.get_tenda_data()
            if not data:
                return False

            # active_clients = [client for client in data.values()]
            self.last_results = data
            return True

    def get_tenda_data(self):
        """Retrieve data from Tenda and return parsed result."""
        base_url = 'http://{}/'.format(self.host)
        auth_url = '{}login/Auth'.format(base_url)
        data_url = '{}goform/getUserList'.format(base_url)
        cookies = {}

        if self.password:
            data = "password={}".format(self.password)
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            requests.post(auth_url, headers=headers, data=data, timeout=10)
            cookies = {'ecos_pw': "{}ert:language=en".format(self.password)}
        request = requests.get(data_url, cookies=cookies, timeout=10)

        devices = {}
        for device in request.json()['onlineList']:
            try:
                devices[device['devMac']] = {
                    'ip': device['devIp'],
                    'mac': device['devMac'],
                    'host': device['devName'],
                    }
            except (KeyError, requests.exceptions.RequestException):
                pass
        return devices

if __name__ == '__main__':
    sc = TendaScanner({CONF_HOST: "192.168.0.40", CONF_PASSWORD: "admin"})
    print(sc.scan_devices())
    print(sc.get_device_name('74:DF:BF:9B:1A:27'))