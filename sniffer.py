import sys
import time
import logging
from threading import Thread

from asciimatics.exceptions import NextScene, StopApplication, ResizeScreenError
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.widgets import Frame, ListBox, Button, Layout, Divider, Widget, MultiColumnListBox, PopUpDialog
from serial.serialutil import SerialException
from serial.tools import list_ports

from SnifferAPI import CaptureFiles
from SnifferAPI import Sniffer

from Project import config
from Project.client import Client
from Project.shared import get_Address
from Project.shared import CloseSnifferException
from Project.logging_packets import initialize_packets_logging_to_Filebeat
from Project.logging_service import initialize_service_logging

mySniffer = None
client = None
logger = logging.getLogger(config.SERVICE_LOGGER)


class MainView(Frame, Thread):
    def __init__(self, screen, client):
        super(MainView, self).__init__(screen,
                                       screen.height * 2 // 3,
                                       screen.width * 2 // 3,
                                       on_load=self.reload_devices,
                                       hover_focus=True,
                                       title="Bluetooth Low Energy Sniffer",
                                       reduce_cpu=True)
        Thread.__init__(self)
        # Save off the model that accesses the contacts database.
        self._client = client
        self._frame_num = 0
        self._devices = []
        self.daemon = True

        # Create the form for displaying the list of contacts.
        self._list_view = ListBox(
            Widget.FILL_FRAME,
            name="devices",
            options=self._get_device_info(),
            on_change=self._on_pick
        )

        self._client_info_view = MultiColumnListBox(
            Widget.FILL_FRAME,
            columns=["<50%", "<50%"],
            label=None,
            name="client_info_view",
            options=self._get_client_info(),
        )

        self._info_layout = Layout([100, 100], fill_frame=True)
        self.add_layout(self._info_layout)
        self._info_layout.add_widget(self._client_info_view, column=0)
        self._info_layout.add_widget(self._list_view, column=1)

        self._divider_layout = Layout([1])
        self.add_layout(self._divider_layout)
        self._divider_layout.add_widget(Divider())

        self._button_layout = Layout([1, 1])
        self._follow_button = Button("Follow", self._follow)
        self.add_layout(self._button_layout)
        self._button_layout.add_widget(self._follow_button, 0)
        self._button_layout.add_widget(Button("Quit", self._quit), 1)

        self.fix()
        self._on_pick()

        self.start()

    def _on_pick(self):
        self._follow_button.disabled = self._list_view.value is None

    def _follow(self):
        self.save()
        raise NextScene("Follow Device")

    def _get_device_info(self):
        list_of_device_info = []
        count = 0
        if self._devices:
            for device in self._devices:
                count += 1
                list_of_device_info.append(("{} {}".format(
                    device.name if device.name else "Unknown Device", get_Address(device.address)), count))
        else:
            list_of_device_info = []
        return list_of_device_info

    def reload_devices(self):
        self._list_view.options = self._get_device_info()

    def _get_client_info(self):
        client_options = []
        items = 0
        for client_info_key, client_info_value in self._client.__dict__.items():
            items += 1
            client_options.append(([client_info_key, str(client_info_value)], items))
        return client_options

    def update_client_info(self):
        self._client_info_view.options = self._get_client_info()

    def run(self):
        mySniffer.scan()
        while True:

            time.sleep(config.UPDATE_SCREEN_INTERVAL)
            self._devices = mySniffer.getDevices().asList()
            self.update_client_info()
            self.reload_devices()
            self._info_layout.update_widgets()

    def _quit(self):
        self._scene.add_effect(
            PopUpDialog(self._screen,
                        "Are you sure you want to quit?",
                        ["Cancel", "Quit"],
                        on_close=self._quit_confirm))

    @staticmethod
    def _quit_confirm(selected):
        if selected == 1:
            raise StopApplication("User pressed quit")


class FollowView(Frame):
    def __init__(self, screen, client, device):
        super(FollowView, self).__init__(screen,
                                       screen.height * 2 // 3,
                                       screen.width * 2 // 3,
                                       hover_focus=True,
                                       title="Bluetooth Low Energy Sniffer - Following Device {}"
                                         .format(get_Address(device.address) if device != None else ""))

        self._device = device
        self._client = client

        self._client_info_view = MultiColumnListBox(
            Widget.FILL_FRAME,
            columns=[">50%"],
            label="Client Information",
            name="client_info_view",
            options=self._get_client_info(),
            on_change=self._get_client_info()
        )

        self._follow_button = Button("Follow", self._back)
        layout = Layout([100], fill_frame=True)
        self.add_layout(layout)
        layout.add_widget(Divider())
        layout2 = Layout([1, 1])
        self.add_layout(layout2)
        layout2.add_widget(self._follow_button, 0)
        layout2.add_widget(Button("Quit", self._quit_confirm), 0)
        layout2.add_widget(Button("Back", self._quit_confirm), 1)
        self.fix()

    def _back(self):
        raise NextScene("Main")

    def _get_client_info(self):
        client_options = []
        items = 0
        for client_info_key, client_info_value in self._client.__dict__.items():
            items += 1
            client_options.append(([client_info_key, client_info_value], items))
        return client_options

    @staticmethod
    def _quit_confirm():
        raise StopApplication("User pressed quit")



def setup(delay=6):
    # Display the libpcap logfile location

    global mySniffer
    global client

    client = Client()

    initialize_service_logging(client=client)
    logging.getLogger(config.SERVICE_LOGGER)
    logger.info("Starting service")

    if config.SAVE_TO_PCAP:
        logging.info("Capturing data to " + CaptureFiles.captureFilePath)

    if config.SAVE_TO_FILEBEAT:
        initialize_packets_logging_to_Filebeat()
        logger.info("Capturing data to Filebeat")

    # Try to open the serial port, here we start logging

    # Initialize the device without specified serial port
    logger.info(list(list_ports.grep(config.SNIFFER_PORT_KEYWORD_SEARCH)))
    for port in list_ports.grep(config.SNIFFER_PORT_KEYWORD_SEARCH):
        try:
            #TODO: This is hack, should have proper automatic port discovery
            logger.info(port.device)
            mySniffer = Sniffer.Sniffer(port.device)
            mySniffer.start()
            time.sleep(delay)
            mySniffer.scan()
            time.sleep(delay)
        except SerialException as e:
            logger.error("Searching Sniffer on port {}, but not found with error {}".format(port.device, str(e)))
            raise CloseSnifferException
        except Exception:
            logger.exception("exc_info", exc_info=True)
            raise CloseSnifferException
        else:
            client.add_sniffer(mySniffer)
            logger.info("Service successfully started")
            break

def scanForDevices(scantime=5):
    mySniffer.scan()
    time.sleep(scantime)
    devs = mySniffer.getDevices().asList()
    return devs


def selectDevice(devlist):
    """
    Attempts to select a specific Device from the supplied DeviceList
    """
    count = 0

    if len(devlist):
        print ("Found {0} BLE devices:\n".format(str(len(devlist))))
        # Display a list of devices, sorting them by index number
        for d in devlist.asList():
            """@type : Device"""
            count += 1
            print ("  [{0}] {1} ({2}:{3}:{4}:{5}:{6}:{7}, RSSI = {8})".format(count, d.name,
                                                                             "%02X" % d.address[0],
                                                                             "%02X" % d.address[1],
                                                                             "%02X" % d.address[2],
                                                                             "%02X" % d.address[3],
                                                                             "%02X" % d.address[4],
                                                                             "%02X" % d.address[5],
                                                                             d.RSSI))
        try:
            i = int(input("\nSelect a device to sniff, or '0' to scan again\n> "))
        except KeyboardInterrupt:
            raise KeyboardInterrupt

        except:
            return None

        # Select a device or scan again, depending on the input
        if (i > 0) and (i <= count):
            # Select the indicated device
            return devlist.find(i - 1)
        else:
            # This will start a new scan
            return None


def dumpPackets():
    """Dumps incoming packets to the display"""
    # Get (pop) unprocessed BLE packets.
    packets = mySniffer.getPackets()
    # Display the packets on the screen in verbose mode
    if args.verbose:
        for packet in packets:
            if packet.blePacket is not None:
                # Display the raw BLE packet payload
                # Note: 'BlePacket' is nested inside the higher level 'Packet' wrapper class
                print (packet.blePacket.payload)
            else:
                print (packet)
    else:
        print ('.' * len(packets))

def main():
    """Main program execution point"""

    # Scan for devices in range until the user makes a selection
    try:
        d = None
        while d is None:
            print("Scanning for BLE devices (5s) ...")
            devlist = scanForDevices()
            if len(devlist):
                # Select a device
                d = selectDevice(devlist)

        # Start sniffing the selected device
        print("Attempting to follow device {0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % d.address[0],
                                                                           "%02X" % d.address[1],
                                                                           "%02X" % d.address[2],
                                                                           "%02X" % d.address[3],
                                                                           "%02X" % d.address[4],
                                                                           "%02X" % d.address[5]))
        # Make sure we actually followed the selected device (i.e. it's still available, etc.)
        if d is not None:
            mySniffer.follow(d)
        else:
            print("ERROR: Could not find the selected device")

        # Dump packets
        while True:
            dumpPackets()
            time.sleep(1)

    except (KeyboardInterrupt, ValueError, IndexError) as e:
        # Close gracefully on CTRL+C
        if 'KeyboardInterrupt' not in str(type(e)):
            print("Caught exception:", e)
        mySniffer.doExit()
        sys.exit(-1)

def demo(screen, scene):
    global client
    main_scene = MainView(screen, client)
    scenes = [
        Scene([main_scene], -1, name="Main"),
        Scene([FollowView(screen, client, None)], -1, name="Follow Device")
    ]
    screen.play(scenes, stop_on_resize=True, start_scene=scene)

last_scene = None

if __name__ == '__main__':

    logger = logging.getLogger(config.SERVICE_LOGGER)
    last_scene = None
    setup(6)
    while True:

        try:
            Screen.wrapper(demo, catch_interrupt=True, arguments=[last_scene])
            mySniffer.doExit()
            sys.exit(-1)
        except ResizeScreenError as e:
            last_scene = e.scene
        except CloseSnifferException:
            logger.info("Service has been closed")
            mySniffer.doExit()
            sys.exit(-1)
        except StopApplication:
            logger.info("Service has been closed")
            mySniffer.doExit()
            sys.exit(-1)
        except Exception as e:
            logger.exception("exc_info", exc_info=True)




#C:\Users\blazb\AppData\Local\Programs\Python\Python36\python.exe

