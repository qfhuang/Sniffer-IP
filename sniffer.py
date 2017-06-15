import sys
import time
import logging
from queue import Queue

from apscheduler.schedulers.background import BackgroundScheduler
from asciimatics.exceptions import NextScene, StopApplication, ResizeScreenError
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.widgets import Frame, ListBox, Button, Layout, Divider, Widget, PopUpDialog
from serial.serialutil import SerialException
from serial.tools import list_ports

from SnifferAPI import CaptureFiles
from SnifferAPI import Sniffer

from Project import config
from Project.client import Client
from Project.shared import get_Address
from Project.logging_service import initialize_service_logging, initialize_scheduler_logging, \
    initialize_packets_logging_to_Filebeat

mySniffer = None
followed_device = None
client = None
last_scene = None
queue = Queue()
initialize_scheduler_logging()

class MainView(Frame):
    def __init__(self, screen):
        super(MainView, self).__init__(screen,
                                       screen.height * 2 // 3,
                                       screen.width * 2 // 3,
                                       on_load=self.reload_devices,
                                       hover_focus=True,
                                       title="Bluetooth Low Energy Sniffer",
                                       reduce_cpu=True)
        self._screen = screen
        self._frame_num = 0
        self._devices = []

        # Create the form for displaying the list of found devices.
        self._list_view = ListBox(
            Widget.FILL_FRAME,
            name="devices",
            options=self._get_device_info(),
            on_change=self._on_pick
        )

        # Create the form for displaying the list of client information.
        global client
        self._client_info_view = client.get_client_widget()

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

        global  followed_device
        followed_device = None

        self.fix()
        self._on_pick()

        self.sched = BackgroundScheduler(daemon=True, logger=logging.getLogger(config.SCHEDULER_LOGGER))

    def start_service(self):
        if not self.sched.running:
            self.sched.start()
        self.sched.add_job(self.run, 'interval', seconds=config.UPDATE_SCREEN_INTERVAL, max_instances=1, id="scanning")
        logger = logging.getLogger(config.SERVICE_LOGGER)
        logger.info("Started scanning")

    def stop_service(self):
        self.sched.remove_all_jobs()
        logger = logging.getLogger(config.SERVICE_LOGGER)
        logger.info("Stopped scanning")

    def _on_pick(self):
        self._follow_button.disabled = self._list_view.value is None

    def _follow(self):
        self.sched.remove_all_jobs()
        self.save()
        global followed_device
        followed_device = self._devices[self.data["devices"]-1]
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

    def update_client_info(self):
        global client
        self._client_info_view.options = client.get_client_info()

    def run(self):
        global mySniffer, client, queue
        logger = logging.getLogger(config.SERVICE_LOGGER)
        starttime = time.time()
        try:
            if mySniffer == None or client.port == None:
                if not setup(config.SETUP_DELAY):
                    if client.is_active:
                        logger.warning("Client is inactive")
                    client.is_active = False
                    self.update_client_info()
                    self._screen.force_update()
                    time.sleep(60)
                    return

            if not client.is_active:
                if not client.is_active:
                    logger.info("Client is active")
                client.is_active = True
                self.update_client_info()
                self._screen.force_update()

            mySniffer.scan()
            time.sleep((config.UPDATE_SCREEN_INTERVAL - ((time.time() - starttime) % config.UPDATE_SCREEN_INTERVAL)) -1)
            self._devices = mySniffer.getDevices().asList()
            client.update_client_with_sniffer(mySniffer)
            self.update_client_info()
            self.reload_devices()
            self._info_layout.update_widgets()
        except Exception as e:
            #Closing ser port is already done in Sniffer API
            if client.is_active: logger.exception("Background Service Exception (scanning)", exc_info=True)
            client = Client()
            self.update_client_info()
            self._list_view.options = []
            mySniffer = None
        self._screen.force_update()

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
    def __init__(self, screen, device):
        super(FollowView, self).__init__(screen,
                                       screen.height * 2 // 3,
                                       screen.width * 2 // 3,
                                       hover_focus=True,
                                       title="Bluetooth Low Energy Sniffer - Following Device {}"
                                         .format(get_Address(device.address) if device != None else ""))

        self._device = device
        self._packets = []

        # Create the form for displaying the list of sniffed packets.
        self._list_view = ListBox(
            Widget.FILL_FRAME,
            name="packets",
            options=self._get_packets_info(),
        )

        # Create the form for displaying the list of client information.
        global client
        self._client_info_view = client.get_client_widget()

        self._info_layout = Layout([100, 100], fill_frame=True)
        self.add_layout(self._info_layout)
        self._info_layout.add_widget(self._client_info_view, column=0)
        self._info_layout.add_widget(self._list_view, column=1)

        self._divider_layout = Layout([1])
        self.add_layout(self._divider_layout)
        self._divider_layout.add_widget(Divider())

        layout2 = Layout([1, 1])
        self.add_layout(layout2)
        layout2.add_widget(Button("Quit", self._quit), 0)
        layout2.add_widget(Button("Back", self._back), 1)
        self.fix()

        self.sched = BackgroundScheduler(daemon=True, logger=logging.getLogger(config.SCHEDULER_LOGGER))

    def start_service(self):
        if not self.sched.running:
            self.sched.start()
        self.sched.add_job(self.run, 'interval', seconds=config.UPDATE_SCREEN_INTERVAL, max_instances=1, id="following")
        logger = logging.getLogger(config.SERVICE_LOGGER)
        logger.info("Started following")

    def stop_service(self):
        self.sched.remove_all_jobs()
        logger = logging.getLogger(config.SERVICE_LOGGER)
        logger.info("Stopped following")

    def _back(self):
        self.sched.remove_all_jobs()
        raise NextScene("Main")

    def _get_packets_info(self):
        list_of_packets = []
        count = 0
        if self._packets:
            for packet in self._packets:
                count += 1
                list_of_packets.append(("RSSI: {} dBm | Payload: {}".format(packet.RSSI,
                    packet.blePacket.payload if packet.blePacket else packet), count))
        else:
            list_of_packets = []
        return list_of_packets

    def reload_packets(self):
        self._list_view.options = self._get_packets_info()

    def update_client_info(self):
        global client
        self._client_info_view.options = client.get_client_info()

    def run(self):
        global mySniffer, client, queue, followed_device
        starttime = time.time()
        try:
            if mySniffer == None or client.port == None or followed_device == None:
                queue.put(item=("Change scene", NextScene("Main")))

            if mySniffer.state != 1:
                mySniffer.follow(self._device)

            self._packets = mySniffer.getPackets()
            time.sleep((config.UPDATE_SCREEN_INTERVAL - ((time.time() - starttime) % config.UPDATE_SCREEN_INTERVAL)) - 0.5)
            client.update_client_with_sniffer(mySniffer)
            self.update_client_info()
            self.reload_packets()
            self._info_layout.update_widgets()
            self._screen.force_update()
        except Exception as e:
            #Closing ser port is already done in Sniffer API
            time.sleep(1)
            logger = logging.getLogger(config.SERVICE_LOGGER)
            logger.exception("Background Service Exception (following)", exc_info=True)
            client = Client()
            self.update_client_info()
            self._list_view.options = []
            mySniffer = None

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


def setup(delay):
    global mySniffer, client

    logger = logging.getLogger(config.SERVICE_LOGGER)
    if client.is_active: logger.info("Trying to start a service")

    if config.SAVE_TO_PCAP:
        if client.is_active: logger.info("Capturing data to " + CaptureFiles.captureFilePath)

    if config.SAVE_TO_FILEBEAT:
        initialize_packets_logging_to_Filebeat()
        if client.is_active: logger.info("Capturing data to Filebeat")

    # Initialize the device without specified serial port
    # TODO: This is HACK, should have proper automatic port discovery - TROLL this is so dirty
    for port in list_ports.grep(config.SNIFFER_PORT_KEYWORD_SEARCH):
        try:
            mySniffer = Sniffer.Sniffer(port.device)
            mySniffer.start()
            time.sleep(delay)
            mySniffer.scan()
            time.sleep(delay)
        except SerialException as e:
            if client.is_active:
                logger.warning("Setup Exception - Searching Sniffer on port {}, but not found with error {}".format(port.device, str(e)))
            if mySniffer != None: mySniffer.doExit()
            mySniffer = None
        except Exception as e:
            if client.is_active:
                logger.warning("Setup Exception {}".format(str(e)))
            if mySniffer != None: mySniffer.doExit()
            mySniffer = None
        else:
            client.update_client_with_sniffer(mySniffer)
            if client.is_active:
                logger.info("Service successfully started")
            return True
    if client.is_active: logger.warning("Setup was unsuccessful")
    return False

def demo(screen, scene):
    global client, followed_device, queue

    main_scene = MainView(screen)
    scenes = [
        Scene([main_scene], -1, name="Main"),
        Scene([FollowView(screen, followed_device)], -1, name="Follow Device")
    ]

    screen.set_scenes(scenes, start_scene=scene)

    prev_index = None
    while True:
        curr_index = screen._scene_index
        if not queue.empty():
            item_type, item = queue.get()

            if item_type == "Change scene":
                curr_scene = screen._scenes[curr_index]
                try:
                    raise item
                except NextScene as e:
                    curr_scene.exit()

                    for i, scene in enumerate(screen._scenes):
                        if curr_scene.name == e.name:
                            screen._scene_index = i
                            break

        if curr_index != prev_index:
            if prev_index != None:
                screen._scenes[prev_index].effects[0].stop_service()
            screen._scenes[curr_index].effects[0].start_service()

        prev_index = curr_index
        screen.draw_next_frame(repeat=True)
        time.sleep(0.05)


        #TODO: Screen resizing
        #if screen.has_resized():
            #screen._scenes[screen._scene_index].exit()
            #raise ResizeScreenError("Screen resized",
            #                    screen._scenes[screen._scene_index])


def main():
    logger = logging.getLogger(config.SERVICE_LOGGER)
    global client, last_scene
    client = Client()
    initialize_service_logging(client=client)
    sched = BackgroundScheduler(daemon=True, logger=logging.getLogger(config.SCHEDULER_LOGGER))
    sched.start()
    sched.add_job(client.send_client_status, 'interval', seconds=config.SEND_CLIENT_STATUS_INTERVAL, max_instances=1, id="status")
    while True:
        try:
            Screen.wrapper(demo, catch_interrupt=True, arguments=[last_scene])
            if mySniffer: mySniffer.doExit()
            sys.exit(-1)
        except StopApplication:
            logger.info("Application Exit (user pressed Quit)")
            if mySniffer: mySniffer.doExit()
            sys.exit(-1)
        except Exception as e:
            logger.exception("Application Exit (Unknown Exception)", exc_info=True)
            if mySniffer: mySniffer.doExit()
            sys.exit(-1)

if __name__ == '__main__':
    main()




#C:\Users\blazb\AppData\Local\Programs\Python\Python36\python.exe

