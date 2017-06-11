import datetime
import sys
import time
import logging
from threading import Thread

import serial
from apscheduler.schedulers.background import BackgroundScheduler

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
from Project.shared import get_Address, ReloadSniffer
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
        self._screen = screen
        self._frame_num = 0
        self._devices = []
        self.daemon = True
        self.name = "scanning"

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


        self.start()

        self.fix()
        self._on_pick()

        #self.sched = BackgroundScheduler(daemon=True)
        #self.sched.start()
        #self.sched.add_job(self.run, 'interval', seconds=config.UPDATE_SCREEN_INTERVAL, max_instances=1)

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
        global mySniffer
        logger = logging.getLogger(config.SERVICE_LOGGER)
        while 1:
            starttime = time.time()
            try:
                if mySniffer is None or self._client.port is None:
                    setup(6)

                mySniffer.scan()
                time.sleep(config.UPDATE_SCREEN_INTERVAL - ((time.time() - starttime) % config.UPDATE_SCREEN_INTERVAL))
                self._devices = mySniffer.getDevices().asList()
                self.update_client_info()
                self.reload_devices()
                self._info_layout.update_widgets()
                self._screen.force_update()
            except Exception as e:
                time.sleep(5)
                logger.exception("Background Service Exception", exc_info=True)
                if mySniffer: mySniffer.doExit()
                time.sleep(10)
                self._client = Client()
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

        layout = Layout([100], fill_frame=True)
        self.add_layout(layout)
        layout.add_widget(Divider())
        layout2 = Layout([1, 1])
        self.add_layout(layout2)
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
    global mySniffer
    global client

    initialize_service_logging(client=client)
    logger = logging.getLogger(config.SERVICE_LOGGER)
    logger.info("Trying to start a service")

    if config.SAVE_TO_PCAP:
        logger.info("Capturing data to " + CaptureFiles.captureFilePath)

    if config.SAVE_TO_FILEBEAT:
        initialize_packets_logging_to_Filebeat()
        logger.info("Capturing data to Filebeat")

    # Try to open the serial port, here we start logging

    # Initialize the device without specified serial port
    for port in list_ports.grep(config.SNIFFER_PORT_KEYWORD_SEARCH):
        try:
            #TODO: This is hack, should have proper automatic port discovery
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
            client.update_client_with_sniffer(mySniffer)
            logger.info("Service successfully started")
            break

last_scene = None

def demo(screen, scene):
    global client
    main_scene = MainView(screen, client)
    scenes = [
        Scene([main_scene], -1, name="Main"),
        Scene([FollowView(screen, client, None)], -1, name="Follow Device")
    ]

    screen.set_scenes(scenes)

    while True:
        screen.draw_next_frame(repeat=True)
        time.sleep(0.05)


    #screen.play(scenes, stop_on_resize=True, start_scene=scene)





def main():
    global client, last_scene
    client = Client()
    while True:
        try:
            Screen.wrapper(demo, catch_interrupt=True, arguments=[last_scene])
            if mySniffer: mySniffer.doExit()
            sys.exit(-1)
        except ResizeScreenError as e:
            last_scene = e.scene
        except ReloadSniffer:
            logger.warning("Reloading Sniffer")
            if mySniffer: mySniffer.doExit()
        except CloseSnifferException:
            logger.info("Service has been closed (CloseSnifferException)")
            if mySniffer: mySniffer.doExit()
            sys.exit(-1)
        except Exception as e:
            logger.exception("Service has been closed (Unknown Exception)", exc_info=True)
            if mySniffer: mySniffer.doExit()
            sys.exit(-1)

if __name__ == '__main__':
    main()




#C:\Users\blazb\AppData\Local\Programs\Python\Python36\python.exe

