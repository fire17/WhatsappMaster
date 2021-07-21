"""
wa-automate-python module

.. moduleauthor:: Mukul Hase <mukulhase@gmail.com>, Adarsh Sanjeev <adarshsanjeev@gmail.com>
"""

import binascii
import io
import logging
import os
import time
import datetime
import re
import shutil
import tempfile
from base64 import b64decode
from io import BytesIO
from json import dumps, loads
import traceback
import json as json
import re
from threading import Thread
import threading

import requests
from PIL import Image
from axolotl.kdf.hkdfv3 import HKDFv3
from axolotl.util.byteutil import ByteUtil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from .helper import convert_to_base64
from .objects.chat import UserChat, factory_chat
from .objects.contact import Contact
from .objects.message import MessageGroup, factory_message
from .objects.number_status import NumberStatus
from .wapi_js_wrapper import WapiJsWrapper

from .objects.message import *

__version__ = '1.3.15'


class WhatsAPIDriverStatus(object):
	Unknown = 'Unknown'
	NoDriver = 'NoDriver'
	NotConnected = 'NotConnected'
	NotLoggedIn = 'NotLoggedIn'
	LoggedIn = 'LoggedIn'


class WhatsAPIException(Exception):
	pass


class ChatNotFoundError(WhatsAPIException):
	pass


class ContactNotFoundError(WhatsAPIException):
	pass


class WhatsAPIDriver(object):
	"""
	This is our main driver objects.
		.. note::
		   Runs its own instance of selenium
		"""
	_PROXY = None

	_URL = "https://web.whatsapp.com"

	_LOCAL_STORAGE_FILE = 'localStorage.json'

	_SELECTORS = {
		'qrCode': "canvas[aria-label=\"Scan me!\"]",
		'qrCodePlain': "div[data-ref]",
		'QRReloader': 'div[data-ref] > span > div',
		'mainPage': ".two",
	}

	logger = logging.getLogger(__name__)
	driver = None

	Q = []
	Qstarted = False

	# Profile points to the Firefox profile for firefox and Chrome cache for chrome
	# Do not alter this
	_profile = None

	def get_local_storage(self):
		return self.driver.execute_script('return window.localStorage;')

	def set_local_storage(self, data):
		self.driver.execute_script(''.join(
			["window.localStorage.setItem('{}', '{}');".format(k, v.replace("\n", "\\n") if isinstance(v, str) else v)
			 for k, v in data.items()]))

	def save_firefox_profile(self, remove_old=False):
		"""Function to save the firefox profile to the permanant one"""
		self.logger.info("Saving profile from %s to %s" % (self._profile.path, self._profile_path))

		if remove_old:
			if os.path.exists(self._profile_path):
				try:
					shutil.rmtree(self._profile_path)
				except OSError:
					pass

			shutil.copytree(os.path.join(self._profile.path), self._profile_path,
							ignore=shutil.ignore_patterns("parent.lock", "lock", ".parentlock"))
		else:
			for item in os.listdir(self._profile.path):
				if item in ["parent.lock", "lock", ".parentlock"]:
					continue
				s = os.path.join(self._profile.path, item)
				d = os.path.join(self._profile_path, item)
				if os.path.isdir(s):
					shutil.copytree(s, d,
									ignore=shutil.ignore_patterns("parent.lock", "lock", ".parentlock"))
				else:
					shutil.copy2(s, d)

		with open(os.path.join(self._profile_path, self._LOCAL_STORAGE_FILE), 'w') as f:
			f.write(dumps(self.get_local_storage()))

	def set_proxy(self, proxy):
		self.logger.info("Setting proxy to %s" % proxy)
		proxy_address, proxy_port = proxy.split(":")
		self._profile.set_preference("network.proxy.type", 1)
		self._profile.set_preference("network.proxy.http", proxy_address)
		self._profile.set_preference("network.proxy.http_port", int(proxy_port))
		self._profile.set_preference("network.proxy.ssl", proxy_address)
		self._profile.set_preference("network.proxy.ssl_port", int(proxy_port))

	def close(self):
		"""Closes the selenium instance"""
		self.driver.close()


	def __init1__(
		self,
		client="firefox",
		username="API",
		proxy=None,
		command_executor=None,
		loadstyles=False,
		profile = "/app/google-chrome/Profile",
		headless=False,
		autoconnect=True,
		logger=None,
		extra_params=None,
		chrome_options=None,
		# executable_path="/app/vendor/geckodriver/"
		binPath = None,
		executable_path=None, nv = "nv"
	):
		"""Initialises the webdriver"""

		print("((((((((((((((((()))))))))))))))))")
		print("((((((((((((((((()))))))))))))))))")
		print("((((((((((((((((()))))))))))))))))")
		print("((((((((((((((((()))))))))))))))))")
		print("((((((((((((((((())))))))))))))))) headless",headless,nv)
		print("((((((((((((((((())))))))))))))))) STATTING WEBDRIVER profile - ",profile)
		# self.license_key = ""
		self.logger = logger or self.logger
		extra_params = extra_params or {}

		if profile is not None:
			self._profile_path = profile
			self.logger.info("Checking for profile at %s" % self._profile_path)
			if not os.path.exists(self._profile_path):
				self.logger.critical("Could not find profile at %s" % profile)
				raise WhatsAPIException("Could not find profile at %s" % profile)
		else:
			self._profile_path = None

		self.client = client.lower()
		if self.client == "firefox":
			if self._profile_path is not None:
				self._profile = webdriver.FirefoxProfile(self._profile_path)
			else:
				self._profile = webdriver.FirefoxProfile()
			if not loadstyles:
				# Disable CSS
				self._profile.set_preference("permissions.default.stylesheet", 2)
				# Disable images
				self._profile.set_preference("permissions.default.image", 2)
				# Disable Flash
				self._profile.set_preference(
					"dom.ipc.plugins.enabled.libflashplayer.so", "false"
				)
			if proxy is not None:
				self.set_proxy(proxy)

			options = Options()

			if headless:
				options.set_headless()

			options.profile = self._profile

			capabilities = DesiredCapabilities.FIREFOX.copy()
			capabilities["webStorageEnabled"] = True

			self.logger.info("Starting webdriver")
			if executable_path is not None:
				executable_path = os.path.abspath(executable_path)

				self.logger.info("Starting webdriver")
				self.driver = webdriver.Firefox(
					# firefox_binary=firefox_binary,
					capabilities=capabilities,
					options=options,
					executable_path=executable_path,
					**extra_params,
				)
			else:
				self.logger.info("Starting webdriver")
				self.driver = webdriver.Firefox(
					# firefox_binary=firefox_binary,
					capabilities=capabilities, options=options, **extra_params
				)

		elif self.client == "chrome":
			print("HHHHHHHHHHHHHHHHHHHHHXXXXXXXXX",headless)
			print("HHHHHHHHHHHHHHHHHHHHHXXXXXXXXX",headless)
			print("HHHHHHHHHHHHHHHHHHHHHXXXXXXXXX",headless)
			print("HHHHHHHHHHHHHHHHHHHHHXXXXXXXXX",headless)
			print("HHHHHHHHHHHHHHHHHHHHHXXXXXXXXX",headless)
			print("HHHHHHHHHHHHHHHHHHHHHXXXXXXXXX",headless)

			if binPath is None:
				self._profile = webdriver.ChromeOptions()
				if self._profile_path is not None:
					self._profile.add_argument("user-data-dir=%s" % self._profile_path)
				if proxy is not None:
					self._profile.add_argument("--proxy-server=%s" % proxy)
				if headless:
					self._profile.add_argument("headless")
				if chrome_options is not None:
					self._profile = chrome_options
					## for option in chrome_options:
					##     self._profile.add_argument(option)
				self.logger.info("Starting webdriver")
				bPath = ""
				bPath = os.environ.get("CHROMEDRIVER_PATH")
				self.driver = webdriver.Chrome(executable_path=bPath,chrome_options=self._profile, **extra_params)
			else:
				chrome_options = webdriver.ChromeOptions()
				binPath = "/usr/bin/google-chrome"
				profileDir = "/session/rprofile2"
				# executable_path = "/home/magic/wholesomegarden/WhatsappMaster/chromedriver"
				# profileDir = "/home/magic/wholesomegarden/WhatsappMaster"+profileDir
				executable_path = "/root/WhatsappMaster/chromedriver"
				profileDir = "/root/WhatsappMaster"+profileDir
				print(binPath, executable_path)
				print(binPath, executable_path)
				print(binPath, executable_path)
				print(binPath, executable_path)
				# input()
				chrome_options.binary_location = binPath
				# chrome_options.add_argument('incognito')
				# chrome_options.add_argument('headless')
				if headless:
					chrome_options.add_argument("--headless")
				chrome_options.add_argument("--disable-dev-shm-usage")
				chrome_options.add_argument("--no-sandbox")
				chrome_options.add_argument("--window-size=1420,3600")
				chrome_options.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36")
				# user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36'
				# chrome_options.add_argument('user-agent={0}'.format(user_agent))
				chrome_options.add_experimental_option('prefs', {'intl.accept_languages': 'en,en_US;q=0.9'})

				# chrome_options.add_argument("--user-agent=New User Agent")
				chrome_options.add_argument("user-data-dir="+profileDir);
				chrome_options.add_argument('--profile-directory='+profileDir+"rprofile2/Profile 1")

				self.driver = webdriver.Chrome(executable_path,chrome_options=chrome_options)



		elif client == "remote":
			if self._profile_path is not None:
				self._profile = webdriver.FirefoxProfile(self._profile_path)
			else:
				self._profile = webdriver.FirefoxProfile()
			capabilities = DesiredCapabilities.FIREFOX.copy()
			self.driver = webdriver.Remote(
				command_executor=command_executor,
				desired_capabilities=capabilities,
				**extra_params,
			)

		else:
			self.logger.error("Invalid client: %s" % client)
		self.username = username
		self.wapi_functions = WapiJsWrapper(self.driver, self)

		self.driver.set_script_timeout(500)
		self.driver.implicitly_wait(10)

		if autoconnect:
			self.connect()

	def __init__(self, client="firefox", username="API", proxy=None, command_executor=None, loadstyles=False,
				 profile=None, headless=False, autoconnect=True, logger=None, extra_params=None, chrome_options=None,
				 executable_path=None, script_timeout=60, element_timeout=30, license_key="AAC1879F-DBB54B88-9FA197B2-51F83FAE", wapi_version='master'):
		"""Initialises the webdriver"""

		self.logger = logger or self.logger
		self.license_key = license_key
		extra_params = extra_params or {}
		self.history = []

		if profile is not None:
			self._profile_path = profile
			self.logger.info("Checking for profile at %s" % self._profile_path)
			if not os.path.exists(self._profile_path):
				self.logger.critical("Could not find profile at %s" % profile)
				raise WhatsAPIException("Could not find profile at %s" % profile)
		else:
			self._profile_path = None

		self.client = client.lower()
		if self.client == "firefox":
			if self._profile_path is not None:
				self._profile = webdriver.FirefoxProfile(self._profile_path)
			else:
				self._profile = webdriver.FirefoxProfile()
			if not loadstyles:
				# Disable CSS
				self._profile.set_preference('permissions.default.stylesheet', 2)
				# Disable images
				self._profile.set_preference('permissions.default.image', 2)
				# Disable Flash
				self._profile.set_preference('dom.ipc.plugins.enabled.libflashplayer.so',
											 'false')
			# Defaults to no proxy
			self._profile.set_preference("network.proxy.type", 0)
			if proxy is not None:
				self.set_proxy(proxy)

			options = Options()

			if headless:
				options.headless = True

			options.profile = self._profile

			capabilities = DesiredCapabilities.FIREFOX.copy()
			capabilities['webStorageEnabled'] = True

			self.logger.info("Starting webdriver")
			if executable_path is not None:
				executable_path = os.path.abspath(executable_path)

				self.logger.info("Starting webdriver")
				self.driver = webdriver.Firefox(capabilities=capabilities, options=options,
												executable_path=executable_path,
												**extra_params)
			else:
				self.logger.info("Starting webdriver")
				self.driver = webdriver.Firefox(capabilities=capabilities, options=options,
												**extra_params)

		elif self.client == "chrome":
			self._profile = webdriver.ChromeOptions()
			if self._profile_path is not None:
				self._profile.add_argument("--user-data-dir=%s" % self._profile_path)
			if proxy is not None:
				self._profile.add_argument('--proxy-server=%s' % proxy)
			if headless:
				self._profile.add_argument('--headless')
				self._profile.add_argument('--disable-gpu')
				self._profile.add_argument('--remote-debugging-port=9222')
				self._profile.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36')
			if chrome_options is not None:
				self._profile = chrome_options

			if executable_path is not None:
				self.logger.info("Starting webdriver")
				self.driver = webdriver.Chrome(executable_path=executable_path, chrome_options=self._profile, **extra_params)
			else:
				self.logger.info("Starting webdriver")
				self.driver = webdriver.Chrome(chrome_options=self._profile, **extra_params)

		elif client == 'remote':
			if self._profile_path is not None:
				self._profile = webdriver.FirefoxProfile(self._profile_path)
			else:
				self._profile = webdriver.FirefoxProfile()

			options = Options()

			if headless:
				options.headless = True

			capabilities = DesiredCapabilities.FIREFOX.copy()
			self.driver = webdriver.Remote(
				command_executor=command_executor,
				desired_capabilities=capabilities,
				options=options,
				**extra_params
			)

		else:
			self.logger.error("Invalid client: %s" % client)
		self.username = username
		self.wapi_functions = WapiJsWrapper(self.driver, self, wapi_version)

		self.driver.set_script_timeout(script_timeout)
		self.element_timeout = element_timeout

		if autoconnect:
			self.connect()

	def __init__0(self, client="firefox", username="API", proxy=None, command_executor=None, loadstyles=False,
				 profile=None, headless=False, autoconnect=True, logger=None, extra_params=None, chrome_options=None,
				 executable_path=None, script_timeout=60, element_timeout=30, license_key=None, wapi_version='master'):
		"""Initialises the webdriver"""

		self.logger = logger or self.logger
		self.license_key = license_key
		extra_params = extra_params or {}

		if profile is not None:
			self._profile_path = profile
			self.logger.info("Checking for profile at %s" % self._profile_path)
			if not os.path.exists(self._profile_path):
				self.logger.critical("Could not find profile at %s" % profile)
				raise WhatsAPIException("Could not find profile at %s" % profile)
		else:
			self._profile_path = None

		self.client = client.lower()
		if self.client == "firefox":
			if self._profile_path is not None:
				self._profile = webdriver.FirefoxProfile(self._profile_path)
			else:
				self._profile = webdriver.FirefoxProfile()
			if not loadstyles:
				# Disable CSS
				self._profile.set_preference('permissions.default.stylesheet', 2)
				# Disable images
				self._profile.set_preference('permissions.default.image', 2)
				# Disable Flash
				self._profile.set_preference('dom.ipc.plugins.enabled.libflashplayer.so',
											 'false')
			# Defaults to no proxy
			self._profile.set_preference("network.proxy.type", 0)
			if proxy is not None:
				self.set_proxy(proxy)

			options = Options()

			if headless:
				options.headless = True

			options.profile = self._profile

			capabilities = DesiredCapabilities.FIREFOX.copy()
			capabilities['webStorageEnabled'] = True

			self.logger.info("Starting webdriver")
			if executable_path is not None:
				executable_path = os.path.abspath(executable_path)

				self.logger.info("Starting webdriver")
				self.driver = webdriver.Firefox(capabilities=capabilities, options=options,
												executable_path=executable_path,
												**extra_params)
			else:
				self.logger.info("Starting webdriver")
				self.driver = webdriver.Firefox(capabilities=capabilities, options=options,
												**extra_params)

		elif self.client == "chrome":
			self._profile = webdriver.ChromeOptions()
			if self._profile_path is not None:
				self._profile.add_argument("--user-data-dir=%s" % self._profile_path)
			if proxy is not None:
				self._profile.add_argument('--proxy-server=%s' % proxy)
			if headless:
				self._profile.add_argument('--headless')
				self._profile.add_argument('--disable-gpu')
				self._profile.add_argument('--remote-debugging-port=9222')
				self._profile.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36')
			if chrome_options is not None:
				for option in chrome_options:
					self._profile.add_argument(option)

			if executable_path is not None:
				self.logger.info("Starting webdriver")
				self.driver = webdriver.Chrome(executable_path=executable_path, chrome_options=self._profile, **extra_params)
			else:
				self.logger.info("Starting webdriver")
				self.driver = webdriver.Chrome(chrome_options=self._profile, **extra_params)

		elif client == 'remote':
			if self._profile_path is not None:
				self._profile = webdriver.FirefoxProfile(self._profile_path)
			else:
				self._profile = webdriver.FirefoxProfile()

			options = Options()

			if headless:
				options.headless = True

			capabilities = DesiredCapabilities.FIREFOX.copy()
			self.driver = webdriver.Remote(
				command_executor=command_executor,
				desired_capabilities=capabilities,
				options=options,
				**extra_params
			)

		else:
			self.logger.error("Invalid client: %s" % client)
		self.username = username
		self.wapi_functions = WapiJsWrapper(self.driver, self, wapi_version)

		self.driver.set_script_timeout(script_timeout)
		self.element_timeout = element_timeout

		if autoconnect:
			self.connect()

	def get_status(self):
		"""
		Returns status of the driver

		:return: Status
		:rtype: WhatsAPIDriverStatus
		"""
		if self.driver is None:
			return WhatsAPIDriverStatus.NotConnected
		if self.driver.session_id is None:
			return WhatsAPIDriverStatus.NotConnected
		try:
			self.driver.find_element_by_css_selector(self._SELECTORS['mainPage'])
			return WhatsAPIDriverStatus.LoggedIn
		except NoSuchElementException:
			pass
		try:
			self.driver.find_element_by_css_selector(self._SELECTORS['qrCode'])
			return WhatsAPIDriverStatus.NotLoggedIn
		except NoSuchElementException:
			pass
		return WhatsAPIDriverStatus.Unknown

	def connect(self):
		self.driver.get(self._URL)

		profilePath = ""
		if self.client == "chrome":
			profilePath = ""
		else:
			profilePath = self._profile.path

		local_storage_file = os.path.join(profilePath, self._LOCAL_STORAGE_FILE)
		if os.path.exists(local_storage_file):
			with open(local_storage_file) as f:
				self.set_local_storage(loads(f.read()))

			self.driver.refresh()

	def quit(self):
		self.wapi_functions.quit()
		self.driver.quit()

	###########################################
	# API Methods
	###########################################
	def is_logged_in(self):
		"""Returns if user is logged. Can be used if non-block needed for wait_for_login"""

		# instead we use this (temporary) solution:
		# return 'class="app _3dqpi two"' in self.driver.page_source
		return self.driver.execute_script(
			"if (document.querySelector('*[data-icon=chat]') !== null) { return true } else { return false }")

	def is_connected(self):
		"""Returns if user's phone is connected to the internet."""
		return self.wapi_functions.isConnected()

	def wait_for_login(self, timeout=90):
		"""
		Waits for the app to log in or for the QR to appear
		:return: bool: True if has logged in, false if asked for QR
		"""
		WebDriverWait(self.driver, timeout).until(EC.visibility_of_element_located((By.CSS_SELECTOR, self._SELECTORS['mainPage'] + ',' + self._SELECTORS['qrCode'])))
		try:
			self.driver.find_element_by_css_selector(self._SELECTORS['mainPage'])
			return True
		except NoSuchElementException:
			self.driver.find_element_by_css_selector(self._SELECTORS['qrCode'])
			return False

	def screenshot(self, filename):
		self.driver.get_screenshot_as_file(filename)

	def get_battery_level(self):
		"""
		Check the battery level of device

		:return: int: Battery level
		"""
		return self.wapi_functions.getBatteryLevel()

	def set_presence(self, present):
		"""
		Set presence to 'online' or not
		"""
		return self.wapi_functions.setPresence(present)

	def set_profile_status(self, status):
		return self.wapi_functions.setMyStatus(status)

	def set_profile_name(self, name):
		return self.wapi_functions.setMyName(name)

	#################
	# QR
	#################
	def get_qr_plain(self):
		self.reload_qr()
		return WebDriverWait(self.driver, self.element_timeout) \
			.until(EC.visibility_of_element_located((By.CSS_SELECTOR, self._SELECTORS['qrCodePlain']))) \
			.get_attribute("data-ref")

	def get_qr(self, filename=None):
		"""Get pairing QR code from client"""
		self.reload_qr()
		qr = WebDriverWait(self.driver, self.element_timeout) \
			.until(EC.visibility_of_element_located((By.CSS_SELECTOR, self._SELECTORS['qrCode'])))

		if filename is None:
			fd, fn_png = tempfile.mkstemp(prefix=self.username, suffix='.png')
		else:
			fd = os.open(filename, os.O_RDWR | os.O_CREAT)
			fn_png = os.path.abspath(filename)
		self.logger.debug("QRcode image saved at %s" % fn_png)
		qr.screenshot(fn_png)
		os.close(fd)
		return fn_png

	def get_qr_base64(self):
		self.reload_qr()
		qr = WebDriverWait(self.driver, self.element_timeout) \
			.until(EC.visibility_of_element_located((By.CSS_SELECTOR, self._SELECTORS['qrCode'])))

		return qr.screenshot_as_base64

	def reload_qr(self):
		try:
			self.driver.find_element_by_css_selector(self._SELECTORS['QRReloader']).click()
		except NoSuchElementException:
			pass

	#################
	# Chats & Contacts
	#################
	def get_contact_from_id(self, contact_id):
		"""
		Fetches a contact given its ID

		:param contact_id: Contact ID
		:type contact_id: str
		:return: Contact or Error
		:rtype: Contact
		"""
		contact = self.wapi_functions.getContact(contact_id)

		if contact is None:
			raise ContactNotFoundError("Contact {0} not found".format(contact_id))

		return Contact(contact, self)

	def get_chat_from_id(self, chat_id):
		"""
		Fetches a chat given its ID

		:param chat_id: Chat ID
		:type chat_id: str
		:return: Chat or Error
		:rtype: Chat
		"""
		chat = self.wapi_functions.getChatById(chat_id)
		if chat:
			return factory_chat(chat, self)

		raise ChatNotFoundError("Chat {0} not found".format(chat_id))

	def get_chat_from_name(self, chat_name):
		"""
		Fetches a chat given its name

		:param chat_name: Chat name
		:type chat_name: str
		:return: Chat or Error
		:rtype: Chat
		"""
		chat = self.wapi_functions.getChatByName(chat_name)
		if chat:
			return factory_chat(chat, self)

		raise ChatNotFoundError("Chat {0} not found".format(chat_name))

	def get_chat_from_phone_number(self, number):
		"""
		Gets chat by phone number
		Number format should be as it appears in Whatsapp ID
		For example, for the number:
		+972-51-234-5678
		This function would receive:
		972512345678

		:param number: Phone number
		:return: Chat
		:rtype: Chat
		"""
		for chat in self.get_all_chats():
			if not isinstance(chat, UserChat) or number not in chat.id:
				continue
			return chat

		raise ChatNotFoundError('Chat for phone {0} not found'.format(number))

	def get_contacts(self):
		"""
		Fetches list of all contacts
		This will return chats with people from the address book only
		Use get_all_chats for all chats

		:return: List of contacts
		:rtype: list[Contact]
		"""
		all_contacts = self.wapi_functions.getAllContacts()
		return [Contact(contact, self) for contact in all_contacts]

	def get_my_contacts(self):
		"""
		Fetches list of added contacts

		:return: List of contacts
		:rtype: list[Contact]
		"""
		my_contacts = self.wapi_functions.getMyContacts()
		return [Contact(contact, self) for contact in my_contacts]

	def get_all_groups(self):
		chats = self.wapi_functions.getAllGroups()
		if chats:
			return [factory_chat(chat, self) for chat in chats]
		else:
			return []

	def get_all_chats(self):
		"""
		Fetches all chats

		:return: List of chats
		:rtype: list[Chat]
		"""
		chats = self.wapi_functions.getAllChats()
		if chats:
			return [factory_chat(chat, self) for chat in chats]
		else:
			return []

	def open_chat(self, chat_id):
		return self.wapi_functions.openChat(chat_id)

	def get_all_chat_ids(self):
		"""
		Fetches all chat ids

		:return: List of chat ids
		:rtype: list[str]
		"""
		return self.wapi_functions.getAllChatIds()

	def chat_send_seen(self, chat_id):
		"""
		Send a seen to a chat given its ID

		:param chat_id: Chat ID
		:type chat_id: str
		"""
		return self.wapi_functions.sendSeen(chat_id)

	def chat_load_earlier_messages(self, chat_id):
		self.wapi_functions.loadEarlierMessages(chat_id)

	def chat_load_all_earlier_messages(self, chat_id):
		self.wapi_functions.loadAllEarlierMessages(chat_id)

	def async_chat_load_all_earlier_messages(self, chat_id):
		self.wapi_functions.asyncLoadAllEarlierMessages(chat_id)

	def are_all_messages_loaded(self, chat_id):
		return self.wapi_functions.areAllMessagesLoaded(chat_id)

	def get_profile_pic_from_id(self, id):
		profile_pic_url = self.wapi_functions.getProfilePicFromServer(id)
		if profile_pic_url:
			return requests.get(profile_pic_url).content
		else:
			return False

	def check_number_status(self, number_id):
		"""
		Check if a number is valid/registered in the whatsapp service

		:param number_id: number id
		:return:
		"""
		number_status = self.wapi_functions.checkNumberStatus(number_id)
		return NumberStatus(number_status, self)

	def contact_block(self, id):
		return self.wapi_functions.contactBlock(id)

	def contact_unblock(self, id):
		return self.wapi_functions.contactUnblock(id)

	def is_chat_online(self, chat_id):
		return self.wapi_functions.isChatOnline(chat_id)

	def get_chat_last_seen(self, chat_id):
		return self.wapi_functions.getLastSeen(chat_id)

	def delete_chat(self, chat_id):
		"""
		Delete a chat

		:param chat_id: id of chat
		:return:
		"""
		return self.wapi_functions.deleteConversation(chat_id)

	#################
	# Messages
	#################
	# def get_unread(self, include_me=False, include_notifications=False, use_unread_count=False):

	def get_unread(self, include_me=False, include_notifications=False, use_unread_count=False):
		# include_me=True
		# print("UUU")
		# code = "return WAPI.getUnreadMessages(false, false, false);" #'"+base64+"')"
		# raw_message_groups = self.driver.execute_script(script = code)
		code = "return WAPI.getAllUnreadMessages()"
		raw_message_groups = self.driver.execute_script(script = code)
		# raw_message_groups = self.wapi_functions.getUnreadMessages(include_me, include_notifications, True)

		# print("UUUF")
		# self.driver.execute_script(script=code)
		# print("UNREAD",str(len(raw_message_groups)))
		# for m in raw_message_groups[0]:
			# print(m, ":::", raw_message_groups[0][m])

		new_messages = []
		initHistory = False
		if len(self.history) == 0:
			initHistory = True

		for m in raw_message_groups:
			if m["id"] not in self.history:
				self.history.append(m["id"])
				if not initHistory:
					if m["sender"] is not None:
						if include_me or ("isMe" in m["sender"] and not m["sender"]["isMe"]):
							# for k in m:
							# 	print (k, ":::",m[k])
							print(m["chat"]["id"],"  ===  ",m["chat"]["id"],"  ===  ",m["content"])
							new_messages.append(m)
						else:
							pass # TODO: CONFIRMATION FOR SENT MESSAGE with DETAILS :D

		# print("history len({0})".format(len(self.history)))
		for m in new_messages:
			print()
			print("NEEEWWWWWWWWWWWWWW MSG")
			print(m["sender"]["id"],"::::",m["content"])
			print()
			print()
			print()
		# print("NEEEWWWWWWWWWWWWWW")
		# print()
		# return new_messages
		if new_messages is not None:
			try:
				return self.factorUnread(new_messages)
			except :
				traceback.print_exc()
				return []
		return []

	def factorUnread(self, raw_message_groups):
		# TODO: really factor
		return raw_message_groups

		unread_messages = []
		if raw_message_groups is not None:
			for raw_message_group in raw_message_groups:
				chat = factory_chat(raw_message_group, self)
				messages = list(
					filter(None.__ne__, [factory_message(message, self) for message in raw_message_group['messages']]))
				messages.sort(key=lambda message: message.timestamp)
				unread_messages.append(MessageGroup(chat, messages))
				return unread_messages
		return []

	def get_unread0(self, include_me=False, include_notifications=False, use_unread_count=False):
		"""
		Fetches unread messages
		:param include_me: Include user's messages
		:type include_me: bool or None
		:peearam include_notifications: Include events happening on chat
		:type include_notifications: bool or None
		:param use_unread_count: If set uses chat's 'unreadCount' attribute to fetch last n messages from chat
		:type use_unread_count: bool
		:return: List of unread messages grouped by chats
		:rtype: list[MessageGroup]
		"""
		include_me=True
		print("UUU")
		# code = "WAPI.getUnreadMessages(false, false, false)" #'"+base64+"')"
		# raw_message_groups = self.driver.execute_script(script = code)
		print("UUUF")
		# self.driver.execute_script(script=code)
		# print("UNREAD",str(raw_message_groups))
		raw_message_groups = self.wapi_functions.getUnreadMessages(include_me, include_notifications, True)
		print("UUUX")

		unread_messages = []
		if raw_message_groups is not None:
			for raw_message_group in raw_message_groups:
				chat = factory_chat(raw_message_group, self)
				messages = list(
					filter(None.__ne__, [factory_message(message, self) for message in raw_message_group['messages']]))
				messages.sort(key=lambda message: message.timestamp)
				unread_messages.append(MessageGroup(chat, messages))

		return unread_messages

	def get_unread_messages_in_chat(self,
									id,
									include_me=False,
									include_notifications=False):
		"""
		I fetch unread messages from an asked chat.

		:param id: chat id
		:type  id: str
		:param include_me: if user's messages are to be included
		:type  include_me: bool
		:param include_noFtifications: if events happening on chat are to be included
		:type  include_notifications: bool
		:return: list of unread messages from asked chat
		:rtype: list
		"""
		# get unread messages
		messages = self.wapi_functions.getUnreadMessagesInChat(
			id,
			include_me,
			include_notifications
		)

		# process them
		unread = [factory_message(message, self) for message in messages]

		# return them
		return unread

	# get_unread_messages_in_chat()

	def get_all_messages_in_chat(self, chat, include_me=False, include_notifications=False):
		"""
		Fetches messages in chat

		:param include_me: Include user's messages
		:type include_me: bool or None
		:param include_notifications: Include events happening on chat
		:type include_notifications: bool or None
		:return: List of messages in chat
		:rtype: list[Message]
		"""
		message_objs = self.wapi_functions.getAllMessagesInChat(chat.id, include_me, include_notifications)

		for message in message_objs:
			yield (factory_message(message, self))

	def get_all_message_ids_in_chat(self, chat, include_me=False, include_notifications=False):
		"""
		Fetches message ids in chat

		:param include_me: Include user's messages
		:type include_me: bool or None
		:param include_notifications: Include events happening on chat
		:type include_notifications: bool or None
		:return: List of message ids in chat
		:rtype: list[str]
		"""
		return self.wapi_functions.getAllMessageIdsInChat(chat.id, include_me, include_notifications)

	def get_message_by_id(self, message_id):
		"""
		Fetch a message

		:param message_id: Message ID
		:type message_id: str
		:return: Message or False
		:rtype: Message
		"""
		result = self.wapi_functions.getMessageById(message_id)

		if result:
			result = factory_message(result, self)

		return result

	def chat_send_message(self, chat_id, message):
		result = self.wapi_functions.sendMessage(chat_id, message)

		return isinstance(result, str)

	def reply_message(self, chat_id, message_id, message):
		result = self.wapi_functions.reply(chat_id, message, message_id)

		return bool(result)

	def privateReply(self, message_id, message, chatID):
		# chatId, body, quotedMsg
		code = "WAPI.reply('"+chatID+"', '"+message+"', '"+message_id+"')"
		self.driver.execute_script(script=code)

	def forward_messages(self, chat_id_to, message_ids, skip_my_messages=False):
		return self.wapi_functions.forwardMessages(chat_id_to, message_ids, skip_my_messages)

	def chat_reply_message(self, message_id, message):
		result = self.wapi_functions.ReplyMessage(message_id, message)

		if not isinstance(result, bool):
			return factory_message(result, self)
		return result

	def send_message_to_id(self, recipient, message):
		"""
		Send a message to a chat given its ID

		:param recipient: Chat ID
		:type recipient: str
		:param message: Plain-text message to be sent.
		:type message: str
		"""
		# return self.sendMessageQuick(recipient,message)
		# return self.wapi_functions.sendMessageToID(recipient, message)
		return self.wapi_functions.sendMessageToID(recipient, message)

	def convert_to_base64(self, path, is_thumbnail=False, inv = False, hardresize = False):
		"""
		:param path: file path
		:return: returns the converted string and formatted for the send media function send_media
		"""
		if inv:
			return "base64," + ""
			return b64encode("".encode())

		mime = magic.Magic(mime=True)
		content_type = mime.from_file(path)
		archive = ""
		if is_thumbnail:
			if hardresize:
				try:
					path = self._resize_image(path, f"{path}.bkp", size = [400,400])
				except:
					try:
						path = self._resize_image(path, f"{path}.bkp", size = [299,299])
					except:
						try:
							path = self._resize_image(path, f"{path}.bkp", size = [100,100])
						except:
							traceback.print_exc()

			else:
				try:
					path = self._resize_image(path, f"{path}.bkp")
				except:
					try:
						path = self._resize_image(path, f"{path}.bkp", size = [100,100])
					except:
						traceback.print_exc

		with open(path, "rb") as image_file:
			if inv:
				archive = b64encode()
			else:
				archive = b64encode(image_file.read())
				archive = archive.decode("utf-8")
		if is_thumbnail:
			return archive
		return "data:" + content_type + ";base64," + archive

	def getQuote(self,quotedStanzaID, res=['xxx']):
		return self.wapi_functions.getMessageQuote(quotedStanzaID,res)

	def send_image_as_sticker(self, path, chatid):
		"""
		Converts the file to base64 and sends it using the sendImageAsSticker function of wapi.js
		:param path: file path
		:param chatid: chatId to be sent
		:param caption:
		:return:
		"""
		img = Image.open(path)
		img.thumbnail((512, 512))
		webp_img = io.BytesIO()
		img.save(webp_img, 'webp')
		webp_img.seek(0)
		imgBase64 = convert_to_base64(webp_img, is_thumbnail=True)
		return self.wapi_functions.sendImageAsSticker(imgBase64, chatid, {})

	def send_media(self, path, chatid, caption):
		"""
		Converts the file to base64 and sends it using the sendImage function of wapi.js
		:param path: file path
		:param chatid: chatId to be sent
		:param caption:
		:return:
		"""
		base64 = convert_to_base64(path)
		filename = os.path.split(path)[-1]
		return self.wapi_functions.sendImage(base64, chatid, filename, caption)

	def send_voice_note(self, path, chatid):
		"""
		Attempts to send a file as a voice note
		"""
		base64 = convert_to_base64(path)
		return self.wapi_functions.sendImage(base64, chatid, 'ptt.ogg', '', None, True, True)

	def send_video_as_gif(self, path, chatid, caption):
		"""
		:param path: video file path
		:param chatid: chatId to be sent
		:param caption: text to send with video
		:return:
		"""
		imgBase64 = convert_to_base64(path)
		filename = os.path.split(path)[-1]
		return self.wapi_functions.sendVideoAsGif(imgBase64, chatid, filename, caption)

	def send_giphy(self, giphy_url, chat_id, caption):
		match = re.search(r'https?:\/\/media\.giphy\.com\/media\/([a-zA-Z0-9]+)', giphy_url)
		if match:
			giphy_id = match.group(1)
			filename = giphy_id + '.mp4'
			resp = requests.get('https://i.giphy.com/' + filename)
			b64 = convert_to_base64(io.BytesIO(resp.content))
			return self.wapi_functions.sendVideoAsGif(b64, chat_id, filename, caption)

	def send_contact(self, chat_id, contact_ids):
		return self.wapi_functions.sendContact(chat_id, contact_ids)

	def send_location(self, chat_id, lat, long, text):
		return self.wapi_functions.sendLocation(chat_id, lat, long, text)

	def send_message_with_thumbnail(self, path, chatid, url, title, description, text):
		"""
			converts the file to base64 and sends it using the sendImage function of wapi.js
		:param path: image file path
		:param chatid: chatId to be sent
		:param url: of thumbnail
		:param title: of thumbnail
		:param description: of thumbnail
		:return:
		"""
		imgBase64 = convert_to_base64(path, is_thumbnail=True)
		return self.wapi_functions.sendMessageWithThumb(imgBase64, url, title, description, text, chatid)

	def send_message_with_auto_preview(self, chat_id, url, text):
		return self.wapi_functions.sendLinkWithAutoPreview(chat_id, url, text)

	def delete_message(self, chat_id, message_array, revoke=False):
		"""
		Delete a chat

		:param chat_id: id of chat
		:param message_array: one or more message(s) id
		:param revoke: Set to true so the message will be deleted for everyone, not only you
		:return:
		"""
		return self.wapi_functions.deleteMessage(chat_id, message_array, revoke)

	def set_typing_simulation(self, chat_id, typing):
		return self.wapi_functions.simulateTyping(chat_id, typing)

	def download_media(self, media_msg, force_download=False):
		if not force_download:
			try:
				if media_msg.content:
					return BytesIO(b64decode(media_msg.content))
			except AttributeError:
				pass

		file_data = b64decode(self.wapi_functions.downloadFile(media_msg.client_url))

		if not file_data:
			raise Exception('Impossible to download file')

		media_key = b64decode(media_msg.media_key)
		derivative = HKDFv3().deriveSecrets(media_key,
											binascii.unhexlify(MediaMessage.crypt_keys[media_msg.type]),
											112)
		# derivative = HKDFv3().deriveSecrets(media_key,
											# binascii.unhexlify(media_msg.crypt_keys[media_msg.type]),
											# 112)

		parts = ByteUtil.split(derivative, 16, 32)
		iv = parts[0]
		cipher_key = parts[1]
		e_file = file_data[:-10]

		cr_obj = Cipher(algorithms.AES(cipher_key), modes.CBC(iv), backend=default_backend())
		decryptor = cr_obj.decryptor()
		return BytesIO(decryptor.update(e_file) + decryptor.finalize())

	#################
	# Groups
	#################
	def contact_get_common_groups(self, contact_id):
		"""
		Returns groups common between a user and the contact with given id.

		:return: Contact or Error
		:rtype: Contact
		"""
		for group in self.wapi_functions.getCommonGroups(contact_id):
			yield factory_chat(group, self)

	def create_group(self, name, chat_ids):
		return self.wapi_functions.createGroup(name, chat_ids)

	def group_get_participants_ids(self, group_id):
		return self.wapi_functions.getGroupParticipantIDs(group_id)

	def group_get_participants(self, group_id):
		participant_ids = self.group_get_participants_ids(group_id)

		for participant_id in participant_ids:
			yield self.get_contact_from_id(participant_id)

	def group_get_admin_ids(self, group_id):
		return self.wapi_functions.getGroupAdmins(group_id)

	def group_get_admins(self, group_id):
		admin_ids = self.group_get_admin_ids(group_id)

		for admin_id in admin_ids:
			yield self.get_contact_from_id(admin_id)

	def add_participant_group(self, idGroup, idParticipant):
		return self.wapi_functions.addParticipant(idGroup, idParticipant)

	def remove_participant_group(self, idGroup, idParticipant):
		return self.wapi_functions.removeParticipant(idGroup, idParticipant)

	def promove_participant_admin_group(self, idGroup, idParticipant):
		return self.wapi_functions.promoteParticipant(idGroup, idParticipant)

	def demote_participant_admin_group(self, idGroup, idParticipant):
		return self.wapi_functions.demoteParticipant(idGroup, idParticipant)

	def leave_group(self, chat_id):
		"""
		Leave a group

		:param chat_id: id of group
		:return:
		"""
		return self.wapi_functions.leaveGroup(chat_id)

	#################
	# Observer
	#################
	def subscribe_new_messages(self, observer):
		self.wapi_functions.new_messages_observable.subscribe_new_messages(observer)

	def subscribe_acks(self, observer):
		self.wapi_functions.new_messages_observable.subscribe_acks(observer)

	def subscribe_live_location_updates(self, observer, chat_id):
		self.wapi_functions.new_messages_observable.subscribe_live_location_updates(observer, chat_id)

	def unsubscribe_new_messages(self, observer):
		self.wapi_functions.new_messages_observable.unsubscribe_new_messages(observer)

	def unsubscribe_acks(self, observer):
		self.wapi_functions.new_messages_observable.unsubscribe_acks(observer)

	def unsubscribe_live_location_updates(self, observer, chat_id):
		self.wapi_functions.new_messages_observable.unsubscribe_live_location_updates(observer, chat_id)


	def tryOut(self, target, args, timeout = 3, click = False):
		res = None
		t = time.time()
		while(res is None and time.time() - t < timeout):
			try:
				res = target(args)
			except Exception as e:
				print("EEEEEEEEEEEEE",args,"---",e)
				# print(e)
				# print()
				time.sleep(1)
		if click and res is not None:
			again = True
			t2 = time.time()
			while(again and time.time() - t2 < timeout):
				try:
					res.click()
					again = False
				except Exception as e:
					again = True
					print("EEEEEEEEEEEEE","click","---",e)
				# print()
		return res

	def dictDiff(self,newDict,oldDict):
		newList = list(newDict.keys())
		oldList = list(oldDict.keys())
		if len(newList) == len(oldList):
			return None

		diffList = list(set(x) - set(y))
		diff = {}
		for k in diffList:
			diff[k] = newList[k]
		return diff

	def listDiff(self,newList,oldList):
		if len(newList) == len(oldList):
			return None

		diffList = list(set(newList) - set(oldList))
		print("!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!")
		print(len(diffList),"--------------",diffList)
		return diffList


	def groupIcon(self, group_id, imagepath):
		print("SETTING GROUP ICON!")
		# imagepath = self.download_image(pic_url=imageurl)
		# res = self.driver.set_group_icon(group_id, imagepath)
		base64 = image = self.convert_to_base64(imagepath,is_thumbnail=True, hardresize=True)
		code = "WAPI.setGroupIcon('"+group_id+"', '"+base64+"')"
		res = self.driver.execute_script(script = code)
		# self.driver.execute_script(script=code)
		print("SETTING GROUP ICON! SET",str(res))

		return res



	def newGroup(self,
	f = 1,
	newGroupName = 'New Group Name',
	number = "+972512170493",
	local = False,
	image = None
	):
		oldChats = self.get_all_chats()
		invite = None
		local = False

		if False:
			for a in range(f):
				dots = self.tryOut(self.driver.find_element_by_xpath,"//span[@data-testid='menu']",click=True)
				newgroup = self.tryOut(self.driver.find_element_by_tag_name,'li', click=True)
				input = self.tryOut(self.driver.find_element_by_tag_name,'input',click=True)
				input.send_keys(number+Keys.ENTER+Keys.ENTER)
				# txt = self.tryOut(input.send_keys,"+972512170493")
				# txt = self.tryOut(input.send_keys,Keys.ENTER)
				# contact = self.tryOut(driver1.find_element_by_class_name,'q2PP6',click=True)
				# next = self.tryOut(driver1.find_element_by_class_name,'_2_g1_',click=True)
				nameInput = self.tryOut(self.driver.find_element_by_class_name,'_1awRl',click=True)
				if local:
					nameInput.send_keys(newGroupName+Keys.ENTER)
				else:
					print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
					print("NEW GRUP WITH EMOJI! ",newGroupName)
					# self.driver.execute_script(JS_ADD_TEXT_TO_INPUT,nameInput,newGroupName)
					self.driver.execute_script("arguments[0].innerHTML = '{}'".format(newGroupName),nameInput)
					nameInput.send_keys('.')
					nameInput.send_keys(Keys.BACKSPACE)
					nameInput.send_keys(Keys.ENTER)
					print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
					print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")

					# nameInput = self.tryOut(self.driver.find_element_by_class_name,'_1awRl',click=True)
					# nameInput.send_keys(" xxx "+Keys.ENTER)
		else:
			if "+" is number[0]:
				number = number[1:]

			# number += "@c.us"

			# name, 0, 0, contactsId.map(id => ({ id }))
			# nums = "[{id: '"+number+"@c.us"+"'}]"
			# code = "WAPI.createGroup('"+newGroupName+"',0,0, '"+nums"')"
			# # code = "WAPI.createGroup('"+newGroupName+"', '"+number+"@c.us"+"')"

			# contacts = [number]
			# status = self.driver.driver.createGroup('Test17',contacts)




			# print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@",number)
			# ngT = StoppableThread(target = self.ng, args = [[newGroupName, number+"@c.us"]])
			# ngT.start()
			print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
			print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
			code = "WAPI.createGroup('"+newGroupName+"', '"+number+"@c.us"+"')"
			self.driver.execute_script(script=code)
			# self.ng(newGroupName, number+"@c.us")
			# print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@")(
			print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
			print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
			print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@")


		# time.sleep(3)
		# ngT.stop()
		# print("YO")
		newChats = self.get_all_chats()
		print("YO")
		res = None
		t = time.time()
		timeout = 10
		while(len(newChats) == len(oldChats) and time.time() - t < timeout):
			try:
				newChats = self.get_all_chats()
				print(len(newChats),len(oldChats))

			except Exception as e:
				print("EEEEEEEEEEEEE",args,"---",e)
				# print(e)
				# print()
				time.sleep(.5)

		diff =  self.listDiff(newChats,oldChats)
		# print("DIFF",diff)
		newGroup = ""
		if len(diff) == 1:
			newGroup = diff[0]

		if "tuple" in str(type(newGroup)):
			newGroup = newGroup[0]
		# print(newGroup)
		print(newGroup,"NEW GROUP")
		newGroupID = newGroup.id
		print(newGroupID,"NEW GROUP")
		print(newGroupID,"NEW GROUP")
		print(newGroupID,"NEW GROUP")
		# G = self.getgetGroup(newGroupID)

		# print(G)
		# print(G)
		# print(G)
		# print(G)
		# print(G)
		#
		# metadata = self.metadata(newGroupID)
		# print(newGroupID, metadata)
		# print(newID, metadata)

		if False:
			upload_img = False
			dotsSide = self.tryOut(self.driver.find_element_by_xpath,"//div[@class='VPvMz']/div/div/div/span[@data-testid='menu']",click=True)
			groupInfo = self.tryOut(self.driver.find_element_by_xpath,"//li",click=True)
			# if image is not None and upload_img:
			# 	print("!!!!!!!")
			#
			# 	changePhoto = self.tryOut(self.driver.find_element_by_xpath,"//div[@class='_1huBh']",click=True)
			# 	# time.sleep(3)
			# 	# print("!!!!!!!")
			# 	uploadPicture = self.tryOut(self.driver.find_element_by_xpath,"//div[@title='Upload photo']",click=True)
			# 	uploadPicture.send_keys(image)
			# 	# time.sleep(3)
			# 	# print("!!!!!!!")
			# 	# uploadPicture.send_keys(image+Keys.ENTER)

			''' try to get invite '''
			inviteToChat = self.tryOut(self.driver.find_element_by_xpath,"//div[text()='Invite to group via link']",click=True)
			time.sleep(0.3)
			inviteURL = self.tryOut(self.driver.find_element_by_xpath,"//a[@id='group-invite-link-anchor']",click=True)
			time.sleep(0.3)
			invite = inviteURL.get_attribute('outerHTML').split("</a>")[0].split(">")[1]
			time.sleep(0.3)
			back = self.tryOut(self.driver.find_element_by_xpath,"//button[@class='hYtwT']",click=True)
			time.sleep(0.3)
			back = self.tryOut(self.driver.find_element_by_xpath,"//button[@class='hYtwT']",click=True)

		# xit = self.tryOut(self.driver.find_element_by_xpath,"//button[@data-testid='x']",click=True)


		# invite

		# print("OLD",len(oldChats),oldChats)
		# print()
		# print()
		# print("NEW",len(newChats),newChats)
		# diff =  self.tryOut(self.dictDiff(newChats,oldChats))
		diff =  self.listDiff(newChats,oldChats)

		# newGroupID = diff[0]
		invite = meta = self.metadata(newGroupID)
		print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
		print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@",meta)
		print("XXXXXXXXXXXXXXXXXX")
		print("    NEW GROUP     ")
		print("XXXXXXXXXXXXXXXXXX")
		print("XXXXXXXXXXXXXXXXXX")
		print("XXXXXXXXXXXXXXXXXX")
		print("XXXXXXXXXXXXXXXXXX")
		print("XXXXXXXXXXXXXXXXXX")
		print("XXXXXXXXXXXXXXXXXX",invite)
		if image is not None:
			self.groupIcon(newGroupID,image)
			print("ICON SETTING")
		return newGroupID, invite
		# print("DIFF",diff)
		if len(diff) == 1:
			return diff[0], invite
		return diff, invite
		'''
		from app import *
		'''


	def getChat(self, nameOrNumber):
		if nameOrNumber is None:
			return None
		chat = None
		if str(nameOrNumber).isnumeric():
			chat = self.get_chat_from_phone_number(nameOrNumber, createIfNotFound=False)
		elif "@" in nameOrNumber:
			chat = self.get_chat_from_id(nameOrNumber)
		else:
			chat = self.get_chat_from_name(nameOrNumber)
			# messages = chat.get_messages()
		return chat


	def getMessages(self, number):
		chat = self.getChat(number)
		print("&&&&&&&&&&&&&&&")
		print("CHATID",chat.id)
		return chat.get_messages(include_me=True, include_notifications=False)

	def getLastMessage(self, number,offset=0,report = False):

		lastMSG = self.getMessages(number)[::-1][offset].content
		if report:
			self.sendMessage(number,"REPORTING")
		return lastMSG


	def sendAsync(self, data):
		chat, content = data
		chat.send_message(content)

	def startQ(self):
		msgT = Thread(target = self.rollQAsync, args = [None])
		msgT.start()

	def rollQAsync(self, data = None):
		while True:
			time.sleep(0.1)
			if len(self.Q) > 0:
				print("Q LENGTH",len(self.Q))
				q = self.Q.pop(0)
				if q is not None and len(q) == 2:
					number, content = q
					print("Q SENDING",number,"\n",content[:150])
					try:
						res = self.send_message_to_id(number,content)
						print("RES",res)
						print("MESSAGE SENT!",number,"\n",content[:150]+".........")
						print(":::::::::::::::::::::::::::::::::")

					except Exception as e:
						traceback.print_exc()
						print("ERROR SENDING MESSAGE TO ",number, "E:",e)


	def sendMessageQuick(self, number, content):
		# self.wapi_functions.sendMessageToID(recipient, message)
		print("NUMBER",number, content)
		# content = "XXXXXXXXXX"
		code = "WAPI.sendMessageToID('"+number+"', '"+content+"')"
		self.driver.execute_script(script=code)
		return True

	def sendMessage(self, number, content, quick = False):
		if quick:
			self.Q.insert(0,[number,content])
		else:
			self.Q.append([number,content])
		# self.Q.append([number,content])
		if not self.Qstarted:
			self.Qstarted = True
			self.startQ()


		# print("SENDING MESSAGE::::::::::",number, "::::::",content)
		# chat = self.getChat(number)
		# print("GOT CHAT::::::::::",chat)
		# msgT = Thread(target = self.sendAsync, args = [[chat,content]])
		# msgT.start()
		# # chat.send_message(content)
		# print("FINISHED SENDING")
		return True

	def jsonToDict(self, json_msg):
		# print("@@@@@@@@@@@@@@@@@")
		# print(json_msg)
		dict = json.loads(json_msg)
		# print("@@@@@@@@@@@@@@@@@")
		return dict

	def dictToJson(self, dict):
		return json.dumps(dict, indent = 0).replace("\n","")


	def loadDB(self, number = "DB"):
		return self.getDB(number)

	def getDB(self, number = "DB"):
		db = {}
		# if True:
		# print("!!!!!!!!!!")
		# print(number)
		try:
			# print(number)
			# print(number)
			print("NNNNNNNNNNN",number)
			lastMsg = self.getLastMessage(number, report = False)
			# if "*" in lastMsg:
			# 	lastMsg = lastMsg.split("*")[1]
			print("NNNNNNNNN")
			print(lastMsg)
			print("NNNNNNNNN")
			p = re.compile('(?<!\\\\)\'')
			lastMsg = p.sub('\"', lastMsg)

			db = self.jsonToDict(lastMsg)
		# else:
		except Exception as e:
			print("EEEEEEEEEEEEEEEE loading db",e)
			traceback.print_exc()

		return db

	def updateDB(self, data, number="DB"):
		if "dict" in str(type(data)):
			js = self.dictToJson(data)
			traceback.print_exc()
			# print("jjjjjjjjjjssssssss",js)
			p = re.compile('(?<!\\\\)\'')
			js = p.sub('\"', js)

			self.sendMessage(number,js)
		else:
			self.sendMessage(number,data)
		return True


	def ng(self, idGroup, idParticipant):
		# idGroup, idParticipant = data
		# newGroupName, number+"@c.us"
		return self.wapi_functions.createGroup(idGroup, idParticipant)

	def ng0(self, data):
		idGroup, idParticipant = data
		# newGroupName, number+"@c.us"
		return self.wapi_functions.createGroup(idGroup, idParticipant)
