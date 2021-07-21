# ReminderService.py
from User import User
from Reminder import Reminder
from Conv import Conv
# from app import Service
# from ctparse import ctparemidrse
# from datetime import datetime
from bs4 import BeautifulSoup
import requests

from dateparser.search import search_dates

import time
import datetime
import re

from threading import Thread

known = {"morning":"at 08:00","afternoon":"at 16:00", "evening":"at 18:00", "in in":"in","at at":"at", "בבוקר":"08:00", "בצהריים":"12:00", "בערב":"18:00"}
days = "Sunday,Monday,Tuesday,Wednesday,Thursday,Friday,Saturday".split(",")

# class ReminderService(Service):
class ReminderService():
	id = "Reminders"
	name = "🔔 Reminders 🔔"
	welcome =  "*Welcome to Reminders 🔔 Service*\nYou can now send a message and we will *send* you a reminder :)\n*שלחו* הודעה ואנחנו כבר נזכיר לכם :)"
	help = "Reminders help message"
	shortDescription = "Get your reminders as whatsapp messages!"
	imageurl = "https://i.pinimg.com/originals/f9/e5/d2/f9e5d2f17f4cb6d050fea1a7f7a874fd.png"

	share = None

	examples = {"example1":{"text":"","thumbnail":None, "answer":"This is awesome in 5 seconds"}, "example2":{"text":"","thumbnail":None, "answer":"להתקשר לברוך מחר בבוקר"}}

	def __init__(self,db, api):
		ReminderService.share = self
		self.db = db
		self.api = api
		if "upcoming" not in self.db or "dict" not in str(type(self.db["upcoming"])):
			self.db["upcoming"] = {}
		if "users" not in self.db:
			self.db["users"] = {}


		self.id = ReminderService.id
		self.name = ReminderService.name
		self.welcome = ReminderService.welcome
		self.help = ReminderService.help


	def go(self):
		while(True):

			if "upcoming" not in self.db or "dict" not in str(type(self.db["upcoming"])):
				self.db["upcoming"] = {}
			if "users" not in self.db :
				self.db["users"] = {}

			# while len(self.db["upcoming"]) > 0:
			# 	key = self.db["upcoming"].pop(0)
			# 	origin, content = item

			for key in list(self.db["upcoming"].keys()):
				t = self.db["upcoming"][key]
				if time.time()-t > 0:
					userID,remID = key.split("_")
					self.remind(userID, remID)
				# self.api.backup(self.db)



			time.sleep(1)


	def remind(self, userID, remID):
		userID, remID = str(userID), str(remID)
		combID = userID+"_"+remID
		if userID in self.db["users"]:
			user = self.db["users"][userID]
			if remID in user.reminders["unsent"]:
				rem = user.reminders["unsent"][remID]
				print("!!!!!!!",rem,rem.message)
				if self.api.send(userID,rem.message):
					if user.markSent(remID):
						if combID in self.db["upcoming"]:
							self.db["upcoming"].pop(combID)
							self.backup()
							# ReminderService.backup()
						else:
							print("EEEEEEEEE", "wasn't in upcoming")

					else:
						print("EEEEEEEEE", "could not mark!")

				else:
					print("EEEEEEEEE", "could not send!")

	def updateDB(self, db):
		# self.db = db
		if "upcoming" not in db:
			db["upcoming"] = {}

		if "users" not in db:
			db["users"] = {}

		self.db = {"upcoming":db["upcoming"], "users":User.jsonUsersToUsers(db["users"])}

	def process(self, info):
		origin, user, content = None, None, None
		if "origin" in info:
			origin = info["origin"]
		if "user" in info:
			user = info["user"]
		if "content" in info:
			content = info["content"]

		if "users" not in self.db:
			self.db["users"] = {}

		dbChanged = False

		userID = str(origin)
		if userID not in self.db["users"]:

			user = User(userID)
			self.db["users"][userID] = user

			# user.conv.manager("WELCOME "+userID)
			# self.api.send(userID, "WELCOME "+userID)
			dbChanged = True

		user = self.db["users"][userID]
		user.conv.human(content)
		timestr = ""

		if not user.conv.ongoing:
		# check for commands
			print("AAAAAAAAAAAAAAAAAA")
			m, t, timestr = ReminderService.parseMsg(content)
			if t is None:
				user.conv.manager("When to remind you?"	)
				self.api.send(userID, "When shall I remind you ?")
				user.conv.ongoing = True
			else:
				self.convFinished(user, set = True)

			rem = self.newReminder(userID, m, t)



		else:
			print("BBBBBBBBBBBBBBBBBBBBB")
			user.conv.tries += 1
			m, t, timestr = ReminderService.parseMsg(content)
			## GET LAST REMINDER

			if t is None:
				user.conv.manager("Sorry I didnt understand when  "+ str(user.conv.tries))
				self.api.send(userID, "Sorry I didn't unserstand when...")

			else:
				rem = user.lastRem
				rem.sendTime = t

				self.convFinished(user, set = True)

		if self.convFinished(user):
			rem = user.lastRem

			if rem.sendTime is not None:
				user.conv.manager(" ".join(["THANK YOU! WILL REMIND YOU TO ",rem.message, "at",time.ctime(rem.sendTime)," (",timestr,")"]))
				self.api.send(userID, " ".join(["THANK YOU! WILL REMIND YOU TO ",rem.message, "at",time.ctime(rem.sendTime)," (",timestr,")"]))

				combID = userID+"_"+rem.id
				self.db["upcoming"][combID] = rem.sendTime
				dbChanged = True
			else:
				print("XXXXXXXXXXXXXXXXXXXXXXXX", "unhandled")

			self.convFinished(user, set = None)
			user.conv.ongoing = False
		else:
			print("***continue conv!!!!!!!!!!!!!!!!!!")

		if dbChanged:
			self.backup()
			# self.api.backup(self.db)

	def backup(self):
		# self.api.backup(self.db)
		self.api.backup({"upcoming":self.db["upcoming"],"users":User.usersToJSONusers(self.db["users"])})

	def process1(self, info):
		origin, user, content = None, None, None
		if "origin" in info:
			origin = info["origin"]
		if "user" in info:
			user = info["user"]
		if "content" in info:
			content = info["content"]

		if "users" not in self.db:
				self.db["users"] = {}

		if user not in self.db["users"]:
			self.db["users"][user] = user
			# self.api.send(origin, "WELCOME "+user)
			# self.api.backup(self.db)
			self.backup()


		# self.db["upcoming"].append([origin, content])
		dbChanged = False
		userID = str(user)

		# dbChanged = False
		if userID not in self.db["users"]:
			user = User(userID)
			self.db["users"][userID] = user

			user.conv.manager("WELCOME "+userID)
			# self.api.send(userID, "*Welcome to Danilator 💚 Service*\nYou can now send a name of a song to get it's lyrics translations :)")
			dbChanged = True

		user = self.db["users"][userID]
		#
		# for a in range(10):
		# 	self.api.send(userID, str(a))
		target = content
		urlChecks = ["http","youtu","spotify.com"]
		url = False
		for check in urlChecks:
			if check.lower() in target.lower():
				url = True
		if url:
			target = str(re.search("(?P<url>https?://[^\s]+)", target).group("url"))

		self.api.send(origin, "Checking Lyrics for:\n*"+target+"*\n"+"Please wait a bit")

		# self.api.send(userID, )

		# import requests
		# from bs4 import BeautifulSoupYO
		# example = "We are the champions"
		# song = example.replace(" ","+")

		target = target.replace(" ","+")
		lyricsLink = "http://danilator.wholesome.garden/lyrics/"+target
		print (lyricsLink)
		page = requests.get(lyricsLink)
		# if str(page.status_code) == "200":
		soup = BeautifulSoup(page.content, 'html.parser')
		# print(soup.prettify())
		# print(soup.body[""])

		# txt = str(str(P).split('))

		title = soup.findAll("h3")[0].text.replace("                   ","").replace("                ","").replace("\n","")
		while title[-1:] is " ":
			title = title[:-1]

		P = soup.find_all('p')
		lyrics = []
		for pp in P:
			lyrics.append(pp.text.replace("\n","").replace("                ","").replace("              ",""))

		for l in lyrics:
			print("LLL:",l)

		firstLang = lyrics[0::4][:-1]
		secondLang = lyrics[1::4][:-1]

		cleanLyrics = "💚 *Danilator* 💚\n"
		cleanLyrics += "*"+title+"*"+"\n\n"

		for i in range(len(firstLang)):
			cleanLyrics += firstLang[i] +"\n"+ secondLang[i]+"\n\n"
		cleanLyrics+="Made with 💚\n"
		cleanLyrics+="from "+lyricsLink

		# self.api.send(userID, cleanLyrics)
		self.api.send(origin, cleanLyrics)

		if dbChanged:
			self.backup()
			# self.api.backup(self.db)



	def getDB():
		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("USERS")
		print(self.db["users"])

		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("JSON")
		jsonUsers = User.usersToJSONusers(self.db["users"])
		print(jsonUsers)

		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("recovered USERS")
		print(User.jsonUsersToUsers(jsonUsers))

		return {"users":jsonUsers,"upcoming":self.db["upcoming"]}
		# return {"users":self.db["users"],"upcoming":self.db["upcoming"]}


	def setDB0(db):
		self.db["upcoming"] = db["upcoming"]
		self.db["users"] = User.jsonUsersToUsers(db["users"])

	def backup0():
		ReminderService.backupDelegate(db = ReminderService.getDB(),service = ReminderService.serviceName)

	def loadDB0():
		res = ReminderService.backupDelegate(db = None,service = ReminderService.serviceName)
		if res is not None:
			resave = False
			if "upcoming" not in res:
				res["upcoming"] = {}
				resave = True
			if "users" not in res:
				res["users"] = {}
				resave = True
			ReminderService.setDB(res)
			if resave:
				ReminderService.backup()


	def asyncRoll():
		print("YOY YOYOYOY YOY OY OY ")
		print("YOY YOYOYOY YOY OY OY ")
		print("YOY YOYOYOY YOY OY OY ")
		print("YOY YOYOYOY YOY OY OY ")
		print("YOY YOYOYOY YOY OY OY ")
		print("DANILATOR")
		t = Thread(target = ReminderService.rollUpcoming,args = [None,])
		t.start()

	def rollUpcoming(data):
		"!!!!!!!!!!!!!!!!!!!!!!@@@@@@@@@@@@@@@@@@@@@@@"
		while(True):
			for key in list(self.db["upcoming"].keys()):
				t = self.db["upcoming"][key]
				if time.time()-t > 0:
					userID,remID = key.split("_")
					ReminderService.send(userID, remID)
			time.sleep(1)


	# shared = None
	#
	# def __init__(self):
	#     shared = sel
	#     pass #load from back

	def go0(sendDelegate = None, backupDelegate = None):
		## LOAD FROM DAL

		self.db["users"] = {}
		self.db["upcoming"] = {}
		ReminderService.init = True
		ReminderService.asyncRoll()
		ReminderService.sendDelegate = sendDelegate
		ReminderService.backupDelegate = backupDelegate
		ReminderService.loadDB()


	def process0(userID, message):

		print(ReminderService.init,"!!!!!!!!!!!!")
		if not ReminderService.init:
			ReminderService.go()


		dbChanged = False
		userID = str(userID)

		# dbChanged = False
		if userID not in self.db["users"]:
			user = User(userID)
			self.db["users"][userID] = user

			# user.conv.manager("WELCOME "+userID)
			# self.api.send(userID, "*Welcome to Danilator 💚 Service*\nYou can now send a name of a song to get it's lyrics translations :)")
			dbChanged = True

		user = self.db["users"][userID]
		#
		# for a in range(10):
		# 	self.api.send(userID, str(a))
		target = content
		urlChecks = ["http","youtu","spotify.com"]
		url = False
		for check in urlChecks:
			if check.lower() in target.lower():
				url = True
		if url:
			target = str(re.search("(?P<url>https?://[^\s]+)", target).group("url"))
		self.api.send(userID, "Checking Lyrics for:\n*"+target+"*\n"+"Please wait a bit")

		# import requests
		# from bs4 import BeautifulSoupYO
		# example = "We are the champions"
		# song = example.replace(" ","+")

		target = target.replace(" ","+")
		lyricsLink = "http://danilator.wholesome.garden/lyrics/"+target
		print (lyricsLink)
		page = requests.get(lyricsLink)
		# if str(page.status_code) == "200":
		soup = BeautifulSoup(page.content, 'html.parser')
		# print(soup.prettify())
		# print(soup.body[""])

		# txt = str(str(P).split('))

		title = soup.findAll("h3")[0].text.replace("                   ","").replace("                ","").replace("\n","")
		while title[-1:] is " ":
			title = title[:-1]

		P = soup.find_all('p')
		lyrics = []
		for pp in P:
			lyrics.append(pp.text.replace("\n","").replace("                ","").replace("              ",""))

		for l in lyrics:
			print("LLL:",l)

		firstLang = lyrics[0::4][:-1]
		secondLang = lyrics[1::4][:-1]

		cleanLyrics = "💚 *Danilator* 💚\n"
		cleanLyrics += "*"+title+"*"+"\n\n"

		for i in range(len(firstLang)):
			cleanLyrics += firstLang[i] +"\n"+ secondLang[i]+"\n\n"
		cleanLyrics+="Made with 💚\n"
		cleanLyrics+="from "+lyricsLink

		self.api.send(userID, cleanLyrics)
		# if False:
		# 	self.api.send(userID, "Could not fetch lyrics %0AE: "+e)


		#
		# for l in lyrics:
		# 	print(":::"+l+"::::")
		#
		# Made with 💚
		#
		# lyrics
		#
		#
		#
		#
		#
		# user.conv.human(message)
		# timestr = ""
		#
		# if not user.conv.ongoing:
		# # check for commands
		# 	print("AAAAAAAAAAAAAAAAAA")
		# 	m, t, timestr = ReminderService.parseMsg(message)
		# 	if t is None:
		# 		user.conv.manager("When to remind you?")
		# 		self.api.send(userID, "When shall I remind you ?")
		# 		user.conv.ongoing = True
		# 	else:
		# 		self.convFinished(user, set = True)
		#
		# 	rem = self.newReminder(userID, m, t)
		#
		#
		#
		# else:
		# 		print("BBBBBBBBBBBBBBBBBBBBB")
		# 		user.conv.tries += 1
		# 		m, t, timestr = ReminderService.parseMsg(message)
		# 		## GET LAST REMINDER
		#
		# 		if t is None:
		# 			user.conv.manager("Sorry I didnt understand when  "+ str(user.conv.tries))
		# 			self.api.send(userID, "Sorry I didn't unserstand when...")
		#
		# 		else:
		# 			rem = user.lastRem
		# 			rem.sendTime = t
		#
		# 			self.convFinished(user, set = True)
		#
		# if self.convFinished(user):
		# 	rem = user.lastRem
		#
		# 	if rem.sendTime is not None:
		# 		user.conv.manager(" ".join(["THANK YOU! WILL REMIND YOU TO ",rem.message, "at",time.ctime(rem.sendTime)," (",timestr,")"]))
		# 		self.api.send(userID, " ".join(["THANK YOU! WILL REMIND YOU TO ",rem.message, "at",time.ctime(rem.sendTime)," (",timestr,")"]))
		#
		# 		combID = userID+"_"+rem.id
		# 		self.db["upcoming"][combID] = rem.sendTime
		# 		dbChanged = True
		# 	else:
		# 		print("XXXXXXXXXXXXXXXXXXXXXXXX", "unhandled")
		#
		# 	self.convFinished(user, set = None)
		# 	user.conv.ongoing = False
		# else:
		# 	print("***continue conv!!!!!!!!!!!!!!!!!!")
		#
		if dbChanged:
			ReminderService.backup()


	def convFinished(self, user, set = -1):
		if set is -1:
			convFin = True
			for key in user.conv.fin:
				if user.conv.fin[key] is None:
					convFin = False
			return convFin
		else:
			for key in user.conv.fin:
				user.conv.fin[key] = set

	def send0(userID, remID):
		userID, remID = str(userID), str(remID)
		combID = userID+"_"+remID
		if userID in self.db["users"]:
			user = self.db["users"][userID]
			if remID in user.reminders["unsent"]:
				rem = user.reminders["unsent"][remID]
				print("!!!!!!!",rem)
				if self.api.send(userID,rem.message):
					if user.markSent(remID):
						if combID in self.db["upcoming"]:
							self.db["upcoming"].pop(combID)
							ReminderService.backup()
						else:
							print("EEEEEEEEE", "wasn't in upcoming")

					else:
						print("EEEEEEEEE", "could not mark!")

				else:
					print("EEEEEEEEE", "could not send!")



	def actuallySend(userID, message):
		print("TRY SENDING ON WHATSAPP! TO:", userID, "MESSAGE:", message)
		return ReminderService.sendDelegate(userID,message)

		# return False #for errors

	def getRE(key):
		return re.compile(re.escape(key.lower()), re.IGNORECASE)


	def formatKnown(txt):
		for key in known:
			keyRE = ReminderService.getRE(key)
			changed = keyRE.sub(known[key],txt)
			if txt != changed:
				print("-------CHANGED",txt,"TO",changed)
				txt = changed
		return txt

	def parseMsg(txt, tries = 0):
		print("============================")
		print(txt)
		formatted = ReminderService.formatKnown(txt)
		timestr = ""
		res = search_dates(formatted, add_detected_language=True)
		when = None
		if res is None:
			return txt, when, timestr
		if True:#try:
			# print("######################",formatted)
			# print(res)
			date = res[0][1].timestamp()
			timestr = res[0][0]
			lang = res[0][2]
			## remove timestr from reminder

			diff = time.time()-date
			# print("DIFF",diff, time.ctime(date))
			if diff > 0 and tries < 3:
				print("RETRY ")
				if tries == 0:
					new = ReminderService.changeDay(formatted)
				else:
					new = formatted.replace(timestr,"in "+timestr)
				return ReminderService.parseMsg(new, tries+1 )
			else:
				when = date
		# if True:#except:
		#     print("EEEEEEEEEEEEEEEEEEEEEE res:",res)
		#     return txt, None, ""

		if timestr is not "":
			formatted = txt.replace(timestr,"")
		return formatted, when, timestr

	def changeDay(txt):
		# print("CCCCCCCCCCCCC C C C C C C, ",txt,"\n")
		temp = txt + ""
		today = datetime.date.today().strftime("%A")
		currday = days.index(today)
		dates = []
		for d in range(7):
			c = (d+currday+1)%7
			dates.append(days[c])
		print("DATES::::::::::::::::::")
		print(dates)

		kc = 0
		for key in dates:
			kc+=1
			realday = "in "+str(kc)+" day"
			if c>1:
				realday+="s"
			print("DDDDDD ",realday)
			keyRE = ReminderService.getRE(key)
			changed = keyRE.sub(realday,txt)
			print("TTTTTTTT",changed)
			print
			txt = changed
		if temp != txt:
			print("CHANGED FROM -",temp," TO -",txt)
		else:
			print("NOT CHANGED DAY")
		return txt

	def newReminder(self, userID, message, when = None):

		user = self.db["users"][userID]
		if user is None:
			print("user not found")
			return None

		user.remCount += 1
		remID = str(user.remCount)
		rem = Reminder(remID, userID, message, when)
		user.reminders["unsent"][remID] = rem
		user.lastRem = rem

		return rem

	def welcomeUser(self, origin):
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		if "users" not in self.db:
			self.db["users"] = {}
		if origin not in self.db["users"]:
			self.db["users"][origin] = origin
			self.backup()
