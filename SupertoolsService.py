#Service.py

import time
import json
import requests
import traceback

class SupertoolsService(object):
	id = "Supertools"
	name = "🚀Supertools🚀"
	welcome = "ברוכים הבאים *לסופרטולז לוואטסאפ!* 🚀 \nחדשים כאן? >> תרשמו לסופרטולז אונבורדינג:\nhttps://mailchi.mp/3b8bd6eb28cd/st10\n\nסופרטולז היא קהילה שנועדה לאגד אנשים שרוצים כוחות־על בעולם דיגיטלי. כאלה שרוצים להפוך לצבא של איש אחד דרך כלים טכנולוגיים משני־חיים. כאלה שרוצים להטמיע את אותם כלים כאן ועכשיו. בלי כל הדיבורים באוויר.\n\nכל פוסט חדש שעולה לסופרטולז ישלח כאן בקבוצה :)"
	help = "send a message to get it back"
	imageurl = "https://scontent.ftlv6-1.fna.fbcdn.net/v/t1.0-9/s960x960/90941246_10158370682234287_4145441832110653440_o.jpg?_nc_cat=110&ccb=2&_nc_sid=825194&_nc_ohc=8s_3FhJStQUAX-yKU8c&_nc_ht=scontent.ftlv6-1.fna&tp=7&oh=cc43986a0035414deb90a706d7b7fc2b&oe=602D4239"
	shortDescription = "קבלו את הפוסטים ישר לווטסאפ"
	share = None
	db = {}
	examples = {}
	# examples = {"services":{"text":"Show Public Services","thumbnail":None}}

	def __init__(self, db, api):
		SupertoolsService.share = self

		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Echo",SupertoolsService.share)
		self.db = db
		self.api = api
		self.permalinksURL = "http://fbpagerss.herokuapp.com/summary"

		if "permalinks" in self.db:
			print("WORKING! PERMALINKS")
			print("WORKING! PERMALINKS")
			print("WORKING! PERMALINKS")
			print("WORKING! PERMALINKS")
			print("WORKING! PERMALINKS")
		else:
			print("@@@@@@@@@@@@@@@@")
			print(self.db)

			self.db["permalinks"] = {}
			print(self.db)
			print("@@@@@@@@@@@@@@@@")


		if "users" not in self.db:
			self.db["users"] = {}

		if "permalinks" not in self.db:
			print("@@@@@@@@@@@@@@@@")
			print(self.db)

			self.db["permalinks"] = {}
			print(self.db)
			print("@@@@@@@@@@@@@@@@")

	def formatPost(self,next):
		key, data = next

		text = ""
		thumb = None
		if len(data) > 0:
			author = data["author"]
			text = data["post"]+"\nOriginal Post: "+key

			thumb = {"imageurl":self.imageurl,"title":author+" on Supertools","desc":"Open to view full post","link":key}


		return text, thumb

	def go(self):
		if "users" not in self.db:
			self.db["users"] = {}

		if "permalinks" not in self.db:
			self.db["permalinks"] = {}
			print("##########################",self.db)
			print("##########################",self.db)
			print("##########################",self.db)
			print("##########################",self.db)
			print("##########################",self.db)

		# Give time for DB to load properly
		time.sleep(10)
		while(True):
			backup = False
			siteDB = {}
			try:
				print("getting permalinks")
				siteDB = self.getPermalinks()
				print("got permalinks", len(siteDB), list(siteDB.keys()))
			except:
				traceback.print_exc()

			linksToPush = {}
			for link in siteDB:
				# print(self.db)
				if "permalinks" not in self.db:
					self.db["permalinks"] = {}
					print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
					print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
					print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
					print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
					print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
				if "users" in self.db and len(self.db["users"]) > 0:
					# # self.db["users"] = {}
					# print("XXXXXXXXXXXXXXXXXXXXXXXXXxUUUU")
					# print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
					# print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
					# print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
					# print("XXXXXXXXXXXXXXXXXXXXXXXXXx")
				# print("##########################",self.db)
				# print("##########################",self.db)
				# print("##########################",self.db)
					if link not in self.db["permalinks"]:
						print("NEW PERMALINK",link)
						print("NEW PERMALINK",link)
						print("NEW PERMALINK",link)
						print("NEW PERMALINK",link)
						print("NEW PERMALINK",link)
						linksToPush[link] = siteDB[link]
						self.db["permalinks"][link] = "Seen"
						backup = True

			while(len(linksToPush)>0):
				next = linksToPush.popitem()
				for user in self.db["users"]:
					text, thumb = self.formatPost(next)
					self.api.send(user,text,thumb)

			if backup and len(self.db["users"])>0:
				self.backup()

			time.sleep(60)

	def getPermalinks(self):
		links = {}
		r = requests.get(self.permalinksURL)
		links = r.json()
		return links

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

		if origin not in self.db["users"]:
			self.db["users"][origin] = origin
			self.backup()

		# sendBack = content
		#
		# withLink = True
		# if withLink:
		# 	answer = ":answerid:555"
		# 	myLink = self.api.genLink(origin, answer)
		# 	sendBack += "\n\n"+answer+":\n"+myLink
		#
		# self.db["upcoming"].append([origin, sendBack])
		# self.api.send(origin, "WELCOME "+user)

	def welcomeUser(self, origin):
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW")
		if "users" not in self.db:
			self.db["users"] = {}
		if origin not in self.db["users"]:
			# self.api.send(origin, "YO!")
			self.db["users"][origin] = origin
			self.backup()

	def backup(self):
		self.api.backup(self.db)

	def updateDB(self, db):
		self.db = db
		# self.db = User.jsonUsersToUsers(db)
