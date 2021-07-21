#Service.py
import time

class SpeechToTextService(object):
	id = "SpeechToText"
	name = "💬️ SpeechToText 💬"
	# name = "💬️ סליחה אוטומטית 💬"
	welcome = "*Welcome to SpeechToText Service* \nSend or forward us a voice recording and we will transcribe it for you...\n\n*ברוכים הבאים לשירות תמלול לטקסט!* \n *שלחו* או העבירו לנו *הקלטות קוליות* ותקבלו אותם כטקסט\n\n*נסו עכשיו*"
	help = "send a message to get it back"
	# imageurl = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQmaJKloEMiBpQRA9woJw4XnuWXCWeN2BO70w&usqp=CAU"
	# imageurl = "https://cdn2.iconfinder.com/data/icons/mulitmedia/256/15-512.png"
	# imageurl = "https://apprecs.org/ios/images/app-icons/256/fd/1241342461.jpg"
	# imageurl = "https://cdn2.vectorstock.com/i/1000x1000/11/01/transcription-blue-concept-icon-audio-files-vector-29171101.jpg"
	imageurl = "https://i.imgur.com/n2jjnz3.jpg?1"
	shortDescription = "SpeechToText SpeechToText SpeechToText"
	share = None
	examples = {}
	# examples = {"services":{"text":"Show Public Services","thumbnail":None}}

	def __init__(self,db, api):
		SpeechToTextService.share = self

		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		# print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! SpeechToText",SpeechToTextService.share)
		self.db = db
		self.api = api
		if "upcoming" not in self.db:
			self.db["upcoming"] = []
		if "users" not in self.db:
			self.db["users"] = {}

	def go(self):
		if False:
			while(True):
				if "upcoming" not in self.db:
					self.db["upcoming"] = []
				if "users" not in self.db:
					self.db["users"] = {}

				while len(self.db["upcoming"]) > 0:
					item = self.db["upcoming"].pop(0)
					origin, content = item
					self.api.send(origin, content, autoPreview = True)
					# self.api.send(origin, content, thumnail = "test")
					# self.api.backup(self.db)

				time.sleep(1)

	def process(self, info):
		origin, user, content = None, None, None
		if "origin" in info:
			origin = info["origin"]
		if "user" in info:
			user = info["user"]
		if "content" in info:
			content = info["content"]

		if False:
			if "users" not in self.db:
				self.db["users"] = {}

			if user not in self.db["users"]:
				self.db["users"][user] = user
				self.api.send(origin, "WELCOME "+user)
				self.backup()

			sendBack = content

			withLink = True
			if withLink:
				answer = ":answerid:555"
				myLink = self.api.genLink(origin, answer)
				sendBack += "\n\n"+answer+":\n"+myLink

			self.db["upcoming"].append([origin, content])
			# self.db["upcoming"].append([origin, sendBack])
		# self.api.send(origin, "_סליחה התקבלה🙏_")



	def backup(self):
		self.api.backup(self.db)

	def updateDB(self, db):
		self.db = db
		# self.db = User.jsonUsersToUsers(db)

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
