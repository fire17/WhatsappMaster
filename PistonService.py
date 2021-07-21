#Service.py
import time
import requests


pheaders = {
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
'Accept-Language' : 'en-US,en;q=0.5',
'Accept-Encoding' : 'gzip',
"Cache-Control": "no-cache",
"Pragma": "no-cache",
'DNT' : '1', # Do Not Track Request Header
'Connection' : 'close' }
class PistonService(object):
	id = "Piston"
	name = "Piston!"
	welcome = "*Welcome to Piston! Service* \n\nWe Run Code..."
	help = "send a message to get it back"
	imageurl = "https://yt3.ggpht.com/ytc/AAUvwnhgdHkoOO5ESnB-7wkQuBY1MrroC1emLGA6TynMlg=s900-c-k-c0x00ffffff-no-rj"
	shortDescription = "Piston Piston Piston"
	share = None

	examples = {"_":{"text":"Hello World","thumbnail":None}}

	def __init__(self,db, api):
		PistonService.share = self

		print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Piston",PistonService.share)
		self.db = db
		self.api = api
		if "upcoming" not in self.db:
			self.db["upcoming"] = []
		if "users" not in self.db:
			self.db["users"] = {}

	def go(self):
		while(False):
			if "upcoming" not in self.db:
				self.db["upcoming"] = []
			if "users" not in self.db:
				self.db["users"] = {}

			while len(self.db["upcoming"]) > 0:
				item = self.db["upcoming"].pop(0)
				origin, content = item
				self.api.send(origin, content, thumnail = "test")
				# self.api.backup(self.db)

			time.sleep(1)

	def piston(self,code = "print('Hello World')", data = {"language": "python"}, purl = "https://emkc.org/api/v1/piston/execute"):
		if "source" not in data:
			data["source"] = ""
		data["source"] = code

		print("SENDING DATA:",str(data))
		r = requests.post(purl, data, headers=pheaders)
		if r.status_code == 200:
			out = r.json()
			# out = "".join("".join(r.json()["output"].split("[")[1:])[::-1].split("]")[1:])[::-1]
			return True, out
		return False, r.json()["stdout"]


	def process(self, info):
		origin, user, content = None, None, None
		if "origin" in info:
			origin = info["origin"]
		if "user" in info:
			user = info["user"]
		if "content" in info:
			content = info["content"]

		# if "users" not in self.db:
		# 	self.db["users"] = {}
		#
		# if user not in self.db["users"]:
		# 	self.db["users"][user] = user
		# 	self.api.send(origin, "WELCOME "+user)
		# 	self.backup()
		pre = ""
		if len(content) < 2:
			res, dict = self.piston()
		else:
			res, dict = self.piston(code = content)
			# pre = "X"

		output = dict.pop("output")
		extra = dict

		self.api.send(origin, pre+"Code Finished: "+str(res)+"\n"+output+"\n"+"\n"+str(extra))
		# sendBack = content
		#
		# withLink = True
		# if withLink:
		# 	answer = ":answerid:555"
		# 	myLink = self.api.genLink(origin, answer)
		# 	sendBack += "\n\n"+answer+":\n"+myLink
		#
		# self.db["upcoming"].append([origin, sendBack])


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
