# Reminder.py
## check language
## commands
## repeats
from json import JSONEncoder

class Reminder(JSONEncoder):

	id = -1
	userID = -1
	message = "__"
	sendTime = None
	sent = False
	repeat = False
	hasTime = False


	def toJSON(self):
		return json.dumps(self, default=lambda o: o.__dict__,
			sort_keys=True, indent=0)

	def jsonRemsToRems(d):
		D = {"sent":{},"unsent":{}}

		# print("dddddddddddddddddd")
		# print(d)
		# print("dddddddddddddddddd")
		disableHistory = True
		if not disableHistory:
			for u in d["sent"]:
				D["sent"][u] = Reminder.dictToRem(d["sent"][u])
		else:
			D["sent"] = {}
		for u in d["unsent"]:
			D["unsent"][u] = Reminder.dictToRem(d["unsent"][u])

		# print("ddddddddddddddddddDDDD")
		# print(d)
		# print("ddddddddddddddddddDDDd")
		return D

	def dictToRem(d):
		# print("DDDDDDDDDDDDDDDDDD")
		# print(d)
		id			= d["id"]
		userID		= d["userID"]
		message				= d["message"]
		sendTime		 = d["sendTime"]
		if sendTime is not None:
			try:
				sendTime = float(sendTime)
			except :
				pass
		repeat			= d["repeat"]
		return Reminder(id, userID = userID, message = message, sendTime = sendTime, repeat = repeat)

	def __init__(self, id, userID, message, sendTime,repeat = False):
		self.id          = id
		self.userID      = userID
		self.message     = message
		self.sendTime    = sendTime
		self.repeat      = repeat
		self.hasTime     = sendTime is not None

		print("NEW REMINDER CREATED!",self, self.id, self.userID, self.message, self.sendTime, self.repeat, self.hasTime,'\n')
