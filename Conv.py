# Conv.py
import json
class Conv():

	userID = -1
	lastTurn = None
	ongoing = False
	fin = {"msg":None,"year":None,"month":None,"day":None,"hour":None,"minute":None}
	tries = 0
	human = []
	manager = []

	def toJSON(self):
		return json.dumps(self, default=lambda o: o.__dict__,
			sort_keys=True, indent=0)

	def dictToConv(d, maxHist = 5):
		userID			= d["userID"]
		lastTurn		= d["lastTurn"]
		ongoing			= d["ongoing"]
		fin				= d["fin"]
		tries		 = d["tries"]
		human_msg	 = d["human_msg"][:maxHist]
		manager_msg = d["manager_msg"][:maxHist]
		return Conv(userID, lastTurn = lastTurn, ongoing = ongoing, fin = fin, tries = tries, human_msg = human_msg, manager_msg = manager_msg)

		# return Conv(id, prefs= prefs, reminders = reminders, remCount = remCount, conv = conv, lastRem = lastRem)


	def __init__(self, userID, lastTurn = None, ongoing = False, fin = {"msg":None,"year":None,"month":None,"day":None,"hour":None,"minute":None}, tries = 0, human_msg = [], manager_msg = []):
		self.userID = userID
		self.lastTurn = lastTurn
		self.ongoing = ongoing
		self.fin = fin
		self.tries = tries
		self.human_msg = human_msg
		self.manager_msg = manager_msg

	def human(self, msg):
		self.human_msg.append(msg)
		self.lastTurn = "human"
		print("@ HUMAN:",msg)
		print()

	def manager(self,msg):
		self.manager_msg.append(msg)
		self.lastTurn = "manager"
		print("@ MANAGER:",msg)
		print()
